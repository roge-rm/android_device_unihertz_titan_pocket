/* Read-only, bounded input/LED timing probe for an announced stock test.
 * Sets the clock on its own input fd only; never injects input or writes LEDs.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/input.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <time.h>
#include <unistd.h>

static double monotonic_seconds(void) {
    struct timespec t;
    if (clock_gettime(CLOCK_MONOTONIC, &t)) return -1;
    return t.tv_sec + t.tv_nsec / 1e9;
}

int main(void) {
    setvbuf(stdout, NULL, _IOLBF, 0);
    int input = open("/dev/input/event3", O_RDONLY | O_NONBLOCK);
    if (input < 0) { perror("input open"); return 1; }
    char name[80] = {0};
    int clock_id = CLOCK_MONOTONIC;
    if (ioctl(input, EVIOCGNAME(sizeof(name)), name) < 0 ||
        strcmp(name, "aw9523-key") ||
        ioctl(input, EVIOCSCLOCKID, &clock_id) < 0) {
        fprintf(stderr, "Input identity/clock guard failed\n");
        close(input); return 1;
    }
    int led = open("/sys/class/leds/button-backlight/brightness", O_RDONLY);
    if (led < 0) { perror("LED open"); close(input); return 1; }
    double start = monotonic_seconds();
    if (start < 0) { close(input); close(led); return 1; }
    printf("{\"kind\":\"start\",\"time\":%.6f,\"duration\":40,\"sample_ms\":50}\n", start);
    while (monotonic_seconds() - start < 40) {
        struct input_event event;
        ssize_t count;
        while ((count = read(input, &event, sizeof(event))) == sizeof(event)) {
            if (event.type == EV_KEY || (event.type == EV_SYN && event.code == SYN_DROPPED))
                printf("{\"kind\":\"input\",\"time\":%.6f,\"type\":%u,\"code\":%u,\"value\":%d}\n",
                       event.time.tv_sec + event.time.tv_usec / 1e6,
                       event.type, event.code, event.value);
        }
        if (count < 0 && errno != EAGAIN && errno != EINTR) {
            perror("input read"); close(input); close(led); return 1;
        }
        char value[32] = {0};
        double before = monotonic_seconds();
        ssize_t size = pread(led, value, sizeof(value) - 1, 0);
        double after = monotonic_seconds();
        int brightness;
        if (size <= 0 || sscanf(value, "%d", &brightness) != 1) {
            fprintf(stderr, "LED read failed\n"); close(input); close(led); return 1;
        }
        printf("{\"kind\":\"led\",\"before\":%.6f,\"after\":%.6f,\"value\":%d}\n",
               before, after, brightness);
        usleep(50000);
    }
    printf("{\"kind\":\"stop\",\"time\":%.6f}\n", monotonic_seconds());
    close(input); close(led); return 0;
}
