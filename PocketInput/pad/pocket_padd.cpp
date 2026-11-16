// SPDX-License-Identifier: Apache-2.0
// Swipe scroll for the keyboard touchpad. Reads the mtk-pad evdev node and
// sends one-finger drags through a uinput touchscreen on the internal display.
// InputReader keeps the real pad disabled (see mtk-pad.idc), so nothing else
// acts on its events. init starts this only while persist.sys.pocket.pad_scroll=1.
//
// It also publishes sys.pocket.pad_guard: "drag START" while a drag is live,
// "lift START END" after it and empty when idle at start and exit. Times are
// CLOCK_MONOTONIC milliseconds, the clock of SystemClock.uptimeMillis. The Pocket IME runtime reads it to drop letter
// keys during and just after a drag.

#include <dirent.h>
#include <fcntl.h>
#include <linux/input.h>
#include <linux/uinput.h>
#include <poll.h>
#include <signal.h>
#include <sys/ioctl.h>
#include <time.h>
#include <unistd.h>

#include <cerrno>
#include <cstring>
#include <string>

#include <android-base/logging.h>
#include <android-base/properties.h>

#include "pad_gesture.h"

namespace {

constexpr const char* kPadName = "mtk-pad";
constexpr const char* kVirtualName = "pocket-pad-scroll";
constexpr const char* kGuardProp = "sys.pocket.pad_guard";

volatile sig_atomic_t gStop = 0;

void onSignal(int) { gStop = 1; }

long long monotonicMillis() {
    timespec ts{};
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return static_cast<long long>(ts.tv_sec) * 1000 + ts.tv_nsec / 1000000;
}

long long gDragStart = -1;

void guardDrag() {
    gDragStart = monotonicMillis();
    android::base::SetProperty(kGuardProp, "drag " + std::to_string(gDragStart));
}

void guardLift() {
    android::base::SetProperty(kGuardProp, "lift " + std::to_string(gDragStart) + " " +
                                                   std::to_string(monotonicMillis()));
}

int openPad(pocketpad::Geometry* geo) {
    DIR* dir = opendir("/dev/input");
    if (!dir) return -1;
    int found = -1;
    while (dirent* entry = readdir(dir)) {
        if (strncmp(entry->d_name, "event", 5) != 0) continue;
        std::string path = std::string("/dev/input/") + entry->d_name;
        int fd = open(path.c_str(), O_RDONLY | O_CLOEXEC | O_NONBLOCK);
        if (fd < 0) continue;
        char name[64] = {};
        if (ioctl(fd, EVIOCGNAME(sizeof(name) - 1), name) >= 0 && strcmp(name, kPadName) == 0) {
            input_absinfo x{}, y{};
            if (ioctl(fd, EVIOCGABS(ABS_MT_POSITION_X), &x) == 0 && x.maximum > 0)
                geo->padWidth = x.maximum;
            if (ioctl(fd, EVIOCGABS(ABS_MT_POSITION_Y), &y) == 0 && y.maximum > 0)
                geo->padHeight = y.maximum;
            LOG(INFO) << "Reading " << path << ", " << geo->padWidth << "x" << geo->padHeight;
            found = fd;
            break;
        }
        close(fd);
    }
    closedir(dir);
    return found;
}

bool absSetup(int fd, int code, int max) {
    uinput_abs_setup abs{};
    abs.code = code;
    abs.absinfo.minimum = 0;
    abs.absinfo.maximum = max;
    return ioctl(fd, UI_ABS_SETUP, &abs) == 0;
}

int openVirtual(const pocketpad::Geometry& geo) {
    int fd = open("/dev/uinput", O_WRONLY | O_CLOEXEC | O_NONBLOCK);
    if (fd < 0) {
        PLOG(ERROR) << "Can't open /dev/uinput";
        return -1;
    }
    bool ok = ioctl(fd, UI_SET_EVBIT, EV_KEY) == 0 && ioctl(fd, UI_SET_KEYBIT, BTN_TOUCH) == 0 &&
              ioctl(fd, UI_SET_EVBIT, EV_ABS) == 0 && ioctl(fd, UI_SET_PROPBIT, INPUT_PROP_DIRECT) == 0 &&
              absSetup(fd, ABS_X, geo.padWidth) && absSetup(fd, ABS_Y, geo.padHeight) &&
              absSetup(fd, ABS_MT_SLOT, 0) && absSetup(fd, ABS_MT_TRACKING_ID, 0xffff) &&
              absSetup(fd, ABS_MT_POSITION_X, geo.padWidth) &&
              absSetup(fd, ABS_MT_POSITION_Y, geo.padHeight);
    uinput_setup setup{};
    setup.id.bustype = BUS_VIRTUAL;
    strncpy(setup.name, kVirtualName, UINPUT_MAX_NAME_SIZE - 1);
    ok = ok && ioctl(fd, UI_DEV_SETUP, &setup) == 0 && ioctl(fd, UI_DEV_CREATE) == 0;
    if (!ok) {
        PLOG(ERROR) << "Can't create the virtual touchscreen";
        close(fd);
        return -1;
    }
    return fd;
}

void emit(int fd, int type, int code, int value) {
    input_event ev{};
    ev.type = type;
    ev.code = code;
    ev.value = value;
    if (write(fd, &ev, sizeof(ev)) != sizeof(ev)) PLOG(WARNING) << "uinput write";
}

void send(int fd, const std::vector<pocketpad::Output>& out) {
    static int trackingId = 0;
    for (const auto& o : out) {
        emit(fd, EV_ABS, ABS_MT_SLOT, 0);
        if (o.type == pocketpad::Output::UP) {
            emit(fd, EV_ABS, ABS_MT_TRACKING_ID, -1);
            emit(fd, EV_KEY, BTN_TOUCH, 0);
        } else {
            if (o.type == pocketpad::Output::DOWN) {
                trackingId = (trackingId + 1) & 0xffff;
                emit(fd, EV_ABS, ABS_MT_TRACKING_ID, trackingId);
                emit(fd, EV_KEY, BTN_TOUCH, 1);
            }
            emit(fd, EV_ABS, ABS_MT_POSITION_X, o.x);
            emit(fd, EV_ABS, ABS_MT_POSITION_Y, o.y);
            emit(fd, EV_ABS, ABS_X, o.x);
            emit(fd, EV_ABS, ABS_Y, o.y);
        }
        emit(fd, EV_SYN, SYN_REPORT, 0);
        if (o.type == pocketpad::Output::DOWN) guardDrag();
        if (o.type == pocketpad::Output::UP) guardLift();
    }
}

// Reads protocol A frames from the pad until it goes away or we're stopped.
void run(int pad, int out, pocketpad::Gesture& gesture) {
    pocketpad::FingerTracker finger;
    bool dropping = false;
    int x = 0, y = 0;
    input_event events[64];
    while (!gStop) {
        pollfd p{pad, POLLIN, 0};
        int ready = poll(&p, 1, 500);
        if (ready < 0 && errno == EINTR) continue;
        if (ready < 0 || (p.revents & (POLLERR | POLLHUP | POLLNVAL))) return;
        if (ready == 0) continue;
        ssize_t n = read(pad, events, sizeof(events));
        if (n < 0 && (errno == EAGAIN || errno == EINTR)) continue;
        if (n <= 0) return;
        for (size_t i = 0; i < static_cast<size_t>(n) / sizeof(input_event); i++) {
            const input_event& ev = events[i];
            if (ev.type == EV_SYN && ev.code == SYN_DROPPED) {
                // Lost events: end any drag, skip to the next report and
                // read the touch state again.
                send(out, gesture.cancel());
                dropping = true;
            } else if (dropping) {
                if (ev.type != EV_SYN || ev.code != SYN_REPORT) continue;
                dropping = false;
                unsigned char keys[KEY_MAX / 8 + 1] = {};
                finger = pocketpad::FingerTracker();
                if (ioctl(pad, EVIOCGKEY(sizeof(keys)), keys) >= 0) {
                    finger.touch = keys[BTN_TOUCH / 8] & (1 << (BTN_TOUCH % 8));
                    finger.tool = keys[BTN_TOOL_FINGER / 8] & (1 << (BTN_TOOL_FINGER % 8));
                }
                // Tracking id of the pad's current slot, which is the only finger used.
                input_absinfo id = {};
                if (ioctl(pad, EVIOCGABS(ABS_MT_TRACKING_ID), &id) >= 0) finger.trackingId(id.value);
            } else if (ev.type == EV_KEY && (ev.code == BTN_TOUCH || ev.code == BTN_TOOL_FINGER)) {
                finger.key(ev.code == BTN_TOUCH, ev.code == BTN_TOOL_FINGER, ev.value);
            } else if (ev.type == EV_ABS && ev.code == ABS_MT_TRACKING_ID) {
                finger.trackingId(ev.value);
            } else if (ev.type == EV_ABS && ev.code == ABS_MT_POSITION_X) {
                x = ev.value;
            } else if (ev.type == EV_ABS && ev.code == ABS_MT_POSITION_Y) {
                y = ev.value;
            } else if (ev.type == EV_SYN && ev.code == SYN_REPORT) {
                send(out, gesture.onFrame(finger.down(), x, y));
            }
        }
    }
}

}  // namespace

int main() {
    signal(SIGTERM, onSignal);
    signal(SIGINT, onSignal);
    android::base::SetProperty(kGuardProp, "");
    while (!gStop) {
        pocketpad::Geometry geo;
        int pad = openPad(&geo);
        if (pad < 0) {
            sleep(2);
            continue;
        }
        int out = openVirtual(geo);
        if (out < 0) {
            close(pad);
            // Nothing to retry quickly: log once, then wait so init doesn't restart us in a loop.
            LOG(ERROR) << "No virtual touchscreen, pocket_padd is idle";
            while (!gStop) sleep(3600);
            break;
        }
        pocketpad::Gesture gesture(geo);
        run(pad, out, gesture);
        send(out, gesture.cancel());
        ioctl(out, UI_DEV_DESTROY);
        close(out);
        close(pad);
        if (!gStop) LOG(WARNING) << "Lost " << kPadName << ", looking again";
    }
    android::base::SetProperty(kGuardProp, "");
    return 0;
}
