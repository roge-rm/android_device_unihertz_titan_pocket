#!/usr/bin/env python3
"""Host checks of logger command parsing, missing-devtmpfs fallback and timer paths."""
import pocket_paths
import hashlib
import json
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parent.parent


def function(source, name):
    pos = source.index(name + '(')
    start = source.rfind('\n', 0, pos) + 1
    brace = source.index('{', pos)
    end, depth = brace + 1, 1
    while depth:
        depth += (source[end] == '{') - (source[end] == '}')
        end += 1
    return source[start:end]


def main():
    init = ROOT / 'kernel-upgrade/ram-probe/init.c'
    commands = ROOT / 'kernel-upgrade/ram-probe/commands.h'
    text = init.read_text()
    code = r'''
#include <assert.h>
#include <errno.h>
#include <setjmp.h>
#include <stdio.h>
#include <string.h>
#include "commands.h"
#define MS_NOSUID 2
#define PROBE_RETURN_SECONDS 120
#define RB_AUTOBOOT 1
typedef int pid_t;
static int scenario, mounts, nodes, forks, sleeps, reboots, reports, jump_reason;
static jmp_buf jump;
static int directory(const char *path) { assert(!strcmp(path, "/dev")); return scenario == 7 ? -1 : 0; }
static int mock_mount(const char *a, const char *b, const char *type, int flags, const char *opts) {
    (void)a; (void)b; assert(flags == MS_NOSUID && !strcmp(opts, "mode=0755"));
    mounts++;
    assert(!strcmp(type, mounts == 1 ? "devtmpfs" : "tmpfs"));
    if (mounts == 1) {
        if (scenario == 0) return 0;
        errno = scenario == 2 ? EBUSY : ENODEV; return -1;
    }
    if (scenario == 3) { errno = EACCES; return -1; }
    return 0;
}
static int device_node(const char *path, unsigned major_number, unsigned minor_number) {
    static const char *names[] = {"/dev/console", "/dev/null", "/dev/kmsg"};
    static const unsigned majors[] = {5,1,1}, minors[] = {1,3,11};
    assert(nodes < 3 && !strcmp(path,names[nodes]));
    assert(major_number == majors[nodes] && minor_number == minors[nodes]);
    nodes++;
    return scenario >= 4 && scenario <= 6 && nodes == scenario-3 ? -1 : 0;
}
static int mock_fork(void) { forks++; return scenario == 10 ? 123 : scenario == 11 ? 0 : -1; }
static unsigned mock_sleep(unsigned seconds) { assert(seconds == (sleeps ? 1 : 120)); sleeps++; return sleeps == 1 ? 1 : 0; }
static int mock_reboot(int command) { assert(command == RB_AUTOBOOT); reboots++; return -1; }
static void report(const char *message) { assert(message); reports++; }
static void mock_exit(int status) { assert(status == 1); jump_reason = 1; longjmp(jump,1); }
static void mock_pause(void) { jump_reason = 2; longjmp(jump,1); }
#define mount mock_mount
#define fork mock_fork
#define sleep mock_sleep
#define reboot mock_reboot
#define _exit mock_exit
#define pause mock_pause
'''
    code += function(text, 'setup_devices') + '\n' + function(text, 'return_timer')
    code += r'''
static enum tpdiag_command reference(const unsigned char *line, size_t size) {
    if (size > 31 || memchr(line,0,size)) return TPDIAG_NONE;
    if (size && line[size-1] == '\r') size--;
    if (size == 6 && !memcmp(line,"reboot",6)) return TPDIAG_REBOOT;
    if (size == 17 && !memcmp(line,"reboot-bootloader",17)) return TPDIAG_BOOTLOADER;
    return TPDIAG_NONE;
}
int main(void) {
    unsigned cases = 0;
    const char *lines[] = {"reboot", "reboot-bootloader", "reboot\r", "reboot-bootloader\r", "", " reboot", "reboot ", "REBOOT", "shell", "reboot;id"};
    struct tpdiag_parser parser = {0};
    for (unsigned pass=0;pass<100;pass++) for (unsigned i=0;i<sizeof(lines)/sizeof(lines[0]);i++) {
        size_t size = strlen(lines[i]);
        for (size_t j=0;j<size;j++) assert(tpdiag_feed(&parser,lines[i][j]) == TPDIAG_NONE);
        assert(tpdiag_feed(&parser,'\n') == reference((const unsigned char *)lines[i],size)); cases++;
    }
    for (unsigned size=0;size<256;size++) {
        unsigned char line[256]; memset(line,'x',sizeof(line));
        if (size >= 6) memcpy(line,"reboot",6);
        for (unsigned j=0;j<size;j++) assert(tpdiag_feed(&parser,line[j]) == TPDIAG_NONE);
        assert(tpdiag_feed(&parser,'\n') == reference(line,size)); cases++;
    }
    const unsigned char invalid[] = {'r','e','b','o','o','t',0,'x'};
    for (unsigned i=0;i<sizeof(invalid);i++) assert(tpdiag_feed(&parser,invalid[i]) == TPDIAG_NONE);
    assert(tpdiag_feed(&parser,'\n') == TPDIAG_NONE); cases++;
    for (scenario=0;scenario<8;scenario++) {
        mounts=nodes=0; int result=setup_devices();
        assert(result == (scenario >= 3 ? -1 : 0));
        if (scenario==0 || scenario==2) assert(mounts==1 && nodes==3);
        if (scenario==1) assert(mounts==2 && nodes==3);
        if (scenario==3) assert(mounts==2 && nodes==0);
        if (scenario>=4 && scenario<=6) assert(mounts==2 && nodes==scenario-3);
        if (scenario==7) assert(mounts==0 && nodes==0);
    }
    for (scenario=10;scenario<13;scenario++) {
        forks=sleeps=reboots=reports=jump_reason=0;
        if (!setjmp(jump)) return_timer();
        assert(forks==1);
        if (scenario==10) assert(sleeps==0 && reboots==0 && jump_reason==0);
        if (scenario==11) assert(sleeps==2 && reboots==1 && reports==1 && jump_reason==1);
        if (scenario==12) assert(sleeps==0 && reboots==1 && reports==1 && jump_reason==2);
    }
    printf("%u command cases, 8 device-filesystem cases and 3 return-timer paths passed\n",cases);
    return 0;
}
'''
    output = ROOT / 'artifacts/kernel-upgrade/recovery-logger-check'
    output.mkdir(parents=True, exist_ok=True)
    (output / 'check.c').write_text(code)
    clang = str(pocket_paths.ndk_bin() / 'clang')
    subprocess.run([clang, '-Wall', '-Wextra', '-Werror', '-fsanitize=address,undefined',
                    '-I' + str(commands.parent), str(output / 'check.c'), '-o', str(output / 'check')], check=True)
    result = subprocess.run([str(output / 'check')], capture_output=True, text=True)
    if result.returncode:
        raise RuntimeError(result.stderr)
    record = {'result': result.stdout.strip(),
              'inputs': [{'path': str(p.relative_to(ROOT)), 'sha256': hashlib.sha256(p.read_bytes()).hexdigest()}
                         for p in [init, commands]],
              'scope': 'Real source functions with mocked mount/device/reboot/fork calls; no target execution or actual host mount/reboot'}
    (ROOT / 'evidence/kernel-upgrade/recovery-probe-preparation/logger-host-check.json').write_text(json.dumps(record, indent=2) + '\n')
    print(result.stdout, end='')


if __name__ == '__main__':
    main()
