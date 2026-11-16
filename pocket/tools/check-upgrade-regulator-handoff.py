#!/usr/bin/env python3
"""Compile actual regulator cleanup/setup callbacks against event-recording mocks.

Host evidence only: this does not establish rail voltages, PMIC correctness,
consumer safety, or successful boot on hardware.
"""
import pocket_paths
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess

ROOT = Path(__file__).resolve().parent.parent
OUT = pocket_paths.build_root()/'artifacts/diagnostic-5.10/regulator-handoff-check'


def function(source, name):
    import re
    match = re.search(r'^static (?:int|void)(?: __init)? ' + name + r'\(', source, re.M)
    assert match, name
    begin = source.index('{', match.start())
    depth, end = 1, begin + 1
    while depth:
        depth += (source[end] == '{') - (source[end] == '}')
        end += 1
    return source[match.start():end]


def main():
    path = ROOT / 'tools/kernel-source/upgrade-5.10/drivers/regulator/core.c'
    source = path.read_text()
    setup_start = source.index('#ifdef CONFIG_DEBUG_KERNEL\n/* Diagnostic only:')
    setup_end = source.index('#endif', setup_start) + len('#endif')
    setup = source[setup_start:setup_end]
    assert 'static bool regulator_ignore_unused;' in setup
    assert '__initdata' not in setup  # delayed work can outlive init memory
    work = function(source, 'regulator_init_complete_work_function')
    start = work.index('#ifdef CONFIG_DEBUG_KERNEL')
    end = work.index('#endif', start) + len('#endif')
    assert work.index('regulator_register_resolve_supply') < start
    assert end < work.index('regulator_late_cleanup')
    # Control callback is the actual work function with only the new guard removed.
    control = (work[:start] + work[end:]).replace(
        'regulator_init_complete_work_function', 'control_work_function', 1)
    code = r'''
#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#define __init
#define REGULATOR_CHANGE_STATUS 1
#define ERR_PTR(x) (x)
struct regulation_constraints { bool always_on; };
struct regulator_dev {
    struct regulation_constraints *constraints;
    int use_count, valid, enabled, disable_error, supply_error, id;
};
struct device { struct regulator_dev *rdev; };
struct work_struct { int unused; };
static int regulator_class, full, rail_count = 2;
static struct regulator_dev rails[2];
static struct device devices[2];
static char events[4096];
static unsigned event_count, disables, resolutions, warnings;
static void event(char kind, int id) {
    assert(event_count + 2 < sizeof(events));
    events[event_count++] = kind;
    events[event_count++] = '0' + id;
    events[event_count] = 0;
}
static struct regulator_dev *dev_to_rdev(struct device *d) { return d->rdev; }
static bool regulator_ops_is_valid(struct regulator_dev *r, int op) {
    assert(op == REGULATOR_CHANGE_STATUS); event('v', r->id); return r->valid;
}
static void regulator_lock(struct regulator_dev *r) { event('l', r->id); }
static void regulator_unlock(struct regulator_dev *r) { event('u', r->id); }
static int _regulator_is_enabled(struct regulator_dev *r) {
    event('s', r->id); return r->enabled;
}
static bool have_full_constraints(void) { event('f', 0); return full; }
static int _regulator_do_disable(struct regulator_dev *r) {
    event('d', r->id); disables++; return r->disable_error;
}
static int regulator_resolve_supply(struct regulator_dev *r) {
    event('r', r->id); resolutions++; return r->supply_error;
}
#define rdev_info(r, ...) event('i', (r)->id)
#define rdev_err(r, ...) event('e', (r)->id)
#define rdev_warn(r, ...) event('w', (r)->id)
#define rdev_dbg(r, ...) event('b', (r)->id)
#ifdef CONFIG_DEBUG_KERNEL
static void log_warning(const char *msg) {
    assert(strcmp(msg, "regulator: Not disabling unused regulators\n") == 0);
    event('W', 0); warnings++;
}
#define pr_warn(...) log_warning(__VA_ARGS__)
static const char *bootarg_name;
static int (*bootarg_handler)(char *);
#define __setup(name, handler) \
    static void register_setup(void) { bootarg_name = name; bootarg_handler = handler; }
#else
#define register_setup() ((void)0)
#endif
/* __setup registers a prefix handler in Linux; exercise the extracted handler
 * through that registration, with both bare and =1 command-line tokens. */
static int parse_bootarg(const char *token) {
#ifdef CONFIG_DEBUG_KERNEL
    size_t n = strlen(bootarg_name);
    if (!strncmp(token, bootarg_name, n))
        return bootarg_handler((char *)token + n);
#else
    (void)token;
#endif
    return 0;
}
static int class_for_each_device(int *cls, void *start, void *data,
                                 int (*fn)(struct device *, void *)) {
    assert(cls == &regulator_class && start == NULL && data == NULL);
    for (int i = 0; i < rail_count; i++) {
        int ret = fn(&devices[i], data);
        if (ret) return ret;
    }
    return 0;
}
'''
    code += setup + '\n' + function(source, 'regulator_register_resolve_supply')
    code += '\n' + function(source, 'regulator_late_cleanup')
    code += '\n' + work + '\n' + control
    code += r'''
static void clear_events(void) {
    event_count = disables = resolutions = warnings = 0; events[0] = 0;
}
int main(void) {
    struct regulation_constraints c = {0};
    struct work_struct work = {0};
    unsigned cases = 0;
    register_setup();
    for (unsigned bits = 0; bits < 128; bits++) {
        for (int status = -1; status <= 1; status++) {
            for (int boot = 0; boot < 4; boot++) {
                c.always_on = !!(bits & 1);
                full = !!(bits & 16);
                for (int i = 0; i < rail_count; i++) {
                    rails[i] = (struct regulator_dev) {
                        .constraints = bits & 2 ? NULL : &c,
                        .valid = !!(bits & 4), .use_count = !!(bits & 8),
                        .enabled = status, .disable_error = bits & 32 ? -EIO : 0,
                        .supply_error = bits & 64 ? -EPROBE_DEFER : 0, .id = i,
                    };
                    devices[i].rdev = &rails[i];
                }
                clear_events();
                control_work_function(&work);
                char control[sizeof(events)]; strcpy(control, events);
                unsigned control_disables = disables;
#ifdef CONFIG_DEBUG_KERNEL
                regulator_ignore_unused = false;
#endif
                const char *tokens[] = { "", "regulator_ignore_unused",
                    "regulator_ignore_unused=1", "unrelated_argument" };
                int parsed = parse_bootarg(tokens[boot]);
                bool ignored = false;
#ifdef CONFIG_DEBUG_KERNEL
                ignored = boot == 1 || boot == 2;
#endif
                assert(parsed == ignored);
                clear_events();
                regulator_init_complete_work_function(&work);
                assert(resolutions == 2); /* errors don't stop later suppliers */
                if (ignored) {
                    assert(disables == 0 && warnings == 1);
                    assert(!strcmp(events, bits & 64 ? "r0b0r1b1W0" : "r0r1W0"));
                } else {
                    assert(warnings == 0 && disables == control_disables);
                    assert(!strcmp(events, control));
                    bool should_disable = !(bits & 1 && !(bits & 2)) &&
                        (bits & 4) && !(bits & 8) && status > 0 && full;
                    assert(disables == (should_disable ? 2u : 0u));
                }
                cases++;
            }
        }
    }
#ifdef CONFIG_DEBUG_KERNEL
    printf("debug: %u parsed/default, supplier and cleanup/error cases passed\n", cases);
#else
    printf("nondebug: %u unregistered/default and cleanup/error cases passed\n", cases);
#endif
    return 0;
}
'''
    code = code.replace('#define REGULATOR_CHANGE_STATUS 1',
                        '#define REGULATOR_CHANGE_STATUS 1\n#define EPROBE_DEFER 517')
    OUT.mkdir(parents=True, exist_ok=True)
    cpath = OUT / 'check.c'
    cpath.write_text(code)
    compiler = shutil.which(os.environ.get('CC', 'clang'))
    if not compiler and 'CC' not in os.environ:
        ndk = pocket_paths.ndk_bin() / 'clang'
        compiler = str(ndk) if ndk.is_file() else shutil.which('cc')
    assert compiler, 'C compiler unavailable'
    records = []
    for debug in (False, True):
        binary = OUT / ('check-debug' if debug else 'check-nondebug')
        command = [compiler, '-std=c11', '-Wall', '-Wextra', '-Werror',
                   '-Wno-unused-parameter', '-fsanitize=address,undefined', '-g']
        if debug:
            command.append('-DCONFIG_DEBUG_KERNEL')
        command += [str(cpath), '-o', str(binary)]
        subprocess.run(command, check=True)
        result = subprocess.run([str(binary)], check=True, capture_output=True, text=True)
        (OUT / (binary.name + '.stdout.txt')).write_text(result.stdout)
        print(result.stdout, end='')
        records.append({'debug_kernel': debug, 'cases': 1536,
                        'command': command, 'stdout': result.stdout.strip()})
    record = {
        'source': str(path.relative_to(ROOT)),
        'source_sha256': hashlib.sha256(path.read_bytes()).hexdigest(),
        'harness_sha256': hashlib.sha256(cpath.read_bytes()).hexdigest(),
        'artifact_directory': str(OUT), 'results': records,
        'scope': 'Actual source setup, supplier callback, late cleanup and delayed-work callback with mocks; default event traces compared to same callback with new guard removed. No hardware or PMIC/voltage qualification; no enable/voltage operation added. Boot token dispatch mocked, not the kernel command-line parser.',
    }
    evidence = ROOT / 'evidence/kernel-upgrade/regulator-handoff-check.json'
    evidence.parent.mkdir(parents=True, exist_ok=True)
    evidence.write_text(json.dumps(record, indent=2) + '\n')


if __name__ == '__main__':
    main()
