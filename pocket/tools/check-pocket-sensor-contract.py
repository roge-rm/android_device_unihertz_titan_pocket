#!/usr/bin/env python3
"""Check the sensor hub kernel against the stock vendor sensor HAL contract (SENSORS_PORT.md).

Static only, no phone. Reads the first-boot kernel build (.config, System.map, vmlinux), the 5.10
and official 4.14 sensors-1.0 source, the stock kernel config and the stock vendor
(sensors.mt6771.so, init.sensor_1_0.rc, vendor_file_contexts). Usage: check-pocket-sensor-contract.py [OUT.json]

Checks:
- every symbol in our sensors-1.0 Kconfig has the stock value;
- each hub directory stock builds is built here and its initcall is linked;
- each /dev/m_*_misc the HAL opens exists here exactly when stock builds it, and init and the
  vendor file contexts cover it;
- each sysfs attribute the HAL names is created by our core, or is missing from stock's 4.14 core too;
- /dev/sensorlist is 7 entries of 16 bytes and the HAL reads 112 bytes;
- sensor_event.h, sensor_list.c and hwmsensor.h match stock apart from known 5.10 changes.
"""
import pocket_paths
import hashlib
import json
import os
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
BUILD = pocket_paths.build_root() / 'kernel-firstboot-5.10'
SOURCE = Path(os.environ.get('POCKET_KERNEL_SOURCE', str(ROOT / 'tools/kernel-source/upgrade-5.10')))
STOCK_SRC = ROOT / 'tools/kernel-source/android_kernel_unihertz_titan_pocket-3335ddf5dd7fac4fdba5d5fd451ad6649c51250c'
SENS = 'drivers/misc/mediatek/sensors-1.0'
STOCK_CONFIG = ROOT / 'firmware/installed-20230105/boot/kernel.config'
VENDOR = ROOT / 'firmware/analysis/rootfs/vendor'
HAL = VENDOR / 'lib64/hw/sensors.mt6771.so'
RC = VENDOR / 'etc/init/hw/init.sensor_1_0.rc'
CONTEXTS = VENDOR / 'etc/selinux/vendor_file_contexts'
OBJDUMP = Path.home() / 'Android/Sdk/ndk/28.2.13676358/toolchains/llvm/prebuilt/linux-x86_64/bin/llvm-objdump'
OUT = Path(sys.argv[1]) if len(sys.argv) > 1 else ROOT / 'evidence/sensors/sensor-contract-check.json'

# Misc device the HAL opens -> (core config, core directory, sysfs prefix). hmdy and pedo have no
# core in the stock tree (their Kconfig lines are commented out), so stock never had them.
MISC = {
    'm_acc_misc': ('CUSTOM_KERNEL_ACCELEROMETER', 'accelerometer', 'acc'),
    'm_gyro_misc': ('CUSTOM_KERNEL_GYROSCOPE', 'gyroscope', 'gyro'),
    'm_mag_misc': ('CUSTOM_KERNEL_MAGNETOMETER', 'magnetometer', 'mag'),
    'm_als_misc': ('CUSTOM_KERNEL_ALSPS', 'alsps', 'als'),
    'm_ps_misc': ('CUSTOM_KERNEL_ALSPS', 'alsps', 'ps'),
    'm_baro_misc': ('CUSTOM_KERNEL_BAROMETER', 'barometer', 'baro'),
    'm_act_misc': ('CUSTOM_KERNEL_ACTIVITY_SENSOR', 'activity_sensor', 'act'),
    'm_situ_misc': ('CUSTOM_KERNEL_SITUATION', 'situation', 'situ'),
    'm_step_c_misc': ('CUSTOM_KERNEL_STEP_COUNTER', 'step_counter', 'step_c'),
    'm_fusion_misc': ('CUSTOM_KERNEL_SENSOR_FUSION', 'sensorfusion', 'fusion'),
    'm_bio_misc': ('CUSTOM_KERNEL_BIOMETRIC_SENSOR', 'biometric', 'bio'),
    'm_hmdy_misc': (None, 'humidity', 'hmdy'),
    'm_pedo_misc': (None, 'pedometer', 'pedo'),
}
ATTR_SUFFIXES = ('enablenodata', 'active', 'delay', 'batch', 'flush', 'cali', 'devnum', 'libinfo', 'dev')


def sha(p):
    return hashlib.sha256(Path(p).read_bytes()).hexdigest()


def config(path):
    out = {}
    for line in Path(path).read_text().splitlines():
        m = re.match(r'CONFIG_(\w+)=(.*)', line) or re.match(r'# CONFIG_(\w+) is not set', line)
        if m:
            out[m.group(1)] = m.group(2) if m.lastindex == 2 else 'n'
    return out


def kconfig_symbols(top):
    syms, todo = [], [top]
    while todo:
        k = todo.pop()
        text = k.read_text()
        syms += re.findall(r'^config (\w+)', text, re.M)
        todo += [SOURCE / s for s in re.findall(r'^source "([^"]+)"', text, re.M)]
    return syms


def attrs(core_dir, prefix):
    found = set()
    for c in core_dir.glob('*.c'):
        for name in re.findall(r'DEVICE_ATTR(?:_RW|_RO|_WO)?\((\w+)', c.read_text()):
            if name.startswith(prefix):
                found.add(name)
    return found


def main():
    fail, res = [], {}
    ours, stock = config(BUILD / '.config'), config(STOCK_CONFIG)
    smap = (BUILD / 'System.map').read_text()
    vml = (BUILD / 'vmlinux').read_bytes()
    hal = HAL.read_bytes()

    # 1. Kconfig values as stock
    syms = ['MTK_SENSOR_SUPPORT', 'MTK_SENSOR_ARCHITECTURE'] + kconfig_symbols(SOURCE / SENS / 'Kconfig')
    diff = {s: [stock.get(s, 'n'), ours.get(s, 'n')] for s in syms if stock.get(s, 'n') != ours.get(s, 'n')}
    res['config'] = {'symbols': len(syms), 'differ_from_stock': diff}
    if diff:
        fail.append('config')

    # 2. Hub directories stock builds are built and linked
    hubs = {}
    for mk in sorted((SOURCE / SENS).glob('*/Makefile')):
        for cfg, sub in re.findall(r'^obj-\$\(CONFIG_(\w+)\)\s*\+=\s*(\w+)/', mk.read_text(), re.M):
            d = mk.parent / sub
            inits = []
            for c in d.glob('*.c'):
                inits += re.findall(r'^(?:module_init|late_initcall)\((\w+)\)', c.read_text(), re.M)
            want = stock.get(cfg, 'n') == 'y'
            linked = {f: bool(re.search(r'^[0-9a-f]+ [tT] ' + re.escape(f) + r'$', smap, re.M)) for f in inits}
            hubs[f'{mk.parent.name}/{sub}'] = {'config': cfg, 'stock': want, 'ours': ours.get(cfg, 'n') == 'y', 'initcalls': linked}
            if want != (ours.get(cfg, 'n') == 'y') or (want and not (linked and all(linked.values()))):
                fail.append('hub ' + sub)
    res['hubs'] = hubs

    # 3. Misc devices, init and file contexts
    rc, ctx = RC.read_text(), CONTEXTS.read_text()
    misc = {}
    for name, (cfg, core, prefix) in MISC.items():
        opened = ('/dev/' + name).encode() + b'\0' in hal
        stock_on = bool(cfg) and stock.get(cfg, 'n') == 'y'
        ours_on = bool(cfg) and ours.get(cfg, 'n') == 'y'
        built = ours_on and (name.encode() + b'\0') in vml
        row = {'hal_opens': opened, 'stock': stock_on, 'ours': built,
               'init_rc': f'/dev/{name}' in rc, 'file_context': re.search(r'^/dev/' + name + r'\b', ctx, re.M) is not None}
        if stock_on:
            ours_attrs = attrs(SOURCE / SENS / core, prefix)
            stock_attrs = attrs(STOCK_SRC / SENS / core, prefix)
            hal_attrs = {a.decode() for a in re.findall(rb'\0(' + prefix.encode() + rb'(?:' + b'|'.join(s.encode() for s in ATTR_SUFFIXES) + rb'))\0', hal)}
            missing = sorted(hal_attrs - ours_attrs)
            row.update({'attrs': sorted(ours_attrs), 'hal_attrs_missing': missing,
                        'missing_on_stock_too': not set(missing) & stock_attrs})
            if ours_attrs != stock_attrs or not row['missing_on_stock_too']:
                fail.append('attrs ' + name)
        if stock_on != built or (opened and stock_on and not (row['init_rc'] and row['file_context'])):
            fail.append('misc ' + name)
        misc[name] = row
    res['misc'] = misc

    # 4. /dev/sensorlist size and the HAL read
    sl = (SOURCE / SENS / 'hwmon/sensor_list/sensor_list.c').read_text()
    enum = re.search(r'enum \{\s*(.*?)maxhandle', sl, re.S).group(1)
    handles = [h.strip() for h in enum.split(',') if h.strip()]
    entry = int(re.search(r'struct sensorlist_info_t \{\s*char name\[(\d+)\];', sl).group(1))
    dis = subprocess.run([str(OBJDUMP), '-d', '--no-show-raw-insn', str(HAL)], capture_output=True, text=True, check=True).stdout
    ctor = re.search(r'<_ZN10SensorListC2Ev>:\n(.*?)\n\n', dis, re.S).group(1)
    reads = re.findall(r'mov\s+w2, #0x([0-9a-f]+)\s.*\n.*bl\s+\S+ <read@plt>', ctor)
    res['sensorlist'] = {'handles': handles, 'entry_bytes': entry, 'kernel_bytes': len(handles) * entry,
                         'hal_read_bytes': [int(r, 16) for r in reads],
                         'hal_custom_lib': 'libsensor_custom.so' if b'libsensor_custom.so\0' in hal else None,
                         'custom_lib_shipped': any(VENDOR.parent.rglob('libsensor_custom.so'))}
    if handles != ['accel', 'gyro', 'mag', 'als', 'ps', 'baro', 'sar'] or entry != 16 or res['sensorlist']['hal_read_bytes'] != [112]:
        fail.append('sensorlist')

    # 5. Headers and files the HAL depends on, against stock
    same = {}
    for rel in ['hwmon/include/sensor_event.h', 'hwmon/include/hwmsensor.h', 'hwmon/include/sensors_io.h',
                'hwmon/sensor_list/sensor_list.c', 'situation/situation.h', 'sensorfusion/fusion.h',
                'step_counter/step_counter.h', 'gyroscope/inc/gyroscope.h', 'magnetometer/inc/mag.h']:
        a, b = (STOCK_SRC / SENS / rel).read_bytes(), (SOURCE / SENS / rel).read_bytes()
        same[rel] = a == b
    # situation.h may differ only on the ws line (5.10 wakeup_source_register)
    sa = (STOCK_SRC / SENS / 'situation/situation.h').read_text().splitlines()
    sb = (SOURCE / SENS / 'situation/situation.h').read_text().splitlines()
    situ_ok = len(sa) == len(sb) and all(x == y or (re.match(r'\s*struct wakeup_source\b.*\bws\[', x) and re.match(r'\s*struct wakeup_source\b.*\bws\[', y))
                                         for x, y in zip(sa, sb))
    res['same_as_stock'] = same
    res['situation_h_only_ws_differs'] = situ_ok
    if not all(v for k, v in same.items() if k != 'situation/situation.h') or not situ_ok:
        fail.append('headers')

    res['inputs'] = {str(p): sha(p) for p in [BUILD / '.config', BUILD / 'System.map', BUILD / 'vmlinux', HAL, RC, CONTEXTS]}
    res['failures'] = fail
    res['limits'] = ['Static only: SCP CHRE answers, event data, HAL behaviour and SELinux at runtime are untested on the phone']
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(res, indent=1) + '\n')
    for name, row in misc.items():
        print(f"{name:14} hal={row['hal_opens']!s:5} stock={row['stock']!s:5} ours={row['ours']!s:5} missing_attrs={row.get('hal_attrs_missing', '-')}")
    print('hubs built as stock:', sum(1 for h in hubs.values() if h['ours'] == h['stock']), 'of', len(hubs))
    print('sensorlist:', res['sensorlist'])
    print('config differs:', diff or 'none')
    print('sensor contract check:', 'FAIL ' + ', '.join(fail) if fail else 'pass')
    raise SystemExit(1 if fail else 0)


if __name__ == '__main__':
    main()
