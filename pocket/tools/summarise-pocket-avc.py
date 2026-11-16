#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Summarise SELinux denials from dmesg and logcat captures.

A denial is keyed on (scontext type, tcontext type, tclass, permission set); pid, inode,
name, path, comm and property names are dropped. Plain or gzip files are read, and lines
without "avc: denied" are skipped. Each key shows its line count, the number of files it
was seen in and a bucket id from SELINUX_ENFORCING.md ("?" when no rule matches).
--previous takes an earlier capture set and lists keys that are new or gone.
Reads only the files named; writes only --json when given.
"""
import argparse
import collections
import gzip
import json
from pathlib import Path
import re
import sys

AVC = re.compile(r'avc:\s+denied\s+\{([^}]*)\}.*?scontext=u:r:([\w]+):s0[^ ]*\s+tcontext=u:object_r:([\w]+):s0[^ ]*\s+tclass=(\w+)')
AVC_ANY_T = re.compile(r'avc:\s+denied\s+\{([^}]*)\}.*?scontext=u:r:([\w]+):s0[^ ]*\s+tcontext=u:[rs]:([\w]+):s0[^ ]*\s+tclass=(\w+)')

# First match wins. (bucket, source set or None, target set or None, class set or None)
RULES = [
    ('3a', None, {'sysfs_mm'}, {'dir'}),
    ('1a', {'kernel'}, {'device', 'configfs'}, {'dir', 'chr_file', 'blk_file'}),
    ('7', {'kernel'}, {'kernel'}, {'capability'}),
    ('7', {'nfc'}, {'nfc_vendor_data_file'}, None),
    ('1b', {'system_suspend'}, {'sysfs', 'sysfs_batteryinfo', 'sysfs_rtc'}, {'file'}),
    ('1c', {'init'}, {'sysfs_devices_block'}, None),
    ('1d', {'wlan_assistant'}, None, None),
    ('3b', {'surfaceflinger'}, {'hidl_memory_hwservice', 'hal_allocator_default'}, None),
    ('3c', {'vendor_init'}, {'system_prop', 'vts_status_prop', 'init_service_status_private_prop'}, {'file'}),
    ('3d', None, {'aac_drc_prop', 'camera_config_prop'}, None),
    ('4a', {'hal_power_pocket'}, None, None),
    ('4a', {'servicemanager'}, {'hal_power_pocket'}, None),
    ('4b', {'hal_audio_sysbta'}, None, None),
    ('6a', {'vendor_init'}, {'device'}, {'file'}),
    ('6b', {'kcmdlinectrl', 'misctrl'}, {'para_block_device'}, None),
    ('2a', {'nvram_daemon', 'fuelgauged_nvram', 'ccci_mdinit', 'mtk_hal_bluetooth'},
     {'proc_cmdline', 'sysfs_dt_firmware_android', 'gsi_metadata_file'}, None),
    ('2d', {'init'}, {'socket_device'}, {'sock_file'}),
    ('2c', None, {'default_prop'}, {'file'}),
    ('5', {'vendor_init'}, {'build_bootimage_prop'}, None),
    ('5', {'mediacodec'}, {'dalvik_dynamic_config_prop'}, None),
    ('5', {'rild', 'bip'}, {'radio_cdma_ecm_prop', 'vendor_default_prop', 'net_dns_prop'}, None),
    ('5', {'surfaceflinger', 'cameraserver', 'audioserver', 'untrusted_app'}, {'vendor_default_prop'}, None),
    ('5', {'system_server', 'system_app'}, {'default_android_service'}, None),
    ('5', {'isolated_app', 'secure_element'}, None, None),
    ('2e', {'system_server'}, {'tkcore_systa_file'}, None),
    ('2e', {'vendor_init'}, {'nfc_data_file', 'proc', 'proc_dirty'}, None),
    ('2b', None, {'sysfs_boot_mode', 'sysfs_boot_info', 'proc_version', 'vendor_mtk_sec_video_path_support_prop'}, None),
]


def bucket(s, t, c):
    for b, ss, ts, cs in RULES:
        if (ss is None or s in ss) and (ts is None or t in ts) and (cs is None or c in cs):
            return b
    return '?'


def read(path):
    p = Path(path)
    op = gzip.open if p.suffix == '.gz' else open
    with op(p, 'rt', errors='replace') as f:
        yield from f


def scan(paths):
    """Return {key: [lines, set of files]} for the files."""
    out = {}
    for path in paths:
        for line in read(path):
            if 'avc:' not in line or 'denied' not in line:
                continue
            m = AVC.search(line) or AVC_ANY_T.search(line)
            if not m:
                continue
            perms, s, t, c = m.groups()
            key = (s, t, c, ' '.join(sorted(perms.split())))
            e = out.setdefault(key, [0, set()])
            e[0] += 1
            e[1].add(Path(path).name)
    return out


def fmt(key):
    return f'{key[0]} {key[1]}:{key[2]} {{ {key[3]} }}'


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('files', nargs='+', type=Path, help='dmesg or logcat captures, plain or .gz')
    ap.add_argument('--previous', nargs='+', type=Path, help='earlier captures to diff against')
    ap.add_argument('--json', type=Path, help='also write the result here')
    a = ap.parse_args()
    cur = scan(a.files)
    rows = [dict(bucket=bucket(*k[:3]), source=k[0], target=k[1], tclass=k[2], perms=k[3].split(),
                 lines=v[0], files=sorted(v[1])) for k, v in cur.items()]
    rows.sort(key=lambda r: (r['bucket'], -r['lines'], r['source'], r['target']))
    result = dict(files=[str(f) for f in a.files], unique=len(rows), lines=sum(r['lines'] for r in rows),
                  buckets=collections.Counter(r['bucket'] for r in rows), keys=rows)
    print(f'{result["unique"]} unique keys, {result["lines"]} lines')
    for b, n in sorted(result['buckets'].items()):
        print(f'  bucket {b}: {n} keys, {sum(r["lines"] for r in rows if r["bucket"] == b)} lines')
    for r in rows:
        print(f'{r["bucket"]:>3} {r["lines"]:5} {fmt((r["source"], r["target"], r["tclass"], " ".join(r["perms"])))}')
    if a.previous:
        prev = scan(a.previous)
        new = sorted(set(cur) - set(prev))
        gone = sorted(set(prev) - set(cur))
        result['previous'] = dict(files=[str(f) for f in a.previous], unique=len(prev),
                                  new=[dict(key=fmt(k), bucket=bucket(*k[:3]), lines=cur[k][0]) for k in new],
                                  gone=[dict(key=fmt(k), bucket=bucket(*k[:3]), lines=prev[k][0]) for k in gone])
        print(f'\nvs previous ({len(prev)} keys): {len(new)} new, {len(gone)} gone')
        for k in new:
            print(f'  new  {bucket(*k[:3]):>3} {cur[k][0]:5} {fmt(k)}')
        for k in gone:
            print(f'  gone {bucket(*k[:3]):>3} {prev[k][0]:5} {fmt(k)}')
    if a.json:
        a.json.write_text(json.dumps(result, indent=1) + '\n')


if __name__ == '__main__':
    sys.exit(main())
