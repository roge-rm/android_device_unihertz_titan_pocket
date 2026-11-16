#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Offline check of the overlaid vendor image against the stock vendor image (January, or May 2024 for v12 and v13).

Walks both ext4 trees with debugfs and fails unless exactly the intended files
changed, every other inode keeps its number, content, mode, owner, times and
xattrs, and the changed files keep their stock metadata and SELinux label.
Also checks the AVB footer and hashtree, regenerates FEC independently, runs
e2fsck, and parses the new fstab with the rules of the Android 16 libfstab
source. For v2 it also checks the pruned CIL against the composition tool's
prune() and the pinned proposal hashes, the unencrypted /data line, the added trustkernel.rc trigger, and that
every other inode and fstab line equals v1. For v3 it also checks that the
TrustKernel keymaster 4.0 HAL block is the only one gone from the vendor
manifest, the kernel FCM level is 6, its service is disabled, and every other
inode equals v2. For v4 it also checks that the vendor_flash_recovery service is
disabled and every other inode equals v3. For v5 it checks the six connectivity
modules against their build records and the current build output, their
vermagic, the modules.dep and modules.alias entries from their modinfo, the one
added system_app fm_device rule, that firmware, NVRAM and HAL files equal v4,
and that every other inode equals v4. For v6 it checks the v5 module and policy
checks, that the vendor manifest is stock with only the kernel FCM level 6 and the
keymaster rc is stock, and that every other inode equals v5. For v7 it runs the
v6 checks, checks that media_codecs_mediatek_video.xml is stock but for the VP9
decoder's size limit, that power-default.xml is gone, that the modules equal the
current build output, and that every other inode equals v6. For v8 it runs the
v7 checks, checks that build.prop is stock plus the FSC off line at the end, and
that every other inode equals v7. For v9 it runs the v8 checks, checks that the vendor CIL is
v8 with mtk_hal_power out of hal_power_server and exactly the listed M3 lines added, that
vendor_file_contexts is stock plus the bip and wfca socket lines, that init.mt6771.rc also
lacks the schedtune lines, that the fuelgauged rc is stock plus oneshot, and that every
other inode equals v8. For v10 it runs the v9 checks, checks that the vendor CIL is v9 plus exactly
the listed M7 lines, that vendor_file_contexts is v9 plus the wakeup source lines, and that
every other inode equals v9. For v11 it runs the v10 checks, checks that camerahalserver.rc is
stock but for the launcher path and its comment, that the launcher and shim equal their build
record and take the stock camerahalserver's and libmtkcam_metastore.so's metadata and labels,
that vendor_file_contexts is v10 plus the launcher line, the vendor CIL equals v10, and that
every other inode equals v10. v12 is v11 on the May 2024 stock, checked against v11 and the
files where May differs from January. For v13 it runs the v12 checks, checks that /bin/teed is
the stock teed patched by build-pocket-teed-shim.py (hash equals the record, libpocketteed.so
first in DT_NEEDED, tee_exec, 0755, group 2000), that /lib64/libpocketteed.so is vendor_file 0644
uid 0 and exports __system_property_get, and that nothing else differs from v12.
Reads only; writes scratch under the output directory and removes it.
"""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys

ROOT = Path(__file__).resolve().parent.parent
SPEC = importlib.util.spec_from_file_location('overlay', ROOT / 'tools/prepare-pocket-vendor-overlay.py')
OV = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(OV)
LIBFSTAB = OV.BOSTON / 'source/system/core/fs_mgr/libfstab/fstab.cpp'
V1_IMAGE = OV.OVERLAY_DIR / 'v1/vendor.img'
V1_SHA256 = '7138db67461149b0674f590da632752616e5d1ea7c7f90ab1b284f19e6c80c79'
V2_IMAGE = OV.OVERLAY_DIR / 'v2/vendor.img'
V2_SHA256 = '33793d7aa76804c80193c21e21dd96700c4a49c6a162361ee64d9d862dd08e77'
V3_IMAGE = OV.OVERLAY_DIR / 'v3/vendor.img'
V3_SHA256 = 'cc6ad504133f89717629564f53005628af0ba056cc263f96c6724daa809b85df'
V4_IMAGE = OV.OVERLAY_DIR / 'v4/vendor.img'
V5_IMAGE = OV.OVERLAY_DIR / 'v5/vendor.img'
V5_SHA256 = None  # v5 is rebuilt in place, so v6 checks the v5 image against its own record instead
V6_IMAGE = OV.OVERLAY_DIR / 'v6/vendor.img'  # also rebuilt in place; v7 checks it against its record
V7_IMAGE = OV.OVERLAY_DIR / 'v7/vendor.img'  # also rebuilt in place; v8 checks it against its record
V8_IMAGE = OV.OVERLAY_DIR / 'v8/vendor.img'  # also rebuilt in place; v9 checks it against its record
V9_IMAGE = OV.OVERLAY_DIR / 'v9/vendor.img'  # also rebuilt in place; v10 checks it against its record
V11_IMAGE = OV.OVERLAY_DIR / 'v11/vendor.img'  # v12 checks it against its record
V12_IMAGE = OV.OVERLAY_DIR / 'v12/vendor.img'  # v13 checks it against its record
V10_IMAGE = OV.OVERLAY_DIR / 'v10/vendor.img'  # also rebuilt in place; v11 checks it against its record
V4_SHA256 = 'e2a230ac4f741b97b93fac56bd076c61c83142a6a0209b0ebbb2155c17bd4a12'

# Independent expectation; the record is checked against it, not trusted.
MODIFIED = {'/etc/fstab.mt6771', '/etc/init/hw/init.mt6771.rc', '/etc/init/hw/init.mt6771.usb.rc',
            '/etc/selinux/plat_pub_versioned.cil', '/etc/selinux/vendor_seapp_contexts',
            '/etc/selinux/vendor_sepolicy.cil'}
ADDED = {'/etc/selinux/genfs_labels_version.txt': '/etc/selinux/plat_sepolicy_vers.txt'}
REMOVED = {f'/etc/selinux/{n}' for n in OV.REMOVE}
FS_SUPER_ALLOWED = ('Free blocks:', 'Free inodes:')


class Report:
    def __init__(self):
        self.checks, self.failures = [], []

    def check(self, name, ok, detail=None):
        self.checks.append({'check': name, 'ok': bool(ok), **({'detail': detail} if detail is not None else {})})
        if not ok:
            self.failures.append(name)


def walk(image):
    """Return {path: mode} for every inode reachable from the root."""
    paths, queue = {'/': '40755'}, ['/']
    while queue:
        batch, queue = queue, []
        out = OV.debugfs(image, [f'ls -p "{d}"' for d in batch])
        for d, (_, text) in zip(batch, out):
            for line in text.splitlines():
                parts = line.split('/')
                if len(parts) < 8 or parts[5] in ('.', '..'):
                    continue
                path = (d.rstrip('/') + '/' + parts[5])
                mode = parts[2].lstrip('0')
                paths[path] = mode
                if mode.startswith('40'):
                    queue.append(path)
    return paths


def content_hashes(image, paths, scratch):
    """sha256 of every regular file, dumped in one debugfs session."""
    scratch.mkdir(parents=True)
    files = [p for p, m in paths.items() if m.startswith('100')]
    cmds = [f'dump "{p}" "{scratch / str(i)}"' for i, p in enumerate(files)]
    for start in range(0, len(cmds), 400):
        OV.debugfs(image, cmds[start:start + 400])
    out = {}
    for i, p in enumerate(files):
        out[p] = OV.sha256(scratch / str(i))
        (scratch / str(i)).unlink()
    scratch.rmdir()
    return out


def read_file(image, path, scratch):
    dest = scratch / 'read.bin'
    data = OV.dump(image, path, dest)
    dest.unlink()
    return data


# Android fstab rules, taken from the libfstab source that ships with Android 16.
def fstab_rules(source):
    text = source.read_text()
    mount = re.findall(r'\{"(\w+)", (?:MS_\w+|0)\}', text[text.index('kMountFlagsList'):text.index('};', text.index('kMountFlagsList'))])
    body = text[text.index('bool ParseFsMgrFlags'):text.index('bool IsDtFstabCompatible')]
    booleans = re.findall(r'CheckFlag\("([^"]+)", \w+\);', body)
    prefixes = re.findall(r'StartsWith\(flag, "([^"]+)"\)', body)
    exact = re.findall(r'flag == "([^"]+)"', body)
    rejected = re.findall(r'StartsWith\(flag, "([^"]+)"\)(?: \|\| StartsWith\(flag, "([^"]+)"\))?\) \{\n\s+LERROR << "flag no longer supported', body)
    rejected = {x for pair in rejected for x in pair if x}
    return {'mount_flags': mount, 'booleans': booleans, 'prefixes': prefixes, 'exact': exact,
            'rejected': sorted(rejected), 'source_sha256': OV.sha256(source)}


def parse_fstab(text, rules):
    """Parse like ParseFstabFromString. Unknown flags go to warnings, as on device."""
    entries, errors, warnings = [], [], []
    for n, line in enumerate(text.split('\n'), 1):
        fields = line.replace('\t', ' ').split()
        if not fields or fields[0].startswith('#'):
            continue
        if len(fields) < 5:
            errors.append(f'line {n}: expected 5 fields, got {len(fields)}')
            continue
        e = {'line': n, 'blk_device': fields[0], 'mount_point': fields[1], 'fs_type': fields[2],
             'mount_flags': [], 'fs_options': [], 'fs_mgr_flags': [], 'args': {}}
        for flag in fields[3].split(','):
            (e['mount_flags'] if flag in rules['mount_flags'] else e['fs_options']).append(flag)
        for flag in fields[4].split(','):
            if not flag or flag == 'defaults':
                continue
            if flag in rules['booleans'] or flag in rules['exact']:
                e['fs_mgr_flags'].append(flag)
                continue
            prefix = next((p for p in rules['prefixes'] if flag.startswith(p)), None)
            if prefix is None:
                warnings.append(f'line {n}: unknown flag {flag}')
            elif prefix in rules['rejected']:
                errors.append(f'line {n}: unsupported flag {flag}')
            else:
                e['args'][prefix.rstrip('=')] = flag.split('=', 1)[1] if '=' in flag else ''
        if 'encryptable' in e['args'] and 'voldmanaged' not in e['args']:
            errors.append(f'line {n}: encryptable without voldmanaged (FDE)')
        entries.append(e)
    if not entries:
        errors.append('no entries')
    return entries, errors, warnings


def cil_types(paths):
    names = set()
    for p in paths:
        names |= set(re.findall(r'^\((?:type|typealias) ([^\s()]+)\)', p.read_text(), re.M))
    return names


def cil_declared(path):
    return set(re.findall(r'^\((?:type|typeattribute|typealias|role|attribute) ([^\s()]+)\)',
                          path.read_text(), re.M))


def v5_checks(r, from_v5, args, record, new_fs, base_fs, base_hash, new_hash, new_paths, new_mods, index_want, scratch,
              bn='v5', extra=()):
    """The v5 modules, their index files, the FM rule and the untouched stock files."""
    rec = record.get('modules', {})
    r.check('module hashes equal the record',
            {m: i['sha256'] for m, i in new_mods.items()} == {m: rec.get(m, {}).get('sha256') for m in OV.CONN_MODULES},
            {m: i['sha256'] for m, i in new_mods.items()})
    try:
        built, symvers = OV.connectivity_modules()
        fresh = {m: i['sha256'] for m, i in built.items()} == {m: i['sha256'] for m, i in new_mods.items()}
        detail = {'kernel_module_symvers_sha256': symvers, 'stale': sorted(
            m for m in built if built[m]['sha256'] != new_mods[m]['sha256'])}
        fresh = fresh and record.get('kernel_module_symvers_sha256') == symvers
    except SystemExit as e:
        fresh, detail = False, str(e)
    r.check('modules equal the current build output, built against the current kernel Module.symvers', fresh, detail)
    vm = {m: i['info'].get('vermagic') for m, i in new_mods.items()}
    r.check(f'vermagic of all six is {OV.MODULE_VERMAGIC.split()[0]}',
            all(v == [OV.MODULE_VERMAGIC] for v in vm.values()), vm)
    for path, want in index_want.items():
        got = read_file(new_fs, path, scratch).decode()
        r.check(f'{path.rsplit("/", 1)[1]} matches the modules\' modinfo', got == want,
                {'changed_from_stock': path in record.get('replaced', [])})
    dep = read_file(new_fs, OV.MODULES_DEP, scratch).decode()
    listed = re.findall(rf'{re.escape(OV.DEVICE_MODULE_DIR)}/(\w+)\.ko', dep)
    r.check('modules.dep names only modules present in /lib/modules',
            all(f'{OV.MODULE_DIR}/{m}.ko' in new_paths for m in listed), sorted(set(listed)))
    load = read_file(new_fs, f'{OV.MODULE_DIR}/modules.load', scratch).decode().split()
    r.check('modules.load still lists all six', all(f'{m}.ko' in load for m in OV.CONN_MODULES), load)
    old_cil = read_file(base_fs, f'{OV.SELINUX}/vendor_sepolicy.cil', scratch).decode()
    new_cil = read_file(new_fs, f'{OV.SELINUX}/vendor_sepolicy.cil', scratch).decode().split('\n')
    old_lines = old_cil.split('\n')
    at = old_lines.index(OV.FM_RULE_ANCHOR) if OV.FM_RULE_ANCHOR in old_lines else -1
    if bn == 'v9':
        end = len(old_lines) - 1 if old_lines[-1] == '' else len(old_lines)
        want_cil = old_lines[:end] + OV.M7_CIL_ADDED + old_lines[end:]
        added = [l for l in new_cil if l not in old_lines]
        gone = [l for l in old_lines if l not in new_cil]
        r.check('vendor CIL is v9 with exactly the listed M7 lines appended',
                new_cil == want_cil and not gone and set(added) <= set(OV.M7_CIL_ADDED),
                {'added': added, 'gone': gone})
        r.check('M7 adds no allow rule',
                not [l for l in added if l.startswith('(allow')], None)
    elif bn == 'v8':
        want_cil = OV.overlay_m3_policy(old_cil)[0].split('\n')
        added = [l for l in new_cil if l not in old_lines]
        gone = [l for l in old_lines if l not in new_cil]
        r.check('vendor CIL is v8 with mtk_hal_power out of hal_power_server and the listed M3 lines appended',
                new_cil == want_cil and gone == [OV.HAL_POWER_SERVER_OLD]
                and new_cil[len(old_lines) - 1:len(old_lines) - 1 + len(OV.M3_CIL_ADDED)] == OV.M3_CIL_ADDED,
                {'added': len(added), 'gone': gone})
        r.check('every added CIL line is listed in M3_CIL_ADDED and none adds hal_power_service',
                set(added) - {OV.HAL_POWER_SERVER_NEW} <= set(OV.M3_CIL_ADDED)
                and not [l for l in added if l.startswith('(allow') and 'hal_power_service' in l],
                sorted(set(added) - set(OV.M3_CIL_ADDED)))
        want_m5 = [f'(dontaudit {d} default_prop (file (read getattr map open)))' for d in OV.M5_DEFAULT_PROP_DOMAINS]
        r.check('M5 default_prop dontaudits are present and nothing allows default_prop',
                all(l in added for l in want_m5)
                and not [l for l in added if l.startswith('(allow') and ' default_prop ' in l],
                {'want': want_m5})
    elif from_v5:
        r.check(f'vendor CIL equals {bn}', new_cil == old_lines, [l for l in new_cil if l not in old_lines])
    else:
        r.check('vendor CIL is v4 plus the system_app fm_device rule after the platform_app one',
                at > 0 and new_cil == old_lines[:at + 1] + OV.FM_RULE_ADDED + old_lines[at + 1:],
                [l for l in new_cil if l not in old_lines])
    groups = {'firmware': lambda p: '/firmware/' in p, 'nvram': lambda p: 'nvram' in p.lower(),
              'hal': lambda p: '/hw/' in p or p.startswith('/etc/vintf/')}
    counts, diff = {}, []
    for g, f in groups.items():
        paths = [p for p in base_hash if f(p)]
        counts[g] = len(paths)
        diff += [p for p in paths if new_hash.get(p) != base_hash[p]
                 and not (from_v5 and p == OV.VINTF_MANIFEST) and p not in extra]
    r.check('stock firmware, NVRAM and HAL files equal ' + (f'{bn} (the vendor manifest is checked on its own)' if from_v5 else 'v4'), not diff and all(counts.values()),
            {'files': counts, 'differ': diff[:20]})


def teed_checks(r, OV, old_fs, new_fs, new_meta, new_hash, record, scratch):
    """v13: the patched teed and the teed shim."""
    tool = OV.teed_tool()
    stock = read_file(old_fs, OV.TEED, scratch)
    teed = read_file(new_fs, OV.TEED, scratch)
    shim = read_file(new_fs, OV.TEED_SHIM, scratch)
    rec = record.get('teed_edit', {})
    try:
        regions = tool.check_patched(stock, teed, tool.NAME)
        err = None
    except SystemExit as e:
        regions, err = None, str(e)
    r.check('stock teed is the pinned file and teed is it patched by add_needed() and nothing else',
            OV.sha256_bytes(stock) == tool.TEED_SHA256 and err is None, err or regions)
    needed = tool.needed(teed)
    r.check('teed hash equals the record and libpocketteed.so is its first DT_NEEDED',
            OV.sha256_bytes(teed) == rec.get('sha256') and needed[:1] == [tool.NAME]
            and needed[1:] == tool.needed(stock), needed)
    m = new_meta[OV.TEED]
    label = [x for x in m['xattrs'] if x.startswith('security.selinux')]
    r.check('teed is labelled tee_exec, mode 0755, group 2000',
            len(label) == 1 and 'u:object_r:tee_exec:s0' in label[0] and m['mode'].endswith('0755') and m['gid'] == 2000,
            {'label': label, 'mode': m['mode'], 'gid': m['gid']})
    try:
        fresh = OV.teed_shim()['sha256']
    except SystemExit as e:
        fresh = str(e)
    rec_shim = record.get('teed_shim', {}).get('sha256')
    r.check('teed shim equals the current build output and its record',
            OV.sha256_bytes(shim) == fresh == rec_shim, OV.sha256_bytes(shim))
    m = new_meta[OV.TEED_SHIM]
    label = [x for x in m['xattrs'] if x.startswith('security.selinux')]
    r.check('teed shim is labelled vendor_file, mode 0644, uid 0',
            len(label) == 1 and 'u:object_r:vendor_file:s0' in label[0] and m['mode'].endswith('0644') and m['uid'] == 0,
            {'label': label, 'mode': m['mode'], 'uid': m['uid']})
    f = scratch / 'libpocketteed.so'
    f.write_bytes(shim)
    text = subprocess.run([str(tool.LLVM / 'llvm-readelf'), '--dyn-syms', str(f)], capture_output=True, text=True,
                          check=True).stdout
    exported = sorted({l.split()[-1] for l in text.splitlines() if ' FUNC ' in l and ' GLOBAL ' in l and ' UND ' not in l})
    r.check('teed shim exports __system_property_get', '__system_property_get' in exported, exported)


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument('--version', choices=OV.VERSIONS, default=OV.VERSION)
    ap.add_argument('--image', type=Path)
    ap.add_argument('--v1-image', type=Path, default=V1_IMAGE)
    ap.add_argument('--v2-image', type=Path, default=V2_IMAGE)
    ap.add_argument('--v3-image', type=Path, default=V3_IMAGE)
    ap.add_argument('--v4-image', type=Path, default=V4_IMAGE)
    ap.add_argument('--v5-image', type=Path, default=V5_IMAGE)
    ap.add_argument('--v6-image', type=Path, default=V6_IMAGE)
    ap.add_argument('--v7-image', type=Path, default=V7_IMAGE)
    ap.add_argument('--v8-image', type=Path, default=V8_IMAGE)
    ap.add_argument('--v9-image', type=Path, default=V9_IMAGE)
    ap.add_argument('--v10-image', type=Path, default=V10_IMAGE)
    ap.add_argument('--v11-image', type=Path, default=V11_IMAGE)
    ap.add_argument('--v12-image', type=Path, default=V12_IMAGE)
    ap.add_argument('--composition-record', type=Path, default=OV.COMPOSITION_RECORD)
    ap.add_argument('--stock-vendor', type=Path)
    ap.add_argument('--policy-install', type=Path, default=OV.POLICY_INSTALL)
    ap.add_argument('--policy-handoff', type=Path, default=OV.POLICY_HANDOFF)
    ap.add_argument('--ramdisk-fstab', type=Path, default=OV.RAMDISK_FSTAB)
    ap.add_argument('--libfstab-source', type=Path, default=LIBFSTAB)
    ap.add_argument('--report', type=Path, help='write the JSON report here (refuses overwrite)')
    args = ap.parse_args()
    args.image = args.image or OV.OVERLAY_DIR / args.version / 'vendor.img'
    args.stock_vendor = args.stock_vendor or OV.stock_vendor_for(args.version)[0]
    stock_sha = OV.stock_vendor_for(args.version)[1]
    v2 = args.version in ('v2', 'v3', 'v4', 'v5', 'v6', 'v7', 'v8', 'v9', 'v10', 'v11', 'v12', 'v13')
    v3 = args.version in ('v3', 'v4', 'v5', 'v6', 'v7', 'v8', 'v9', 'v10', 'v11', 'v12', 'v13')
    v4 = args.version in ('v4', 'v5', 'v6', 'v7', 'v8', 'v9', 'v10', 'v11', 'v12', 'v13')
    v5 = args.version in ('v5', 'v6', 'v7', 'v8', 'v9', 'v10', 'v11', 'v12', 'v13')
    v6 = args.version in ('v6', 'v7', 'v8', 'v9', 'v10', 'v11', 'v12', 'v13')
    v7 = args.version in ('v7', 'v8', 'v9', 'v10', 'v11', 'v12', 'v13')
    v8 = args.version in ('v8', 'v9', 'v10', 'v11', 'v12', 'v13')
    v9 = args.version in ('v9', 'v10', 'v11', 'v12', 'v13')
    v10 = args.version in ('v10', 'v11', 'v12', 'v13')
    v11 = args.version in ('v11', 'v12', 'v13')
    v13 = args.version == 'v13'
    cam_added = set(OV.CAM_ADDED) if v11 else set()
    teed_added = {OV.TEED_SHIM} if v13 else set()
    if v11:
        ADDED.update({p: ref for p, (_, ref) in OV.CAM_ADDED.items()})
    if v13:
        ADDED[OV.TEED_SHIM] = OV.TEED_SHIM_REF
    v3_files = {OV.VINTF_MANIFEST, OV.KM_RC}
    # v6 has the stock keymaster rc again, so only the manifest differs from stock.
    v3_stock_diff = {OV.VINTF_MANIFEST} if v6 else v3_files
    v4_files = {OV.FR_RC}
    # modules.dep and modules.alias are added below if regenerating them changes them.
    v5_files = {f'{OV.MODULE_DIR}/{m}.ko' for m in OV.CONN_MODULES} | {f'{OV.SELINUX}/vendor_sepolicy.cil'}
    modified = (MODIFIED | ({OV.TRUSTKERNEL_RC} if v2 else set()) | (v3_stock_diff if v3 else set())
                | (v4_files if v4 else set()) | (v5_files if v5 else set()))
    v7_files = {OV.CODECS_XML}
    # v7 also deletes stock's AIDL IPower declaration.
    gone_v7 = {OV.POWER_VINTF} if v7 else set()
    if v7:
        modified |= v7_files
    v8_files = {OV.BUILD_PROP}
    if v8:
        modified |= v8_files
    # v9: the vendor CIL and init.mt6771.rc are already modified; these two are stock in v8.
    v9_files = {OV.FG_RC, OV.FILE_CONTEXTS, OV.HWSERVICE_CONTEXTS, f'{OV.SELINUX}/vendor_sepolicy.cil', OV.INIT_RC}
    if v9:
        modified |= v9_files
    # v10: only the vendor CIL and the file contexts change from v9.
    v10_files = {OV.FILE_CONTEXTS, f'{OV.SELINUX}/vendor_sepolicy.cil'}
    # v11: camerahalserver.rc and the file contexts, and the two added files.
    v11_files = {OV.CAM_RC, OV.FILE_CONTEXTS}
    if v11:
        modified |= {OV.CAM_RC}
    if v13:
        modified |= {OV.TEED}
    if args.report and args.report.exists():
        raise SystemExit(f'{args.report} exists')

    r = Report()
    out_dir = args.image.parent
    record_path = out_dir / 'record.json'
    record = json.loads(record_path.read_text()) if record_path.exists() else {}
    image_sha = OV.sha256(args.image)
    r.check('stock image is the pinned ' + ('May 2024' if args.version in ('v12', 'v13') else 'January') + ' vendor image', OV.sha256(args.stock_vendor) == stock_sha)
    r.check('image matches its record', record.get('image', {}).get('sha256') == image_sha
            and record.get('version', 'v1') == args.version, image_sha)

    # AVB footer and hashtree.
    stock_info, info = OV.footer(args.stock_vendor), OV.footer(args.image)
    same = {k: (stock_info[k], info[k]) for k in stock_info if k != 'root_digest' and stock_info[k] != info[k]}
    r.check('footer geometry, salt, props and algorithm match stock', not same, same or None)
    r.check('vendor AVB algorithm is NONE', info['algorithm'] == 'NONE')
    v = OV.run([sys.executable, OV.AVBTOOL, 'verify_image', '--image', args.image], env=OV.tool_env(), check=False)
    r.check('avbtool verify_image (hashtree digest)', v.returncode == 0, (v.stdout + v.stderr).strip().splitlines()[-1:])

    scratch = out_dir / 'check-scratch'
    if scratch.exists():
        raise SystemExit(f'{scratch} exists')
    scratch.mkdir()
    try:
        # FEC regenerated by the fec tool from data plus tree must match the image bytes.
        tree_end = info['original_image_size'] + info['tree_size']
        data_tree, fec_out = scratch / 'data-tree.img', scratch / 'fec.bin'
        OV.extract_fs(args.image, data_tree, tree_end)
        OV.run([OV.PREBUILT_BIN / 'fec', '--encode', '--roots', info['fec_num_roots'], data_tree, fec_out])
        with open(args.image, 'rb') as f:
            f.seek(tree_end)
            fec_image = f.read(info['fec_size'])
        r.check('FEC region regenerates identically', fec_out.read_bytes()[:info['fec_size']] == fec_image)
        data_tree.unlink(), fec_out.unlink()

        new_fs, old_fs = scratch / 'new.ext4', scratch / 'old.ext4'
        OV.extract_fs(args.image, new_fs, info['original_image_size'])
        OV.extract_fs(args.stock_vendor, old_fs, stock_info['original_image_size'])
        fsck = OV.run([OV.PREBUILT_BIN / 'e2fsck', '-fn', new_fs], check=False)
        r.check('e2fsck -fn clean', fsck.returncode == 0, fsck.stdout.strip().splitlines()[-1:])

        sb = [OV.debugfs(fs, ['stats -h'])[0][1].splitlines() for fs in (old_fs, new_fs)]
        sb_diff = [(a, b) for a, b in zip(*sb) if a != b and not a.startswith(FS_SUPER_ALLOWED)]
        r.check('superblock unchanged apart from free counts', not sb_diff and len(sb[0]) == len(sb[1]), sb_diff or None)

        # Tree walk.
        old_paths, new_paths = walk(old_fs), walk(new_fs)
        removed = set(old_paths) - set(new_paths)
        added = set(new_paths) - set(old_paths)
        r.check('removed files are exactly the stale precompiled policy' + (' and power-default.xml (v7)' if v7 else ''),
                removed == REMOVED | gone_v7, sorted(removed))
        r.check('added files are exactly the genfs version file' + (' and the camera launcher and shim (v11)' if v11 else '') + (' and the teed shim (v13)' if v13 else ''),
                added == set(ADDED), sorted(added))
        old_hash = content_hashes(old_fs, old_paths, scratch / 'old-files')
        new_hash = content_hashes(new_fs, new_paths, scratch / 'new-files')
        new_mods = {}
        if v5:
            # Expected module index files, from the modinfo of the modules in the image.
            for m in OV.CONN_MODULES:
                data = read_file(new_fs, f'{OV.MODULE_DIR}/{m}.ko', scratch)
                info = OV.modinfo(data)
                new_mods[m] = {'sha256': OV.sha256_bytes(data), 'info': info,
                               'depends': [d for d in info.get('depends', [''])[0].split(',') if d],
                               'alias': info.get('alias', [])}
            index_want = {}
            for path, edit in ((OV.MODULES_DEP, OV.overlay_modules_dep), (OV.MODULES_ALIAS, OV.overlay_modules_alias)):
                stock = read_file(old_fs, path, scratch).decode()
                index_want[path] = edit(stock, new_mods)
                if index_want[path] != stock:
                    v5_files.add(path)
                    modified.add(path)
        changed = {p for p in set(old_hash) & set(new_hash) if old_hash[p] != new_hash[p]}
        r.check('changed content is exactly the intended files', changed == modified, sorted(changed))

        common = sorted(set(old_paths) & set(new_paths))
        old_meta = OV.stat_paths(old_fs, common + sorted(ADDED.values()))
        new_meta = OV.stat_paths(new_fs, common + sorted(ADDED))
        meta_diff = []
        for p in common:
            ignore = {'inode', 'size'} if p in modified else set()
            # Directories holding edited entries may change size if a block was added.
            if p in {x.rsplit('/', 1)[0] or '/' for x in modified | set(ADDED) | REMOVED | gone_v7}:
                ignore = {'size'}
            d = {k: (old_meta[p].get(k), new_meta[p].get(k)) for k in old_meta[p]
                 if k not in ignore and old_meta[p].get(k) != new_meta[p].get(k)}
            if d:
                meta_diff.append({p: d})
        for p, ref in ADDED.items():
            d = {k: (old_meta[ref].get(k), new_meta[p].get(k)) for k in old_meta[ref]
                 if k not in ('inode', 'size') and old_meta[ref].get(k) != new_meta[p].get(k)}
            if d:
                meta_diff.append({p: d})
        r.check('mode, owner, times, flags and xattrs intact (unchanged inodes keep their number)',
                not meta_diff, meta_diff[:20] or None)
        labels = sorted({x for m in new_meta.values() for x in m['xattrs'] if x.startswith('security.selinux')})
        unlabelled = [p for p, m in new_meta.items() if not any(x.startswith('security.selinux') for x in m['xattrs'])]
        r.check('every inode has an SELinux label', not unlabelled, unlabelled[:20] or None)

        # Labels must name types the V14 composition declares.
        install = args.policy_install
        cils = [install / 'system/etc/selinux/plat_sepolicy.cil',
                install / 'system_ext/etc/selinux/system_ext_sepolicy.cil',
                install / 'vendor/etc/selinux/vendor_sepolicy.cil']
        types = cil_types(cils)
        label_types = {re.search(r'u:object_r:([^:]+):s0', l)[1] for l in labels}
        r.check('all file labels are declared types in the V14 composition',
                label_types <= types, sorted(label_types - types) or sorted(label_types))

        # Overlay content.
        handoff = json.loads(args.policy_handoff.read_text())
        want = {'/' + k.split('/', 1)[1]: h for k, h in handoff['install_files'].items() if k.startswith('vendor/')}
        if v2:
            want.update({f'{OV.SELINUX}/{n}': h for n, h in OV.PRUNED.items()})
        if v5:
            # Checked below as the pruned file plus the FM rule.
            del want[f'{OV.SELINUX}/vendor_sepolicy.cil']
        if v9:
            # Checked below against the stock file plus the socket lines.
            del want[OV.FILE_CONTEXTS]
            want.pop(OV.HWSERVICE_CONTEXTS, None)
        bad = {p: new_hash.get(p) for p, h in want.items() if new_hash.get(p) != h}
        r.check('every vendor policy file equals the frozen V14 handoff hash' + (' or the pinned pruned hash' if v2 else ''),
                not bad, bad or None)

        if v2:
            pruned, dropped = OV.pruned_policy(args.policy_install / 'vendor/etc/selinux', args.composition_record)
            got = {n: read_file(new_fs, f'{OV.SELINUX}/{n}', scratch) for n in OV.PRUNED}
            proposal = {n: (OV.COMPOSITION_DIR / n).read_bytes() for n in OV.PRUNED if (OV.COMPOSITION_DIR / n).exists()}
            expect_cil = dict(pruned)
            if v5:
                expect_cil['vendor_sepolicy.cil'] = OV.overlay_fm_policy(pruned['vendor_sepolicy.cil'].decode())[0].encode()
                if v9:
                    expect_cil['vendor_sepolicy.cil'] = OV.overlay_m3_policy(expect_cil['vendor_sepolicy.cil'].decode(), m7=v10)[0].encode()
            r.check('pruned CIL equals prune() of the V14 files and the generated proposal CIL'
                    + (' (v5: vendor CIL plus the FM rule' + (', v9: and the M3 lines' if v9 else '') + (', v10: and the M7 lines' if v10 else '') + ')' if v5 else ''),
                    got == expect_cil and proposal == pruned, {n: OV.sha256_bytes(d) for n, d in got.items()})
            left = {n: sorted(dropped & set(re.findall(r'[\w.]+', d.decode()))) for n, d in got.items()}
            r.check(f'none of the {len(dropped)} dropped names remain in the pruned CIL',
                    not any(left.values()), {n: v for n, v in left.items() if v} or None)
            label_dropped = sorted(label_types & dropped)
            r.check('no file label uses a dropped name', not label_dropped, label_dropped or None)

            # v1 to v3 were deleted in housekeeping; the comparison runs when v1 is still there.
            have_v1 = args.v1_image.exists()
            r.check('v1 comparison run' if have_v1 else 'v1 comparison skipped, v1 image not kept', True,
                    None if have_v1 else str(args.v1_image))
            if have_v1:
                # Everything but the two pruned files equals v1, metadata included.
                r.check('v1 image is the pinned v1 output', OV.sha256(args.v1_image) == V1_SHA256)
                v1_info = OV.footer(args.v1_image)
                v1_fs = scratch / 'v1.ext4'
                OV.extract_fs(args.v1_image, v1_fs, v1_info['original_image_size'])
                v1_paths = walk(v1_fs)
                v1_hash = content_hashes(v1_fs, v1_paths, scratch / 'v1-files')
                v2_paths = {f'{OV.SELINUX}/{n}' for n in OV.PRUNED} | {OV.FSTAB, OV.TRUSTKERNEL_RC}
                if v3:
                    v2_paths |= v3_stock_diff
                if v4:
                    v2_paths |= v4_files
                if v5:
                    v2_paths |= v5_files
                if v7:
                    v2_paths |= v7_files
                if v8:
                    v2_paths |= v8_files
                if v9:
                    v2_paths |= v9_files
                if v11:
                    v2_paths |= {OV.CAM_RC} | cam_added | teed_added | ({OV.TEED} if v13 else set())
                v1_changed = sorted(p for p in set(v1_hash) | set(new_hash) if v1_hash.get(p) != new_hash.get(p))
                v2_paths |= gone_v7
                r.check('content differs from v1 only in the pruned CIL, the fstab and trustkernel.rc'
                        + (' (v3: plus the vendor manifest and keymaster rc)' if v3 else '')
                        + (' (v4: plus the flash recovery rc)' if v4 else '')
                        + (' (v5: plus the modules and the vendor CIL)' if v5 else '')
                        + (' (v7: plus the video codec list)' if v7 else '')
                        + (' (v8: plus build.prop)' if v8 else '')
                        + (' (v9: plus the file contexts and the fuelgauged rc)' if v9 else ''),
                        set(v1_paths) - gone_v7 == set(new_paths) - cam_added - teed_added and set(v1_changed) == v2_paths, v1_changed)
                v1_meta = OV.stat_paths(v1_fs, sorted(v1_paths))
                v1_diff = []
                for p in sorted(set(v1_paths) - gone_v7):
                    # Rewritten files may take another free inode number when v3 adds edits.
                    ignore = {'inode', 'size'} if p in v2_paths or (v3 and p in modified | set(ADDED)) else set()
                    d = {k: (v1_meta[p].get(k), new_meta[p].get(k)) for k in v1_meta[p]
                         if k not in ignore and v1_meta[p].get(k) != new_meta[p].get(k)}
                    if d and not (p in (OV.SELINUX, '/etc', '/etc/init') + ((OV.MODULE_DIR,) if v5 else ())
                                  + (('/etc/vintf/manifest',) if v7 else ()) and set(d) == {'size'}):
                        v1_diff.append({p: d})
                r.check('metadata and labels equal v1 for every inode', not v1_diff, v1_diff[:20] or None)

        if v3:
            # v3 is v2 apart from the two keymaster files, v4 is v3 apart from the flash recovery rc,
            # v5 is v4 apart from the modules and the vendor CIL.
            v12 = args.version == 'v12'
            base_image, base_sha, base_files, bn = ((args.v12_image, None, {OV.TEED, OV.FSTAB} | teed_added, 'v12') if v13
                                                    else (args.v11_image, None, set(), 'v11') if v12
                                                    else (args.v10_image, None, v11_files | cam_added, 'v10') if v11
                                                    else (args.v9_image, None, v10_files, 'v9') if v10
                                                    else (args.v8_image, None, v9_files, 'v8') if v9
                                                    else (args.v7_image, None, v8_files, 'v7') if v8
                                                    else (args.v6_image, None, v7_files, 'v6') if v7
                                                    else (args.v5_image, V5_SHA256, v3_files, 'v5') if v6
                                                    else (args.v4_image, V4_SHA256, v5_files, 'v4') if v5
                                                    else (args.v3_image, V3_SHA256, v4_files, 'v3') if v4
                                                    else (V2_IMAGE, V2_SHA256, v3_files, 'v2'))
            base_what = {'v12': 'patched teed, the teed shim and the fstab', 'v11': 'files where May stock differs from January stock', 'v10': 'camerahalserver.rc, file contexts and the added launcher and shim', 'v9': 'vendor CIL and file contexts', 'v8': 'vendor CIL, file contexts, init.mt6771.rc and the fuelgauged rc', 'v7': 'build.prop', 'v6': 'video codec list', 'v5': 'vendor manifest and keymaster rc', 'v2': 'vendor manifest and keymaster rc', 'v3': 'flash recovery rc',
                         'v4': 'six connectivity modules' + (', module index files' if v5_files - {
                             f'{OV.MODULE_DIR}/{m}.ko' for m in OV.CONN_MODULES} - {f'{OV.SELINUX}/vendor_sepolicy.cil'}
                             else '') + ' and the vendor CIL'}[bn]
            allowed = set(base_files)
            jan_meta = {}
            if v12:
                # v12 is v11 on the May base: they differ only where May stock differs from January stock.
                jan_fs = scratch / 'jan.ext4'
                jan_info = OV.footer(OV.STOCK_VENDOR)
                r.check('January stock image is the pinned one', OV.sha256(OV.STOCK_VENDOR) == OV.STOCK_VENDOR_SHA256)
                OV.extract_fs(OV.STOCK_VENDOR, jan_fs, jan_info['original_image_size'])
                jan_paths = walk(jan_fs)
                jan_hash = content_hashes(jan_fs, jan_paths, scratch / 'jan-files')
                jan_meta = OV.stat_paths(jan_fs, sorted(jan_paths))
                may_meta = OV.stat_paths(old_fs, sorted(old_paths))
                stock_moved = ({p for p in set(jan_paths) | set(old_paths) if jan_hash.get(p) != old_hash.get(p)}
                               | set(jan_paths) ^ set(old_paths))
                allowed |= stock_moved
            if v6:
                # v6 to v8 are rebuilt with the current modules, so the modules and index files may differ from the base.
                allowed |= v5_files - {f'{OV.SELINUX}/vendor_sepolicy.cil'}
                base_rec = json.loads((base_image.parent / 'record.json').read_text())
                r.check(f'{bn} image matches its record', base_rec.get('image', {}).get('sha256') == OV.sha256(base_image))
            else:
                r.check(f'{bn} image is the pinned {bn} output', OV.sha256(base_image) == base_sha)
            base_info = OV.footer(base_image)
            base_fs = scratch / 'base.ext4'
            OV.extract_fs(base_image, base_fs, base_info['original_image_size'])
            base_tree = walk(base_fs)
            base_hash = content_hashes(base_fs, base_tree, scratch / 'base-files')
            base_changed = sorted(p for p in set(base_hash) | set(new_hash) if base_hash.get(p) != new_hash.get(p))
            gone_base = set() if v8 else gone_v7
            r.check(f'content differs from {bn} only in the {base_what}',
                    (set(base_tree) ^ set(new_paths) <= stock_moved if v12
                     else set(base_tree) - gone_base == set(new_paths) - (teed_added if v13 else cam_added))
                    and base_files | gone_base <= set(base_changed) <= allowed | gone_base,
                    base_changed)
            base_meta = OV.stat_paths(base_fs, sorted(base_tree))
            base_diff = []
            for p in sorted(set(base_tree) - gone_base):
                if v12 and p not in new_meta:
                    continue
                ignore = {'inode', 'size'} if p in allowed else {'inode'} if p in modified | set(ADDED) else set()
                if v12 and p in jan_meta and p in may_meta and jan_meta[p].get('inode') != may_meta[p].get('inode'):
                    ignore = ignore | {'inode'}
                if v12 and base_tree[p].startswith('40'):
                    ignore = ignore | {'size'}
                    if jan_meta.get(p, {}).get('links') != may_meta.get(p, {}).get('links'):
                        ignore = ignore | {'links'}
                d = {k: (base_meta[p].get(k), new_meta[p].get(k)) for k in base_meta[p]
                     if k not in ignore and base_meta[p].get(k) != new_meta[p].get(k)}
                if d and not (p in ('/etc/vintf', '/etc/init') + ((OV.SELINUX, OV.MODULE_DIR) if v5 else ())
                              + (('/etc', '/etc/vintf/manifest') if v7 else ()) and set(d) == {'size'}):
                    base_diff.append({p: d})
            r.check(f'metadata and labels equal {bn} for every inode', not base_diff, base_diff[:20] or None)
            old_man = read_file(old_fs, OV.VINTF_MANIFEST, scratch).decode().split('\n')
            new_man = read_file(new_fs, OV.VINTF_MANIFEST, scratch).decode().split('\n')
            at = [i for i in range(len(old_man)) if old_man[i:i + len(OV.KM_HAL_BLOCK)] == OV.KM_HAL_BLOCK]
            expect = None
            if len(at) == 1:
                expect = old_man if v6 else old_man[:at[0]] + old_man[at[0] + len(OV.KM_HAL_BLOCK):]
                expect = [OV.KERNEL_FCM_NEW if l == OV.KERNEL_FCM_LINE else l for l in expect]
            if v6:
                r.check('vendor manifest is stock with the keymaster 4.0 HAL block kept, kernel FCM 5 to 6',
                        expect == new_man and old_man.count(OV.KERNEL_FCM_LINE) == 1 and new_man.count(OV.KERNEL_FCM_NEW) == 1, at)
                r.check('keymaster rc is the stock file',
                        read_file(new_fs, OV.KM_RC, scratch) == read_file(old_fs, OV.KM_RC, scratch)
                        and 'disabled' not in read_file(new_fs, OV.KM_RC, scratch).decode())
            else:
                r.check('vendor manifest is stock minus the keymaster 4.0 HAL block, kernel FCM 5 to 6',
                        expect == new_man and old_man.count(OV.KERNEL_FCM_LINE) == 1, at)
            vintf = sorted(p for p in new_paths if p.startswith('/etc/vintf/') and p.endswith('.xml')
                           and re.search(rb'android\.hardware\.(keymaster|security\.keymint)',
                                         read_file(new_fs, p, scratch)))
            if v6:
                r.check('only the stock keymaster 4.0 HAL is declared, no KeyMint', vintf == ['/etc/vintf/manifest.xml'] and
                        b'security.keymint' not in read_file(new_fs, OV.VINTF_MANIFEST, scratch), vintf)
            else:
                r.check('no vendor VINTF file declares a keymaster or KeyMint HAL', not vintf, vintf or None)
                old_km = read_file(old_fs, OV.KM_RC, scratch).decode().split('\n')
                new_km = read_file(new_fs, OV.KM_RC, scratch).decode().split('\n')
                g = old_km.index(OV.KM_RC_GROUP) if OV.KM_RC_GROUP in old_km else -1
                r.check('keymaster rc is stock plus a disabled line after its group line',
                        g > 0 and new_km == old_km[:g + 1] + OV.KM_RC_ADDED + old_km[g + 1:], new_km)
            if v4:
                old_fr = read_file(old_fs, OV.FR_RC, scratch).decode().split('\n')
                new_fr = read_file(new_fs, OV.FR_RC, scratch).decode().split('\n')
                g = old_fr.index(OV.FR_RC_ANCHOR) if OV.FR_RC_ANCHOR in old_fr else -1
                r.check('vendor_flash_recovery rc is stock plus a disabled line after its oneshot line',
                        g > 0 and new_fr == old_fr[:g + 1] + OV.FR_RC_ADDED + old_fr[g + 1:], new_fr)
                r.check('vendor_flash_recovery service is disabled and is the only service in its rc',
                        sum(l.startswith('service ') for l in new_fr) == 1
                        and new_fr[0].startswith('service vendor_flash_recovery ') and '    disabled' in new_fr)
            if v5:
                v5_checks(r, v6, args, record, new_fs, base_fs, base_hash, new_hash, new_paths, new_mods, index_want, scratch,
                          bn if v6 else 'v5', {OV.TEED, OV.FSTAB} if v13 else stock_moved if v12 else v11_files if v11 else v10_files if v10 else v9_files if v9 else ((v8_files if v8 else set()) | ((v7_files | gone_v7) if not v8 else set())) if v7 else ())
            if v7:
                old_cx = read_file(old_fs, OV.CODECS_XML, scratch).decode()
                new_cx = read_file(new_fs, OV.CODECS_XML, scratch).decode()
                r.check('media_codecs_mediatek_video.xml is stock but for the VP9 decoder size limit 1920x1088',
                        new_cx == OV.overlay_codecs(old_cx)[0]
                        and [(x, y) for x, y in zip(old_cx.split('\n'), new_cx.split('\n')) if x != y]
                        == [(OV.VP9_SIZE_LINE, OV.VP9_SIZE_NEW)]
                        and len(old_cx.split('\n')) == len(new_cx.split('\n')),
                        [l for l in new_cx.split('\n') if l not in old_cx.split('\n')])
                r.check('power-default.xml is absent, no vendor VINTF file declares android.hardware.power',
                        OV.POWER_VINTF not in new_paths and not [p for p in new_paths if p.startswith('/etc/vintf/')
                        and p.endswith('.xml') and b'<name>android.hardware.power</name>' in read_file(new_fs, p, scratch)])
                mtk = sorted(p for p in new_paths if p.startswith('/etc/vintf/') and p.endswith('.xml')
                             and b'vendor.mediatek.hardware.mtkpower' in read_file(new_fs, p, scratch))
                r.check(f'the mtkpower HIDL block, its rc and the power HAL binary stay as in {bn}',
                        mtk == ['/etc/vintf/manifest.xml'] and all(
                            new_hash.get(p) == base_hash.get(p) and p in new_hash for p in new_paths
                            if 'mtkpower' in p or 'power-service' in p or 'power_hal' in p), mtk)
            if v8:
                old_bp = read_file(old_fs, OV.BUILD_PROP, scratch).decode()
                new_bp = read_file(new_fs, OV.BUILD_PROP, scratch).decode()
                r.check('build.prop is stock plus the FSC off line at the end',
                        new_bp == OV.overlay_build_prop(old_bp)[0]
                        and new_bp == old_bp + '\n'.join(OV.FSC_PROP_ADDED) + '\n'
                        and new_bp.count('vendor.debug.fsc.fsc.enable=') == 1,
                        [l for l in new_bp.split('\n') if l not in old_bp.split('\n')])
            base_fs.unlink()
        vers = read_file(new_fs, '/etc/selinux/plat_sepolicy_vers.txt', scratch).decode().strip()
        genfs = read_file(new_fs, '/etc/selinux/genfs_labels_version.txt', scratch).decode().strip()
        r.check('vendor policy API stays 30.0 with genfs 202504', vers == '30.0' and genfs == '202504', [vers, genfs])
        r.check('API30 compat/mapping present in the system side of the composition',
                (install / 'system/etc/selinux/mapping/30.0.cil').exists()
                and (install / 'system/etc/selinux/mapping/30.0.compat.cil').exists()
                and (install / 'system/etc/selinux/plat_sepolicy_genfs_202504.cil').exists())

        old_rc = read_file(old_fs, OV.INIT_RC, scratch).decode().split('\n')
        new_rc = read_file(new_fs, OV.INIT_RC, scratch).decode().split('\n')
        gone = [l for l in old_rc if l not in new_rc]
        dropped = [OV.KEYMASTER_LINE] + (OV.STUNE_DROP if v9 else [])
        r.check('init.mt6771.rc only loses the late-fs wait_for_keymaster line' + (' and the six schedtune lines (v9)' if v9 else ''),
                len(old_rc) == len(new_rc) + len(dropped) and gone == dropped
                and [l for l in old_rc if l not in dropped] == new_rc, gone)
        if v9:
            old_fg = read_file(old_fs, OV.FG_RC, scratch).decode().split('\n')
            new_fg = read_file(new_fs, OV.FG_RC, scratch).decode().split('\n')
            g = old_fg.index(OV.FG_RC_ANCHOR) if OV.FG_RC_ANCHOR in old_fg else -1
            r.check('fuelgauged rc is stock plus a oneshot line after its group line',
                    g > 0 and new_fg == old_fg[:g + 1] + OV.FG_RC_ADDED + old_fg[g + 1:]
                    and sum(l.startswith('service ') for l in new_fg) == 1, new_fg)
            old_fc = read_file(old_fs, OV.FILE_CONTEXTS, scratch).decode()
            new_fc = read_file(new_fs, OV.FILE_CONTEXTS, scratch).decode()
            fc_added = OV.FC_ADDED + (OV.FC_M7_ADDED if v10 else []) + (OV.FC_CAM_ADDED if v11 else [])
            r.check('vendor_file_contexts is stock plus the bip_socket and wfca_rds lines at the end'
                    + (' and the wakeup source lines (v10)' if v10 else '') + (' and the camera launcher line (v11)' if v11 else ''),
                    new_fc == old_fc + '\n'.join(fc_added) + '\n' and new_fc == OV.overlay_file_contexts(old_fc, m7=v10, cam=v11)[0],
                    fc_added)
            if v10:
                bad = [l for l in OV.FC_M7_ADDED if not l.startswith('#') and not (
                    l.startswith('/sys/devices/platform/') and l.endswith('/wakeup[0-9]+(/.*)?  u:object_r:sysfs_wakeup:s0'))]
                r.check('every M7 file context labels a wakeupN dir under /sys/devices/platform as sysfs_wakeup', not bad, bad or None)
            old_hws = read_file(old_fs, OV.HWSERVICE_CONTEXTS, scratch).decode()
            new_hws = read_file(new_fs, OV.HWSERVICE_CONTEXTS, scratch).decode()
            r.check('vendor_hwservice_contexts only relabels IMtkPerf and IMtkPower to mtk_hal_power_hwservice',
                    new_hws == OV.overlay_hwservice_contexts(old_hws)[0]
                    and [(a, b) for a, b in zip(old_hws.split('\n'), new_hws.split('\n')) if a != b] == OV.HWS_CHANGED
                    and old_hws.count('\n') == new_hws.count('\n'), OV.HWS_CHANGED)
            cil = read_file(new_fs, f'{OV.SELINUX}/vendor_sepolicy.cil', scratch).decode().split('\n')
            r.check('vendor CIL: mtk_hal_power_hwservice is a hwservice type, mtk_hal_power adds and finds it, hal_power_client finds it, and mtk_hal_power is out of hal_power_server',
                    '(type mtk_hal_power_hwservice)' in cil
                    and any(l.startswith('(typeattributeset hwservice_manager_type (') and ' mtk_hal_power_hwservice ' in l for l in cil)
                    and '(allow mtk_hal_power mtk_hal_power_hwservice (hwservice_manager (add find)))' in cil
                    and '(allow hal_power_client mtk_hal_power_hwservice (hwservice_manager (find)))' in cil
                    and OV.HAL_POWER_SERVER_NEW in cil and OV.HAL_POWER_SERVER_OLD not in cil, None)
        if v11:
            old_cam = read_file(old_fs, OV.CAM_RC, scratch).decode()
            new_cam = read_file(new_fs, OV.CAM_RC, scratch).decode()
            r.check('camerahalserver.rc is stock but for the launcher path, with one comment line before it',
                    new_cam == OV.overlay_cam_rc(old_cam)[0]
                    and new_cam.split('\n')[2:] == old_cam.split('\n')[1:], new_cam.split('\n')[:2])
            try:
                shim = OV.camera_shim()
                fresh = {p: c['sha256'] for p, c in shim.items()}
            except SystemExit as e:
                fresh = str(e)
            got = {p: new_hash.get(p) for p in OV.CAM_ADDED}
            r.check('launcher and shim equal the current build output and its record',
                    got == fresh and got == {p: c.get('sha256') for p, c in record.get('camera_shim', {}).items()}, got)
            want_label = {'/bin/hw/camerahalserver-pocket': 'mtk_hal_camera_exec', '/lib64/libpocketcammeta.so': 'vendor_file'}
            got_label = {p: [x for x in new_meta[p]['xattrs'] if x.startswith('security.selinux')] for p in OV.CAM_ADDED}
            r.check('launcher is labelled mtk_hal_camera_exec and the shim vendor_file',
                    all(len(got_label[p]) == 1 and f'u:object_r:{t}:s0' in got_label[p][0] for p, t in want_label.items()), got_label)
        if v13:
            teed_checks(r, OV, old_fs, new_fs, new_meta, new_hash, record, scratch)
        old_usb = read_file(old_fs, OV.USB_RC, scratch).decode().split('\n')
        new_usb = read_file(new_fs, OV.USB_RC, scratch).decode().split('\n')
        usb_diff = [(a, b) for a, b in zip(old_usb, new_usb) if a != b]
        r.check('init.mt6771.usb.rc only changes vendor.usb.controller to 11201000.usb3',
                len(old_usb) == len(new_usb)
                and usb_diff == [(OV.USB_CONTROLLER_LINE, OV.USB_CONTROLLER_NEW)] * OV.USB_CONTROLLER_COUNT, usb_diff)
        rc_files = [p for p in new_paths if p.endswith('.rc')]
        mentions = sorted(p for p in rc_files
                          if b'wait_for_keymaster' in read_file(new_fs, p, scratch))
        r.check('factory/meta init paths keep their stock wait_for_keymaster, normal boot has none',
                mentions == ['/etc/init/hw/factory_init.rc', '/etc/init/hw/meta_init.rc'], mentions)

        # fstab with Android 16 libfstab rules.
        rules = fstab_rules(args.libfstab_source)
        r.check('libfstab rule tables extracted', 'formattable' in rules['booleans'] and 'avb' in rules['booleans']
                and 'fileencryption=' in rules['prefixes'] and rules['rejected'] and 'inlinecrypt' not in rules['mount_flags'],
                {k: len(rules[k]) for k in ('mount_flags', 'booleans', 'prefixes', 'exact', 'rejected')})
        fstab_text = read_file(new_fs, OV.FSTAB, scratch).decode()
        entries, errors, warnings = parse_fstab(fstab_text, rules)
        r.check('fstab parses with libfstab rules, no unknown-flag warnings', not errors and not warnings,
                (errors + warnings) or None)
        by_mp = {}
        for e in entries:
            by_mp.setdefault(e['mount_point'], []).append(e)
        one = lambda mp: by_mp.get(mp, [None])[0]
        meta = one('/metadata')
        r.check('metadata is md_udc, first stage', meta and meta['blk_device'] == '/dev/block/by-name/md_udc'
                and 'first_stage_mount' in meta['fs_mgr_flags'])
        logical = sorted(e['blk_device'] for e in entries if 'logical' in e['fs_mgr_flags'])
        r.check('logical partitions are exactly system/product/vendor, no system_ext',
                logical == ['product', 'system', 'vendor'] and '/system_ext' not in by_mp, logical)
        data = one('/data')
        if v2:
            enc = v13
            if enc:
                r.check('/data keeps FBEv2, inlinecrypt and the metadata key directory, no checkpoint or resize',
                        data and data['args'].get('fileencryption') == 'aes-256-xts:aes-256-cts:v2'
                        and 'inlinecrypt' in data['fs_options']
                        and data['args'].get('keydirectory') == '/metadata/vold/metadata_encryption'
                        and not {'checkpoint', 'encryptable', 'forceencrypt', 'forcefdeorfbe'} & set(data['args'])
                        and not {'resize', 'checkpoint=block'} & set(data['fs_mgr_flags'])
                        and 'latemount' in data['fs_mgr_flags'] and data['blk_device'] == '/dev/block/by-name/userdata',
                        data and data['args'])
            else:
                r.check('/data has no encryption or checkpoint flags',
                        data and not {'fileencryption', 'keydirectory', 'metadata_encryption', 'checkpoint',
                                      'encryptable', 'forceencrypt', 'forcefdeorfbe'} & set(data['args'])
                        and 'inlinecrypt' not in data['fs_options'] and 'latemount' in data['fs_mgr_flags']
                        and data['blk_device'] == '/dev/block/by-name/userdata', data and data['args'])
            data_lines = [l for l in fstab_text.splitlines() if (f := OV.fstab_fields(l)) and f[1] == '/data']
            want_line = OV.ENCRYPTED_DATA if enc else OV.UNENCRYPTED_DATA
            r.check('/data line is the reviewed ' + ('encrypted' if enc else 'unencrypted') + ' line',
                    data_lines == [want_line], data_lines)
            if have_v1:
                v1_fstab = read_file(v1_fs, OV.FSTAB, scratch).decode().split('\n')
                new_lines = fstab_text.split('\n')
                fstab_diff = [(a, b) for a, b in zip(v1_fstab, new_lines) if a != b]
                r.check('every other fstab line equals v1', len(v1_fstab) == len(new_lines) and len(fstab_diff) == 1
                        and OV.fstab_fields(fstab_diff[0][0])[1] == '/data', fstab_diff)
                # trustkernel.rc: v1 plus one copy of the stock unencrypted block under the new trigger.
                v1_tk = read_file(v1_fs, OV.TRUSTKERNEL_RC, scratch).decode().split('\n')
                new_tk = read_file(new_fs, OV.TRUSTKERNEL_RC, scratch).decode().split('\n')
                s0, e0 = OV.trustkernel_block(v1_tk, OV.TK_STOCK_TRIGGER)
                s1, e1 = OV.trustkernel_block(new_tk, OV.TK_NEW_TRIGGER) if new_tk.count(OV.TK_NEW_TRIGGER) == 1 else (1, 1)
                r.check('trustkernel.rc has the unsupported block, equal to the stock unencrypted block but for its trigger',
                        new_tk[s1 + 1:e1] == v1_tk[s0 + 1:e0] and len(v1_tk[s0 + 1:e0]) == 2
                        and all('vendor.trustkernel.fs.' in l for l in new_tk[s1 + 1:e1]), new_tk[s1:e1])
                rest = new_tk[:s1 - 1] + new_tk[e1 + 1:]
                r.check('rest of trustkernel.rc equals v1', rest == v1_tk and new_tk[s1 - 1] == OV.TK_COMMENT
                        and new_tk[e1] == '', [l for l in new_tk if l not in v1_tk])
                v1_fs.unlink()
        else:
            r.check('/data keeps FBEv2, inlinecrypt and metadata encryption',
                    data and data['args'].get('fileencryption') == 'aes-256-xts:aes-256-cts:v2'
                    and 'inlinecrypt' in data['fs_options']
                    and data['args'].get('keydirectory') == '/metadata/vold/metadata_encryption'
                    and 'latemount' in data['fs_mgr_flags'] and data['blk_device'] == '/dev/block/by-name/userdata')
        prov = {mp: one(mp) for mp in OV.PROTECTED}
        r.check('provisioning filesystems present and never auto-formatted',
                all(e and 'formattable' not in e['fs_mgr_flags'] and 'nofail' not in e['fs_mgr_flags']
                    for e in prov.values()), {mp: e and e['fs_mgr_flags'] for mp, e in prov.items()})
        ramdisk, rerrors, rwarnings = parse_fstab(args.ramdisk_fstab.read_text(), rules)
        r.check('first-stage fstab parses', not rerrors, (rerrors + rwarnings) or None)
        rd = {e['mount_point']: e for e in ramdisk}
        key = lambda e: {k: v for k, v in e.items() if k != 'line'}
        r.check('logical entries identical to the first-stage fstab',
                all(key(one(m)) == key(rd[m]) for m in ('/system', '/product', '/vendor')))
        info_diff = {m: {'vendor': one(m)['fs_mgr_flags'], 'first_stage': rd[m]['fs_mgr_flags']}
                     for m in rd if one(m) and key(one(m)) != key(rd[m])}
        r.checks.append({'check': 'info: entries that differ from the first-stage fstab', 'ok': True,
                         'detail': info_diff})
        raw = sorted(e['mount_point'] for e in entries if e['fs_type'] == 'emmc')
        r.checks.append({'check': 'info: raw emmc entries kept from stock', 'ok': True, 'detail': raw})

        # Vendor policy names declared only by the retained system_ext policy.
        se_only = (cil_declared(install / 'system_ext/etc/selinux/system_ext_sepolicy.cil')
                   - cil_declared(install / 'system/etc/selinux/plat_sepolicy.cil')
                   - cil_declared(install / 'vendor/etc/selinux/vendor_sepolicy.cil')
                   - cil_declared(install / 'vendor/etc/selinux/plat_pub_versioned.cil'))
        vtokens = set(re.findall(r'[\w.]+', read_file(new_fs, f'{OV.SELINUX}/vendor_sepolicy.cil', scratch).decode()))
        coupled = sorted(se_only & vtokens)
        r.checks.append({'check': 'info: vendor policy names declared only by the V14 system_ext policy',
                         'ok': True, 'detail': {'count': len(coupled), 'names': coupled[:40]}})
    finally:
        shutil.rmtree(scratch, ignore_errors=True)

    report = {'schema': 1, 'version': args.version, 'image': str(args.image), 'image_sha256': image_sha,
              'stock_sha256': stock_sha, 'libfstab_source_sha256': rules['source_sha256'],
              'libfstab_rules': {k: rules[k] for k in ('booleans', 'prefixes', 'exact', 'rejected')},
              'passed': not r.failures, 'failures': r.failures, 'checks': r.checks,
              'device_accessed': False}
    text = json.dumps(report, indent=1) + '\n'
    if args.report:
        args.report.write_text(text)
    for c in r.checks:
        print(('PASS ' if c['ok'] else 'FAIL ') + c['check'])
    print('passed' if not r.failures else f'{len(r.failures)} failed')
    return 0 if not r.failures else 1


if __name__ == '__main__':
    sys.exit(main())
