#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Compose the real product split policy the way init does, with every neverallow check on.

Inputs are the built product output (system, system_ext, product) and the private vendor
overlay image. The compile order and flags follow Android 16 init OpenSplitPolicy, except
that -N is left out so all assertions are checked. A second run with -N shows what init
itself would get. When the real composition fails, the tool lists the names that only the
V14 system_ext policy supplied, sorts them into keep/drop groups and compiles diagnostic
compositions of that proposal. It then repeats the V14 context checks and checks the merged
contexts and the adbd FunctionFS labels against the nearest policy that compiles.

Reads product output, the vendor image and V14 artifacts; writes only under --output.
Generated CIL, policies and contexts there stay private.
"""
import pocket_paths
import argparse
import collections
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import shutil
import subprocess
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parent.parent
SPEC = importlib.util.spec_from_file_location('pocket_cil', ROOT / 'tools/audit-pocket-policy-compat.py')
C = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(C)
BULK = pocket_paths.build_root()
PRODUCT = BULK / 'product-out/target/product/titan_pocket'
HOST = BULK / 'product-out/host/linux-x86/bin'
VENDORS = {
    'v4': (pocket_paths.private_vendor_overlay() / 'v4/vendor.img',
           'e2a230ac4f741b97b93fac56bd076c61c83142a6a0209b0ebbb2155c17bd4a12'),
    'v5': (pocket_paths.private_vendor_overlay() / 'v5/vendor.img',
           '2fc3883ff95c7aa273f7eebde1a14f37948c76dec394a9fa90a756b4fc7b85ae'),
    'v6': (pocket_paths.private_vendor_overlay() / 'v6/vendor.img',
           'e6a8d8b373af4f4cbd0a563b6d549c79c291ac2782b28903899ed6c667cac5a3'),
    'v7': (pocket_paths.private_vendor_overlay() / 'v7/vendor.img',
           'f5b8f83b34cd3aa104df404f9f3cc7dbe8bc5f97ad81a2089ad6b05140b95026'),
    'v8': (pocket_paths.private_vendor_overlay() / 'v8/vendor.img',
           '2ee1bdaacf4ed66757163e212bd7b0077f2a3c7c3ba6cefe5647166d11027dd1'),
    'v9': (pocket_paths.private_vendor_overlay() / 'v9/vendor.img',
           '9ea85868867be3e292fe0f3698482eccd5b98f0ad6a0d0d9ad4c093409f8685d'),
    'v10': (pocket_paths.private_vendor_overlay() / 'v10/vendor.img',
            '60813178dcf6934eafbb4b5e8dc037257624d08e447b123b07f74058fad74d18')}


def vendor_pin(version):
    """Pinned image and hash, or for a version not in the table the hash in its record.json."""
    if version in VENDORS:
        return VENDORS[version]
    d = pocket_paths.private_vendor_overlay() / version
    try:
        rec = json.loads((d / 'record.json').read_text())
        return d / 'vendor.img', rec['image']['sha256']
    except (OSError, KeyError, ValueError):
        raise SystemExit(f'Unknown vendor version {version}: not pinned and no usable {d}/record.json')


EXTRA_CIL = []  # extra CIL files, set from --extra-cil in main
VENDOR_IMG = VENDOR_SHA = None  # set from --vendor in main
V14 = ROOT / 'artifacts/m2/policy/source-contract-real-product-v14'
VALIDATORS = ROOT / 'artifacts/m2/policy/context-closure-v3'
INIT_SOURCE = pocket_paths.platform_source() / 'system/core/init/selinux.cpp'
DECL = {'type', 'typeattribute', 'typealias', 'role', 'boolean', 'tunable', 'class', 'classpermission', 'macro'}
OPS = {'and', 'or', 'not', 'xor', 'all'}

# Names kept in product system_ext: labels for kernel nodes and for properties that vendor or
# init still set or read. Everything else only V14 supplied is a stock system-side process,
# app or service that the LineageOS system image does not ship.
KEEP_TYPES = {
    'sysfs_boot_info', 'sysfs_headset', 'sysfs_pmu', 'sysfs_vbus', 'mcupm_device', 'mtd_device',
    'system_mtk_ctl_emdlogger1_prop', 'system_mtk_ctl_emdlogger2_prop', 'system_mtk_ctl_emdlogger3_prop',
    'system_mtk_ctl_mdlogger_prop', 'system_mtk_init_svc_aee_aedv_prop', 'system_mtk_init_svc_emdlogger1_prop',
    'system_mtk_init_svc_md_monitor_prop', 'system_mtk_persist_mtk_aee_prop'}


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def load(path):
    return C.forms(Path(path).read_text())


def declared(docs):
    out = {}
    for name, doc in docs.items():
        for s in doc:
            if s and s[0] in DECL and isinstance(s[1], str):
                out.setdefault(s[1], (s[0], name))
    return out


def referenced(doc):
    names = set()
    for s in doc:
        names |= set(C.atoms(s[2:] if s and s[0] in DECL else s))
    return names


def sub(e, dropped):
    """Replace dropped (undeclared, uninhabited) names by the empty set."""
    if isinstance(e, str):
        return None if e in dropped else e
    if e and isinstance(e[0], str) and e[0] in OPS:
        op = e[0]
        if op == 'all':
            return e
        args = [sub(a, dropped) for a in e[1:]]
        if op == 'and':
            return None if any(a is None for a in args) else [op] + args
        if op in ('or', 'xor'):
            args = [a for a in args if a is not None]
            if not args:
                return None
            return [op] + args if len(args) == 2 else (args[0] if isinstance(args[0], list) else [args[0]])
        return ['all'] if args[0] is None else ['not', args[0]]
    items = [x for x in (sub(a, dropped) for a in e) if x is not None]
    return items or None


def prune(doc, dropped):
    out, removed, changed = [], 0, 0
    for s in doc:
        h = s[0]
        if (h in ('type', 'typeattribute', 'typealias') and s[1] in dropped) or \
           (h == 'roletype' and s[2] in dropped) or \
           (h == 'typealiasactual' and (s[1] in dropped or s[2] in dropped)):
            removed += 1
            continue
        new = s
        if h == 'expandtypeattribute':
            names = sub(s[1], dropped)
            new = None if names is None else [h, names] + s[2:]
        elif h == 'typeattributeset':
            e = None if s[1] in dropped else sub(s[2], dropped)
            new = None if e is None else [h, s[1], e]
        elif h in ('allow', 'dontaudit', 'auditallow', 'neverallow', 'allowx', 'neverallowx', 'auditallowx', 'dontauditx'):
            a, b = sub(s[1], dropped), sub(s[2], dropped)
            new = None if a is None or b is None else [h, a, b] + s[3:]
        elif h in ('typetransition', 'typechange', 'typemember'):
            new = None if any(isinstance(x, str) and x in dropped for x in s[1:]) else s
        elif h == 'genfscon':
            new = None if set(C.atoms(s[3])) & dropped else s
        elif set(C.atoms(s)) & dropped:
            raise ValueError('Unhandled statement with a dropped name: ' + C.encode(s)[:200])
        if new is None:
            removed += 1
            continue
        changed += new is not s and new != s
        out.append(new)
    return out, removed, changed


def write_cil(path, doc):
    path.write_text('\n'.join(C.encode(s) for s in doc) + '\n')


def debugfs_dump(image, src, dest):
    dest.mkdir(parents=True, exist_ok=True)
    subprocess.run(['debugfs', '-R', f'rdump {src} {dest}', str(image)], capture_output=True)


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--output', type=Path, required=True)
    ap.add_argument('--report', type=Path, required=True)
    ap.add_argument('--vendor', default='v10',
                    help='vendor overlay version. v4 to v10 are pinned here; a later version uses the sha256 in its record.json')
    ap.add_argument('--extra-cil', type=Path, action='append', default=[],
                    help='CIL file added last to every composition, with all neverallow checks on; repeat for more files')
    a = ap.parse_args()
    global VENDOR_IMG, VENDOR_SHA
    VENDOR_IMG, VENDOR_SHA = vendor_pin(a.vendor)
    for x in a.extra_cil:
        if not x.is_file():
            raise SystemExit(f'Extra CIL not found: {x}')
    EXTRA_CIL.extend(x.resolve() for x in a.extra_cil)
    if a.output.exists():
        raise SystemExit('Output exists; keep earlier evidence')
    a.output.mkdir(parents=True)
    out = a.output
    if digest(VENDOR_IMG) != VENDOR_SHA:
        raise SystemExit('Vendor overlay image changed')
    debugfs_dump(VENDOR_IMG, '/etc/selinux', out / 'vendor')
    debugfs_dump(VENDOR_IMG, '/etc/init', out / 'vendor-init')
    odm = subprocess.run(['debugfs', '-R', 'ls -l /odm/etc/selinux', str(VENDOR_IMG)], capture_output=True, text=True)
    V = out / 'vendor/selinux'
    secilc, checkpolicy, fc_sort = HOST / 'secilc', HOST / 'checkpolicy', HOST / 'fc_sort'
    plat = PRODUCT / 'system/etc/selinux'
    ext = PRODUCT / 'system/system_ext/etc/selinux'
    prod = PRODUCT / 'product/etc/selinux'
    vers = (V / 'plat_sepolicy_vers.txt').read_text().strip()
    genfs = (V / 'genfs_labels_version.txt').read_text().strip()
    real = dict(
        plat=plat / 'plat_sepolicy.cil', plat_mapping=plat / f'mapping/{vers}.cil',
        plat_compat=plat / f'mapping/{vers}.compat.cil', system_ext=ext / 'system_ext_sepolicy.cil',
        system_ext_mapping=ext / f'mapping/{vers}.cil', system_ext_compat=ext / f'mapping/{vers}.compat.cil',
        product=prod / 'product_sepolicy.cil', product_mapping=prod / f'mapping/{vers}.cil',
        plat_pub_versioned=V / 'plat_pub_versioned.cil', vendor=V / 'vendor_sepolicy.cil',
        genfs=plat / f'plat_sepolicy_genfs_{genfs}.cil')
    hashes = {str(p): digest(p) for p in list(real.values()) + EXTRA_CIL + [secilc, checkpolicy, fc_sort, INIT_SOURCE, VENDOR_IMG]}

    def compose(name, files, strict=True):
        d = out / name
        d.mkdir()
        f = dict(files)
        cmd = [str(secilc), str(f['plat']), '-m', '-M', 'true', '-G'] + ([] if strict else ['-N']) + [
            '-c', '30', str(f['plat_mapping']), '-o', str(d / 'policy'), '-f', str(d / 'file_contexts')]
        for k in ('plat_compat', 'system_ext', 'system_ext_mapping', 'system_ext_compat', 'product',
                  'product_mapping', 'plat_pub_versioned', 'vendor', 'genfs'):
            if f.get(k) and Path(f[k]).exists():
                cmd.append(str(f[k]))
        cmd += [str(x) for x in EXTRA_CIL]
        r = subprocess.run(cmd, capture_output=True, text=True)
        log = r.stdout + r.stderr
        (d / 'compile.log').write_text(log)
        pol = d / 'policy'
        rec = dict(name=name, command=cmd, returncode=r.returncode, neverallow_disabled=not strict,
                   neverallow_failures=log.count('neverallow check failed'),
                   first_errors=[l for l in log.splitlines() if l and not l.startswith(' ')][:6],
                   input_sha256={str(p): digest(p) for p in cmd if p.endswith('.cil')})
        if r.returncode == 0 and pol.exists():
            rec['binary'] = dict(bytes=pol.stat().st_size, sha256=digest(pol))
        return rec

    runs = [compose('real-strict', real), compose('real-init-flags', real, strict=False)]

    legacy = a.vendor == "v1"
    missing, hal_attrs, dropped, stub, mapping, keep_lines = {}, set(), set(), [], [], []
    vrem = vchg = prem = pchg = 0
    base = lambda n: n[:-5] if n.endswith("_30_0") else n
    if legacy:
        # Names the real composition lacks that V14 system_ext supplied
        v14ext = dict(v14_system_ext=V14 / 'install/system_ext/etc/selinux/system_ext_sepolicy.cil',
                      v14_system_ext_mapping=V14 / 'install/system_ext/etc/selinux/mapping/30.0.cil')
        v14compat = V14 / 'install/system/etc/selinux/mapping/30.0.compat.cil'
        hashes.update({str(p): digest(p) for p in list(v14ext.values()) + [v14compat]})
        docs = {k: load(p) for k, p in {**real, **v14ext}.items()}
        rd = declared({k: docs[k] for k in real})
        vd = declared({k: docs[k] for k in v14ext})
        only_v14 = {n: vd[n] for n in vd if n not in rd}
        users = collections.defaultdict(list)
        for k in real:
            refs = referenced(docs[k])
            for n in only_v14:
                if n in refs:
                    users[n].append(k)
        missing = {n: dict(kind=only_v14[n][0], declared_by=only_v14[n][1], used_by=users[n]) for n in sorted(users)}
        hal_attrs = {n for n, v in missing.items() if v['declared_by'] == 'v14_system_ext' and v['kind'] == 'typeattribute'}
        keep = KEEP_TYPES | hal_attrs
        base = lambda n: n[:-5] if n.endswith('_30_0') else n
        dropped = {n for n in missing if base(n) not in keep}
        unknown_keep = KEEP_TYPES - {base(n) for n in missing}
        if unknown_keep:
            raise SystemExit('Keep list names not in the missing set: ' + ' '.join(sorted(unknown_keep)))

        # Diagnostic A: add the whole V14 system_ext to the product system_ext
        d = out / 'inputs'
        d.mkdir()
        (d / 'v14-merged-system_ext.cil').write_text(real['system_ext'].read_text() + v14ext['v14_system_ext'].read_text())
        runs.append(compose('diag-v14-system_ext-upstream-compat', {**real, 'system_ext': d / 'v14-merged-system_ext.cil',
                            'system_ext_mapping': v14ext['v14_system_ext_mapping']}))
        runs.append(compose('diag-v14-system_ext-v14-compat', {**real, 'system_ext': d / 'v14-merged-system_ext.cil',
                            'system_ext_mapping': v14ext['v14_system_ext_mapping'], 'plat_compat': v14compat}))

        # Diagnostic B: the proposal. Declarations only for the keep set; dead names emptied in vendor.
        vend, vrem, vchg = prune(docs['vendor'], dropped)
        ppub, prem, pchg = prune(docs['plat_pub_versioned'], dropped)
        write_cil(d / 'vendor_sepolicy.cil', vend)
        write_cil(d / 'plat_pub_versioned.cil', ppub)
        ext_decl = {s[1] for s in docs['v14_system_ext'] if s[0] in ('type', 'typeattribute', 'typealias')}
        stub, _, _ = prune(docs['v14_system_ext'], ext_decl - keep)
        stub = [s for s in stub if s[0] in ('type', 'typeattribute', 'roletype', 'typeattributeset', 'genfscon', 'expandtypeattribute')]
        write_cil(d / 'system_ext_additions.cil', stub)
        (d / 'system_ext_sepolicy.cil').write_text(real['system_ext'].read_text() + (d / 'system_ext_additions.cil').read_text())
        keep_map = {k + '_30_0' for k in KEEP_TYPES}
        mapping = [s for s in docs['v14_system_ext_mapping'] if (s[1][0] if s[0] == 'expandtypeattribute' else s[1]) in keep_map]
        write_cil(d / 'system_ext_30.0.cil', mapping)
        proposal = {**real, 'system_ext': d / 'system_ext_sepolicy.cil', 'system_ext_mapping': d / 'system_ext_30.0.cil',
                    'vendor': d / 'vendor_sepolicy.cil', 'plat_pub_versioned': d / 'plat_pub_versioned.cil'}
        runs.append(compose('diag-proposal-upstream-compat', proposal))
        runs.append(compose('diag-proposal-upstream-compat-init-flags', proposal, strict=False))
        runs.append(compose('diag-proposal-scoped-compat', {**proposal, 'plat_compat': v14compat}))
    ref = out / ("diag-proposal-scoped-compat/policy" if legacy else "real-strict/policy")
    if not ref.exists():
        for r in runs:
            print(r['name'], r['returncode'], r['first_errors'][:3])
        raise SystemExit('Reference policy did not compile; see ' + str(out))
    subprocess.run([str(checkpolicy), '-M', '-b', '-C', '-o', str(ref) + '.cil', str(ref)], capture_output=True, check=True)
    bincil = C.forms(Path(str(ref) + '.cil').read_text())
    types = {s[1] for s in bincil if s[0] == 'type'}

    # FunctionFS and adbd in the compiled binary
    attrs = collections.defaultdict(set)
    for s in bincil:
        if s[0] == 'typeattributeset':
            attrs[s[1]].update(C.atoms(s[2]))
    member = lambda t: {x for x, m in attrs.items() if t in m} | {t}
    allows = collections.defaultdict(set)
    for s in bincil:
        if s[0] == 'allow':
            allows[(s[1], s[2], s[3][0])].update(C.atoms(s[3][1]))

    def has(src, tgt, cls, perms):
        got = set()
        for x in member(src):
            for y in member(tgt) | ({'self'} if src == tgt else set()):
                got |= allows.get((x, y, cls), set())
        return sorted(set(perms) - got)
    ffs = dict(
        policycaps=sorted(s[1] for s in bincil if s[0] == 'policycap'),
        genfscon=[C.encode(s) for s in bincil if s[0] == 'genfscon' and s[1] == 'functionfs'],
        functionfs_type_declared='functionfs' in types)
    ffs['permissions'] = [dict(query=q, missing=has(*q)) for q in [
        ('vendor_init', 'device', 'dir', ['create', 'add_name', 'write', 'search', 'setattr']),
        ('init', 'device', 'dir', ['mounton', 'search']),
        ('init', 'functionfs', 'filesystem', ['mount', 'unmount']),
        ('init', 'functionfs', 'dir', ['search', 'setattr']),
        ('adbd', 'device', 'dir', ['search']),
        ('adbd', 'functionfs', 'dir', ['search']),
        ('adbd', 'functionfs', 'file', ['open', 'read', 'write', 'ioctl'])]]
    rc_lines = []
    for f in sorted((out / 'vendor-init').rglob('*.rc')):
        for i, line in enumerate(f.read_text(errors='replace').splitlines(), 1):
            if 'usb-ffs/adb' in line:
                rc_lines.append(f'{f.relative_to(out / "vendor-init")}:{i}: {line.strip()}')
    ffs['vendor_rc_lines'] = rc_lines

    # Context checks
    ctx = out / 'contexts'
    ctx.mkdir()
    checkfc, checkseapp = VALIDATORS / 'checkfc', VALIDATORS / 'checkseapp'
    hashes.update({str(checkfc): digest(checkfc), str(checkseapp): digest(checkseapp)})
    D = {'plat': plat, 'system_ext': ext, 'product': prod, 'vendor': V}
    tests = []

    def run(name, cmd, expected=True, group='v14'):
        r = subprocess.run(list(map(str, cmd)), capture_output=True, text=True)
        tests.append(dict(group=group, name=name, command=list(map(str, cmd)), returncode=r.returncode,
                          output=(r.stdout + r.stderr)[-2000:], expected_success=expected,
                          passed=(r.returncode == 0) == expected))
    for part in ('vendor', 'system_ext'):
        for suf, flag in [('file_contexts', None), ('property_contexts', '-p'), ('service_contexts', '-s'),
                          ('hwservice_contexts', '-l')]:
            run(f'{part}_{suf}', [checkfc, '-e'] + ([flag] if flag else []) + [ref, D[part] / f'{part}_{suf}'])
        run(f'{part}_seapp_contexts', [checkseapp, '-p', ref] + (['-c'] if part == 'vendor' else []) +
            [D[part] / f'{part}_seapp_contexts'])
    run('vndservice_contexts', [checkfc, '-e', '-v', ref, V / 'vndservice_contexts'])
    run('device service_contexts', [checkfc, '-s', ref, pocket_paths.DEVICE_TREE / 'sepolicy/system_ext/private/service_contexts'])
    for name, content in [('positive-service', 'mtkIms u:object_r:radio_service:s0\n'),
                          ('unknown-type', 'invalid u:object_r:pocket_missing_type:s0\n'),
                          ('wrong-type-role', 'invalid u:object_r:system_file:s0\n')]:
        (ctx / name).write_text(content)
        run(name, [checkfc, '-s', ref, ctx / name], expected=name == 'positive-service')

    order = ['plat', 'system_ext', 'product', 'vendor']
    duplicates = {}
    for kind, flag, vname in [('file_contexts', None, 'vendor_file_contexts'),
                              ('property_contexts', '-p', 'vendor_property_contexts'),
                              ('service_contexts', '-s', 'vendor_service_contexts'),
                              ('hwservice_contexts', '-l', 'vendor_hwservice_contexts')]:
        parts = [(p, D[p] / f'{p}_{kind}') for p in order[:3]] + [('vendor', V / vname)]
        parts = [(p, f) for p, f in parts if f.exists()]
        merged = ctx / f'merged_{kind}'
        merged.write_text(''.join(f.read_text() + '\n' for _, f in parts))
        run('merged ' + kind, [checkfc] + ([flag] if flag else []) + [ref, merged], group='merged')
        seen = collections.defaultdict(list)
        for part, f in parts:
            for line in f.read_text().splitlines():
                w = line.split('#', 1)[0].split()
                if len(w) < 2:
                    continue
                if kind == 'file_contexts':
                    key, label = (w[0], w[1] if len(w) == 3 else ''), w[-1]
                elif kind == 'property_contexts':
                    key, label = (w[0], 'exact' if 'exact' in w[2:] else 'prefix'), ' '.join(w[1:])
                else:
                    key, label = (w[0],), w[1]
                seen[key].append((part, label))
        conflict = {' '.join(k): v for k, v in seen.items() if len({l for _, l in v}) > 1}
        repeat = {' '.join(k): v for k, v in seen.items() if len(v) > 1 and len({l for _, l in v}) == 1}
        duplicates[kind] = dict(conflicting=conflict, identical_repeats=len(repeat),
                                identical_examples=dict(list(repeat.items())[:8]))
        tests.append(dict(group='merged', name='no conflicting duplicate keys: ' + kind, passed=not conflict,
                          expected_success=True, output=json.dumps(conflict)[:2000]))
    merged = ctx / 'merged_seapp_contexts'
    merged.write_text(''.join((D[p] / f'{p}_seapp_contexts').read_text() + '\n' for p in order))
    run('merged seapp_contexts', [checkseapp, '-p', ref, merged], group='merged')
    for part in order:
        for fname in (f'{part}_keystore2_key_contexts', f'{part}_tee_service_contexts'):
            f = D[part] / fname
            if f.exists():
                bad = [l.strip() for l in f.read_text().splitlines()
                       if (m := re.search(r'u:object_r:([^:\s]+):s0', l.split('#', 1)[0])) and m.group(1) not in types]
                tests.append(dict(group='merged', name='label types declared: ' + fname, passed=not bad,
                                  expected_success=True, output='; '.join(bad)))
        f = D[part] / f'{part}_mac_permissions.xml'
        try:
            ET.parse(f)
            tests.append(dict(group='merged', name='parses: ' + f.name, passed=True, expected_success=True, output=''))
        except ET.ParseError as e:
            tests.append(dict(group='merged', name='parses: ' + f.name, passed=False, expected_success=True, output=str(e)))
    # Property lines the keep set needs, from V14 system_ext contexts
    if legacy:
        v14prop = (V14 / 'install/system_ext/etc/selinux/system_ext_property_contexts').read_text().splitlines()
        keep_lines = [l for l in v14prop if any(f':{t}:s0' in l for t in KEEP_TYPES)]
        proposed = ctx / 'proposed_system_ext_property_contexts'
        proposed.write_text((ext / 'system_ext_property_contexts').read_text() + '\n' + '\n'.join(keep_lines) + '\n')
        run('proposed system_ext_property_contexts', [checkfc, '-p', ref, proposed], group='proposal')

    # adbd paths through the merged, sorted file_contexts; the last full match wins
    srt = ctx / 'merged_file_contexts.sorted'
    subprocess.run([str(fc_sort), '-i', str(ctx / 'merged_file_contexts'), '-o', str(srt)], check=True, capture_output=True)
    specs = []
    for line in srt.read_text().splitlines():
        w = line.split('#', 1)[0].split()
        if len(w) >= 2:
            specs.append((re.compile('^(?:' + w[0] + ')$'), w[1] if len(w) == 3 else '', w[-1]))

    def label(path, ftype):
        hit = None
        for rx, ft, l in specs:
            if ft in ('', ftype) and rx.match(path):
                hit = l
        return hit
    for path, ftype, want in [('/dev/usb-ffs', '-d', 'device'), ('/dev/usb-ffs/adb', '-d', 'device'),
                              ('/dev/usb-ffs/aoa/ep1', '--', 'usbaccessory_device'),
                              ('/system/bin/adbd', '--', 'adbd_exec')]:
        got = label(path, ftype)
        t = got.split(':')[2] if got else None
        tests.append(dict(group='adbd', name='file label: ' + path, passed=t == want and t in types,
                          expected_success=True, output=str(got)))

    # V14 system_ext context lines the product lacks whose label type still exists
    lost = {}
    if legacy:
        merged_props = {l.split()[0] for l in (ctx / 'merged_property_contexts').read_text().splitlines()
                        if l.split('#', 1)[0].strip()}
        for fname in ('system_ext_property_contexts', 'system_ext_service_contexts', 'system_ext_file_contexts',
                      'system_ext_seapp_contexts'):
            have = set((ext / fname).read_text().splitlines())
            rows = dict(type_absent=0, type_present=[])
            for line in (V14 / 'install/system_ext/etc/selinux' / fname).read_text().splitlines():
                w = line.split('#', 1)[0].split()
                if not w or line in have or (fname.startswith('system_ext_property') and w[0] in merged_props):
                    continue
                m = re.search(r'(?:u:object_r:|domain=)([^:\s]+)', line)
                if m and m.group(1) in types:
                    rows['type_present'].append(line.strip())
                else:
                    rows['type_absent'] += 1
            lost[fname] = rows

    # Per-name record
    names = {}
    for n, v in missing.items():
        b = base(n)
        if n in hal_attrs:
            decision = 'product system_ext public: attribute declaration'
        elif b in KEEP_TYPES:
            decision = 'product system_ext public: type, 30.0 mapping and context line'
        else:
            decision = 'drop: empty it in vendor overlay v2'
        names[n] = dict(v, base=b, decision=decision)
    result = dict(
        schema=1, tool_sha256=digest(Path(__file__)), input_sha256=hashes, device_accessed=False,
        init_source=dict(path=str(INIT_SOURCE), sha256=digest(INIT_SOURCE),
                         note='OpenSplitPolicy order; init passes -N and -c 30 (SEPOLICY_VERSION=30)'),
        vendor_version=a.vendor, extra_cil=[str(x) for x in EXTRA_CIL], diagnostics_skipped=not legacy,
        vendor=dict(image=str(VENDOR_IMG), sha256=VENDOR_SHA, plat_sepolicy_vers=vers, genfs_labels_version=genfs,
                    odm_selinux=odm.stdout.strip() or odm.stderr.strip(),
                    files={f.name: digest(f) for f in sorted(V.iterdir())}),
        compositions=runs,
        missing_names=dict(count=len(missing), hal_attributes=len(hal_attrs),
                           keep_types=sorted(KEEP_TYPES), dropped=len(dropped), names=names),
        proposal_effects=dict(vendor_statements_removed=vrem, vendor_statements_changed=vchg,
                              plat_pub_statements_removed=prem, plat_pub_statements_changed=pchg,
                              system_ext_addition_statements=len(stub), system_ext_mapping_statements=len(mapping),
                              keep_property_lines=keep_lines),
        functionfs=ffs, context_reference_policy=str(ref), context_tests=tests,
        context_passed={g: f"{sum(t['passed'] for t in tests if t['group'] == g)}/{sum(1 for t in tests if t['group'] == g)}"
                        for g in ('v14', 'merged', 'proposal', 'adbd')},
        duplicates=duplicates, v14_context_lines_not_in_product=lost)
    a.report.write_text(json.dumps(result, indent=1) + '\n')
    for r in runs:
        print(r['name'], r['returncode'], r.get('binary', {}).get('bytes'), r['first_errors'][:1])
    print('missing', len(missing), 'hal', len(hal_attrs), 'keep types', len(KEEP_TYPES), 'dropped', len(dropped))
    print('contexts', result['context_passed'])
    for t in tests:
        if not t['passed']:
            print('FAIL', t['group'], t['name'], t['output'][:300].replace('\n', ' | '))
    print('functionfs', [q for q in ffs['permissions'] if q['missing']], ffs['policycaps'])


if __name__ == '__main__':
    main()
