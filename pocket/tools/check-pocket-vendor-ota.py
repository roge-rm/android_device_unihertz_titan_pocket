#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Offline check of a full OTA's vendor overlay steps (releasetools.py).

Reads the OTA's updater-script and checks that the vendor check comes before any write, the
overlay is written, a failed addon.d save aborts before boot, boot is followed by the second
backuptool restore, recovery is written, and no vendor image or vendor block update is in
the package. Then runs the OTA's own pocket_vendor.sh, under dash with the build's toybox, on
vendor trees dumped from images, with the image's real free blocks and inodes:
  - the May 2024 stock vendor: apply must give the overlay image file for file (content,
    owner, mode and label) and a second apply must change nothing
  - an earlier overlay built on May (v12) must give the overlay too, and an overlay phone
    must get no writes
  - the January 2023 stock vendor, and the May vendor with one rc changed: both must fail
    with nothing written
  - the May vendor with the apply stopped part way, at several points: a second apply must
    finish the job
Each run's writes, renames and removes are replayed with debugfs on a copy of the image it
started from, so the space plan is tried against the real allocator, then e2fsck -fn must
pass and the replayed files must have the overlay hashes. Owner, mode and label come from
the script's POCKET_VENDOR_META_LOG, as a host user can't set them. No phone access, no root.
"""
import pocket_paths
import argparse
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import zipfile

ROOT = Path(__file__).resolve().parent.parent
SPEC = importlib.util.spec_from_file_location('vota', ROOT / 'tools/prepare-pocket-vendor-ota.py')
VO = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(VO)
OV = VO.OV
BULK = OV.BULK
OTA = BULK / 'product-out/target/product/titan_pocket/lineage_titan_pocket-ota.zip'
JANUARY = OV.STOCK_VENDOR
TOYBOX = OV.HOST_BIN / 'toybox'
DEVICE = pocket_paths.DEVICE_TREE / 'ota'
# Host toybox has no sync; the recovery one does.
APPLETS = ('sha256sum', 'cut', 'dd', 'cp', 'mv', 'rm', 'stat', 'grep', 'sed', 'readlink', 'mkdir',
           'dirname', 'chown', 'chmod', 'chcon', 'blockdev', 'mount', 'umount', 'touch')


def sha256(path):
    return OV.sha256(path)


def fail(msg):
    raise SystemExit('FAIL: ' + msg)


def script_checks(z, results):
    script = z.read('META-INF/com/google/android/updater-script').decode().splitlines()
    names = z.namelist()

    def find(pattern, start=0):
        return [i for i, l in enumerate(script) if i >= start and re.search(pattern, l)]

    check = find(r'pocket_vendor\.sh", "check", map_partition\("vendor"\)')
    apply = find(r'pocket_vendor\.sh", "apply", map_partition\("vendor"\)')
    if len(check) != 1 or len(apply) != 1:
        fail(f'expected one vendor check and one apply, got {len(check)} and {len(apply)}')
    writes = {
        'block_image_update': find(r'block_image_update\('),
        'update_dynamic_partitions': find(r'update_dynamic_partitions\('),
        'boot': find(r'package_extract_file\("boot\.img", "/dev/block/by-name/boot"\)'),
        'recovery': find(r'package_extract_file\("recovery\.img", "/dev/block/by-name/recovery"\)'),
        'backuptool': find(r'backuptool\.sh'),
        'format': find(r'\bformat\('),
        'vendor apply': apply,
    }
    for name, lines in writes.items():
        if lines and min(lines) < check[0]:
            fail(f'{name} at line {min(lines) + 1} comes before the vendor check at line {check[0] + 1}')
    if not writes['boot'] or not writes['recovery'] or not writes['block_image_update']:
        fail('boot, recovery or block writes are missing')
    if apply[0] > min(writes['update_dynamic_partitions'] + writes['block_image_update']):
        fail('the vendor overlay is not written before system')
    for i in check + apply:
        if not re.search(r'== "0" \|\| abort\("E300[12]', script[i]):
            fail(f'line {i + 1} does not abort when the script fails')
    restores = find(r'backuptool\.sh", "restore"')
    backups = find(r'backuptool\.sh", "backup"')
    saves = find(r'pocket_addond\.sh", "save"')
    loads = find(r'pocket_addond\.sh", "load"')
    boot = writes['boot'][0]
    if len(restores) != 2 or len(backups) != 1 or len(saves) != 1 or len(loads) != 1:
        fail(f'backups {backups} restores {restores} saves {saves} loads {loads}')
    if not backups[0] < saves[0] < restores[0] < boot < loads[0] < restores[1]:
        fail('backup, save, restore, boot, load, restore are out of order')
    if not re.search(r'"save"\) == "0" \|\| abort\(', script[saves[0]]):
        fail('a failed addon.d save does not abort before boot is written')
    vendor_writes = find(r'block_image_update\(map_partition\("vendor"\)') + find(r'"/dev/block/by-name/vendor"')
    if vendor_writes:
        fail(f'vendor is written as a block device at lines {vendor_writes}')
    bad = [n for n in names if re.match(r'vendor\.(new\.dat|transfer\.list|patch\.dat|img|map)', n)]
    if bad:
        fail(f'vendor image entries in the OTA: {bad}')
    ops = [l for l in z.read('dynamic_partitions_op_list').decode().splitlines() if l and not l.startswith('#')]
    if any(not re.fullmatch(r'resize (system|product) \d+', l) for l in ops):
        fail(f'the op list does more than resize system and product: {ops}')
    results['updater_script'] = {
        'vendor_check_line': check[0] + 1, 'vendor_apply_line': apply[0] + 1,
        'first_other_write_line': min(min(v) for k, v in writes.items() if v and k != 'vendor apply') + 1,
        'save_line': saves[0] + 1, 'boot_line': boot + 1, 'restore_lines': [r + 1 for r in restores],
        'load_line': loads[0] + 1, 'recovery_line': writes['recovery'][0] + 1,
        'dynamic_partitions_op_list': ops, 'vendor_entries_in_ota': bad}


def payload_checks(payload, manifest, results):
    """Stock-derived files ship only as edits; whole files are ours."""
    files = sorted(str(p.relative_to(payload / 'files')) for p in (payload / 'files').rglob('*') if p.is_file())
    shipped = sorted(e['path'].lstrip('/') for e in manifest['entries'] if e['kind'] in ('add', 'replace'))
    if files != shipped:
        fail(f'whole files in the payload {files} are not the add and replace entries {shipped}')
    for e in manifest['entries']:
        if e['kind'] == 'replace' and not re.fullmatch(r'/lib/modules/\w+\.ko', e['path']):
            fail(f'{e["path"]} ships whole but is derived from stock')
        if e['kind'] == 'patch':
            for a in e['accept']:
                base = payload / 'patch' / e['path'].lstrip('/') / a['sha256']
                if not base.with_suffix('.ops').is_file():
                    fail(f'{e["path"]}: no edit from {a["from"]}')
    results['payload'] = {'whole_files': files, 'patched': sum(e['kind'] == 'patch' for e in manifest['entries']),
                          'literal_bytes': sum(p['literal_bytes'] for p in manifest['patches'].values()),
                          'history': manifest['history'], 'plan': manifest['plan']}


def tree_state(root):
    """{path: sha256 or 'link:target' or 'dir'} for every entry under root."""
    out = {}
    for d, dirs, files in os.walk(root):
        r = os.path.relpath(d, root)
        rel = '/' if r == '.' else '/' + r
        out[rel] = 'dir'
        for name in dirs + files:
            p = os.path.join(d, name)
            r = (rel.rstrip('/') + '/' + name)
            if os.path.islink(p):
                out[r] = 'link:' + os.readlink(p)
            elif os.path.isfile(p):
                out[r] = sha256(p)
    return out


def rdump(image, dest):
    if dest.exists():
        shutil.rmtree(dest)
    dest.mkdir(parents=True)
    # debugfs can't set owners as a user; it says so per file and dumps the content anyway.
    subprocess.run([OV.HOST_BIN / 'debugfs', '-R', f'rdump / {dest}', image], capture_output=True)
    if not (dest / 'build.prop').is_file():
        fail(f'rdump of {image} failed')


class Runner:
    def __init__(self, work, payload):
        self.work, self.payload = work, payload
        self.scratch = work / 'scratch'

    def run(self, mode, target, free, stop=None):
        """Returns (rc, output, ops, meta) for one run of the OTA's script."""
        log, opslog = self.work / 'meta.log', self.work / 'ops.log'
        for f in (log, opslog):
            if f.exists():
                f.unlink()
        env = {'PATH': str(self.work / 'bin'), 'POCKET_VENDOR_META_LOG': str(log),
               'POCKET_VENDOR_OPS_LOG': str(opslog), 'POCKET_VENDOR_WORK': str(self.scratch),
               'POCKET_VENDOR_FREE': f'{free[0]} {free[1]}'}
        if stop is not None:
            env['POCKET_VENDOR_STOP_AFTER'] = str(stop)
        p = subprocess.run(['/usr/bin/dash', str(self.payload.parent / 'pocket_vendor.sh'), mode, str(target),
                            str(self.payload)], env=env, capture_output=True, text=True)
        ops = [l.split() for l in opslog.read_text().splitlines()] if opslog.exists() else []
        meta = {}
        if log.exists():
            for line in log.read_text().splitlines():
                path, uid, gid, mode_, label = line.split()
                meta['/' + path] = (int(uid), int(gid), mode_, label)
        return p.returncode, (p.stdout + p.stderr).strip(), ops, meta

    def source(self, entries, path):
        e = entries['/' + path]
        return self.scratch / 'new' / path if e['kind'] == 'patch' else self.payload / 'files' / path


def free_of(image):
    blocks, inodes, bs = VO.image_stats(image)
    if bs != 4096:
        fail(f'{image} block size {bs}')
    return blocks, inodes


def replay(runner, entries, image, ops, existing):
    """Do the script's writes, renames and removes with debugfs on image.

    existing: set of regular file paths in the image, kept up to date. Returns the lowest
    free block count seen after a run of writes.
    """
    low = None
    i = 0
    while i < len(ops):
        kind = ops[i][0]
        seg = []
        while i < len(ops) and ops[i][0] == kind:
            seg.append(ops[i])
            i += 1
        cmds = []
        for op in seg:
            path = op[1]
            d, name = os.path.split('/' + path)
            cmds.append(f'cd "{d or "/"}"')
            if kind == 'write':
                cmds.append(f'write "{runner.source(entries, path[:-len(".pocket-new")])}" "{name}"')
                existing.add('/' + path)
            elif kind == 'rename':
                dst = os.path.basename(op[2])
                if '/' + op[2] in existing:
                    cmds.append(f'rm "{dst}"')
                cmds += [f'ln "{name}" "{dst}"', f'unlink "{name}"']
                existing.discard('/' + path)
                existing.add('/' + op[2])
            else:
                cmds.append(f'rm "{name}"')
                existing.discard('/' + path)
        OV.debugfs(image, cmds, write=True)
        if kind == 'write':
            f = free_of(image)[0]
            low = f if low is None else min(low, f)
    return low


def fsck(image):
    p = subprocess.run([OV.HOST_BIN / 'e2fsck', '-fn', image], capture_output=True, text=True)
    if p.returncode != 0:
        fail(f'e2fsck -fn on the replayed {image.name} returned {p.returncode}:\n{p.stdout}{p.stderr}')


def replayed_hashes(image, entries, scratch):
    out = {}
    paths = sorted(entries)
    metas = OV.stat_paths(image, paths, allow_missing=True)
    for p in paths:
        out[p] = OV.sha256_bytes(OV.dump(image, p, scratch)) if metas[p] else '-'
    scratch.unlink(missing_ok=True)
    return out


def compare(after, meta, want, start, entries):
    """Mismatches between a result tree and the overlay image.

    Files the script set metadata on are compared to the overlay's owner, mode and label;
    the rest keep the metadata of the image the run started from.
    """
    mismatches = []
    for p in sorted(set(want) | set(after)):
        w, a = want.get(p), after.get(p)
        if w is None or a is None:
            mismatches.append(f'{p}: only in {"the result" if w is None else "the overlay"}')
            continue
        if w['type'] == 'regular' and a != w['sha256']:
            mismatches.append(f'{p}: content differs')
        if w['type'] == 'directory' and a != 'dir':
            mismatches.append(f'{p}: not a directory')
        if w['type'] == 'symlink' and 'link' in w and a != 'link:' + w['link']:
            mismatches.append(f'{p}: symlink target differs')
        if p in meta:
            got = meta[p]
            exp = (w['uid'], w['gid'], f'{int(w["mode"], 8) & 0o7777:04o}', VO.label_of(w, p))
        else:
            b = start.get(p)
            got = b and (b['uid'], b['gid'], b['mode'], tuple(b['xattrs']), b['type'])
            exp = (w['uid'], w['gid'], w['mode'], tuple(w['xattrs']), w['type'])
        if got != exp:
            mismatches.append(f'{p}: metadata {got} is not {exp}')
    if set(meta) - {p for p, e in entries.items() if e['kind'] != 'remove'}:
        mismatches.append('metadata set on files the manifest does not write')
    return mismatches


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument('--ota', type=Path, default=OTA)
    ap.add_argument('--base', type=Path, default=VO.BASE_IMAGE, help='May 2024 stock vendor.img')
    ap.add_argument('--january', type=Path, default=JANUARY, help='January 2023 stock vendor.img')
    ap.add_argument('--overlay', type=Path, default=OV.OVERLAY_DIR / VO.VERSION / 'vendor.img')
    ap.add_argument('--older', type=Path, default=OV.OVERLAY_DIR / 'v12' / 'vendor.img',
                    help='an earlier overlay built on May')
    ap.add_argument('--work', type=Path, default=ROOT / 'build/vendor-ota-check')
    ap.add_argument('--report', type=Path)
    args = ap.parse_args()
    if sha256(args.base) != VO.BASE_SHA256:
        fail('base is not the pinned May 2024 vendor')
    results = {'ota': str(args.ota), 'ota_sha256': sha256(args.ota), 'device_accessed': False}

    work = args.work
    if work.exists():
        shutil.rmtree(work)
    (work / 'bin').mkdir(parents=True)
    for a in APPLETS:
        (work / 'bin' / a).symlink_to(TOYBOX)
    (work / 'bin/sync').symlink_to('/usr/bin/sync')

    with zipfile.ZipFile(args.ota) as z:
        script_checks(z, results)
        ota = work / 'ota'
        for n in z.namelist():
            if n.startswith('pocket/') and not n.endswith('/'):
                dest = ota / n
                dest.parent.mkdir(parents=True, exist_ok=True)
                dest.write_bytes(z.read(n))
    pocket = ota / 'pocket'
    payload = pocket / 'payload'
    for s in ('pocket_vendor.sh', 'pocket_addond.sh'):
        if (pocket / s).read_bytes() != (DEVICE / s).read_bytes():
            fail(f'{s} in the OTA differs from the device tree')
    manifest = json.loads((payload / 'manifest.json').read_text())
    payload_checks(payload, manifest, results)
    entries = {e['path']: e for e in manifest['entries']}
    target_hash = {p: e['target_sha256'] or '-' for p, e in entries.items()}
    runner = Runner(work, payload)

    scratch = work / 'img'
    scratch.mkdir()
    want = VO.tree(args.overlay, scratch / 'overlay')
    trees = {'may': VO.tree(args.base, scratch / 'may'), 'older': VO.tree(args.older, scratch / 'older')}

    def regular(t):
        return {p for p, m in t.items() if m['type'] == 'regular'}

    def full_run(name, image, start_tree, trees_dir):
        """Check and apply from image's own state; replay on a copy; compare to the overlay."""
        root = trees_dir / name
        rdump(image, root)
        before = tree_state(root)
        free = free_of(image)
        rc, out, _, _ = runner.run('check', root, free)
        if rc != 0:
            fail(f'check on {name} failed: {out}')
        rc, out, ops, meta = runner.run('apply', root, free)
        if rc != 0:
            fail(f'apply on {name} failed: {out}')
        after = tree_state(root)
        bad = compare(after, meta, want, start_tree, entries)
        if bad:
            fail(f'{name} after apply differs from the overlay:\n' + '\n'.join(bad))
        changed = sorted(p for p in set(before) | set(after) if before.get(p) != after.get(p))
        img = work / f'{name}.img'
        shutil.copyfile(image, img)
        low = replay(runner, entries, img, ops, regular(start_tree))
        fsck(img)
        if replayed_hashes(img, entries, work / 'dump.bin') != target_hash:
            fail(f'the replayed {name} image does not have the overlay files')
        planned = re.search(r'space: at least (-?\d+) blocks', out)
        if not planned:
            fail(f'{name}: the space check did not run')
        if low is not None and low < int(planned[1]):
            fail(f'{name}: {low} blocks were free at the lowest point, the plan said at least {planned[1]}')
        r = {'rc': rc, 'output': out, 'free_before': free, 'free_after': free_of(img),
             'planned_lowest_free': int(planned[1]), 'replayed_lowest_free': low,
             'writes': sum(o[0] == 'write' for o in ops), 'renames': sum(o[0] == 'rename' for o in ops),
             'removes': sum(o[0] == 'remove' for o in ops), 'changed_paths': len(changed),
             'paths_compared': len(want), 'mismatches': 0, 'metadata_set': len(meta), 'e2fsck': 'clean'}
        return r, root, img, after, ops

    trees_dir = work / 'trees'
    # May stock with its real free space.
    r, may, may_img, after, may_ops = full_run('may', args.base, trees['may'], trees_dir)
    expect = sorted(p for p, e in entries.items()
                    if (trees['may'].get(p) or {}).get('sha256') != e['target_sha256'])
    if r['changed_paths'] != len(expect):
        fail(f'apply on May changed {r["changed_paths"]} paths, the manifest changes {len(expect)}')
    results['may_apply'] = r

    # A second run on the result writes nothing.
    rc, out, ops, _ = runner.run('apply', may, free_of(may_img))
    if rc != 0 or ops or tree_state(may) != after:
        fail(f'a second apply failed or wrote: {out} {ops}')
    results['may_apply_again'] = {'rc': rc, 'output': out, 'writes': 0}
    shutil.rmtree(may)
    may_img.unlink()

    # An overlay phone gets no writes; an earlier overlay is brought up to date.
    root = trees_dir / 'overlay'
    rdump(args.overlay, root)
    before = tree_state(root)
    rc, out, ops, meta = runner.run('apply', root, free_of(args.overlay))
    if rc != 0 or ops or tree_state(root) != before:
        fail(f'apply on the overlay was not a no-op: rc {rc} {out} {ops}')
    results['overlay_apply'] = {'rc': rc, 'output': out, 'writes': 0, 'metadata_set': len(meta)}
    shutil.rmtree(root)
    # An overlay from before encrypted /data: refused with the wipe message, nothing written.
    older = trees_dir / 'older'
    rdump(args.older, older)
    older_before = tree_state(older)
    rc, out, ops, meta = runner.run('check', older, free_of(args.older))
    if rc == 0 or 'needs a data wipe' not in out or tree_state(older) != older_before or ops or meta:
        fail(f'check on the older overlay did not refuse cleanly: rc {rc} {out}')
    rc, out, ops, meta = runner.run('apply', older, free_of(args.older))
    if rc == 0 or tree_state(older) != older_before or ops or meta:
        fail(f'apply on the older overlay did not abort cleanly: rc {rc} {out}')
    results['older_overlay_apply'] = {'rc': rc, 'output': out, 'files_changed': 0, 'image': str(args.older)}
    shutil.rmtree(older)

    # January stock: refused, nothing written.
    jan = trees_dir / 'january'
    rdump(args.january, jan)
    jan_before = tree_state(jan)
    rc, out, ops, meta = runner.run('apply', jan, free_of(args.january))
    if rc == 0 or tree_state(jan) != jan_before or ops or meta:
        fail(f'apply on the January vendor did not abort cleanly: rc {rc} {out}')
    results['january_apply'] = {'rc': rc, 'output': out, 'files_changed': 0}
    shutil.rmtree(jan)

    # May stock with one rc changed: refused, nothing written.
    may = trees_dir / 'may'
    rdump(args.base, may)
    pristine = trees_dir / 'may-pristine'
    shutil.copytree(may, pristine, symlinks=True)
    odd = may / 'etc/init/trustkernel.rc'
    data = odd.read_bytes() + b'# changed\n'
    odd.unlink()
    odd.write_bytes(data)
    odd_before = tree_state(may)
    rc, out, ops, meta = runner.run('apply', may, free_of(args.base))
    if rc == 0 or tree_state(may) != odd_before or ops or meta:
        fail(f'apply on a changed May vendor did not abort cleanly: rc {rc} {out}')
    results['changed_rc_apply'] = {'rc': rc, 'output': out, 'files_changed': 0}
    shutil.rmtree(may)

    # Stopped part way, then run again: at the first write, once the first step is staged,
    # half way and at the last remove.
    first_rename = next(i for i, o in enumerate(may_ops) if o[0] == 'rename')
    stops = sorted({1, first_rename, len(may_ops) // 2, len(may_ops) - 1})
    partial = []
    for stop in stops:
        shutil.copytree(pristine, may, symlinks=True)
        img = work / 'partial.img'
        shutil.copyfile(args.base, img)
        existing = regular(trees['may'])
        rc, out, ops, _ = runner.run('apply', may, free_of(args.base), stop=stop)
        if rc != 3 or len(ops) != stop:
            fail(f'the apply did not stop after {stop} writes: rc {rc} {out}')
        replay(runner, entries, img, ops, existing)
        free = free_of(img)
        rc, out, ops2, meta = runner.run('apply', may, free)
        if rc != 0:
            fail(f'the retry after {stop} writes failed: {out}')
        bad = compare(tree_state(may), meta, want, trees['may'], entries)
        if bad:
            fail(f'the retry after {stop} writes differs from the overlay:\n' + '\n'.join(bad))
        replay(runner, entries, img, ops2, existing)
        fsck(img)
        if replayed_hashes(img, entries, work / 'dump.bin') != target_hash:
            fail(f'the replayed retry after {stop} writes does not have the overlay files')
        partial.append({'stopped_after': stop, 'stopped_at': ' '.join(ops[-1]) if ops else None,
                        'free_at_retry': free, 'retry_writes': len(ops2), 'retry_output': out,
                        'mismatches': 0, 'e2fsck': 'clean'})
        shutil.rmtree(may)
        img.unlink()
    results['partial_then_retry'] = partial

    shutil.rmtree(work)
    text = json.dumps(results, indent=2) + '\n'
    if args.report:
        args.report.write_text(text)
    print(text + 'PASS')


if __name__ == '__main__':
    main()
