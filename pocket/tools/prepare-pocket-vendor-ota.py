#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Make the vendor overlay payload that OTAs apply to the phone's vendor partition.

Compares the May 2024 stock vendor image, and every earlier overlay built on it, with the
overlay image (v13) file by file and writes pocket_vendor_overlay.zip with:
  manifest.txt   one line per changed path, read by device ota/pocket_vendor.sh
  manifest.json  the same with sizes and the write plan, for the host tools
  files/PATH     files that are wholly ours (added files and the kernel modules we build)
  patch/PATH/HASH.ops, .lit
                 edits of files derived from stock: the phone rebuilds the overlay version
                 from its own copy with hash HASH, so no Unihertz file ships whole

manifest.txt lines, fields split by single spaces:
  vendor_version_min YYYYMMDD     oldest stock release accepted, from ro.vendor.build.custom_version
  KIND STEP PATH TARGET SIZE MODE UID GID LABEL ACCEPT
KIND is add, replace (shipped whole), patch or remove. TARGET is the overlay sha256, "-" for
remove. ACCEPT lists the sha256 values the phone's file may have before the write, comma
separated, "-" for no file: stock May and each earlier overlay. PATH is relative to the
vendor root. STEP is the write batch: each batch is staged beside the old files, then
renamed over them, and the removes come last. The batches are planned so the writes fit the
free blocks and inodes of the May stock vendor (plan_steps, the same model as the script).

.ops lines build the new file in order: "s OFF LEN" copies LEN bytes at OFF of the phone's
file, "l OFF LEN" copies LEN bytes at OFF of the .lit file, our own bytes.

Reads images only, no phone access. The payload stays in private storage with the other
vendor inputs.
"""
import argparse
import difflib
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import zipfile

ROOT = Path(__file__).resolve().parent.parent
SPEC = importlib.util.spec_from_file_location('overlay', ROOT / 'tools/prepare-pocket-vendor-overlay.py')
OV = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(OV)
SPEC = importlib.util.spec_from_file_location('checker', ROOT / 'tools/check-pocket-vendor-overlay.py')
CK = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CK)
TEED = OV.teed_tool()

VERSION = 'v13'
FSTAB_PATH = '/etc/fstab.mt6771'
ENCRYPTED_SINCE = 'v13'
BASE_IMAGE = OV.STOCK_VENDOR_MAY
BASE_SHA256 = OV.STOCK_VENDOR_MAY_SHA256
OUT = OV.OVERLAY_DIR / VERSION / 'ota'
NAME = 'pocket_vendor_overlay.zip'
TEED_PATH = '/bin/teed'
# Only these xattrs go on vendor files; anything else stops the build.
LABEL_XATTR = 'security.selinux'
# Zip entries get a fixed time so the payload is the same on every run.
ZIP_TIME = (2024, 5, 14, 0, 0, 0)
# Shared with ota/pocket_vendor.sh: blocks and inodes that must stay free at every point,
# and one block per written file for its extent and directory growth.
RESERVE_BLOCKS = 8
RESERVE_INODES = 1
EXTRA_BLOCKS = 1
# Matches shorter than this go in the literal bytes.
MIN_COPY = 8
# No run this long in the literal bytes may also be in the phone's file: it is copied from
# there instead, wherever it sits, so the .lit holds no stock runs (check-pocket-installer.py
# --zip scans for them).
STOCK_RUN = 64


def sha256_bytes(data):
    return hashlib.sha256(data).hexdigest()


def tree(image, scratch):
    """{path: meta} for every inode, with content sha256 for regular files."""
    paths = CK.walk(image)
    metas = OV.stat_paths(image, sorted(paths))
    hashes = CK.content_hashes(image, paths, scratch)
    for p, m in metas.items():
        m['sha256'] = hashes.get(p)
    return {k.rstrip('/') or '/': v for k, v in metas.items()}


def xattr_map(meta):
    """{name: value} from ea_get output like 'security.selinux (31) = "u:object_r:...:s0\\000"'."""
    out = {}
    for x in meta['xattrs']:
        m = re.match(r'(\S+) \((\d+)\) = "(.*)"$', x)
        if not m:
            raise SystemExit(f'unparsed xattr: {x}')
        out[m[1]] = m[3]
    return out


def label_of(meta, path):
    xs = xattr_map(meta)
    extra = set(xs) - {LABEL_XATTR}
    if extra:
        raise SystemExit(f'{path}: xattrs the OTA does not set: {sorted(extra)}')
    value = xs.get(LABEL_XATTR, '')
    if value.endswith('\\000'):
        value = value[:-4]
    if not re.fullmatch(r'u:object_r:[a-z0-9_]+:s0', value):
        raise SystemExit(f'{path}: unexpected label {value!r}')
    return value


def same_meta(a, b):
    keys = ('type', 'mode', 'uid', 'gid', 'xattrs', 'link')
    return all(a.get(k) == b.get(k) for k in keys)


def blocks(size, bs):
    return (size + bs - 1) // bs


def teed_provenance(stock, patched):
    """Source offset in the stock teed for each byte of the patched teed, None for our bytes.

    The copies are the two moves add_needed() makes (the string table into the padding, the
    dynamic entries down one slot); the bytes left are our own values: the added name, the
    DT_NEEDED entry, new sizes and addresses.
    """
    phdrs, _, (dyn_off, _), entries = TEED.elf_layout(stock)
    used = next(i for i, (t, _) in enumerate(entries) if t == TEED.DT_NULL)
    tags = dict((t, v) for t, v in entries[:used] if t in (TEED.DT_STRTAB, TEED.DT_STRSZ))
    str_off = TEED.vaddr_to_offset(phdrs, tags[TEED.DT_STRTAB])
    str_size = tags[TEED.DT_STRSZ]
    new_phdrs, _, _, new_entries = TEED.elf_layout(patched)
    new_tags = dict((t, v) for t, v in new_entries if t in (TEED.DT_STRTAB, TEED.DT_STRSZ))
    new_off = TEED.vaddr_to_offset(new_phdrs, new_tags[TEED.DT_STRTAB])
    if len(stock) != len(patched):
        raise SystemExit('the patched teed changed size')
    src = list(range(len(stock)))
    for s, d, n in ((str_off, new_off, str_size), (dyn_off, dyn_off + 16, 16 * used)):
        src[d:d + n] = range(s, s + n)
    return [s if stock[s] == patched[i] else None for i, s in enumerate(src)]


def ops_from_provenance(src, patched):
    """Run-length the provenance into ops; literal runs and short copies go in the .lit."""
    runs = []
    for i, s in enumerate(src):
        if runs and runs[-1][0] == 's' and s is not None and runs[-1][1] + runs[-1][2] == s:
            runs[-1][2] += 1
        elif runs and runs[-1][0] == 'l' and s is None:
            runs[-1][2] += 1
        else:
            runs.append(['s', s, 1] if s is not None else ['l', i, 1])
    # Each run is ['s', src_off, n] or ['l', out_off, n].
    return pack(runs, patched)


def pack(runs, out):
    """Turn runs into ops and literal bytes, folding short copies into the literals."""
    ops, lit, pos = [], bytearray(), 0
    for kind, off, n in runs:
        if kind == 's' and n >= MIN_COPY:
            ops.append(('s', off, n))
        else:
            data = out[pos:pos + n]
            if ops and ops[-1][0] == 'l':
                ops[-1] = ('l', ops[-1][1], ops[-1][2] + n)
            else:
                ops.append(('l', len(lit), n))
            lit += data
        pos += n
    return ops, bytes(lit)


def diff_ops(old, new):
    """Ops that rebuild new from old: copies of matching runs, our bytes as literals.

    Text files are matched by lines, and changed lines again by bytes, so a changed line
    ships only its changed bytes.
    """
    runs = []

    def by_bytes(a, a_off, b):
        sm = difflib.SequenceMatcher(None, a, b, autojunk=False)
        for tag, i1, i2, j1, j2 in sm.get_opcodes():
            if tag == 'equal':
                runs.append(['s', a_off + i1, i2 - i1])
            elif j2 > j1:
                runs.append(['l', 0, j2 - j1])

    if b'\0' in old or b'\0' in new:
        by_bytes(old, 0, new)
    else:
        a, b = old.splitlines(keepends=True), new.splitlines(keepends=True)
        a_off = [0]
        for line in a:
            a_off.append(a_off[-1] + len(line))
        b_off = [0]
        for line in b:
            b_off.append(b_off[-1] + len(line))
        sm = difflib.SequenceMatcher(None, a, b, autojunk=False)
        for tag, i1, i2, j1, j2 in sm.get_opcodes():
            if tag == 'equal':
                runs.append(['s', a_off[i1], a_off[i2] - a_off[i1]])
            elif tag == 'replace':
                by_bytes(old[a_off[i1]:a_off[i2]], a_off[i1], new[b_off[j1]:b_off[j2]])
            elif tag == 'insert':
                runs.append(['l', 0, b_off[j2] - b_off[j1]])
    return pack(runs, new)


def copy_stock_runs(ops, lit, old, k=STOCK_RUN):
    """Moves runs of k or more literal bytes that are also anywhere in old to copies of old.

    The diff only copies in order, so a stock line repeated or moved in our version comes out
    as literal bytes. Each literal op is scanned from the left for the longest match in old
    (found through its k/2-byte windows) and split where one of k or more bytes starts.
    """
    half = k // 2
    index = {}
    for o in range(len(old) - half + 1):
        bucket = index.setdefault(old[o:o + half], [])
        if len(bucket) < 256:
            bucket.append(o)
    out_ops, out_lit = [], bytearray()

    def literal(data):
        if out_ops and out_ops[-1][0] == 'l':
            out_ops[-1] = ('l', out_ops[-1][1], out_ops[-1][2] + len(data))
        else:
            out_ops.append(('l', len(out_lit), len(data)))
        out_lit.extend(data)

    for kind, off, n in ops:
        if kind != 'l':
            out_ops.append((kind, off, n))
            continue
        data = lit[off:off + n]
        i = start = 0
        while i + k <= len(data):
            best, at = 0, None
            for o in index.get(data[i:i + half], ()):
                m = half
                while i + m < len(data) and o + m < len(old) and data[i + m] == old[o + m]:
                    m += 1
                if m > best:
                    best, at = m, o
            if best >= k:
                if i > start:
                    literal(data[start:i])
                out_ops.append(('s', at, best))
                i = start = i + best
            else:
                i += 1
        if start < len(data):
            literal(data[start:])
    return out_ops, bytes(out_lit)


def apply_ops(old, ops, lit):
    out = bytearray()
    for kind, off, n in ops:
        out += (old if kind == 's' else lit)[off:off + n]
    return bytes(out)


def plan_steps(writes, free_blocks, free_inodes, bs):
    """Put the writes in batches that fit the May stock vendor's free space.

    writes: [(path, old_size or None, new_size)]. Files that shrink go first, smallest need
    first, so each batch frees room for the next; then the rest, smallest first. Each batch
    is staged next to the old files, so it needs its new blocks and an inode per file, and
    gives back the old ones when renamed. Returns ({path: step}, lowest free blocks).
    """
    def need(w):
        return blocks(w[2], bs) + EXTRA_BLOCKS

    def gain(w):
        return (blocks(w[1], bs) if w[1] is not None else 0) - blocks(w[2], bs)

    order = sorted(writes, key=lambda w: (gain(w) <= 0, need(w), w[0]))
    steps, step, f, i, low = {}, 1, free_blocks, free_inodes, free_blocks
    pending = list(order)
    while pending:
        batch, bf, bi = [], f, i
        for w in list(pending):
            if bf - need(w) >= RESERVE_BLOCKS and bi - 1 >= RESERVE_INODES:
                batch.append(w)
                pending.remove(w)
                bf -= need(w)
                bi -= 1
            elif not batch:
                raise SystemExit(f'{w[0]} does not fit: needs {need(w)} blocks, {f} free')
            else:
                break
        low = min(low, bf)
        for w in batch:
            steps[w[0]] = step
            if w[1] is not None:
                bf += blocks(w[1], bs)
                bi += 1
        f, i, step = bf, bi, step + 1
    return steps, step, low


def image_stats(image):
    out = dict(OV.debugfs(image, ['stats']))['stats']
    get = lambda k: int(re.search(rf'^{k}:\s+(\d+)', out, re.M)[1])
    return get('Free blocks'), get('Free inodes'), get('Block size')


def history(version):
    """Earlier overlay versions built on the May vendor, with their image."""
    out = []
    for v in OV.VERSIONS[:OV.VERSIONS.index(version)]:
        d = OV.OVERLAY_DIR / v
        try:
            rec = json.loads((d / 'record.json').read_text())
        except FileNotFoundError:
            continue
        if rec['stock_vendor']['sha256'] != BASE_SHA256 or not (d / 'vendor.img').exists():
            continue
        if OV.sha256(d / 'vendor.img') != rec['image']['sha256']:
            raise SystemExit(f'{v} image does not match its record')
        out.append((v, d / 'vendor.img'))
    return out


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument('--base', type=Path, default=BASE_IMAGE, help='May 2024 stock vendor.img')
    ap.add_argument('--overlay', type=Path, default=OV.OVERLAY_DIR / VERSION / 'vendor.img')
    ap.add_argument('--record', type=Path, default=OV.OVERLAY_DIR / VERSION / 'record.json')
    ap.add_argument('--out', type=Path, default=OUT)
    args = ap.parse_args()
    if OV.sha256(args.base) != BASE_SHA256:
        raise SystemExit(f'{args.base} is not the pinned May 2024 vendor')
    record = json.loads(args.record.read_text())
    if record['version'] != VERSION or OV.sha256(args.overlay) != record['image']['sha256']:
        raise SystemExit(f'{args.overlay} does not match its {VERSION} record')
    if record['stock_vendor']['sha256'] != BASE_SHA256:
        raise SystemExit(f'{VERSION} is not built on the May 2024 vendor')

    args.out.mkdir(parents=True, exist_ok=True)
    scratch = args.out / 'scratch'
    if scratch.exists():
        shutil.rmtree(scratch)
    scratch.mkdir()
    base = tree(args.base, scratch / 'base')
    new = tree(args.overlay, scratch / 'new')
    older = [(v, img, tree(img, scratch / v)) for v, img in history(VERSION)]
    states = [('May', args.base, base)] + older

    entries = []
    for path in sorted(set(new).union(*(t for _, _, t in states))):
        b = new.get(path)
        olds = [(v, img, t.get(path)) for v, img, t in states]
        if all(a and b and a['sha256'] == b['sha256'] and same_meta(a, b) for _, _, a in olds) or \
                (b is None and all(a is None for _, _, a in olds)):
            continue
        for m in [b] + [a for _, _, a in olds]:
            if m and m['type'] != 'regular':
                raise SystemExit(f'{path}: a {m["type"]} changed; the OTA only handles regular files')
        if ' ' in path or ',' in path:
            raise SystemExit(f'{path}: spaces and commas are not handled')
        stock = base.get(path)
        if not b:
            kind = 'remove'
        elif not stock:
            kind = 'add'
        elif path.startswith('/lib/modules/') and path.endswith('.ko'):
            # Built from source by tools/build-pocket-connectivity-module.py.
            kind = 'replace'
        else:
            kind = 'patch'
        accept = []
        for v, img, a in olds:
            h = a['sha256'] if a else '-'
            if b and h == b['sha256']:
                continue
            if h not in [x['sha256'] for x in accept]:
                accept.append({'sha256': h, 'from': [v], 'image': img, 'size': a and a['size']})
            else:
                next(x for x in accept if x['sha256'] == h)['from'].append(v)
        if path == FSTAB_PATH:
            # Overlays before ENCRYPTED_SINCE have an unencrypted /data; turning encryption on
            # over it needs a wipe, so only the stock fstab (a fresh install) is a base.
            accept = [x for x in accept if x['from'] == ['May'] or
                      any(OV.VERSIONS.index(v) >= OV.VERSIONS.index(ENCRYPTED_SINCE) for v in x['from'])]
        if kind == 'patch' and any(x['sha256'] == '-' for x in accept):
            raise SystemExit(f'{path}: an earlier version has no copy to patch')
        e = {'kind': kind, 'path': path, 'target_sha256': b and b['sha256'],
             'stock_sha256': stock and stock['sha256'], 'stock_size': stock and stock['size'],
             'accept': [{'sha256': x['sha256'], 'from': x['from']} for x in accept]}
        if b:
            e.update(size=b['size'], mode=f'{int(b["mode"], 8) & 0o7777:04o}', uid=b['uid'], gid=b['gid'],
                     label=label_of(b, path))
        e['_accept'] = accept
        entries.append(e)

    # The image diff against stock has to be what the overlay tool says it changed.
    stock_diff = [e for e in entries if e['stock_sha256'] != e['target_sha256'] or
                  not same_meta(base.get(e['path']) or {}, new.get(e['path']) or {})]
    want = {'replaced': set(record['replaced']), 'added': {a['path'] for a in record['added']},
            'removed': set(record['removed'])}
    got = {'replaced': {e['path'] for e in stock_diff if e['kind'] in ('replace', 'patch')},
           'added': {e['path'] for e in stock_diff if e['kind'] == 'add'},
           'removed': {e['path'] for e in stock_diff if e['kind'] == 'remove'}}
    if got != want:
        raise SystemExit(f'image diff differs from the {VERSION} record:\n'
                         + '\n'.join(f'{k}: extra {sorted(got[k] - want[k])} missing {sorted(want[k] - got[k])}'
                                     for k in want if got[k] != want[k]))

    stock_teed = OV.dump(args.base, TEED_PATH, scratch / 'teed.stock')
    new_teed = OV.dump(args.overlay, TEED_PATH, scratch / 'teed.new')
    if sha256_bytes(stock_teed) != TEED.TEED_SHA256 or sha256_bytes(new_teed) != record['teed_edit']['sha256']:
        raise SystemExit('teed hashes differ from the pinned stock and the record')
    TEED.check_patched(stock_teed, new_teed, TEED.NAME)

    # The vendor build date is the same in January and May; the release name isn't.
    release = re.search(rb'^ro\.vendor\.build\.custom_version=Titan_pocket_(\d{8})$',
                        OV.dump(args.base, '/build.prop', scratch / 'prop'), re.M)
    vendor_version_min = int(release[1])

    free_blocks, free_inodes, bs = image_stats(args.base)
    writes = [(e['path'], e['stock_size'], e['size']) for e in entries
              if e['kind'] != 'remove' and e['stock_sha256'] != e['target_sha256']]
    steps, last, low = plan_steps(writes, free_blocks, free_inodes, bs)
    for e in entries:
        e['step'] = last if e['kind'] == 'remove' else steps.get(e['path'], 1)
    entries.sort(key=lambda e: (e['step'], e['path']))

    zpath = args.out / (NAME + '.tmp')
    patches = {}
    with zipfile.ZipFile(zpath, 'w', zipfile.ZIP_DEFLATED) as z:
        def put(name, data, mode=0o644):
            info = zipfile.ZipInfo(name, ZIP_TIME)
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = (0o100000 | mode) << 16
            z.writestr(info, data)
        lines = [f'vendor_version_min {vendor_version_min}']
        for e in entries:
            accept = ','.join(x['sha256'] for x in e['accept']) or '-'
            lines.append(' '.join(str(x) for x in (
                e['kind'], e['step'], e['path'].lstrip('/'), e['target_sha256'] or '-',
                e.get('size', '-'), e.get('mode', '-'), e.get('uid', '-'), e.get('gid', '-'),
                e.get('label', '-'), accept)))
        put('manifest.txt', '\n'.join(lines) + '\n')
        for e in entries:
            if e['kind'] in ('add', 'replace'):
                data = OV.dump(args.overlay, e['path'], scratch / 'file')
                if sha256_bytes(data) != e['target_sha256']:
                    raise SystemExit(f'{e["path"]}: dump differs')
                put('files' + e['path'], data)
            if e['kind'] != 'patch':
                continue
            target = OV.dump(args.overlay, e['path'], scratch / 'file')
            for x in e['_accept']:
                old = OV.dump(x['image'], e['path'], scratch / 'old')
                if sha256_bytes(old) != x['sha256']:
                    raise SystemExit(f'{e["path"]}: dump of {x["from"]} differs')
                if e['path'] == TEED_PATH and x['sha256'] == TEED.TEED_SHA256:
                    ops, lit = ops_from_provenance(teed_provenance(old, target), target)
                else:
                    ops, lit = diff_ops(old, target)
                ops, lit = copy_stock_runs(ops, lit, old)
                if apply_ops(old, ops, lit) != target:
                    raise SystemExit(f'{e["path"]}: ops from {x["from"]} do not rebuild the overlay file')
                name = f'patch{e["path"]}/{x["sha256"]}'
                put(name + '.ops', ''.join(f'{k} {o} {n}\n' for k, o, n in ops))
                put(name + '.lit', lit)
                patches[f'{e["path"]} from {"+".join(x["from"])}'] = {
                    'ops': len(ops), 'literal_bytes': len(lit), 'size': len(target)}
        for e in entries:
            del e['_accept']
        manifest = {'schema': 2, 'version': VERSION, 'base': {'path': str(args.base), 'sha256': BASE_SHA256, 'bytes': args.base.stat().st_size},
                    'overlay': {'path': str(args.overlay), 'sha256': record['image']['sha256'],
                                'bytes': args.overlay.stat().st_size},
                    'history': [v for v, _, _ in older],
                    'vendor_version_min': vendor_version_min, 'entries': entries,
                    'plan': {'free_blocks': free_blocks, 'free_inodes': free_inodes, 'block_size': bs,
                             'steps': last, 'lowest_free_blocks': low, 'reserve_blocks': RESERVE_BLOCKS},
                    'patches': patches}
        put('manifest.json', json.dumps(manifest, indent=2) + '\n')
    os.replace(zpath, args.out / NAME)
    shutil.rmtree(scratch)
    summary = {k: sum(1 for e in entries if e['kind'] == k) for k in ('add', 'replace', 'patch', 'remove')}
    rec = {'payload': str(args.out / NAME), 'sha256': OV.sha256(args.out / NAME), 'entries': summary,
           'history': [v for v, _, _ in older], 'literal_bytes': sum(p['literal_bytes'] for p in patches.values()),
           'plan': manifest['plan'], 'vendor_version_min': vendor_version_min, 'device_accessed': False}
    (args.out / 'record.json').write_text(json.dumps(rec, indent=2) + '\n')
    print(json.dumps(rec, indent=2))
    print(json.dumps(patches, indent=2))


if __name__ == '__main__':
    main()
