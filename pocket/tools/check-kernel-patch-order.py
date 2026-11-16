#!/usr/bin/env python3
"""Replay patches/kernel-upgrade-5.10 one patch at a time and report hooks that name something a later patch adds.

After each patch it checks the files the stack has touched so far: Makefile and Kbuild obj and subdir entries,
-I include folders, Kconfig source lines, includes, and the first-boot fragment's CONFIG_ symbols. A reference
fails when it doesn't resolve at that prefix but does on the full stack. Includes inside #if blocks and symbols
used in code only print as notes, as they drop out until the later patch. Exits 1 on any failure.
The donor is copied to --work (build/kernel-patch-order by default), about 1.2 GB.
"""
import pocket_paths
import argparse
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_BASE = Path(os.environ['POCKET_KERNEL_DONOR']) if os.environ.get('POCKET_KERNEL_DONOR') else pocket_paths.platform_source() / 'kernel/motorola/sm6450'


def patch_files(patch):
    """(path, added) for every file a patch touches."""
    out = []
    lines = patch.read_text().splitlines()
    for i, line in enumerate(lines):
        if line.startswith('--- ') and i + 1 < len(lines) and lines[i + 1].startswith('+++ '):
            new = lines[i + 1][4:].split('\t')[0]
            out.append((new[2:], line[4:].split('\t')[0] == '/dev/null'))
    return out


def logical_lines(text):
    out, cur = [], ''
    for line in text.splitlines():
        if line.endswith('\\'):
            cur += line[:-1] + ' '
            continue
        out.append(cur + line)
        cur = ''
    if cur:
        out.append(cur)
    return out


VAR = re.compile(r'^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*:?=\s*(.*)$')
ASSIGN = re.compile(r'^\s*([A-Za-z0-9_$().-]+?)-(y|m|objs|\$\([^)]*\))\s*[:+]?=\s*(.*)$')
INCDIR = re.compile(r'-I\s*(\S+)')


class Tree:
    def __init__(self, root, files):
        self.root, self.files = root, files
        self.dirs = set()
        for f in files:
            p = f
            while '/' in p:
                p = p.rsplit('/', 1)[0]
                if p in self.dirs:
                    break
                self.dirs.add(p)
        self.by_name = {}
        for f in files:
            self.by_name.setdefault(f.rsplit('/', 1)[-1], []).append(f)

    def read(self, rel):
        return (self.root / rel).read_text(errors='replace')


def norm(path):
    parts = []
    for p in path.split('/'):
        if p in ('', '.'):
            continue
        if p == '..':
            if parts:
                parts.pop()
            continue
        parts.append(p)
    return '/'.join(parts)


def expand(token, mdir, variables):
    for _ in range(4):
        token = token.replace('$(srctree)/', '').replace('$(srctree)', '')
        token = token.replace('$(src)', mdir).replace('$(obj)', mdir)
        token = re.sub(r'\$\(([A-Za-z_][A-Za-z0-9_]*)\)', lambda m: variables.get(m.group(1), m.group(0)), token)
    return token


def make_refs(rel, text):
    """(kind, path, line) references in one Makefile/Kbuild."""
    mdir = rel.rsplit('/', 1)[0]
    variables = {'MTK_PLATFORM': 'mt6771', 'CONFIG_MTK_PLATFORM': 'mt6771', 'SRCARCH': 'arm64', 'ARCH': 'arm64'}
    lines = logical_lines(text)
    composites = set()
    for line in lines:
        m = ASSIGN.match(line)
        if m and m.group(1) not in ('obj', 'subdir', 'lib', 'ccflags', 'asflags', 'subdir-ccflags'):
            composites.add(expand(m.group(1), mdir, variables))
    refs = []
    for line in lines:
        s = line.split('#', 1)[0]
        v = VAR.match(s)
        if v and '$(' not in v.group(2) and not v.group(1).startswith(('obj', 'ccflags')):
            variables[v.group(1)] = v.group(2).strip()
        for inc in INCDIR.findall(s):
            path = expand(inc, mdir, variables)
            if '$' not in path:
                refs.append(('incdir', norm(path), line.strip()))
        m = ASSIGN.match(s)
        if not m:
            continue
        head = m.group(1)
        if head in ('ccflags', 'asflags', 'subdir-ccflags', 'cflags', 'ldflags', 'subdir-asflags', 'always', 'targets',
                    'extra', 'hostprogs', 'clean-files', 'header-test'):
            continue
        if head.endswith(('flags', 'FLAGS')):
            continue
        for tok in m.group(3).split():
            tok = expand(tok, mdir, variables)
            if '$' in tok or tok.startswith('-'):
                continue
            if tok.endswith('/'):
                refs.append(('dir', norm(mdir + '/' + tok), line.strip()))
            elif tok.endswith('.o'):
                stem = tok[:-2]
                if norm(mdir + '/' + stem) in {norm(mdir + '/' + c) for c in composites}:
                    continue
                refs.append(('obj', norm(mdir + '/' + stem), line.strip()))
    return refs


def resolves(tree, kind, path):
    if kind == 'dir':
        return path + '/Makefile' in tree.files or path + '/Kbuild' in tree.files
    if kind == 'obj':
        return any(path + ext in tree.files for ext in ('.c', '.S', '.o_shipped', '.o')) \
            or path + '.o' in tree.files
    if kind == 'incdir':
        return path in tree.dirs
    if kind == 'file':
        return path in tree.files
    raise ValueError(kind)


SOURCE = re.compile(r'^\s*(o?r?source)\s+"([^"]+)"')


def kconfig_refs(rel, text):
    refs = []
    kdir = rel.rsplit('/', 1)[0]
    for line in text.splitlines():
        m = SOURCE.match(line)
        if not m:
            continue
        path = m.group(2).replace('$(SRCARCH)', 'arm64').replace('$SRCARCH', 'arm64')
        if m.group(1) in ('rsource', 'orsource'):
            path = kdir + '/' + path
        if '*' in path or '$' in path:
            continue
        refs.append(('file', norm(path), line.strip()))
    return refs


INCLUDE = re.compile(r'^\s*#\s*include\s*([<"])([^>"]+)[>"]', re.M)


def include_refs(rel, text):
    """(quote, name, guarded) for each include; guarded means inside any #if block (include guards aside)."""
    out, depth = [], 0
    lines = text.splitlines()
    guard = None
    for i, line in enumerate(lines):
        s = line.strip()
        m = re.match(r'#\s*(ifndef|ifdef|if|endif|include)\b\s*(.*)', s)
        if not m:
            continue
        kw, rest = m.groups()
        if kw in ('ifndef', 'ifdef', 'if'):
            # The first #ifndef X followed by #define X is the include guard.
            if kw == 'ifndef' and guard is None and depth == 0 and i + 1 < len(lines) \
                    and re.match(r'#\s*define\s+' + re.escape(rest.split()[0]) + r'\b', lines[i + 1].strip()):
                guard = depth
                continue
            depth += 1
        elif kw == 'endif':
            if depth:
                depth -= 1
        else:
            m2 = re.match(r'([<"])([^>"]+)[>"]', rest)
            if m2:
                out.append((m2.group(1), m2.group(2), depth > 0))
    return out


SYMDEF = re.compile(r'^\s*(?:menu)?config\s+([A-Za-z0-9_]+)', re.M)
SYMUSE = re.compile(r'CONFIG_([A-Za-z0-9_]+)')
KUSE = re.compile(r'^\s*(?:depends on|select|imply|if|default .* if|visible if)\s+(.*)$')


def kconfig_files(root):
    return [p for p in root.rglob('Kconfig*') if p.is_file() and '.git' not in p.parts]


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--patches', default=str(ROOT / 'patches/kernel-upgrade-5.10'))
    ap.add_argument('--base', default=None, help='donor kernel tree (default: platform_source/kernel/motorola/sm6450)')
    ap.add_argument('--work', default=str(ROOT / 'build/kernel-patch-order'), help='scratch folder, replaced')
    ap.add_argument('--keep', action='store_true', help='keep the replayed tree in --work')
    ap.add_argument('--fragment', default=str(ROOT / 'configs/kernel-firstboot-5.10.fragment'))
    a = ap.parse_args()
    patches = sorted(Path(a.patches).resolve().glob('*.patch'))
    base = Path(a.base) if a.base else Path(DEFAULT_BASE)
    work = Path(a.work).resolve()
    tree_dir = work / 'tree'
    if tree_dir.exists():
        shutil.rmtree(tree_dir)
    work.mkdir(parents=True, exist_ok=True)
    subprocess.run(['rsync', '-a', '--exclude=.git', str(base) + '/', str(tree_dir) + '/'], check=True)
    base_files = {str(p.relative_to(tree_dir)) for p in tree_dir.rglob('*') if p.is_file()}
    base_syms = set()
    for k in kconfig_files(tree_dir):
        base_syms.update(SYMDEF.findall(k.read_text(errors='replace')))
    enabled = set(re.findall(r'^CONFIG_([A-Za-z0-9_]+)=[ym]', Path(a.fragment).read_text(), re.M))

    touched_by = {}
    for p in patches:
        for f, added in patch_files(p):
            touched_by.setdefault(f, []).append(p.name)
    added_all = {f for p in patches for f, added in patch_files(p) if added}
    final_files = base_files | added_all

    # Final tree: apply everything to a second view only for the touched files.
    final_dir = work / 'final'
    if final_dir.exists():
        shutil.rmtree(final_dir)
    for f in touched_by:
        if f in base_files:
            (final_dir / f).parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(tree_dir / f, final_dir / f)
    for p in patches:
        subprocess.run(['patch', '-s', '--batch', '--forward', '-p1', '-d', str(final_dir), '-i', str(p)], check=True)

    class Overlay(Tree):
        def read(self, rel):
            q = final_dir / rel
            return q.read_text(errors='replace') if q.exists() else (tree_dir / rel).read_text(errors='replace')

    final = Overlay(tree_dir, final_files)
    final_syms = set(base_syms)
    for f in touched_by:
        if f.rsplit('/', 1)[-1].startswith('Kconfig'):
            final_syms.update(SYMDEF.findall(final.read(f)))

    present = set(base_files)
    touched = set()
    syms = set(base_syms)
    problems = 0
    for p in patches:
        r = subprocess.run(['patch', '-s', '--batch', '--forward', '-p1', '-d', str(tree_dir), '-i', str(p)],
                           capture_output=True, text=True)
        if r.returncode:
            print(f'{p.name}: does not apply: {r.stdout}{r.stderr}')
            problems += 1
            continue
        for f, added in patch_files(p):
            present.add(f)
            touched.add(f)
        tree = Tree(tree_dir, present)
        for f in touched:
            if f.rsplit('/', 1)[-1].startswith('Kconfig'):
                syms.update(SYMDEF.findall(tree.read(f)))
        found, notes = [], []
        for f in sorted(touched):
            name = f.rsplit('/', 1)[-1]
            text = tree.read(f)
            if name in ('Makefile', 'Kbuild') or name.endswith('.mk'):
                for kind, path, line in make_refs(f, text):
                    if not resolves(tree, kind, path) and resolves(final, kind, path):
                        found.append(f'{f}: {kind} {path} ({line})')
                for line in logical_lines(text):
                    for sym in SYMUSE.findall(line.split('#', 1)[0]):
                        if sym in enabled and sym not in syms and sym in final_syms:
                            hook = re.match(r'\s*obj-\$\(CONFIG_' + sym + r'\)\s*[:+]?=.*/', line)
                            (found if hook else notes).append(f'{f}: symbol CONFIG_{sym} not defined yet ({line.strip()[:80]})')
            elif name.startswith('Kconfig'):
                for kind, path, line in kconfig_refs(f, text):
                    if not resolves(tree, kind, path) and resolves(final, kind, path):
                        found.append(f'{f}: source {path}')
                for line in text.splitlines():
                    m = KUSE.match(line)
                    if m:
                        for sym in re.findall(r'\b([A-Z][A-Z0-9_]+)\b', m.group(1)):
                            if sym in enabled and sym not in syms and sym in final_syms:
                                notes.append(f'{f}: Kconfig uses {sym} not defined yet ({line.strip()})')
            elif name.endswith(('.c', '.h', '.S')):
                fdir = f.rsplit('/', 1)[0]
                for q, inc, guarded in include_refs(f, text):
                    out = notes if guarded else found
                    local = norm(fdir + '/' + inc)
                    if q == '"' and local in final.files:
                        if local not in tree.files:
                            out.append(f'{f}: include "{inc}" ({local})')
                        continue
                    base_name = inc.rsplit('/', 1)[-1]
                    now = [c for c in tree.by_name.get(base_name, []) if c == inc or c.endswith('/' + inc)]
                    later = [c for c in final.by_name.get(base_name, []) if c == inc or c.endswith('/' + inc)]
                    if not now and later:
                        out.append(f'{f}: include {q}{inc}{">" if q == "<" else q} (later in {later[0]})')
                for sym in set(SYMUSE.findall(text)):
                    if sym in enabled and sym not in syms and sym in final_syms:
                        notes.append(f'{f}: code uses CONFIG_{sym} not defined yet')
        for line in sorted(set(found)):
            print(f'{p.name}: {line}')
        for line in sorted(set(notes)):
            print(f'{p.name}: note: {line}')
        problems += len(set(found))
    print(f'{len(patches)} patches, {problems} forward references')
    if not a.keep:
        shutil.rmtree(work)
    return 1 if problems else 0


if __name__ == '__main__':
    sys.exit(main())
