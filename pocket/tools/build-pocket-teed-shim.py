#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Build the teed model shim and patch teed to load it.

libpocketteed.so defines __system_property_get and answers the stock "Titan pocket"
for ro.product.model, passing every other name to libc. teed sends that value to
TKCore, which checks it against its licence byte for byte. add_needed() makes the
shim teed's first DT_NEEDED; prepare-pocket-vendor-overlay.py applies it to the
stock teed for vendor overlay v13.

Output: build/teed-shim/, with record.json. --host-test also builds the shim for
the host against a stub libc and runs it. --patch-teed STOCK OUT writes a patched
copy of a stock teed and prints what changed.
"""
import pocket_paths
import argparse
import hashlib
import json
from pathlib import Path
import struct
import subprocess

ROOT = Path(__file__).resolve().parent.parent
SRC = pocket_paths.DEVICE_TREE / 'teed'
SOURCES = ['pocket_teed_prop.c']
OUT = ROOT / 'build/teed-shim'
NAME = 'libpocketteed.so'
LLVM = pocket_paths.ndk_bin()
# Vendor is Android 11; libc and libdl are LLNDK there. teed is 64-bit, so the shim goes in /vendor/lib64.
TARGET = 'aarch64-linux-android30'
FLAGS = ['-O2', '-Wall', '-Wextra', '-Werror', '-fstack-protector-strong', '-D_FORTIFY_SOURCE=2',
         '-shared', '-fPIC', f'-Wl,-soname,{NAME}', '-Wl,--build-id=sha1', '-Wl,-z,relro,-z,now',
         '-Wl,--hash-style=gnu', '-ldl']
# Stock /vendor/bin/teed, the same file in the January 2023 and May 2024 vendor images.
TEED_SHA256 = '25bb49750516aac397724b67b071800e3d929fd459cb71d06e44aa36779a238d'

DT_NULL, DT_NEEDED, DT_STRTAB, DT_STRSZ = 0, 1, 5, 10
PT_LOAD, PT_DYNAMIC = 1, 2
PF_W = 2
PHDR = '<IIQQQQQQ'
SHDR = '<IIQQQQIIQQ'


def sha256(p):
    return hashlib.sha256(Path(p).read_bytes()).hexdigest()


def elf_layout(data):
    """Program headers, section headers and dynamic entries of a 64-bit little-endian ELF."""
    if data[:6] != b'\x7fELF\x02\x01':
        raise SystemExit('not a 64-bit little-endian ELF')
    phoff, shoff = struct.unpack_from('<QQ', data, 0x20)
    phentsize, phnum, shentsize, shnum = struct.unpack_from('<HHHH', data, 0x36)
    phdrs = [(phoff + i * phentsize, struct.unpack_from(PHDR, data, phoff + i * phentsize)) for i in range(phnum)]
    shdrs = [(shoff + i * shentsize, struct.unpack_from(SHDR, data, shoff + i * shentsize)) for i in range(shnum)]
    dyn = [p for _, p in phdrs if p[0] == PT_DYNAMIC]
    if len(dyn) != 1:
        raise SystemExit('expected one PT_DYNAMIC')
    off, size = dyn[0][2], dyn[0][5]
    entries = [struct.unpack_from('<qQ', data, off + 16 * i) for i in range(size // 16)]
    return phdrs, shdrs, (off, size), entries


def vaddr_to_offset(phdrs, vaddr):
    for _, p in phdrs:
        if p[0] == PT_LOAD and p[3] <= vaddr < p[3] + p[5]:
            return p[2] + vaddr - p[3]
    raise SystemExit(f'vaddr {vaddr:#x} is in no PT_LOAD')


def needed(data):
    """DT_NEEDED names, read the way the dynamic linker reads them (DT_STRTAB through PT_LOAD)."""
    phdrs, _, _, entries = elf_layout(data)
    tags = dict((t, v) for t, v in entries if t in (DT_STRTAB, DT_STRSZ))
    strtab = vaddr_to_offset(phdrs, tags[DT_STRTAB])
    out = []
    for t, v in entries:
        if t == DT_NULL:
            break
        if t == DT_NEEDED:
            if v >= tags[DT_STRSZ]:
                raise SystemExit('DT_NEEDED name past DT_STRSZ')
            out.append(data[strtab + v:data.index(b'\0', strtab + v)].decode())
    return out


def add_needed(data, soname):
    """Return data with soname as the first DT_NEEDED, and a list of what changed.

    The dynamic string table is copied, with soname appended, into the zero padding
    after the end of its read-only PT_LOAD (all string offsets stay the same), and that
    segment grows to cover it. The dynamic entries move down one slot into the spare
    DT_NULL padding. The .dynstr section header follows the table. Nothing else changes.
    """
    phdrs, shdrs, (dyn_off, dyn_size), entries = elf_layout(data)
    used = next(i for i, (t, _) in enumerate(entries) if t == DT_NULL)
    if used + 2 > len(entries):
        raise SystemExit('no spare DT_NULL slot in .dynamic')
    if soname in needed(data):
        raise SystemExit(f'{soname} is already needed')
    tags = dict((t, v) for t, v in entries[:used] if t in (DT_STRTAB, DT_STRSZ))
    str_vaddr, str_size = tags[DT_STRTAB], tags[DT_STRSZ]
    str_off = vaddr_to_offset(phdrs, str_vaddr)
    table = data[str_off:str_off + str_size] + soname.encode() + b'\0'

    loads = [(o, p) for o, p in phdrs if p[0] == PT_LOAD]
    seg_hdr, seg = next((o, p) for o, p in loads if p[3] <= str_vaddr < p[3] + p[5])
    if seg[1] & PF_W or seg[5] != seg[6]:
        raise SystemExit('the string table segment is writable or has bss')
    new_off, new_vaddr = seg[2] + seg[5], seg[3] + seg[5]
    end_off, end_vaddr = new_off + len(table), new_vaddr + len(table)
    if any(new_off < p[2] + p[5] and p[2] < end_off for o, p in loads if o != seg_hdr):
        raise SystemExit('no room in the file after the string table segment')
    if any(new_vaddr < p[3] + p[6] and p[3] < end_vaddr for o, p in loads if o != seg_hdr):
        raise SystemExit('no room in memory after the string table segment')
    if any(s[1] != 8 and s[4] < end_off and new_off < s[4] + s[5] for _, s in shdrs):
        raise SystemExit('a section is in the padding after the string table segment')
    if data[new_off:end_off].strip(b'\0'):
        raise SystemExit('the padding after the string table segment is not zero')

    out = bytearray(data)
    out[new_off:end_off] = table
    grown = seg[5] + len(table)
    struct.pack_into(PHDR, out, seg_hdr, *seg[:5], grown, grown, seg[7])
    new_entries = [(DT_NEEDED, str_size)] + [
        (t, new_vaddr if t == DT_STRTAB else len(table) if t == DT_STRSZ else v) for t, v in entries[:used]]
    new_entries += [(DT_NULL, 0)] * (len(entries) - len(new_entries))
    for i, e in enumerate(new_entries):
        struct.pack_into('<qQ', out, dyn_off + 16 * i, *e)
    dynamic_sh = [s for _, s in shdrs if s[1] == 6]
    if len(dynamic_sh) != 1:
        raise SystemExit('expected one SHT_DYNAMIC section header')
    str_hdr, str_sh = shdrs[dynamic_sh[0][6]]
    if str_sh[3] != str_vaddr or str_sh[4] != str_off or str_sh[5] != str_size:
        raise SystemExit('.dynstr section header does not match DT_STRTAB')
    struct.pack_into(SHDR, out, str_hdr, *str_sh[:3], new_vaddr, new_off, len(table), *str_sh[6:])
    changes = [
        {'what': 'PT_LOAD filesz and memsz', 'from': seg[5], 'to': grown},
        {'what': 'dynamic string table copied and extended', 'offset': new_off, 'vaddr': new_vaddr,
         'bytes': len(table), 'added': soname},
        {'what': '.dynamic: DT_NEEDED first, DT_STRTAB and DT_STRSZ moved', 'offset': dyn_off,
         'entries': used + 1, 'slots': len(entries)},
        {'what': '.dynstr section header', 'addr': new_vaddr, 'offset': new_off, 'size': len(table)},
    ]
    return bytes(out), changes


def check_patched(stock, patched, soname):
    """Check patched is stock plus add_needed() and nothing else; return the changed regions."""
    redo, _ = add_needed(stock, soname)
    if redo != patched or len(stock) != len(patched):
        raise SystemExit('patched teed differs from add_needed() of the stock file')
    phdrs, shdrs, (dyn_off, dyn_size), _ = elf_layout(stock)
    want = [soname] + needed(stock)
    if needed(patched) != want:
        raise SystemExit(f'patched teed needs {needed(patched)}, not {want}')
    for _, s in shdrs:
        if s[1] in (0, 8) or s[4] == dyn_off:
            continue
        if stock[s[4]:s[4] + s[5]] != patched[s[4]:s[4] + s[5]]:
            raise SystemExit(f'section at {s[4]:#x} changed')
    new_phdrs, new_shdrs, _, _ = elf_layout(patched)
    link = next(sh[6] for _, sh in shdrs if sh[1] == 6)
    dynstr_hdr, dynstr = new_shdrs[link]
    seg_hdr = next(o for (o, p), (_, q) in zip(phdrs, new_phdrs) if p != q)
    regions = {'PT_LOAD program header': (seg_hdr, seg_hdr + struct.calcsize(PHDR)),
               'new dynamic string table': (dynstr[4], dynstr[4] + dynstr[5]),
               '.dynamic': (dyn_off, dyn_off + dyn_size),
               '.dynstr section header': (dynstr_hdr, dynstr_hdr + struct.calcsize(SHDR))}
    hit = {}
    for i in range(len(stock)):
        if stock[i] != patched[i]:
            name = next((n for n, (a, b) in regions.items() if a <= i < b), None)
            if name is None:
                raise SystemExit(f'byte {i:#x} changed outside the expected regions')
            hit[name] = hit.get(name, 0) + 1
    return {n: {'range': [f'{a:#x}', f'{b:#x}'], 'bytes_changed': hit.get(n, 0)} for n, (a, b) in regions.items()}


HOST_HEADER = r'''
#pragma once
#define PROP_VALUE_MAX 92
typedef struct prop_info prop_info;
int __system_property_get(const char *name, char *value);
const prop_info *__system_property_find(const char *name);
void __system_property_read_callback(const prop_info *pi,
    void (*cb)(void *cookie, const char *name, const char *value, unsigned serial), void *cookie);
'''
HOST_STUB = r'''
#include <string.h>
#include <sys/system_properties.h>
int stub_get_calls;
static const char *lookup(const char *name) {
    if (!strcmp(name, "ro.product.model")) return "Titan Pocket";
    if (!strcmp(name, "ro.product.brand")) return "Unihertz";
    if (!strcmp(name, "ro.board.platform")) return "mt6771";
    return NULL;
}
int __system_property_get(const char *name, char *value) {
    const char *v = lookup(name);
    stub_get_calls++;
    strcpy(value, v ? v : "");
    return v ? (int)strlen(v) : 0;
}
const prop_info *__system_property_find(const char *name) { return (const prop_info *)lookup(name); }
void __system_property_read_callback(const prop_info *pi,
    void (*cb)(void *, const char *, const char *, unsigned), void *cookie) { cb(cookie, "", (const char *)pi, 0); }
'''
HOST_MAIN = r'''
#include <stdio.h>
#include <sys/system_properties.h>
extern int stub_get_calls;
int main(void) {
    const char *names[] = {"ro.product.brand", "ro.product.model", "ro.board.platform", "ro.missing"};
    for (int i = 0; i < 4; i++) {
        char v[PROP_VALUE_MAX] = "x";
        int n = __system_property_get(names[i], v);
        printf("%s=%s (%d)\n", names[i], v, n);
    }
    printf("libc get calls=%d\n", stub_get_calls);
    return 0;
}
'''
HOST_NAMES = ('ro.product.brand=Unihertz (8)\nro.product.model=Titan pocket (12)\n'
              'ro.board.platform=mt6771 (6)\nro.missing= (0)\n')
# The model is answered by the shim; the other three go to libc's get (dlsym path) or to find and
# read_callback (fallback, forced by making dlsym return NULL in the test build only).
HOST_WANT = {'dlsym': HOST_NAMES + 'libc get calls=3\n', 'fallback': HOST_NAMES + 'libc get calls=0\n'}
HOST_DEFINES = {'dlsym': [], 'fallback': ['-Ddlsym=pocket_test_no_dlsym']}
HOST_NO_DLSYM = 'void *pocket_test_no_dlsym(void *handle, const char *name) { (void)handle; (void)name; return 0; }\n'


def host_test(out):
    """Build the shim for the host before a stub libc and check what a caller sees, on both lookup paths."""
    d = out / 'host-test'
    (d / 'sys').mkdir(parents=True, exist_ok=True)
    (d / 'sys/system_properties.h').write_text(HOST_HEADER)
    (d / 'stub.c').write_text(HOST_STUB)
    (d / 'main.c').write_text(HOST_MAIN)
    (d / 'nodlsym.c').write_text(HOST_NO_DLSYM)
    cc = ['cc', '-O2', '-Wall', '-Wextra', '-Werror', f'-I{d}']
    subprocess.run(cc + ['-shared', '-fPIC', d / 'stub.c', '-o', d / 'libstubprop.so'], check=True)
    result = {}
    for mode, defines in HOST_DEFINES.items():
        m = d / mode
        m.mkdir(exist_ok=True)
        subprocess.run(cc + ['-D_GNU_SOURCE', *defines, '-shared', '-fPIC', *[SRC / s for s in SOURCES], *([d / 'nodlsym.c'] if defines else []), '-ldl',
                             '-o', m / NAME], check=True)
        subprocess.run(cc + [d / 'main.c', f'-L{m}', f'-L{d}', '-Wl,--no-as-needed', '-lpocketteed', '-lstubprop',
                             f'-Wl,-rpath,{m}', f'-Wl,-rpath,{d}', '-o', m / 'main'], check=True)
        got = subprocess.run([m / 'main'], capture_output=True, text=True, check=True).stdout
        result[mode] = {'output': got, 'pass': got == HOST_WANT[mode]}
    return {'paths': result, 'pass': all(v['pass'] for v in result.values())}


def build(out):
    out.mkdir(parents=True, exist_ok=True)
    dst = out / NAME
    subprocess.run([str(LLVM / 'clang'), f'--target={TARGET}', *FLAGS, *[str(SRC / s) for s in SOURCES],
                    '-o', str(dst)], check=True)
    subprocess.run([LLVM / 'llvm-strip', '--strip-unneeded', dst], check=True)
    text = subprocess.run([LLVM / 'llvm-readelf', '-h', '-d', '--dyn-syms', dst], capture_output=True, text=True,
                          check=True).stdout
    libs = [l.split('[', 1)[1].rstrip(']') for l in text.splitlines() if '(NEEDED)' in l]
    exported = sorted({l.split()[-1] for l in text.splitlines()
                       if ' FUNC ' in l and ' GLOBAL ' in l and ' UND ' not in l})
    machine = next(l.split(':', 1)[1].strip() for l in text.splitlines() if 'Machine:' in l)
    if set(libs) - {'libc.so', 'libdl.so'}:
        raise SystemExit(f'{NAME} needs {libs}; only libc and libdl are expected')
    if exported != ['__system_property_get']:
        raise SystemExit(f'{NAME} exports {exported}; only __system_property_get is expected')
    if machine != 'AArch64':
        raise SystemExit(f'{NAME} is built for {machine}')
    return {'path': str(dst), 'sha256': sha256(dst), 'bytes': dst.stat().st_size, 'machine': machine,
            'needed': libs, 'exported': exported, 'sources': {str(SRC / s): sha256(SRC / s) for s in SOURCES}}


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument('--output', type=Path, default=OUT)
    ap.add_argument('--host-test', action='store_true')
    ap.add_argument('--patch-teed', nargs=2, type=Path, metavar=('STOCK', 'OUT'))
    args = ap.parse_args()
    if args.patch_teed:
        stock = args.patch_teed[0].read_bytes()
        if hashlib.sha256(stock).hexdigest() != TEED_SHA256:
            raise SystemExit('not the pinned stock teed')
        patched, changes = add_needed(stock, NAME)
        args.patch_teed[1].write_bytes(patched)
        print(json.dumps({'changes': changes, 'changed_regions': check_patched(stock, patched, NAME),
                          'needed': needed(patched), 'sha256': hashlib.sha256(patched).hexdigest()}, indent=1))
        return
    record = {'schema': 1, 'clang': str(LLVM / 'clang'), 'target': TARGET, 'outputs': {NAME: build(args.output)}}
    if args.host_test:
        record['host_test'] = host_test(args.output)
        if not record['host_test']['pass']:
            raise SystemExit('host test failed:\n' + json.dumps(record['host_test']['paths'], indent=1))
    (args.output / 'record.json').write_text(json.dumps(record, indent=1) + '\n')
    print(json.dumps(record, indent=1))


if __name__ == '__main__':
    main()
