#!/usr/bin/env python3
"""Offline installed-stock ELF, VINTF and packaged DEX contract inventory.

Never executes an Android artifact or connects to a device. ELF basename
availability is an optimistic stock inventory, not Android namespace resolution.
"""
import pocket_paths
from concurrent.futures import ThreadPoolExecutor
from collections import Counter, defaultdict
from pathlib import Path
import hashlib
import json
import re
import struct
import subprocess
import xml.etree.ElementTree as ET
import zipfile

ROOT = Path(__file__).resolve().parent.parent
STOCK = ROOT / 'firmware/installed-20230105/rootfs'
OUT = ROOT / 'evidence/m2'
SDK = pocket_paths.android_sdk() / 'build-tools/36.1.0'


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def elf_info(path):
    with path.open('rb') as f:
        head = f.read(20)
    if not head.startswith(b'\x7fELF') or head[5] != 1:
        return None
    if struct.unpack_from('<H', head, 16)[0] not in (2, 3):
        return None  # Kernel modules are a separate audit.
    r = subprocess.run(['readelf', '-h', '-d', '-W', str(path)],
                       capture_output=True, text=True, timeout=20)
    if r.returncode:
        raise ValueError(str(path) + ': ' + r.stderr[:200])
    bits = 64 if head[4] == 2 else 32
    needed = re.findall(r'\(NEEDED\).*Shared library: \[([^]]+)\]', r.stdout)
    sonames = re.findall(r'\(SONAME\).*Library soname: \[([^]]+)\]', r.stdout)
    return {'path': str(path.relative_to(ROOT)), 'bits': bits,
            'machine': struct.unpack_from('<H', head, 18)[0],
            'sha256': digest(path), 'needed': needed,
            'soname': sonames[0] if sonames else None,
            'runpath': re.findall(r'\((?:RUNPATH|RPATH)\).*\[([^]]+)\]', r.stdout)}


def dex_metadata(data):
    if data[:4] != b'dex\n' or data[7] != 0:
        raise ValueError('Unexpected DEX magic')
    def u32(offset): return struct.unpack_from('<I', data, offset)[0]
    strings = []
    for i in range(u32(56)):
        at = u32(u32(60) + 4*i)
        while data[at] & 0x80: at += 1
        at += 1
        end = data.index(0, at)
        strings.append(data[at:end].decode('utf-8', errors='replace'))
    types = [strings[u32(u32(68)+4*i)] for i in range(u32(64))]
    defined = {types[u32(u32(100)+32*i)] for i in range(u32(96))}
    methods = []
    for i in range(u32(88)):
        cls, proto, name = struct.unpack_from('<HHI', data, u32(92)+8*i)
        methods.append((types[cls], strings[name]))
    return {'defined': defined, 'types': set(types), 'methods': set(methods)}


def archive_dex(path):
    result = {'defined': set(), 'types': set(), 'methods': set()}
    with zipfile.ZipFile(path) as z:
        for name in z.namelist():
            if re.fullmatch(r'classes\d*\.dex', name):
                d = dex_metadata(z.read(name))
                for key in result: result[key].update(d[key])
    return result


def main():
    OUT.mkdir(exist_ok=True)
    candidates = [p for p in STOCK.rglob('*') if p.is_file() and not p.is_symlink()]
    vndk = ROOT / 'artifacts/m2/vndk30/root'
    if vndk.exists():
        candidates += [p for p in vndk.rglob('*') if p.is_file() and not p.is_symlink()]
    with ThreadPoolExecutor(max_workers=8) as pool:
        elfs = [v for v in pool.map(elf_info, candidates) if v]
    providers = defaultdict(list)
    for e in elfs:
        providers[e['bits'], Path(e['path']).name].append(e['path'])
        if e['soname'] and e['soname'] != Path(e['path']).name:
            providers[e['bits'], e['soname']].append(e['path'])
    vendor = [e for e in elfs if '/rootfs/vendor/' in e['path']]
    missing, external = defaultdict(list), defaultdict(list)
    for e in vendor:
        for n in e['needed']:
            found = providers[e['bits'], n]
            if not found:
                missing[e['bits'], n].append(e['path'])
            elif not any('/rootfs/vendor/' in p or '/m2/vndk30/' in p for p in found):
                external[e['bits'], n].append(e['path'])
    hal_files = [STOCK/'vendor/etc/vintf/manifest.xml'] + sorted((STOCK/'vendor/etc/vintf/manifest').glob('*.xml'))
    hals = []
    for path in hal_files:
        if not path.exists(): continue
        node = ET.parse(path).getroot()
        for h in node.findall('hal'):
            hals.append({'source': str(path.relative_to(ROOT)), 'name': h.findtext('name'),
                         'format': h.get('format', 'hidl'), 'transport': h.findtext('transport'),
                         'versions': [x.text for x in h.findall('version')],
                         'fqnames': [x.text for x in h.findall('fqname')],
                         'interfaces': [{'name':i.findtext('name'), 'instances':[x.text for x in i.findall('instance')]} for i in h.findall('interface')]})
    ims = STOCK/'system/system/priv-app/ImsService/ImsService.apk'
    imsdex = archive_dex(ims)
    class_providers = defaultdict(list)
    for jar in (STOCK/'system/system/framework').glob('*.jar'):
        if not zipfile.is_zipfile(jar): continue
        for cls in archive_dex(jar)['defined']:
            class_providers[cls].append(str(jar.relative_to(ROOT)))
    ims_external = sorted(t for t in imsdex['types'] if t.startswith(('Lcom/mediatek/', 'Lcom/android/internal/telephony/', 'Landroid/telephony/')) and t not in imsdex['defined'])
    ims_refs = [{'descriptor': t, 'stock_framework_providers': class_providers.get(t, [])} for t in ims_external]
    manifests = []
    for path in [ims]+sorted((STOCK/'system/system/system_ext').glob('*/Agui*/*.apk')):
        if path.name not in ['ImsService.apk','AguiKeyBoardShortcut.apk','AguiSpaceBarKey.apk','AguiShortcutKey.apk','AguiNavControl.apk']:continue
        r = subprocess.run([str(SDK/'aapt'), 'dump', 'xmltree', str(path), 'AndroidManifest.xml'],capture_output=True,text=True,timeout=20)
        cert = subprocess.run([str(SDK/'apksigner'), 'verify', '--print-certs', str(path)],capture_output=True,text=True,timeout=30)
        stem=path.stem
        (OUT/(stem+'-manifest-tree.txt')).write_text(r.stdout)
        (OUT/(stem+'-signer.txt')).write_text(cert.stdout+cert.stderr)
        manifests.append({'path':str(path.relative_to(ROOT)), 'sha256':digest(path),
                          'manifest_sha256':hashlib.sha256(zipfile.ZipFile(path).read('AndroidManifest.xml')).hexdigest(),
                          'aapt_returncode':r.returncode,'certificate_verify_returncode':cert.returncode,
                          'signer_sha256':re.findall(r'certificate SHA-256 digest: ([0-9a-f]+)',cert.stdout),
                          'shared_uid':re.findall(r'android:sharedUserId[^=]*="([^"]+)"',r.stdout),
                          'evidence':str((OUT/(stem+'-manifest-tree.txt')).relative_to(ROOT))})
    permissions = []
    for path in (STOCK/'system/system/etc/permissions').glob('*.xml'):
        try: tree=ET.parse(path)
        except ET.ParseError: continue
        for l in tree.getroot().findall('library'):
            if 'mediatek' in (l.get('name','')+l.get('file','')):
                permissions.append({'xml':str(path.relative_to(ROOT)), **l.attrib})
    result = {'schema':1, 'source':'Verified installed January 2023 extracted image set',
              'tools':{'readelf':'readelf -h -d -W (host parser only)', 'aapt':str(SDK/'aapt'),'apksigner':str(SDK/'apksigner')},
              'elf_count':len(elfs),'vendor_elf_count':len(vendor),
              'vendor_architecture_counts':dict(Counter(e['bits'] for e in vendor)),
              'vendor_elfs':vendor,
              'needed_not_found_in_scanned_stock_regular_files':[{'bits':k[0],'name':k[1],'consumers':v} for k,v in sorted(missing.items())],
              'dependencies_only_found_outside_vendor_and_vndk30':[{'bits':k[0],'name':k[1],'consumers':v} for k,v in sorted(external.items())],
              'hal_declarations':hals, 'packages':manifests,
              'ims':{'apk':str(ims.relative_to(ROOT)), 'sha256':digest(ims), 'defined_class_count':len(imsdex['defined']),
                     'external_relevant_type_refs':ims_refs,
                     'relevant_method_refs':[{'class':cls,'name':name} for cls,name in sorted(imsdex['methods']) if cls.startswith(('Lcom/mediatek/', 'Lcom/android/internal/telephony/', 'Landroid/telephony/')) and cls not in imsdex['defined']]},
              'mediatek_library_registrations':permissions,
              'limitations':['No device access or Android artifact execution','ELF DT_NEEDED/basename availability only; no symbol/version/namespace resolution or dlopen closure','Stock framework DEX providers do not prove equivalent APIs on Lineage','Not-found includes unextracted non-VNDK APEX providers and permitted external runtime libraries','APK signature verification establishes signatures, not redistribution rights or target permission grants','HAL declarations do not prove physical hardware support or compatibility with target FCM']}
    (OUT/'vendor-runtime-audit.json').write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps({k:result[k] for k in ['elf_count','vendor_elf_count','vendor_architecture_counts']},indent=2))
    print('missing dependency names',len(missing),'outside vendor/vndk dependency names',len(external),'HAL entries',len(hals),'IMS relevant external types',len(ims_refs),'APK manifests',len(manifests))


if __name__=='__main__':main()
