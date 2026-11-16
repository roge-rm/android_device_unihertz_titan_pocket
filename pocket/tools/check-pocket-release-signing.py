#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Offline check of a release signed by tools/sign-pocket-release.py.

  - every APK, APEX and CAPEX in the signed target-files is signed by one of our certificates
    or kept PRESIGNED, and none by a test key: the AOSP certificates in
    build/make/target/product/security, the Lineage one, and every certificate the unsigned
    build's apkcerts.txt and apexkeys.txt name, read from the source tree. APEX payloads must
    carry our payload key.
  - vbmeta, vbmeta_system, boot and recovery are signed with our AVB key, vbmeta has flags 3
    and chains boot and vbmeta_system with that key
  - recovery.img's own ramdisk and system's otacerts.zip hold only our releasekey
  - recovery adb: no host keys in the ramdisk, ro.adb.secure=1, a userdebug recovery whose menu
    has Enable ADB (it sets ro.adb.secure.recovery=0, which nothing sets before)
  - the OTA's signature verifies with our releasekey and not with the test key
  - boot.img is the unsigned one apart from the AVB footer, and recovery.img has the same
    header, kernel, dtb, recovery_dtbo and cmdline, with a ramdisk that differs only in
    otacerts.zip
No phone access.
"""
import pocket_paths
import argparse
from concurrent.futures import ThreadPoolExecutor
import gzip
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import zipfile

ROOT = Path(__file__).resolve().parent.parent
SPEC = importlib.util.spec_from_file_location('sign', ROOT / 'tools/sign-pocket-release.py')
SIGN = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(SIGN)
SOURCE = pocket_paths.platform_source()
AVBTOOL = ROOT / 'tools/avbtool.py'
SIGNED_NAMES = ('.apk', '.apex', '.capex')
# A PRESIGNED placeholder APEX with no code, kept on its AOSP key so the platform's shim
# update rules still match. LineageOS's check_keys.py notes it as expected.
KEPT_TEST_SIGNED = {'SYSTEM/apex/com.android.apex.cts.shim.apex'}


def fail(msg):
    raise SystemExit('FAIL: ' + msg)


def cert_digest(pem):
    der = subprocess.run(['openssl', 'x509', '-outform', 'DER'], input=pem, capture_output=True,
                         check=True).stdout
    return hashlib.sha256(der).hexdigest()


def pem_certs(text):
    return re.findall(rb'-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----', text, re.S)


def test_cert_digests(unsigned_tf):
    """SHA-256 of every test certificate the unsigned build could have used."""
    paths = set((SOURCE / 'build/make/target/product/security').glob('*.x509.pem'))
    paths |= set((SOURCE / 'vendor/lineage/build/target/product/security').glob('*.x509.pem'))
    paths |= set((SOURCE / 'external/avb/test/data').glob('*.x509.pem'))
    with zipfile.ZipFile(unsigned_tf) as z:
        text = z.read('META/apkcerts.txt').decode() + z.read('META/apexkeys.txt').decode()
    for rel in re.findall(r'(?:certificate|container_certificate)="([^"]+\.x509\.pem)"', text):
        if (SOURCE / rel).is_file():
            paths.add(SOURCE / rel)
    out = {}
    for p in paths:
        for c in pem_certs(p.read_bytes()):
            out[cert_digest(c)] = str(p.relative_to(SOURCE))
    return out


def avb_pubkey_sha1(key):
    with tempfile.NamedTemporaryFile() as f:
        subprocess.run(['python3', str(AVBTOOL), 'extract_public_key', '--key', str(key), '--output', f.name],
                       check=True)
        return hashlib.sha1(Path(f.name).read_bytes()).hexdigest(), Path(f.name).read_bytes()


def avb_info(image):
    return subprocess.run(['python3', str(AVBTOOL), 'info_image', '--image', str(image)],
                          capture_output=True, text=True, check=True).stdout


def check_apks(signed, keys, test_digests, host, results):
    ours = {}
    for p in keys.glob('*.x509.pem'):
        if not p.is_symlink():
            ours[cert_digest(p.read_bytes())] = p.name
    payload = {}
    for p in keys.glob('*.pem'):
        if p.name.endswith('.x509.pem'):
            continue
        payload[avb_pubkey_sha1(p)[1]] = p.name
    with tempfile.TemporaryDirectory() as tmp, zipfile.ZipFile(signed) as z:
        names = [n for n in z.namelist() if n.endswith(SIGNED_NAMES)
                 and n.split('/')[0] in ('SYSTEM', 'PRODUCT', 'SYSTEM_EXT', 'VENDOR', 'ODM', 'ROOT')]
        paths = []
        for i, n in enumerate(names):
            p = Path(tmp) / f'{i}{Path(n).suffix}'
            p.write_bytes(z.read(n))
            paths.append(p)

        def certs(p):
            r = subprocess.run([str(host / 'bin/apksigner'), 'verify', '--print-certs-pem', str(p)],
                               capture_output=True)
            if r.returncode:
                # Some prebuilt GApps fail apksigner (v1 signature naming a v2 one that isn't there).
                # Read the v1 signer certificate for the test-key scan.
                with zipfile.ZipFile(p) as apk:
                    blocks = [n for n in apk.namelist() if re.match(r'META-INF/[^/]+\.(RSA|DSA|EC)$', n)]
                    der = b''.join(apk.read(n) for n in blocks)
                out = subprocess.run(['openssl', 'pkcs7', '-inform', 'DER', '-print_certs'], input=der,
                                     capture_output=True).stdout if der else b''
                return ('v1', [cert_digest(c) for c in pem_certs(out)]) if pem_certs(out) else None
            return [cert_digest(c) for c in pem_certs(r.stdout)]

        with ThreadPoolExecutor(12) as pool:
            found = list(pool.map(certs, paths))
        counts = {'ours': 0, 'presigned': 0}
        test, unsigned, other, bad_payload, v1_only, kept = [], [], {}, [], [], []
        for n, p, ds in zip(names, paths, found):
            if ds is None:
                unsigned.append(n)
                continue
            if isinstance(ds, tuple):
                v1_only.append(n)
                ds = ds[1]
            if n in KEPT_TEST_SIGNED:
                kept.append(n)
            elif any(d in test_digests for d in ds):
                test.append(f'{n} ({", ".join(test_digests[d] for d in ds if d in test_digests)})')
            elif any(d in ours for d in ds):
                counts['ours'] += 1
            else:
                counts['presigned'] += 1
                other.setdefault(ds[0][:16], []).append(n)
            if n.endswith(('.apex', '.capex')) and any(d in ours for d in ds):
                with zipfile.ZipFile(p) as apex:
                    key = apex.read('apex_pubkey')
                if key not in payload:
                    bad_payload.append(n)
    results['apk_count'] = len(names)
    results['apk_signed_by_our_keys'] = counts['ours']
    results['apk_other_signers'] = {k: sorted(v) for k, v in other.items()}
    results['apk_sample'] = names[:3]
    results['apk_apksigner_fails_v1_cert_read'] = v1_only
    results['apk_kept_aosp_key'] = kept
    if unsigned:
        fail('apksigner could not verify: ' + ', '.join(unsigned[:10]))
    if test:
        fail(f'{len(test)} signed with test keys: ' + '; '.join(test[:20]))
    if bad_payload:
        fail('APEX payload not signed with our key: ' + ', '.join(bad_payload))


def check_avb(out, keys, results):
    sha1, _ = avb_pubkey_sha1(keys / 'avb.pem')
    results['avb_key_sha1'] = sha1
    for name in ('vbmeta', 'vbmeta_system', 'boot', 'recovery'):
        info = avb_info(out / f'{name}.img')
        main_key = re.search(r'^Public key \(sha1\):\s+(\w+)', info, re.M)
        if not main_key or main_key.group(1) != sha1:
            fail(f'{name}.img is not signed with our AVB key')
        if 'Algorithm:                ' + SIGN.AVB_ALGORITHM not in info:
            fail(f'{name}.img algorithm is not {SIGN.AVB_ALGORITHM}')
        results[f'{name}_avb'] = 'our key, ' + SIGN.AVB_ALGORITHM
        if name == 'vbmeta':
            if not re.search(r'^Flags:\s+3$', info, re.M):
                fail('vbmeta flags are not 3')
            chains = dict(re.findall(r'Partition Name:\s+(\w+)\n.*?Public key \(sha1\):\s+(\w+)', info, re.S))
            for part in ('boot', 'vbmeta_system'):
                if chains.get(part) != sha1:
                    fail(f'vbmeta does not chain {part} with our key')
            if 'Partition Name:          recovery' in info:
                fail('vbmeta lists recovery')
            results['vbmeta_flags'] = 3
            results['vbmeta_chains'] = sorted(chains)


def cpio_files(data):
    """newc cpio: name -> bytes for regular files and symlinks."""
    files, off = {}, 0
    while off + 110 <= len(data):
        h = data[off:off + 110]
        if h[:6] != b'070701':
            fail('ramdisk is not newc cpio')
        mode = int(h[14:22], 16)
        size = int(h[54:62], 16)
        namesize = int(h[94:102], 16)
        name = data[off + 110:off + 110 + namesize - 1].decode()
        off = (off + 110 + namesize + 3) & ~3
        if name == 'TRAILER!!!':
            break
        files[name] = (mode, data[off:off + size])
        off = (off + size + 3) & ~3
    return files


def unpack(image, host, dest):
    r = subprocess.run([str(host / 'bin/unpack_bootimg'), '--boot_img', str(image), '--out', str(dest),
                        '--format=mkbootimg'], capture_output=True, text=True, check=True)
    return r.stdout


def ramdisk(dest):
    raw = (dest / 'ramdisk').read_bytes()
    return cpio_files(gzip.decompress(raw) if raw[:2] == b'\x1f\x8b' else raw)


def tags_only(old, new):
    """True if new is old with test-keys tags turned into release-keys."""
    def norm(data):
        lines = data.decode().replace('release-keys', 'test-keys').splitlines()
        return [l for l in lines if l.strip()]
    a = norm(old)
    b = [l + ' test-keys' if l.startswith('ro.build.display.id=') and not l.endswith('test-keys') else l
         for l in norm(new)]
    return a == b


def otacert_digests(otacerts):
    with zipfile.ZipFile(io.BytesIO(otacerts)) as z:
        return sorted(cert_digest(z.read(n)) for n in z.namelist())


def recovery_adb(rd):
    """Recovery adb needs a key until the owner picks Advanced, Enable ADB in the menu.

    Lineage recovery keeps that item only in userdebug builds. It sets ro.adb.secure.recovery=0
    and restarts adbd, which then skips auth on a debuggable build. The ramdisk must hold no host
    keys and must not set ro.adb.secure.recovery itself.
    """
    props = {}
    for name in ('prop.default', 'system/etc/prop.default'):
        if name in rd:
            for line in rd[name][1].decode().splitlines():
                if '=' in line and not line.startswith('#'):
                    k, v = line.split('=', 1)
                    props.setdefault(k.strip(), v.strip())
    for k, want in (('ro.adb.secure', '1'), ('ro.build.type', 'userdebug'), ('ro.debuggable', '1')):
        if props.get(k) != want:
            fail(f'recovery {k} is {props.get(k)}, want {want}')
    for name, (mode, data) in rd.items():
        if name.endswith('.prop') or name.endswith('prop.default'):
            if b'ro.adb.secure.recovery' in data:
                fail(f'recovery {name} sets ro.adb.secure.recovery')
    if 'system/etc/security/pocket_adb_keys' in rd:
        fail('recovery has host adb keys (a development build)')
    keys = rd.get('adb_keys')
    if keys and (keys[0] & 0o170000) != 0o120000:
        fail('recovery /adb_keys is a file, not the link to /product')
    # The menu text is in librecovery_ui.so; the action and adbd's check read the property.
    for name, text in (('system/lib64/librecovery_ui.so', b'Enable ADB'),
                       ('system/bin/recovery', b'ro.adb.secure.recovery'),
                       ('system/bin/adbd', b'ro.adb.secure.recovery')):
        if text not in rd.get(name, (0, b''))[1]:
            fail(f'recovery {name} has no {text.decode()}')
    return 'no host keys, ro.adb.secure=1, userdebug menu with Enable ADB'


def check_images(out, unsigned_tf, keys, host, results):
    release = cert_digest((keys / 'releasekey.x509.pem').read_bytes())
    with tempfile.TemporaryDirectory() as tmp, zipfile.ZipFile(unsigned_tf) as z:
        tmp = Path(tmp)
        for name in ('boot', 'recovery'):
            (tmp / f'unsigned-{name}.img').write_bytes(z.read(f'BOOTABLE_IMAGES/{name}.img'))
        # boot: same bytes up to the unsigned image's original size, then only the footer.
        old, new = (tmp / 'unsigned-boot.img').read_bytes(), (out / 'boot.img').read_bytes()
        size = int(re.search(r'Original image size:\s+(\d+)', avb_info(out / 'boot.img')).group(1))
        old_size = int(re.search(r'Original image size:\s+(\d+)', avb_info(tmp / 'unsigned-boot.img')).group(1))
        if size != old_size or old[:size] != new[:size] or len(old) != len(new):
            fail('signed boot.img differs from the unsigned one before its AVB footer')
        results['boot_compare'] = f'identical first {size} bytes, only the AVB footer differs'
        heads = {}
        for tag, image in (('old', tmp / 'unsigned-recovery.img'), ('new', out / 'recovery.img'),
                           ('boot', out / 'boot.img')):
            d = tmp / tag
            heads[tag] = (unpack(image, host, d), d)
        args = heads['boot'][0]
        old_h, new_h = heads['old'][0], heads['new'][0]
        results['recovery_header'] = new_h.strip()
        results['boot_header'] = args.strip()
        # unpack_bootimg prints mkbootimg args; drop the file paths, which name the unpack folder.
        norm = lambda s, d: s.replace(str(d), '')
        if norm(old_h, heads['old'][1]) != norm(new_h, heads['new'][1]):
            fail('recovery header differs:\n' + old_h + '\n' + new_h)
        for header in (new_h, args):
            for want in ('--header_version 2', '--os_version 11.0.0', '--os_patch_level 2022-09'):
                if want not in header:
                    fail('missing ' + want + ' in ' + header)
        for part in ('kernel', 'dtb', 'recovery_dtbo'):
            if (heads['old'][1] / part).read_bytes() != (heads['new'][1] / part).read_bytes():
                fail('recovery ' + part + ' differs')
        old_rd, new_rd = ramdisk(heads['old'][1]), ramdisk(heads['new'][1])
        diff = sorted(n for n in set(old_rd) | set(new_rd) if old_rd.get(n) != new_rd.get(n))
        # sign_target_files_apks rewrites the build tags in prop.default; nothing else may change.
        if 'prop.default' in diff and tags_only(old_rd['prop.default'][1], new_rd['prop.default'][1]):
            diff.remove('prop.default')
        if diff != ['system/etc/security/otacerts.zip']:
            fail('recovery ramdisk differs in: ' + ', '.join(diff[:20]))
        results['recovery_compare'] = ('same header, kernel, dtb, recovery_dtbo; ramdisk differs only in '
                                       'otacerts.zip and the test-keys tags in prop.default')
        rec = otacert_digests(new_rd['system/etc/security/otacerts.zip'][1])
        if rec != [release]:
            fail('recovery otacerts.zip is not just our releasekey')
        results['recovery_otacerts'] = 'releasekey only'
        results['recovery_adb'] = recovery_adb(new_rd)
    with zipfile.ZipFile(out / 'lineage_titan_pocket-signed-target_files.zip') as z:
        if otacert_digests(z.read('SYSTEM/etc/security/otacerts.zip')) != [release]:
            fail('system otacerts.zip is not just our releasekey')
    results['system_otacerts'] = 'releasekey only'


def check_ota(out, keys, host, results):
    ota = out / 'lineage_titan_pocket-signed-ota.zip'
    tool = host / 'bin/check_ota_package_signature'
    good = subprocess.run([str(tool), str(keys / 'releasekey.x509.pem'), str(ota)], capture_output=True, text=True)
    if good.returncode:
        fail('OTA does not verify with releasekey: ' + good.stdout[-500:] + good.stderr[-500:])
    test = SOURCE / 'build/make/target/product/security/testkey.x509.pem'
    bad = subprocess.run([str(tool), str(test), str(ota)], capture_output=True, text=True)
    if bad.returncode == 0:
        fail('OTA verifies with the test key')
    results['ota_signature'] = 'verifies with releasekey, rejected with testkey'


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument('--out', type=Path, default=SIGN.OUT, help='sign-pocket-release.py output')
    ap.add_argument('--unsigned', type=Path, default=SIGN.TARGET_FILES, help='unsigned target-files')
    ap.add_argument('--keys', type=Path, default=SIGN.KEYS)
    ap.add_argument('--host', type=Path, default=SIGN.HOST)
    ap.add_argument('--report', type=Path)
    args = ap.parse_args()
    keys = args.keys.expanduser().resolve()
    results = {}
    check_avb(args.out, keys, results)
    check_images(args.out, args.unsigned, keys, args.host, results)
    check_ota(args.out, keys, args.host, results)
    check_apks(args.out / 'lineage_titan_pocket-signed-target_files.zip', keys,
               test_cert_digests(args.unsigned), args.host, results)
    text = json.dumps(results, indent=2) + '\n'
    if args.report:
        args.report.write_text(text)
    print(text + 'PASS')


if __name__ == '__main__':
    main()
