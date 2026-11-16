#!/usr/bin/env python3
"""Check tools/package-pocket-boot.py with the first-boot Image.gz and a stub test ramdisk.

Offline only. The stub ramdisk is a test input and never for flashing: its /init
is a non-executable placeholder and the packager refuses it without --test-ramdisk.
Writes images under the bulk artifacts tree and the report to
evidence/kernel-upgrade/boot-package-check.json.
"""
import pocket_paths
import gzip
import hashlib
import json
import os
import runpy
import shutil
import struct
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
BULK = pocket_paths.build_root()
PLATFORM = pocket_paths.platform_source()
BOSTON_AVBTOOL = PLATFORM / 'external/avb/avbtool.py'
OUT = BULK / 'artifacts/boot-package-check'
REPORT = ROOT / 'evidence/kernel-upgrade/boot-package-check.json'
BUILD = ROOT / 'evidence/kernel-upgrade/firstboot-kernel-build.json'
PACKAGER = ROOT / 'tools/package-pocket-boot.py'
FIRSTBOOT_RAMDISK_TOOL = ROOT / 'tools/build-pocket-firstboot-ramdisk.py'
V2_RAMDISK = BULK / 'artifacts/firstboot-5.10-v2/ramdisk.img'
V2_SOURCE = BULK / 'artifacts/firstboot-5.10-v2/init-v2-source.c'    # init.c as v2 was built from it
V5_RAMDISK = BULK / 'artifacts/firstboot-5.10-v5stream/ramdisk.img'
MiB = 1 << 20
# keyboard.dtb from prepare-pocket-keyboard-board.py, as recorded in firstboot-board-keyboard.json.
KEYBOARD_BOARD = BULK / 'artifacts/firstboot-5.10/board/keyboard.dtb'
KEYBOARD_BOARD_SHA = '8c98f6835baeca29d1acf0f7f6d8aedc05a99434c1f0c1e56c2bd849295e019d'
# The modem-on board (MODEM_PORT.md M1): keyboard.dtb with mdcldma, ap/md_ccif0 and md_auxadc okay, trial M only.
MODEM_ON_BOARD = BULK / 'artifacts/firstboot-5.10/board/keyboard-modem-on.dtb'
MODEM_ON_BOARD_SHA = 'a888531a30c9dc26aea51c32c34d63a7b8528080931b183c91ff78f189a22588'
MODEM_NODES = ['/mdcldma@10014000', '/ap_ccif0@10209000', '/md_ccif0@1020a000', '/md_auxadc']


def sha(data):
    return hashlib.sha256(data).hexdigest()


def stub_ramdisk(marker, fstab='first_stage_ramdisk/fstab.mt6771'):
    """newc cpio with /init (mode 0644 placeholder), a marker file and an fstab (none if fstab is None), gzip with mtime 0."""
    init = b'#!/bin/sh\n# Stub test ramdisk for tools/check-pocket-boot-package.py.\n# ' + marker + b'\nexit 1\n'
    entries = [('init', 0o100644, init), (marker.decode(), 0o100644, marker + b'\n')]
    if fstab:
        entries.append((fstab, 0o100644, b'# stub fstab\n'))
    out = bytearray()

    def add(ino, name, mode, data):
        name_bytes = name.encode() + b'\0'
        fields = [ino, mode, 0, 0, 1, 0, len(data), 0, 0, 0, 0, len(name_bytes), 0]
        out.extend(b'070701' + b''.join(b'%08X' % f for f in fields) + name_bytes)
        out.extend(b'\0' * (-len(out) % 4))
        out.extend(data)
        out.extend(b'\0' * (-len(out) % 4))

    for ino, (name, mode, data) in enumerate(entries, 1):
        add(ino, name, mode, data)
    add(0, 'TRAILER!!!', 0, b'')
    return gzip.compress(bytes(out), mtime=0)


def parse_boot(data):
    fields = struct.unpack_from('<10I', data, 8)
    h = dict(zip(['kernel_size', 'kernel_addr', 'ramdisk_size', 'ramdisk_addr', 'second_size', 'second_addr',
                  'tags_addr', 'page_size', 'header_version', 'os_version'], fields))
    h['magic'] = data[:8].decode()
    h['name'] = data[48:64].rstrip(b'\0').decode()
    h['cmdline'] = data[64:576].split(b'\0')[0].decode()
    h['extra_cmdline'] = data[608:1632].split(b'\0')[0].decode()
    h['recovery_dtbo_size'], h['recovery_dtbo_offset'], h['header_size'], h['dtb_size'], h['dtb_addr'] = \
        struct.unpack_from('<IQIIQ', data, 1632)
    v = h['os_version']
    h['os_version_text'] = '%d.%d.%d' % (v >> 25, (v >> 18) & 0x7f, (v >> 11) & 0x7f)
    h['os_patch_level_text'] = '%d-%02d' % (((v >> 4) & 0x7f) + 2000, v & 0xf)
    page = h['page_size']
    pages = lambda n: (n + page - 1) // page * page
    offset = page
    parts = {}
    for name, size in [('kernel', h['kernel_size']), ('ramdisk', h['ramdisk_size']), ('second', h['second_size']),
                       ('recovery_dtbo', h['recovery_dtbo_size']), ('dtb', h['dtb_size'])]:
        parts[name] = (offset, size)
        offset += pages(size)
    h['payload_end'] = offset
    return h, parts


def parse_avb(data):
    """Own parse of the AVB footer, vbmeta header and first hash descriptor."""
    magic, major, minor, original, vb_off, vb_size = struct.unpack('>4sIIQQQ', data[-64:-28])
    assert magic == b'AVBf'
    vb = data[vb_off:vb_off + vb_size]
    assert vb[:4] == b'AVB0'
    (lib_major, lib_minor, auth_size, aux_size, algorithm) = struct.unpack_from('>IIQQI', vb, 4)
    (hash_off, hash_size, sig_off, sig_size, pk_off, pk_size, pkm_off, pkm_size, desc_off, desc_size,
     rollback, flags) = struct.unpack_from('>10QQI', vb, 32)
    aux = vb[256 + auth_size:256 + auth_size + aux_size]
    desc = aux[desc_off:desc_off + desc_size]
    found = None
    pos = 0
    while pos < len(desc):
        tag, length = struct.unpack_from('>QQ', desc, pos)
        if tag == 2 and found is None:
            image_size, alg, name_len, salt_len, digest_len, dflags = struct.unpack_from('>Q32sIIII', desc, pos + 16)
            body = pos + 16 + 8 + 32 + 16 + 60
            name = desc[body:body + name_len].decode()
            salt = desc[body + name_len:body + name_len + salt_len]
            digest = desc[body + name_len + salt_len:body + name_len + salt_len + digest_len]
            found = {'image_size': image_size, 'hash_algorithm': alg.rstrip(b'\0').decode(), 'partition_name': name,
                     'salt': salt.hex(), 'digest': digest.hex(), 'flags': dflags}
        pos += 16 + length
    return {'footer_version': '%d.%d' % (major, minor), 'image_size': len(data), 'original_image_size': original,
            'vbmeta_offset': vb_off, 'vbmeta_size': vb_size, 'required_libavb': '%d.%d' % (lib_major, lib_minor),
            'algorithm_type': algorithm, 'auth_block': auth_size, 'rollback_index': rollback, 'flags': flags,
            'hash_descriptor': found}


def main():
    build = json.loads(BUILD.read_text())
    assert build['returncode'] == 0 and build['stage'] == 'image'
    kernel_path = Path(build['output']) / 'arch/arm64/boot/Image.gz'
    raw_path = Path(build['output']) / 'arch/arm64/boot/Image'
    for path in (kernel_path, raw_path):
        assert sha(path.read_bytes()) == build['artifacts'][str(path)]['sha256'], path
    p = runpy.run_path(str(PACKAGER))
    Refused, package = p['Refused'], p['package']
    if OUT.exists():
        shutil.rmtree(OUT)
    OUT.mkdir(parents=True)
    stub = OUT / 'stub-ramdisk-not-for-flashing.cpio.gz'
    stub.write_bytes(stub_ramdisk(p['STUB_MARKER']))
    assert stub_ramdisk(p['STUB_MARKER']) == stub.read_bytes()

    # Positive run through the command line, twice, for determinism.
    images = []
    for n in (1, 2):
        out = OUT / ('boot-stub-%d.%s.img' % (n, p['TEST_NAME']))
        subprocess.run([sys.executable, '-B', str(PACKAGER), '--kernel', str(kernel_path), '--ramdisk', str(stub),
                        '--output', str(out), '--test-ramdisk'], check=True)
        images.append(out)
    data = images[0].read_bytes()
    deterministic = data == images[1].read_bytes()
    assert deterministic
    record = json.loads(Path(str(images[0]) + '.json').read_text())

    stock = p['STOCK_BOOT'].read_bytes()
    h, parts = parse_boot(data)
    sh, sparts = parse_boot(stock)
    piece = lambda d, part: d[part[0]:part[0] + part[1]]
    kernel_blob, ramdisk_blob, dtb_blob = piece(data, parts['kernel']), piece(data, parts['ramdisk']), piece(data, parts['dtb'])
    table = runpy.run_path(str(ROOT / 'tools/prepare-upgrade-boot-layout.py'))
    entry = table['parse_table'](dtb_blob)['entries'][0]
    board = json.loads(p['BOARD_RECORD'].read_text())['board_dtb']
    overlay_blob = piece(data, parts['recovery_dtbo'])
    overlay_table = table['parse_table'](overlay_blob) if overlay_blob else {'entries': []}
    image = p['inflate_kernel'](kernel_blob)
    text_offset, image_size, flags = struct.unpack_from('<QQQ', image, 8)
    checks = {
        'magic': h['magic'] == 'ANDROID!',
        'header_version_2': h['header_version'] == 2 == sh['header_version'],
        'page_2048': h['page_size'] == 2048 == sh['page_size'],
        'header_size_1660': h['header_size'] == 1660 == sh['header_size'],
        'kernel_addr_0x40200000': h['kernel_addr'] == 0x40200000,
        'ramdisk_addr_as_stock': h['ramdisk_addr'] == 0x55000000 == sh['ramdisk_addr'],
        'tags_addr_as_stock': h['tags_addr'] == 0x54000000 == sh['tags_addr'],
        'dtb_addr_as_stock': h['dtb_addr'] == 0x54000000 == sh['dtb_addr'],
        'os_fields_as_stock': h['os_version'] == sh['os_version'],
        'no_second_stage': h['second_size'] == 0,
        'cmdline': h['cmdline'] == p['CMDLINE'] and h['extra_cmdline'] == '',
        'cmdline_has_loglevel_8': 'loglevel=8' in h['cmdline'].split(),
        'cmdline_has_printk_time_1': 'printk.time=1' in h['cmdline'].split(),
        'cmdline_has_selinux_permissive': 'androidboot.selinux=permissive' in h['cmdline'].split(),
        'cmdline_has_androidboot_hardware_mt6771': 'androidboot.hardware=mt6771' in h['cmdline'].split(),
        'cmdline_has_firmware_class_path': 'firmware_class.path=/vendor/firmware' in h['cmdline'].split(),
        'cmdline_has_loop_max_part_7': 'loop.max_part=7' in h['cmdline'].split(),
        'cmdline_has_cgroup_memory': 'cgroup.memory=nosocket,nokmem' in h['cmdline'].split(),
        'cmdline_has_printk_devkmsg_on': 'printk.devkmsg=on' in h['cmdline'].split(),
        'cmdline_has_panic_10': 'panic=10' in h['cmdline'].split(),
        'cmdline_has_log_buf_len_4M': 'log_buf_len=4M' in h['cmdline'].split(),
        'cmdline_has_aw9523_start_suspended_0': 'aw9523_key.start_suspended=0' in h['cmdline'].split(),
        'ramdisk_has_first_stage_fstab_for_hardware': 'first_stage_ramdisk/fstab.mt6771' in p['cpio_names'](
            gzip.decompress(ramdisk_blob)),
        'fstab_check_accepts_root_fstab': p['check_fstab'](
            gzip.decompress(stub_ramdisk(p['STUB_MARKER'], 'fstab.mt6771')), p['CMDLINE']) is None,
        'cmdline_keeps_stock_bootopt': sh['cmdline'].split()[0] in h['cmdline'].split(),
        'kernel_is_input': kernel_blob == kernel_path.read_bytes(),
        'kernel_inflates_to_built_Image': image == raw_path.read_bytes(),
        'ramdisk_is_stub': ramdisk_blob == stub.read_bytes(),
        'board_record_is_keyboard_board': board['path'] == str(KEYBOARD_BOARD) and board['sha256'] == KEYBOARD_BOARD_SHA,
        'dtb_table_holds_keyboard_board': sha(entry['blob']) == board['sha256'] == KEYBOARD_BOARD_SHA,
        'dtb_identity_as_stock': entry['identity'] == table['parse_table'](piece(stock, sparts['dtb']))['entries'][0]['identity'],
        'limit_image_is_partition_size': len(data) == 0x2000000 == len(stock),
        'limit_payload_fits': h['payload_end'] <= record['avb']['partition_size'] - 0x10000,
        'limit_decompressed_under_200MiB': len(image) <= image_size <= 0xc800000,
        'limit_kernel_reservation_below_dt': h['kernel_addr'] + 0xc800000 <= 0x54000000,
        'limit_2MiB_alignment': (h['kernel_addr'] - text_offset) % 0x200000 == 0 and text_offset == 0,
        'limit_ramdisk_16MiB': h['ramdisk_size'] <= 0x1000000,
        'deterministic': deterministic,
        'recovery_dtbo_present': h['recovery_dtbo_size'] > 0 and len(overlay_blob) == h['recovery_dtbo_size'],
        'recovery_dtbo_is_pinned_bytes': overlay_blob == p['RECOVERY_DTBO'] and sha(overlay_blob) == p['RECOVERY_DTBO_SHA'],
        'recovery_dtbo_table_magic_one_entry': overlay_blob[:4] == bytes.fromhex('d7b7ab1e') and len(overlay_table['entries']) == 1,
        'recovery_dtbo_offset_nonzero_page_aligned': h['recovery_dtbo_offset'] > 0 and h['recovery_dtbo_offset'] % h['page_size'] == 0,
        'recovery_dtbo_offset_after_ramdisk_and_second': h['recovery_dtbo_offset'] == parts['recovery_dtbo'][0] == (
            h['page_size'] + sum(-(-n // h['page_size']) * h['page_size']
                                 for n in (h['kernel_size'], h['ramdisk_size'], h['second_size']))),
        'dtb_offset_follows_recovery_dtbo': parts['dtb'][0] == h['recovery_dtbo_offset'] + (
            -(-h['recovery_dtbo_size'] // h['page_size']) * h['page_size']),
        'limit_boot_dtb_plus_overlay_512KiB': len(entry['blob']) + len(overlay_table['entries'][0]['blob']) <= 0x80000,
    }
    # Modem-on board: packaged only by name, the dtb is the pinned modem-on board, the rest of the image as modem-off.
    on = OUT / ('boot-stub-modem-on.%s.img' % p['TEST_NAME'])
    subprocess.run([sys.executable, '-B', str(PACKAGER), '--kernel', str(kernel_path), '--ramdisk', str(stub),
                    '--output', str(on), '--test-ramdisk', '--board', 'modem-on'], check=True)
    on_data = on.read_bytes()
    oh, oparts = parse_boot(on_data)
    on_entry = table['parse_table'](piece(on_data, oparts['dtb']))['entries'][0]
    on_record = json.loads(p['BOARD_RECORD'].read_text())['board_dtb_modem_on']
    tree = runpy.run_path(str(ROOT / 'tools/prepare-pocket-diagnostic-tree.py'), run_name='boot_package_check')
    off_nodes, on_nodes = tree['DECODE'](entry['blob'])['nodes'], tree['DECODE'](on_entry['blob'])['nodes']

    def refused_name(board, name):
        try:
            package(kernel_path, stub, OUT / name, True, board=board)
        except Refused:
            return True
        return False
    checks.update({
        'modem_on_record_is_pinned_board': on_record['path'] == str(MODEM_ON_BOARD) and on_record['sha256'] == MODEM_ON_BOARD_SHA,
        'modem_on_dtb_table_holds_modem_on_board': sha(on_entry['blob']) == MODEM_ON_BOARD_SHA,
        'modem_on_rest_of_image_as_default': piece(on_data, oparts['kernel']) == kernel_blob and
                                            piece(on_data, oparts['ramdisk']) == ramdisk_blob and oh['cmdline'] == h['cmdline'],
        'default_board_has_modem_nodes_disabled': not any(tree['enabled'](off_nodes, n) for n in MODEM_NODES),
        'modem_on_board_has_modem_nodes_okay': all(tree['enabled'](on_nodes, n) for n in MODEM_NODES),
        'boards_differ_only_in_modem_status': set(off_nodes) == set(on_nodes) and all(
            off_nodes[n] == on_nodes[n] for n in off_nodes if n not in MODEM_NODES) and all(
            {k: v for k, v in off_nodes[n].items() if k != 'status'} == {k: v for k, v in on_nodes[n].items() if k != 'status'}
            for n in MODEM_NODES),
        'modem_on_refused_without_name': refused_name('modem-on', 'boot-stub-x.%s.img' % p['TEST_NAME']),
        'modem_on_name_refused_on_default_board': refused_name('modem-off', 'boot-stub-modem-on-x.%s.img' % p['TEST_NAME']),
    })
    # First-flash v2 ramdisk: wrapper at /init, product init at /init.android.
    fb = runpy.run_path(str(FIRSTBOOT_RAMDISK_TOOL))
    product_path = p['PRODUCT_RAMDISK']
    product_raw = gzip.decompress(product_path.read_bytes())
    source_path = V2_SOURCE
    source_text = source_path.read_text()
    current_text = p['WRAPPER_SOURCE'].read_text()
    v2_raw = gzip.decompress(V2_RAMDISK.read_bytes())
    v2_entries = p['cpio_entries'](v2_raw)
    wrapper = [d for n, m, d in v2_entries if n == 'init'][0]
    product_init = [d for n, m, d in p['cpio_entries'](product_raw) if n == 'init'][0]
    try:
        v2_info = p['ramdisk_info'](V2_RAMDISK.read_bytes(), False, p['CMDLINE'], product_raw, source_text)
    except Refused as e:
        v2_info = {'refused': str(e)}
    checks.update({
        'v2_ramdisk_accepted_with_wrapper': 'wrapper' in v2_info,
        'v2_wrapper_static_aarch64': p['elf_static_aarch64'](wrapper) == [],
        'v2_init_android_is_product_init': [d for n, m, d in v2_entries if n == 'init.android'] == [product_init],
        'v2_wrapper_marker_matches_source': p['WRAPPER_MARKER'] + sha(source_text.encode()).encode() in wrapper,
        'v2_other_records_as_product': [e for e in v2_entries if e[0] not in ('init', 'init.android')] ==
                                       [e for e in p['cpio_entries'](product_raw) if e[0] != 'init'],
        'wrapper_source_scan_clean': p['check_wrapper_source'](source_text) == [],
        'current_wrapper_source_scan_clean': p['check_wrapper_source'](current_text) == [],
    })
    if V5_RAMDISK.exists():
        v5_raw = gzip.decompress(V5_RAMDISK.read_bytes())
        v5_entries = p['cpio_entries'](v5_raw)
        try:
            v5_info = p['ramdisk_info'](V5_RAMDISK.read_bytes(), False, p['CMDLINE'], product_raw, current_text)
        except Refused as e:
            v5_info = {'refused': str(e)}
        checks.update({
            'v5stream_ramdisk_accepted_with_wrapper': 'wrapper' in v5_info,
            'v5stream_other_records_as_v2': [e for e in v5_entries if e[0] != 'init'] ==
                                            [e for e in v2_entries if e[0] != 'init'],
        })

    # unpack_bootimg cross-check, as the diagnostic packager does.
    with tempfile.TemporaryDirectory(dir=OUT) as tmp:
        u = subprocess.run([sys.executable, '-B', str(ROOT / 'tools/unpack_bootimg.py'), '--boot_img', str(images[0]),
                            '--out', tmp], check=True, capture_output=True, text=True)
        checks['unpack_bootimg_roundtrip'] = all((Path(tmp) / n).read_bytes() == b for n, b in
                                                 [('kernel', kernel_blob), ('ramdisk', ramdisk_blob), ('dtb', dtb_blob)])
        unpack_text = u.stdout

    avb = parse_avb(data)
    stock_avb = parse_avb(stock)
    d = avb['hash_descriptor']
    payload = data[:d['image_size']]
    checks.update({
        'avb_partition_boot_as_stock': d['partition_name'] == 'boot' == stock_avb['hash_descriptor']['partition_name'],
        'avb_footer_version_as_stock': avb['footer_version'] == stock_avb['footer_version'],
        'avb_hash_sha256_as_stock': d['hash_algorithm'] == 'sha256' == stock_avb['hash_descriptor']['hash_algorithm'],
        'avb_algorithm_none': avb['algorithm_type'] == 0 and avb['auth_block'] == 0,
        'avb_digest_matches_payload': sha(bytes.fromhex(d['salt']) + payload) == d['digest'],
        'avb_rollback_0_flags_0': avb['rollback_index'] == 0 and avb['flags'] == 0,
        'avb_covers_header_payload': d['image_size'] == avb['original_image_size'] >= h['payload_end'],
    })
    # avbtool verify_image reads the payload from <dir>/<partition>.img, so check copies named boot.img.
    def avbtool(op, blob):
        with tempfile.TemporaryDirectory(dir=OUT) as tmp:
            path = Path(tmp) / 'boot.img'
            path.write_bytes(blob)
            r = subprocess.run([sys.executable, '-B', str(BOSTON_AVBTOOL), op, '--image', str(path)],
                               capture_output=True, text=True)
        return {'returncode': r.returncode, 'output': (r.stdout + r.stderr).replace(str(path), 'boot.img')}

    tool = {op: avbtool(op, data) for op in ('info_image', 'verify_image')}
    checks['boston_avbtool_verify'] = tool['verify_image']['returncode'] == 0
    corrupted = bytearray(data)
    corrupted[parts['kernel'][0] + 4096] ^= 1
    tool['verify_corrupted'] = avbtool('verify_image', bytes(corrupted))
    checks['boston_avbtool_rejects_corrupted_payload'] = (tool['verify_corrupted']['returncode'] != 0
                                                         and 'digest' in tool['verify_corrupted']['output'])

    # One failing case per limit and refusal.
    raw = raw_path.read_bytes()

    def kernel_with(body, image_size=None):
        img = bytearray(body)
        struct.pack_into('<Q', img, 16, image_size if image_size is not None else len(img))
        return gzip.compress(bytes(img), compresslevel=1, mtime=0)

    no_fstab = stub_ramdisk(p['STUB_MARKER'], None)
    wrong_fstab = stub_ramdisk(p['STUB_MARKER'], 'first_stage_ramdisk/fstab.other')
    real_ramdisk_like = gzip.compress(b'070701' + b'0' * 104 + b'not a stub\0', mtime=0)

    def wrapped(binary=wrapper, edit=None):
        raw, _ = fb['wrap'](product_raw, binary)
        if edit:
            records, trailer, _ = fb['read_cpio'](raw)
            edit(records)
            raw = fb['write_cpio'](records, trailer, 512)
        return gzip.compress(raw, mtime=0)

    def patched(offset, value, fmt):
        b = bytearray(wrapper)
        struct.pack_into(fmt, b, offset, value)
        return bytes(b)

    def record_edit(name, mode=None, flip=False):
        def edit(records):
            for r in records:
                if r[1] == name:
                    if mode is not None:
                        r[0][1] = mode
                    if flip:
                        r[2] = r[2][:100] + bytes([r[2][100] ^ 1]) + r[2][101:]
        return edit

    source_sha = sha(source_text.encode()).encode()
    bad_sources = {
        'watchdog': source_text.replace('int main(int argc', 'static int t(void) { return open("/dev/watchdog", O_WRONLY); }\nint main(int argc'),
        'reboot': source_text.replace('int main(int argc', 'static void t(void) { reboot(RB_AUTOBOOT); }\nint main(int argc'),
        'block': source_text.replace('int main(int argc', 'static int t(void) { return open("/dev/block/sda", O_RDWR); }\nint main(int argc'),
    }
    phoff = struct.unpack_from('<Q', wrapper, 32)[0]
    cases = []
    with tempfile.TemporaryDirectory(dir=OUT) as tmp:
        tmp = Path(tmp)
        files = {
            'image_size_over_200MiB.gz': kernel_with(raw, 0xc800000 + 0x1000),
            'inflates_over_200MiB.gz': kernel_with(raw[:64] + bytes(0xc800000 + 1 - 64), 0xc800000),
            'big_incompressible.gz': kernel_with(raw[:64] + os.urandom(33 * MiB)),
            'trailing.gz': kernel_path.read_bytes() + b'\0' * 16,
            'not_arm64.gz': gzip.compress(bytes(4096), mtime=0),
            'ramdisk_over_16MiB.gz': gzip.compress(os.urandom(16 * MiB), compresslevel=1, mtime=0),
            'not_stub_ramdisk.gz': real_ramdisk_like,
            'no_fstab.gz': no_fstab,
            'wrong_fstab.gz': wrong_fstab,
            'v1_no_wrapper.gz': product_path.read_bytes(),
            'wrapper_not_static.gz': wrapped(patched(phoff, 3, '<I')),
            'wrapper_not_aarch64.gz': wrapped(patched(18, 62, '<H')),
            'wrapper_not_executable.gz': wrapped(edit=record_edit('init', mode=0o100644)),
            'wrapper_test_build.gz': wrapped(wrapper + p['WRAPPER_TEST_MARKER']),
            'wrapper_no_marker.gz': wrapped(wrapper.replace(p['WRAPPER_MARKER'], b'X' * len(p['WRAPPER_MARKER']))),
            'init_android_changed.gz': wrapped(edit=record_edit('init.android', flip=True)),
            'fstab_changed.gz': wrapped(edit=record_edit('first_stage_ramdisk/fstab.mt6771', flip=True)),
            'v2.gz': V2_RAMDISK.read_bytes(),
        }
        for name, text in bad_sources.items():
            (tmp / ('source_%s.c' % name)).write_text(text)
            files['source_%s.gz' % name] = wrapped(wrapper.replace(source_sha, sha(text.encode()).encode()))
        (tmp / 'source_other.c').write_text(source_text + '\n')
        for name, blob in files.items():
            (tmp / name).write_bytes(blob)
        existing = tmp / ('existing.%s.img' % p['TEST_NAME'])
        existing.write_bytes(b'x')
        k, s = str(kernel_path), str(stub)
        out = lambda n: str(tmp / ('%s.%s.img' % (n, p['TEST_NAME'])))
        zero_entries = bytearray(p['RECOVERY_DTBO'])
        struct.pack_into('>I', zero_entries, 16, 0)
        zero_entries = bytes(zero_entries)
        for name, kwargs, expect in [
            ('kernel_at_stock_0x40080000', dict(kernel_path=k, ramdisk_path=s, output=out('a'), test_ramdisk=True, kernel_addr=0x40080000), '2 MiB'),
            ('kernel_not_2MiB_aligned_0x40240000', dict(kernel_path=k, ramdisk_path=s, output=out('b'), test_ramdisk=True, kernel_addr=0x40240000), 'aligned'),
            ('kernel_reservation_into_dt', dict(kernel_path=k, ramdisk_path=s, output=out('c'), test_ramdisk=True, kernel_addr=0x48000000), 'reservation'),
            ('image_size_over_200MiB', dict(kernel_path=str(tmp / 'image_size_over_200MiB.gz'), ramdisk_path=s, output=out('d'), test_ramdisk=True), '200 MiB'),
            ('inflates_over_200MiB', dict(kernel_path=str(tmp / 'inflates_over_200MiB.gz'), ramdisk_path=s, output=out('e'), test_ramdisk=True), '200 MiB'),
            ('image_over_partition', dict(kernel_path=str(tmp / 'big_incompressible.gz'), ramdisk_path=s, output=out('f'), test_ramdisk=True), 'partition'),
            ('ramdisk_over_16MiB', dict(kernel_path=k, ramdisk_path=str(tmp / 'ramdisk_over_16MiB.gz'), output=out('g')), '16 MiB'),
            ('gzip_trailing_data', dict(kernel_path=str(tmp / 'trailing.gz'), ramdisk_path=s, output=out('h'), test_ramdisk=True), 'after the first member'),
            ('not_arm64', dict(kernel_path=str(tmp / 'not_arm64.gz'), ramdisk_path=s, output=out('i'), test_ramdisk=True), 'arm64'),
            ('stub_without_test_flag', dict(kernel_path=k, ramdisk_path=s, output=out('j')), 'test stub'),
            ('stub_output_name_unmarked', dict(kernel_path=k, ramdisk_path=s, output=str(tmp / 'boot.img'), test_ramdisk=True), 'file name'),
            ('test_flag_on_non_stub', dict(kernel_path=k, ramdisk_path=str(tmp / 'not_stub_ramdisk.gz'), output=out('k'), test_ramdisk=True), 'not the stub'),
            ('recovery_dtbo_missing', dict(kernel_path=k, ramdisk_path=s, output=out('l'), test_ramdisk=True, recovery_dtbo=b''), 'missing'),
            ('recovery_dtbo_wrong_bytes', dict(kernel_path=k, ramdisk_path=s, output=out('m'), test_ramdisk=True, recovery_dtbo=p['RECOVERY_DTBO'][:-1] + b'\x0a'), 'pinned'),
            ('recovery_dtbo_zero_entries', dict(kernel_path=k, ramdisk_path=s, output=out('n'), test_ramdisk=True, recovery_dtbo=zero_entries), 'pinned'),
            ('dtb_merge_over_512KiB', dict(kernel_path=k, ramdisk_path=s, output=out('o'), test_ramdisk=True), '512 KiB'),
            ('cmdline_without_loglevel_8', dict(kernel_path=k, ramdisk_path=s, output=out('p'), test_ramdisk=True, cmdline=p['CMDLINE'].replace(' loglevel=8', '')), 'loglevel=8'),
            ('cmdline_without_printk_time', dict(kernel_path=k, ramdisk_path=s, output=out('q'), test_ramdisk=True, cmdline=p['CMDLINE'].replace(' printk.time=1', '')), 'printk.time=1'),
            ('cmdline_without_selinux_permissive', dict(kernel_path=k, ramdisk_path=s, output=out('r'), test_ramdisk=True, cmdline=p['CMDLINE'].replace(' androidboot.selinux=permissive', '')), 'androidboot.selinux=permissive'),
            ('cmdline_without_androidboot_hardware', dict(kernel_path=k, ramdisk_path=s, output=out('t0'), test_ramdisk=True, cmdline=p['CMDLINE'].replace(' androidboot.hardware=mt6771', '')), 'androidboot.hardware=mt6771'),
            ('cmdline_without_firmware_class_path', dict(kernel_path=k, ramdisk_path=s, output=out('t1'), test_ramdisk=True, cmdline=p['CMDLINE'].replace(' firmware_class.path=/vendor/firmware', '')), 'firmware_class.path=/vendor/firmware'),
            ('cmdline_without_loop_max_part', dict(kernel_path=k, ramdisk_path=s, output=out('t2'), test_ramdisk=True, cmdline=p['CMDLINE'].replace(' loop.max_part=7', '')), 'loop.max_part=7'),
            ('cmdline_without_cgroup_memory', dict(kernel_path=k, ramdisk_path=s, output=out('t3'), test_ramdisk=True, cmdline=p['CMDLINE'].replace(' cgroup.memory=nosocket,nokmem', '')), 'cgroup.memory=nosocket,nokmem'),
            ('cmdline_without_printk_devkmsg', dict(kernel_path=k, ramdisk_path=s, output=out('t4'), test_ramdisk=True, cmdline=p['CMDLINE'].replace(' printk.devkmsg=on', '')), 'printk.devkmsg=on'),
            ('cmdline_without_panic_10', dict(kernel_path=k, ramdisk_path=s, output=out('t5'), test_ramdisk=True, cmdline=p['CMDLINE'].replace(' panic=10', '')), 'panic=10'),
            ('cmdline_without_log_buf_len', dict(kernel_path=k, ramdisk_path=s, output=out('t7'), test_ramdisk=True, cmdline=p['CMDLINE'].replace(' log_buf_len=4M', '')), 'log_buf_len=4M'),
            ('cmdline_without_aw9523_start_suspended', dict(kernel_path=k, ramdisk_path=s, output=out('t6'), test_ramdisk=True, cmdline=p['CMDLINE'].replace(' aw9523_key.start_suspended=0', '')), 'aw9523_key.start_suspended=0'),
            ('ramdisk_without_fstab', dict(kernel_path=k, ramdisk_path=str(tmp / 'no_fstab.gz'), output=out('u'), test_ramdisk=True), 'no first_stage_ramdisk/fstab.mt6771'),
            ('ramdisk_fstab_for_other_hardware', dict(kernel_path=k, ramdisk_path=str(tmp / 'wrong_fstab.gz'), output=out('v'), test_ramdisk=True), 'no first_stage_ramdisk/fstab.mt6771'),
            ('output_exists', dict(kernel_path=k, ramdisk_path=s, output=str(existing), test_ramdisk=True), 'overwrite'),
            ('ramdisk_without_wrapper_v1', dict(kernel_path=k, ramdisk_path=str(tmp / 'v1_no_wrapper.gz'), output=out('w0')), 'no single /init.android'),
            ('wrapper_not_static', dict(kernel_path=k, ramdisk_path=str(tmp / 'wrapper_not_static.gz'), output=out('w1')), 'is not static'),
            ('wrapper_not_aarch64', dict(kernel_path=k, ramdisk_path=str(tmp / 'wrapper_not_aarch64.gz'), output=out('w2')), 'is not aarch64'),
            ('wrapper_not_executable', dict(kernel_path=k, ramdisk_path=str(tmp / 'wrapper_not_executable.gz'), output=out('w3')), 'not an executable'),
            ('wrapper_host_test_build', dict(kernel_path=k, ramdisk_path=str(tmp / 'wrapper_test_build.gz'), output=out('w4')), 'host test build'),
            ('wrapper_without_marker', dict(kernel_path=k, ramdisk_path=str(tmp / 'wrapper_no_marker.gz'), output=out('w5')), 'no marker'),
            ('wrapper_marker_other_source', dict(kernel_path=k, ramdisk_path=str(tmp / 'v2.gz'), output=out('w6'), wrapper_source=str(tmp / 'source_other.c')), 'does not match the wrapper source'),
            ('init_android_not_product_init', dict(kernel_path=k, ramdisk_path=str(tmp / 'init_android_changed.gz'), output=out('w7')), 'byte-identical to the product first-stage init'),
            ('ramdisk_other_record_changed', dict(kernel_path=k, ramdisk_path=str(tmp / 'fstab_changed.gz'), output=out('w8')), 'differs from the product ramdisk'),
            ('wrapper_without_product_ramdisk', dict(kernel_path=k, ramdisk_path=str(tmp / 'v2.gz'), output=out('w9'), product_ramdisk=None), 'needs the product ramdisk'),
            ('wrapper_source_watchdog', dict(kernel_path=k, ramdisk_path=str(tmp / 'source_watchdog.gz'), output=out('wa'), wrapper_source=str(tmp / 'source_watchdog.c')), 'mentions watchdog'),
            ('wrapper_source_reboot', dict(kernel_path=k, ramdisk_path=str(tmp / 'source_reboot.gz'), output=out('wb'), wrapper_source=str(tmp / 'source_reboot.c')), 'mentions reboot'),
            ('wrapper_source_block_device_write', dict(kernel_path=k, ramdisk_path=str(tmp / 'source_block.gz'), output=out('wc'), wrapper_source=str(tmp / 'source_block.c')), 'names a block device'),
        ]:
            merge_max = package.__globals__['DTB_MERGE_MAX']
            if name == 'dtb_merge_over_512KiB':
                package.__globals__['DTB_MERGE_MAX'] = len(entry['blob']) + len(overlay_table['entries'][0]['blob']) - 1
            try:
                package(**{'wrapper_source': str(V2_SOURCE), **kwargs})
                result = 'accepted'
            except Refused as e:
                result = str(e)
            package.__globals__['DTB_MERGE_MAX'] = merge_max
            ok = result != 'accepted' and expect in result and not (Path(kwargs['output']).exists() and kwargs['output'] != str(existing))
            cases.append({'case': name, 'refused': result != 'accepted', 'message': result, 'pass': ok})
    for img in images[1:]:
        img.unlink()
        Path(str(img) + '.json').unlink()

    passed = all(checks.values()) and all(c['pass'] for c in cases)
    report = {
        'state': 'Offline package check with a stub ramdisk; the image is a test output and never for flashing',
        'passed': passed,
        'packager_sha256': sha(PACKAGER.read_bytes()),
        'checker_sha256': sha(Path(__file__).read_bytes()),
        'kernel': {'path': str(kernel_path), 'sha256': sha(kernel_path.read_bytes()), 'release': build.get('kernel_release')},
        'v2_ramdisk': {'path': str(V2_RAMDISK), 'sha256': sha(V2_RAMDISK.read_bytes()), 'info': v2_info,
                       'product_ramdisk': str(product_path), 'wrapper_source': str(source_path)},
        'stub_ramdisk': {'path': str(stub), 'bytes': stub.stat().st_size, 'sha256': sha(stub.read_bytes()),
                         'contents': ['init (0644 placeholder, exits 1)', p['STUB_MARKER'].decode()]},
        'image': {'path': str(images[0]), 'sha256': sha(data), 'bytes': len(data)},
        'layout': {name: {'offset': o, 'bytes': n} for name, (o, n) in parts.items() if n},
        'header': {k: v for k, v in h.items()},
        'stock_header': {k: v for k, v in sh.items() if k not in ('payload_end',)},
        'avb': avb, 'stock_avb': stock_avb,
        'boston_avbtool': {'path': str(BOSTON_AVBTOOL), 'sha256': sha(BOSTON_AVBTOOL.read_bytes()), **tool},
        'unpack_bootimg': unpack_text,
        'checks': checks,
        'failing_cases': cases,
        'packager_record': record,
        'device_accessed': False,
        'limits': ['No LK or kernel execution; LK behaviour is from REA (firstboot-tkcore-lk-staging.md)',
                   'Stub ramdisk for the image layout; the v2 ramdisk is checked through ramdisk_info only',
                   'Wrapper checks are static (ELF headers, markers, source scan); the wrapper is not run here',
                   'AVB footer is unsigned (NONE); acceptance relies on the unlocked state and vbmeta flags 3'],
    }
    REPORT.write_text(json.dumps(report, indent=2) + '\n')
    failed = [k for k, v in checks.items() if not v] + [c['case'] for c in cases if not c['pass']]
    print('%d checks, %d failing cases: %s' % (len(checks), len(cases), 'all passed' if passed else 'FAILED ' + ', '.join(failed)))
    sys.exit(0 if passed else 1)


if __name__ == '__main__':
    main()
