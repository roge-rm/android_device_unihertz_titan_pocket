#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Verify the combined v11 diagnostic's local provenance and the v11 deltas (ext4/dm config,
localversion, the userdata write budget and the never-written partition list); never access a
phone."""
import hashlib
import json
import re
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
EVIDENCE = ROOT / 'evidence/kernel-upgrade'
PACKAGE = EVIDENCE / 'diagnostic-package-v11'

# super must stay byte-identical to the stock backup after the read-only mount test.
SUPER_BACKUP_SHA = '6f8764f8318282ee6a98b75abd25a1bbf79af9c85a504f2021c41f60ba24fc88'
# The only partition v11 ever writes; the restore returns it to stock.
WRITABLE_PARTITION = 'userdata'
# Nothing else is ever written (draft "Never written").
NEVER_WRITTEN = ['boot', 'super', 'recovery', 'vbmeta', 'dtbo', 'lk', 'preloader', 'proinfo', 'seccfg',
                 'sec1', 'frp', 'otp', 'nvram', 'nvdata', 'nvcfg', 'protect1', 'protect2', 'persist',
                 'md_udc', 'metadata', 'apd', 'expdb', 'para']


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def read(path):
    return json.loads(Path(path).read_text())


def main():
    package = read(PACKAGE / 'candidate-validation.json')
    for item in [package['candidate'], package['restore_image']]:
        assert Path(item['path']).stat().st_size == item['bytes'] == 33554432
        assert digest(item['path']) == item['sha256']
    for path, expected in package['components'].items():
        assert digest(path) == expected, path
    assert digest(ROOT / 'tools/package-pocket-diagnostic.py') == package['builder_sha256']
    build = read(EVIDENCE / 'diagnostic-kernel-build-v11.json')
    assert build['returncode'] == 0 and build['engineering_config_unchanged']
    assert digest(ROOT / 'tools/build-pocket-diagnostic-kernel.py') == build['builder_sha256']
    assert digest(ROOT / 'configs/kernel-diagnostic-5.10-v11.fragment') == build['fragment_sha256']
    assert digest(Path(build['output']) / '.config') == build['config_sha256']
    for path, expected in build['source_hashes'].items():
        assert digest(Path(build['source']) / path) == expected, path
    for path, entry in build['artifacts'].items():
        assert digest(path) == entry['sha256'], path
    ram = read(EVIDENCE / 'diagnostic-ramdisk-v11.json')
    for entry in ram['source_inputs'] + ram['files']:
        assert digest(ROOT / entry['path']) == entry['sha256'], entry['path']
    assert {x['path'] for x in ram['source_inputs']} >= {
        'kernel-upgrade/diagnostic-probe-v11/init.c', 'kernel-upgrade/ram-probe/init.c',
        'kernel-upgrade/ram-probe/ufs-readonly.h', 'kernel-upgrade/tkcore-probe/feature_query.h',
        'kernel-upgrade/diagnostic-probe-v11/probes.h', 'kernel-upgrade/ram-probe/commands.h'}
    board = read(EVIDENCE / 'diagnostic-board-v11.json')
    assert digest(board['board_dtb']['path']) == board['board_dtb']['sha256']
    for path, expected in board['generator_inputs'].items():
        assert digest(ROOT / path) == expected, path
    assert board['nodes'] == 955 and not board['phone_accessed']
    patches = read(EVIDENCE / 'patch-validation.json')
    assert len(patches) == 13
    replay_sources = {}
    for patch in patches:
        assert digest(patch['path']) == patch['sha256']
        for entry in patch['files']:
            assert digest(Path(build['source']) / entry['path']) == entry['sha256']
            replay_sources[entry['path']] = entry['sha256']
    assert replay_sources == build['source_hashes']
    avb = read(PACKAGE / 'host-avb-check.json')
    assert len(avb['cases']) == 7 and avb['source_hashes_before_and_after_match']
    assert digest(ROOT / 'tools/check-recovery-avb.py') == avb['runner_sha256']
    assert any(c.get('image_sha256') == package['candidate']['sha256'] and
               c.get('observed', {}).get('slot_data') for c in avb['cases'])
    capture = read(EVIDENCE / 'diagnostic-capture-check.json')
    assert capture['cases'] == 77 and capture['echo_cases'] == 12 and not capture['commands_sent']
    for path, expected in capture['source_hashes'].items():
        assert digest(ROOT / path) == expected
    fixup = read(EVIDENCE / 'diagnostic-lk-fixup-check-v11.json')
    assert len(fixup['cases']) == 2 and all(c['insertion_count'] == 19 and c['all_expected_results'] for c in fixup['cases'])
    for case in fixup['cases']:
        assert digest(case['input']) == case['sha256']
    args = read(EVIDENCE / 'lk-bootargs-check-v11.json')
    assert len(args['cases']) == 10
    for path, expected in args['input_hashes'].items():
        assert digest(path) == expected
    guard = read(EVIDENCE / 'tkcore-shm-guard-check-v11.json')
    assert guard['actual_guard_tested'] and guard['scenarios'] == 26
    driver = Path(build['source']) / 'drivers/misc/mediatek/tkcore/armtz/tee_tz_drv.c'
    assert 'of_reserved_mem_lookup(owner)' in driver.read_text()
    assert digest(driver) == guard['driver_sha256']
    assert 'devm_ioremap(dev, res->start' in (Path(build['source']) / 'drivers/usb/mtu3/mtu3_plat.c').read_text()
    # ---- v11 config delta: ext4 and dm-linear added, encryption/verity/crypt kept out ----
    config = (Path(build['output']) / '.config').read_text().splitlines()
    for entry in ['CONFIG_EXT4_FS=y', 'CONFIG_MD=y', 'CONFIG_BLK_DEV_DM=y']:
        assert entry in config, entry
    for banned in ['CONFIG_DM_CRYPT=y', 'CONFIG_DM_VERITY=y', 'CONFIG_DM_DEFAULT_KEY=y',
                   'CONFIG_FS_ENCRYPTION=y', 'CONFIG_F2FS_FS=y', 'CONFIG_SCSI_UFS_CRYPTO=y']:
        assert banned not in config, banned
    assert 'CONFIG_LOCALVERSION="-titanpocket-ramdiag-v11"' in config
    assert 'CONFIG_WATCHDOG_OPEN_TIMEOUT=90' in config and 'CONFIG_OF_RESERVED_MEM=y' in config
    symbols = {s.split()[-1] for s in (Path(build['output']) / 'System.map').read_text().splitlines()}
    assert {'dm_linear_init', 'ext4_init_fs'} <= symbols, 'dm-linear and ext4 must be built in'
    assert package['watchdog_userspace_ping_seconds'] == 330 and package['return_timer_seconds'] == 300
    assert package['usb_identity']['serial'] == 'TP510-RAM-V11'
    assert 'ramdiag-v11' in (Path(build['output']) / 'include/generated/utsrelease.h').read_text()
    init = (ROOT / 'kernel-upgrade/diagnostic-probe-v11/init.c').read_text()
    header = (ROOT / 'kernel-upgrade/diagnostic-probe-v11/probes.h').read_text()
    for text in ['#define PROBE_LABEL "TP510-RAM-V11"', '#define PROBE_RETURN_SECONDS 300',
                 '#define PROBE_WATCHDOG_SECONDS (PROBE_RETURN_SECONDS + 30)', '#define PROBE_HASH_DEADLINE_SECONDS 250',
                 '#define PROBE_HASH_BUDGET_SECONDS 260', '#define PROBE_ECHO_SECONDS 60',
                 'tpufs_block_identity(&info, expected)', 'if (tp8_udc_name(entry->d_name))']:
        assert text in init, text
    # ---- v11 read-only rule: the only writable open is the userdata node ----
    opens = re.findall(r'open\([^;]*?,\s*(O_[A-Z_0-9 |]+)\)', init)
    assert [o for o in opens if 'O_RDWR' in o] == ['O_RDWR | O_DIRECT | O_CLOEXEC | O_NOFOLLOW'], 'only userdata is opened writable'
    assert [o for o in opens if 'O_WRONLY' in o] == ['O_WRONLY | O_CLOEXEC | O_NOFOLLOW'], 'only the watchdog is O_WRONLY'
    assert init.count('O_RDWR') == 1
    assert 'open(node, O_RDWR | O_DIRECT | O_CLOEXEC | O_NOFOLLOW)' in init
    assert 'open("/dev/mapper/control", O_RDONLY | O_CLOEXEC | O_NOFOLLOW)' in init
    # The super mount is ext4, read-only, no journal recovery, read-only dm devices.
    assert 'mount(node, mountpoint, "ext4", MS_RDONLY | MS_NODEV | MS_NOSUID | MS_NOEXEC, "noload")' in init
    assert init.count('DM_READONLY_FLAG') == 1 and 'load->flags = DM_READONLY_FLAG' in header and 'DM_SUSPEND_FLAG' not in init
    assert 'BLKDISCARD' not in init and 'BLKDISCARD' not in header and 'mkfs' not in init
    # ---- touchpad reset test: GPIO 9 only, stock's 200/20/200 ms sequence, rails read-only ----
    for text in ['#define TP11_PAD_RESET_GPIO 9', '#define TP11_PAD_HIGH_US 200000u', '#define TP11_PAD_LOW_US 20000u',
                 '#define TP11_PAD_RETRY_GAP_US 5000u']:
        assert text in header, text
    assert 'gpio_request_output_high(TP11_PAD_RESET_GPIO' in init and init.count('pad_reset_test(pad[0]') == 1
    assert 'tp11_pad_needs_reset(pad_error[0], pad_error[1])' in init
    assert 'static const char *const rails[] = {"vio18", "vio28", "vibr"};' in init
    # No regulator or PMIC writes, as v9.
    probe_code = init + header
    for banned in ['regulator_enable', 'pmic_write', 'I2C_SLAVE', 'I2C_SMBUS', 'GPIO_V2_LINE_SET_CONFIG']:
        assert banned not in probe_code, banned
    # ---- v11 write budget: last 1 MiB of userdata, 2 MiB + 4 KiB budget ----
    assert '#define TP10_USERDATA_REGION (1ull << 20)' in init
    assert '#define TP10_USERDATA_MIN_BYTES (64ull << 20)' in init
    assert '#define TP10_WRITE_BUDGET ((2ull << 20) + TP10_BLOCK)' in init and '#define TP10_BLOCK 4096u' in init
    assert '#define TP10_WR_BLOCK 4096u' in header
    assert 'r.budget = 2ull * region + TP10_WR_BLOCK;' in header, 'write budget is 2*region + one block'
    assert '(size_t)TP10_USERDATA_REGION, region_offset / 512' in init, 'the write test gets the last-1 MiB region'
    assert 'size_bytes - TP10_USERDATA_REGION' in init, 'region is the last 1 MiB of userdata'
    assert 'if (size_bytes < TP10_USERDATA_MIN_BYTES)' in init, 'userdata must be at least 64 MiB'
    assert 'tp10_partition_node(disk, part, lbs, controller, "userdata"' in init, 'the writable node is PARTNAME userdata'
    # ---- never written: super hashed last (proves the mount wrote nothing), pre-list excludes super ----
    assert '{"lk", "dtbo", "vbmeta", "boot", "recovery"}' in init and '"super"' not in init.split('static const char *const hash_targets', 1)[1].split('}', 1)[0]
    order = [init.index(s) for s in ['tp8_hash_range(fd, part->name', 'userdata_write_test(disk',
                                     'super_mount_test(disk', 'tp8_hash_range(fd, "super"']]
    assert order == sorted(order), 'super must be hashed last, after the write and mount tests'
    assert SUPER_BACKUP_SHA  # recorded for the on-device compare; the init hashes super, the host compares
    limits = ' '.join(package['limits'])
    assert 'last 1 MiB of userdata' in limits and 'restored on exit' in limits
    assert 'read-only dm-linear mounts of super system/vendor/product' in limits
    # The LP parser requires exactly the stock layout.
    assert 'tp10_lp_stock_names[TP10_LP_STOCK_PARTITIONS] = {"system", "vendor", "product"}' in header
    assert '#define TP10_LP_TARGET_TYPE_LINEAR 0u' in header and 'non_linear_extent' in header
    # ---- probe helper, UFS and ownership-ledger provenance ----
    probes = read(EVIDENCE / 'diagnostic-probes-check-v11.json')
    assert probes['checks'] == 90 and not probes['device_accessed']
    assert digest(ROOT / 'kernel-upgrade/diagnostic-probe-v11/probes.h') == probes['header_sha256']
    assert digest(ROOT / 'kernel-upgrade/diagnostic-probe-v11/init.c') == probes['init_sha256']
    assert digest(ROOT / 'tools/pocket-partition-hashes.py') == probes['tool_sha256']
    assert digest(ROOT / 'tools/check-pocket-diagnostic-v11-probes.py') == probes['validator_sha256']
    ufs = read(EVIDENCE / 'ufs-readonly-check.json')
    assert ufs['host_asan_ubsan_passed'] and ufs['actual_functions_tested']
    assert digest(ROOT / 'kernel-upgrade/ram-probe/ufs-readonly.h') == ufs['header_sha256']
    ownership = read(EVIDENCE / 'security-contract-20261030/tee1-inspection/shm-ownership-ledger.json')
    for path, expected in ownership['source_sha256'].items():
        assert digest(ROOT / path) == expected
    assert digest(ROOT / ownership['stock_log']['path']) == ownership['stock_log']['sha256']
    evidence = [PACKAGE / 'candidate-validation.json', PACKAGE / 'host-avb-check.json']
    evidence += [EVIDENCE / n for n in [
        'diagnostic-kernel-build-v11.json', 'diagnostic-ramdisk-v11.json', 'diagnostic-board-v11.json',
        'patch-validation.json', 'diagnostic-capture-check.json', 'diagnostic-lk-fixup-check-v11.json',
        'lk-bootargs-check-v11.json', 'ufs-readonly-check.json', 'tkcore-shm-guard-check-v11.json',
        'security-contract-20261030/tee1-inspection/shm-ownership-ledger.json', 'diagnostic-probes-check-v11.json']]
    preflight = None
    preflight_path = PACKAGE / 'host-preflight.json'
    if preflight_path.exists():
        preflight = read(preflight_path)
        assert preflight['host_preflight_passed'] and preflight['variant'] == 'v11'
        assert preflight['stock_hashes']['recovery'] == package['restore_image']['sha256']
        assert preflight['staged'][0]['sha256'] == package['candidate']['sha256']
        for name in ['capture-pocket-diagnostic.py', 'capture-recovery-probe.py', 'collect-pocket-diagnostic-return.py', 'pocket-partition-hashes.py']:
            assert any(Path(e['path']).name == name and e['sha256'] == digest(ROOT / 'tools' / name) for e in preflight['staged'])
        evidence.append(preflight_path)
    record = {
        'utc': datetime.now(timezone.utc).isoformat(), 'offline_preparation_complete': True,
        'candidate': package['candidate'], 'stock_restore': package['restore_image'],
        'expected_kernel_release': (Path(build['output']) / 'include/generated/utsrelease.h').read_text().split('"')[1],
        'usb_identity': package['usb_identity'], 'host_staged': preflight is not None,
        'host_preflight_utc': preflight['utc'] if preflight else None,
        'writable_partition': WRITABLE_PARTITION, 'never_written': NEVER_WRITTEN,
        'super_backup_sha256': SUPER_BACKUP_SHA, 'write_budget_bytes': (2 << 20) + 4096,
        'kernel_execution_attempted': False, 'ready_for_unattended_flash': False,
        'evidence_sha256': {str(p): digest(p) for p in evidence},
        'validator_sha256': digest(Path(__file__)),
        'remaining': ['Fresh host/stock/root/hash/BCB/battery preflight and exact-restore staging',
                      'Owner present for recovery-only write and finite Volume Up sequence',
                      'Actual UFS write/FLUSH/FUA, dm-linear mount and the super re-hash on the phone; a super hash other than the backup blocks the first boot',
                      'If the console shows "userdata restore FAILED" or no restore line, wipe data in stock recovery before boot'],
        'limits': ['Static REA establishes the stock contract, not replacement-driver execution',
                   'Kernel configures UFS and negotiates secure SHM/RoT; the whole boot is not read-only',
                   'The only writable open is the userdata node; writes are confined to its last 1 MiB and restored on exit; budget 2 MiB + 4 KiB',
                   'The dm-linear super mount is read-only (ext4 MS_RDONLY, noload); the super re-hash proves it wrote nothing, but only a trial confirms that',
                   'The write test runs against a sparse file on the host; FUA/FLUSH, O_DIRECT and real restore are only seen on the phone',
                   'The TrustKernel keymaster TEE probe is out of this base v11 and left to a later stage',
                   'Not a LineageOS ROM or an installation/hardware-parity qualification']}
    (PACKAGE / 'readiness.json').write_text(json.dumps(record, indent=2) + '\n')
    print('Combined v11 local provenance, config delta, write budget and never-written list pass; fresh host preflight and attended boot remain')


if __name__ == '__main__':
    main()
