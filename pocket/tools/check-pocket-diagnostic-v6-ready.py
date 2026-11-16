#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Verify the combined v6 diagnostic's local provenance; never access a phone."""
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
EVIDENCE = ROOT / 'evidence/kernel-upgrade'
PACKAGE = EVIDENCE / 'diagnostic-package-v6'


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
    build = read(EVIDENCE / 'diagnostic-kernel-build-v6.json')
    assert build['returncode'] == 0 and build['engineering_config_unchanged']
    assert digest(ROOT / 'tools/build-pocket-diagnostic-kernel.py') == build['builder_sha256']
    assert digest(ROOT / 'configs/kernel-diagnostic-5.10-v6.fragment') == build['fragment_sha256']
    assert digest(Path(build['output']) / '.config') == build['config_sha256']
    for path, expected in build['source_hashes'].items():
        assert digest(Path(build['source']) / path) == expected, path
    for path, entry in build['artifacts'].items():
        assert digest(path) == entry['sha256'], path
    ram = read(EVIDENCE / 'diagnostic-ramdisk-v6.json')
    for entry in ram['source_inputs'] + ram['files']:
        assert digest(ROOT / entry['path']) == entry['sha256'], entry['path']
    assert {x['path'] for x in ram['source_inputs']} >= {
        'kernel-upgrade/diagnostic-probe-v6/init.c', 'kernel-upgrade/ram-probe/init.c',
        'kernel-upgrade/ram-probe/ufs-readonly.h', 'kernel-upgrade/tkcore-probe/feature_query.h'}
    board = read(EVIDENCE / 'diagnostic-board-v6.json')
    assert digest(board['board_dtb']['path']) == board['board_dtb']['sha256']
    for path, expected in board['generator_inputs'].items():
        assert digest(ROOT / path) == expected, path
    assert board['nodes'] == 955 and not board['phone_accessed']
    patches = read(EVIDENCE / 'patch-validation.json')
    assert len(patches) == 12
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
    assert capture['cases'] == 42 and not capture['commands_sent']
    for path, expected in capture['source_hashes'].items():
        assert digest(ROOT / path) == expected
    fixup = read(EVIDENCE / 'diagnostic-lk-fixup-check-v6.json')
    assert len(fixup['cases']) == 2 and all(c['insertion_count'] == 19 and c['all_expected_results'] for c in fixup['cases'])
    for case in fixup['cases']:
        assert digest(case['input']) == case['sha256']
    args = read(EVIDENCE / 'lk-bootargs-check-v6.json')
    assert len(args['cases']) == 10
    for path, expected in args['input_hashes'].items():
        assert digest(path) == expected
    guard = read(EVIDENCE / 'tkcore-shm-guard-check-v6.json')
    assert guard['actual_guard_tested'] and guard['scenarios'] == 26
    driver = Path(build['source']) / 'drivers/misc/mediatek/tkcore/armtz/tee_tz_drv.c'
    assert 'of_reserved_mem_lookup(owner)' in driver.read_text()
    assert digest(driver) == guard['driver_sha256']
    assert 'devm_ioremap(dev, res->start' in (Path(build['source']) / 'drivers/usb/mtu3/mtu3_plat.c').read_text()
    config = (Path(build['output']) / '.config').read_text().splitlines()
    assert 'CONFIG_WATCHDOG_OPEN_TIMEOUT=90' in config and 'CONFIG_OF_RESERVED_MEM=y' in config
    assert package['watchdog_userspace_ping_seconds'] == 180 and package['return_timer_seconds'] == 150
    assert package['usb_identity']['serial'] == 'TP510-RAM-V6'
    ufs = read(EVIDENCE / 'ufs-readonly-check.json')
    assert ufs['host_asan_ubsan_passed'] and ufs['actual_functions_tested']
    assert digest(ROOT / 'kernel-upgrade/ram-probe/ufs-readonly.h') == ufs['header_sha256']
    assert digest(ROOT / 'tools/check-pocket-ufs-readonly.py') == ufs['tool_sha256']
    ownership = read(EVIDENCE / 'security-contract-20261030/tee1-inspection/shm-ownership-ledger.json')
    for path, expected in ownership['source_sha256'].items():
        assert digest(ROOT / path) == expected
    assert digest(ROOT / ownership['stock_log']['path']) == ownership['stock_log']['sha256']
    evidence = [PACKAGE / 'candidate-validation.json', PACKAGE / 'host-avb-check.json']
    evidence += [EVIDENCE / n for n in [
        'diagnostic-kernel-build-v6.json', 'diagnostic-ramdisk-v6.json', 'diagnostic-board-v6.json',
        'patch-validation.json', 'diagnostic-capture-check.json', 'diagnostic-lk-fixup-check-v6.json',
        'lk-bootargs-check-v6.json', 'ufs-readonly-check.json', 'tkcore-shm-guard-check-v6.json',
        'security-contract-20261030/tee1-inspection/shm-ownership-ledger.json']]
    preflight = None
    preflight_path = PACKAGE / 'host-preflight.json'
    if preflight_path.exists():
        preflight = read(preflight_path)
        assert preflight['host_preflight_passed'] and preflight['variant'] == 'v6'
        assert preflight['stock_hashes']['recovery'] == package['restore_image']['sha256']
        assert preflight['staged'][0]['sha256'] == package['candidate']['sha256']
        for name in ['capture-pocket-diagnostic.py', 'capture-recovery-probe.py', 'collect-pocket-diagnostic-return.py']:
            assert any(Path(e['path']).name == name and e['sha256'] == digest(ROOT / 'tools' / name) for e in preflight['staged'])
        evidence.append(preflight_path)
    record = {
        'utc': datetime.now(timezone.utc).isoformat(), 'offline_preparation_complete': True,
        'candidate': package['candidate'], 'stock_restore': package['restore_image'],
        'expected_kernel_release': (Path(build['output']) / 'include/generated/utsrelease.h').read_text().split('"')[1],
        'usb_identity': package['usb_identity'], 'host_staged': preflight is not None,
        'host_preflight_utc': preflight['utc'] if preflight else None,
        'kernel_execution_attempted': False, 'ready_for_unattended_flash': False,
        'evidence_sha256': {str(p): digest(p) for p in evidence},
        'validator_sha256': digest(Path(__file__)),
        'remaining': ['Fresh host/stock/root/hash/BCB/battery preflight and exact-restore staging',
                      'Owner present for recovery-only write and finite Volume Up sequence',
                      'Actual replacement-driver initialization, fresh USB/pstore logs and stock restoration verification'],
        'limits': ['Static REA establishes the stock contract, not replacement-driver execution',
                   'Kernel configures UFS and negotiates secure SHM/RoT; the whole boot is not read-only',
                   'Userspace reads bounded block headers and local feature flags; no filesystem or TA session',
                   'Watchdog/init restart fallbacks remain unqualified; physical assistance may be required',
                   'Not a LineageOS ROM or an installation/hardware-parity qualification']}
    (PACKAGE / 'readiness.json').write_text(json.dumps(record, indent=2) + '\n')
    print('Combined v6 local provenance and offline checks pass; fresh host preflight and attended boot remain')


if __name__ == '__main__':
    main()
