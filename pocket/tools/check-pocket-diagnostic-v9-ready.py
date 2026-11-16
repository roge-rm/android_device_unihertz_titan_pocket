#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Verify the combined v9 diagnostic's local provenance; never access a phone."""
import hashlib
import json
import re
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
EVIDENCE = ROOT / 'evidence/kernel-upgrade'
PACKAGE = EVIDENCE / 'diagnostic-package-v9'


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
    build = read(EVIDENCE / 'diagnostic-kernel-build-v9.json')
    assert build['returncode'] == 0 and build['engineering_config_unchanged']
    assert digest(ROOT / 'tools/build-pocket-diagnostic-kernel.py') == build['builder_sha256']
    assert digest(ROOT / 'configs/kernel-diagnostic-5.10-v9.fragment') == build['fragment_sha256']
    assert digest(Path(build['output']) / '.config') == build['config_sha256']
    for path, expected in build['source_hashes'].items():
        assert digest(Path(build['source']) / path) == expected, path
    for path, entry in build['artifacts'].items():
        assert digest(path) == entry['sha256'], path
    ram = read(EVIDENCE / 'diagnostic-ramdisk-v9.json')
    for entry in ram['source_inputs'] + ram['files']:
        assert digest(ROOT / entry['path']) == entry['sha256'], entry['path']
    assert {x['path'] for x in ram['source_inputs']} >= {
        'kernel-upgrade/diagnostic-probe-v9/init.c', 'kernel-upgrade/ram-probe/init.c',
        'kernel-upgrade/ram-probe/ufs-readonly.h', 'kernel-upgrade/tkcore-probe/feature_query.h',
        'kernel-upgrade/diagnostic-probe-v9/probes.h', 'kernel-upgrade/ram-probe/commands.h'}
    board = read(EVIDENCE / 'diagnostic-board-v9.json')
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
    assert capture['cases'] == 63 and capture['echo_cases'] == 12 and not capture['commands_sent']
    for path, expected in capture['source_hashes'].items():
        assert digest(ROOT / path) == expected
    fixup = read(EVIDENCE / 'diagnostic-lk-fixup-check-v9.json')
    assert len(fixup['cases']) == 2 and all(c['insertion_count'] == 19 and c['all_expected_results'] for c in fixup['cases'])
    for case in fixup['cases']:
        assert digest(case['input']) == case['sha256']
    args = read(EVIDENCE / 'lk-bootargs-check-v9.json')
    assert len(args['cases']) == 10
    for path, expected in args['input_hashes'].items():
        assert digest(path) == expected
    guard = read(EVIDENCE / 'tkcore-shm-guard-check-v9.json')
    assert guard['actual_guard_tested'] and guard['scenarios'] == 26
    driver = Path(build['source']) / 'drivers/misc/mediatek/tkcore/armtz/tee_tz_drv.c'
    assert 'of_reserved_mem_lookup(owner)' in driver.read_text()
    assert digest(driver) == guard['driver_sha256']
    assert 'devm_ioremap(dev, res->start' in (Path(build['source']) / 'drivers/usb/mtu3/mtu3_plat.c').read_text()
    mtu3 = Path(build['source']) / 'drivers/usb/mtu3'
    plat = (mtu3 / 'mtu3_plat.c').read_text()
    core = (mtu3 / 'mtu3_core.c').read_text()
    assert 'ssusb->force_vbus = of_device_is_compatible(node, "mediatek,mt6771-mtu3")' in plat
    assert 'mt6771 = of_device_is_compatible' in plat and 'if (!mt6771)' in plat
    assert '!mtu->ssusb->otg_switch.is_u3_drd' in core and 'mtu->max_speed = USB_SPEED_HIGH' in core
    assert 'VBUS_FRC_EN | VBUS_ON' in core
    config = (Path(build['output']) / '.config').read_text().splitlines()
    assert 'CONFIG_WATCHDOG_OPEN_TIMEOUT=90' in config and 'CONFIG_OF_RESERVED_MEM=y' in config
    assert package['watchdog_userspace_ping_seconds'] == 330 and package['return_timer_seconds'] == 300
    assert package['usb_identity']['serial'] == 'TP510-RAM-V9'
    assert 'ramdiag-v9' in (Path(build['output']) / 'include/generated/utsrelease.h').read_text()
    init = (ROOT / 'kernel-upgrade/diagnostic-probe-v9/init.c').read_text()
    for text in ['#define PROBE_LABEL "TP510-RAM-V9"', '#define PROBE_RETURN_SECONDS 300',
                 '#define PROBE_WATCHDOG_SECONDS (PROBE_RETURN_SECONDS + 30)', '#define PROBE_HASH_DEADLINE_SECONDS 250',
                 '#define PROBE_HASH_BUDGET_SECONDS 260', '#define PROBE_ECHO_SECONDS 60',
                 'O_RDONLY | O_CLOEXEC | O_NOFOLLOW', 'tpufs_block_identity(&info, expected)',
                 'if (tp8_udc_name(entry->d_name))']:
        assert text in init, text
    # Partition and tree reads only: no write paths in the new probe code.
    probe_code = init + (ROOT / 'kernel-upgrade/diagnostic-probe-v9/probes.h').read_text()
    probe_code = probe_code.replace('open("/dev/watchdog0", O_WRONLY | O_CLOEXEC | O_NOFOLLOW)', '', 1)
    for banned in ['pwrite', 'O_RDWR', 'O_WRONLY', 'BLKDISCARD', 'mount(', 'ioctl(fd, BLK']:
        assert banned not in probe_code, banned
    for entry in ['CONFIG_I2C=y', 'CONFIG_I2C_CHARDEV=y', 'CONFIG_I2C_MT65XX=y', 'CONFIG_GPIO_CDEV=y']:
        assert entry in config, entry
    i2c = (Path(build['source']) / 'drivers/i2c/busses/i2c-mt65xx.c').read_text()
    assert '{ .compatible = "mediatek,mt6771-i2c", .data = &mt6771_compat }' in i2c and '.dt_clk_div = 1,' in i2c
    buses = board['i2c_buses']
    assert sorted(buses) == ['/i2c@11005000', '/i2c@11007000', '/i2c@11008000', '/i2c@1100f000']
    assert sorted(b['stock_bus_id'] for b in buses.values()) == [0, 3, 4, 6]
    i2c4 = buses['/i2c@11008000']
    assert i2c4['ch_offset'] == 0x100 and len(i2c4['clocks']) == 6, 'i2c4 needs the channel offset and main, dma, arb clocks'
    dts = (Path(board['output']).parent / 'storage.dts').read_text() if (Path(board['output']).parent / 'storage.dts').exists() else None
    if dts is not None:
        node = dts.split('i2c@11008000 {', 1)[1].split('aw9523@58 {', 1)[0]
        assert 'status = [6f 6b 61 79 00];' in node and 'mediatek,ch-offset = [00 00 01 00];' in node
        assert 'clock-names = [6d 61 69 6e 00 64 6d 61 00 61 72 62 00];' in node
    # Clock fix: top_muxes must stay after init (the v8 oops read freed __initconst data).
    clk = (Path(build['source']) / 'drivers/clk/mediatek/clk-mt6771.c').read_text()
    assert re.search(r'^static const struct mtk_mux top_muxes\[\] = \{', clk, re.M), 'top_muxes must not be __initconst'
    assert '__initconst' not in clk.split('top_muxes[]', 1)[0].rsplit('\n', 1)[-1]
    i2c_source = (Path(build['source']) / 'drivers/i2c/busses/i2c-mt65xx.c').read_text()
    assert '"mediatek,ch-offset"' in i2c_source
    # I2C: only I2C_RDWR with a register-pointer write and a read.
    assert probe_code.count('ioctl(r->fd, I2C_RDWR, &transfer)') == 1 and '.nmsgs = 2' in probe_code
    assert '{.addr = t->address, .flags = 0, .len = (uint16_t)t->reg_length, .buf = pointer}' in probe_code
    assert '{.addr = t->address, .flags = I2C_M_RD, .len = (uint16_t)t->read_length, .buf = r->data}' in probe_code
    for banned in ['I2C_SLAVE', 'I2C_SMBUS', 'GPIO_GET_LINEHANDLE', 'GPIOHANDLE', '/state", O_', 'regulator_enable', 'GPIO_V2_LINE_SET_CONFIG']:
        assert banned not in probe_code, banned
    # GPIO line requests: only the passive level read and the aw9523 reset pulse.
    assert init.count('GPIO_V2_GET_LINE_IOCTL') == 2 and init.count('GPIO_V2_LINE_FLAG_OUTPUT') == 2
    level = init.split('static void reset_line_state', 1)[1].split('// Reset pulse callbacks', 1)[0]
    assert level.count('GPIO_V2_GET_LINE_IOCTL') == 1 and 'request.config.flags' not in level
    pulse = init.split('static int reset_request_high', 1)[1].split('static int reset_set', 1)[0]
    assert pulse.count('GPIO_V2_GET_LINE_IOCTL') == 1 and 'request.config.flags = GPIO_V2_LINE_FLAG_OUTPUT;' in pulse
    assert 'request.offsets[0] = TP9_AW9523_RESET_GPIO;' in pulse and '#define TP9_AW9523_RESET_GPIO 178' in probe_code
    assert 'GPIO_V2_LINE_SET_VALUES_IOCTL' in init and init.count('GPIO_V2_LINE_SET_VALUES_IOCTL') == 1
    # No regulator or PMIC writes: regulators are only read through sysfs name and state.
    for banned in ['/sys/class/regulator/%s/state", O_W', 'REGULATOR_', 'pmic_write']:
        assert banned not in probe_code, banned
    assert 'bounded_child("i2c-id", PROBE_I2C_BUDGET_SECONDS, i2c_ids)' in init
    probes = read(EVIDENCE / 'diagnostic-probes-check-v9.json')
    assert probes['checks'] == 62 and not probes['device_accessed']
    assert digest(ROOT / 'kernel-upgrade/diagnostic-probe-v9/probes.h') == probes['header_sha256']
    assert digest(ROOT / 'tools/pocket-partition-hashes.py') == probes['tool_sha256']
    assert digest(ROOT / 'tools/check-pocket-diagnostic-v9-probes.py') == probes['validator_sha256']
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
        'diagnostic-kernel-build-v9.json', 'diagnostic-ramdisk-v9.json', 'diagnostic-board-v9.json',
        'patch-validation.json', 'diagnostic-capture-check.json', 'diagnostic-lk-fixup-check-v9.json',
        'lk-bootargs-check-v9.json', 'ufs-readonly-check.json', 'tkcore-shm-guard-check-v9.json',
        'security-contract-20261030/tee1-inspection/shm-ownership-ledger.json', 'diagnostic-probes-check-v9.json']]
    preflight = None
    preflight_path = PACKAGE / 'host-preflight.json'
    if preflight_path.exists():
        preflight = read(preflight_path)
        assert preflight['host_preflight_passed'] and preflight['variant'] == 'v9'
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
        'kernel_execution_attempted': False, 'ready_for_unattended_flash': False,
        'evidence_sha256': {str(p): digest(p) for p in evidence},
        'validator_sha256': digest(Path(__file__)),
        'remaining': ['Fresh host/stock/root/hash/BCB/battery preflight and exact-restore staging',
                      'Owner present for recovery-only write and finite Volume Up sequence',
                      'Actual replacement-driver initialization, fresh USB/pstore logs and stock restoration verification'],
        'limits': ['Static REA establishes the stock contract, not replacement-driver execution',
                   'Kernel configures UFS and negotiates secure SHM/RoT; the whole boot is not read-only',
                   'Userspace reads bounded block headers, whole stock partitions read-only and local feature flags; no filesystem or TA session',
                   'The aw9523 reset pulse on GPIO 178 is a GPIO write, used only after a NACK; the passive level read requests GPIO 178 and 0 and sets their pin mode to 0',
                   'i2c4 is a multi-channel bus shared with the camera CCU; the channel driver is inferred from the vendor source and unrun',
                   'Watchdog/init restart fallbacks remain unqualified; physical assistance may be required',
                   'Not a LineageOS ROM or an installation/hardware-parity qualification']}
    (PACKAGE / 'readiness.json').write_text(json.dumps(record, indent=2) + '\n')
    print('Combined v9 local provenance and offline checks pass; fresh host preflight and attended boot remain')


if __name__ == '__main__':
    main()
