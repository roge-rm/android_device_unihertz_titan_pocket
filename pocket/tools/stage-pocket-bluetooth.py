#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Prepare and replay-check the Bluetooth gd controller patch, without editing baseline.

The MT6771 connsys controller sets the READ_DEFAULT_ERRONEOUS_DATA_REPORTING bit in its
supported commands but answers the command with a Command Status UNKNOWN_HCI_COMMAND.
The A16 gd HCI layer aborts on a status event for a command that expects a complete event,
so com.android.bluetooth crashed on every start (WIFI_PORT.md, trial A). The patch skips
the read when bluetooth.hci.skip_erroneous_data_reporting is true (product.prop).

The controller also answers Sniff Subrating (0x0811) with a Command Status where the stack
waits for a Command Complete, which aborts the same way once an A2DP speaker connects.
SupportsSniffSubrating() returns false when bluetooth.hci.disable_sniff_subrating is true,
and every caller in the stack gates on it, so the command is never sent.

The audio HAL interface also opens IBluetoothAudioProviderFactory/sysbta in place of
/default when persist.bluetooth.system_audio_hal.enabled is true (product.prop), our
system-side Bluetooth audio HAL in device/unihertz/titan_pocket/bluetooth-audio
(AUDIO_PORT.md). Same change as TrebleDroid's "audio_hal_interface: Optionally use
sysbta HAL".
"""
import pocket_paths
import difflib
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parent.parent
BASE = pocket_paths.platform_source() / 'packages/modules/Bluetooth'
PATCH = ROOT / 'patches/android/0006-bluetooth-skip-erroneous-data-reporting.patch'
OUTPUT = ROOT / 'artifacts/build-overrides/Bluetooth'
CONTROLLER = 'system/gd/hci/controller_impl.cc'
AUDIO = 'system/audio_hal_interface/'
SYSBTA_PROP = 'persist.bluetooth.system_audio_hal.enabled'
DEFAULT_USE = 'kDefaultAudioProviderFactoryInterface.c_str()'
SYSBTA_USE = 'audioProviderFactoryInterface().c_str()'


def edit(text, old, new):
    assert text.count(old) == 1, old[:70]
    return text.replace(old, new, 1)


def sysbta():
    """Point the AIDL provider factory lookups at /sysbta when the property is set."""
    files = {}
    member = ('          std::string() + IBluetoothAudioProviderFactory::descriptor + "/default";\n'
              '  // System-side Bluetooth audio HAL, see persist.bluetooth.system_audio_hal.enabled.\n'
              '  static inline const std::string kSystemAudioProviderFactoryInterface =\n'
              '          std::string() + IBluetoothAudioProviderFactory::descriptor + "/sysbta";\n'
              '  static inline const std::string audioProviderFactoryInterface() {\n'
              '    return osi_property_get_bool("' + SYSBTA_PROP + '", false)\n'
              '                   ? kSystemAudioProviderFactoryInterface\n'
              '                   : kDefaultAudioProviderFactoryInterface;\n'
              '  }\n')
    for header in ['aidl/client_interface_aidl.h', 'aidl/a2dp/client_interface_aidl.h']:
        old = (BASE / AUDIO / header).read_text()
        new = edit(old, '#include "transport_instance.h"\n',
                   '#include "osi/include/properties.h"\n#include "transport_instance.h"\n')
        new = edit(new, '          std::string() + IBluetoothAudioProviderFactory::descriptor + "/default";\n', member)
        files[AUDIO + header] = (old, new)
    for source, count in [('aidl/client_interface_aidl.cc', 4), ('aidl/a2dp/client_interface_aidl.cc', 4)]:
        old = (BASE / AUDIO / source).read_text()
        assert old.count(DEFAULT_USE) == count, source
        files[AUDIO + source] = (old, old.replace(DEFAULT_USE, SYSBTA_USE))
    name = AUDIO + 'hal_version_manager.cc'
    old = (BASE / name).read_text()
    new = edit(old, '#include <hidl/ServiceManagement.h>\n',
               '#include <hidl/ServiceManagement.h>\n\n#include "osi/include/properties.h"\n')
    new = edit(new, '        std::string() + IBluetoothAudioProviderFactory::descriptor + "/default";\n',
               '        std::string() + IBluetoothAudioProviderFactory::descriptor + "/default";\n'
               '// System-side Bluetooth audio HAL, see persist.bluetooth.system_audio_hal.enabled.\n'
               'static const std::string kSystemAudioProviderFactoryInterface =\n'
               '        std::string() + IBluetoothAudioProviderFactory::descriptor + "/sysbta";\n'
               'static const std::string audioProviderFactoryInterface() {\n'
               '  return osi_property_get_bool("' + SYSBTA_PROP + '", false)\n'
               '                 ? kSystemAudioProviderFactoryInterface\n'
               '                 : kDefaultAudioProviderFactoryInterface;\n'
               '}\n')
    assert new.count(DEFAULT_USE) == 2
    files[name] = (old, new.replace(DEFAULT_USE, SYSBTA_USE))
    return files


def main():
    old = (BASE / CONTROLLER).read_text()
    new = edit(old, 'static const std::string kPropertyRpaOffload = "bluetooth.core.le.rpa_offload";\n',
               'static const std::string kPropertyRpaOffload = "bluetooth.core.le.rpa_offload";\n'
               '// Controllers that list READ_DEFAULT_ERRONEOUS_DATA_REPORTING but answer it with a\n'
               '// command status (MT6771 connsys) abort the HCI layer, so it can be skipped.\n'
               'static const std::string kPropertySkipErroneousDataReporting =\n'
               '        "bluetooth.hci.skip_erroneous_data_reporting";\n')
    new = edit(new, '    if (is_supported(OpCode::READ_DEFAULT_ERRONEOUS_DATA_REPORTING)) {\n',
               '    if (is_supported(OpCode::READ_DEFAULT_ERRONEOUS_DATA_REPORTING) &&\n'
               '        !os::GetSystemPropertyBool(kPropertySkipErroneousDataReporting, false)) {\n')
    new = edit(new, '        "bluetooth.hci.skip_erroneous_data_reporting";\n',
               '        "bluetooth.hci.skip_erroneous_data_reporting";\n'
               '// Controllers that answer SNIFF_SUBRATING with a command status (MT6771 connsys) abort the\n'
               '// HCI layer, so the feature can be reported as unsupported.\n'
               'static const std::string kPropertyDisableSniffSubrating =\n'
               '        "bluetooth.hci.disable_sniff_subrating";\n')
    new = edit(new, 'LOCAL_FEATURE_ACCESSOR(SupportsSniffSubrating, 0, 41)\n',
               'bool ControllerImpl::SupportsSniffSubrating() const {\n'
               '  return (GetLocalFeatures(0) & BIT(41)) &&\n'
               '         !os::GetSystemPropertyBool(kPropertyDisableSniffSubrating, false);\n'
               '}\n')
    files = {CONTROLLER: (old, new)}
    files.update(sysbta())
    diff, hashes = [], {}
    for name, (a, b) in files.items():
        p = OUTPUT / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(b)
        full = 'packages/modules/Bluetooth/' + name
        diff += difflib.unified_diff(a.splitlines(True), b.splitlines(True), fromfile='a/' + full, tofile='b/' + full)
        hashes[name] = {'original': hashlib.sha256(a.encode()).hexdigest(), 'modified': hashlib.sha256(b.encode()).hexdigest()}
    for p in OUTPUT.rglob('*'):
        if p.is_file() and str(p.relative_to(OUTPUT)) not in files:
            p.unlink()
    PATCH.write_text(''.join(diff))
    with tempfile.TemporaryDirectory(prefix='bluetooth-patch-') as tmp:
        tree = Path(tmp)
        for name, (a, b) in files.items():
            p = tree / 'packages/modules/Bluetooth' / name
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(a)
        subprocess.run(['patch', '--batch', '--fuzz=0', '-p1', '-d', tmp, '-i', str(PATCH)], check=True, capture_output=True)
        for name, (a, b) in files.items():
            assert (tree / 'packages/modules/Bluetooth' / name).read_text() == b
    out = ROOT / 'evidence/connectivity/bluetooth-patch.json'
    out.write_text(json.dumps({'files': hashes, 'patch': str(PATCH.relative_to(ROOT)), 'replay_exact': True,
                               'shared_source_modified': False, 'runtime_tested': False}, indent=2) + '\n')
    print('Bluetooth gd and sysbta patch replays exactly; shared source unchanged')


if __name__ == '__main__':
    main()
