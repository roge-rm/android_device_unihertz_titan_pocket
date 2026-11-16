#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Prepare and replay-check the audio policy sysbta patch, without editing baseline.

With persist.bluetooth.system_audio_hal.enabled true (product.prop), the policy parser
drops the vendor's Bluetooth modules (bluetooth, bluetooth_qti, a2dp, a2dpsink) and loads
the "sysbta" module from /system/etc/sysbta_audio_policy_configuration.xml in their place.
audioserver then opens it through IDevicesFactory/sysbta, our system-side Bluetooth audio
HAL (device/unihertz/titan_pocket/bluetooth-audio, AUDIO_PORT.md). Same idea as
TrebleDroid's "APM: Optionally force-load audio policy for system-side bt audio HAL", but
it keeps the vendor modules if the sysbta file doesn't parse.

The HAL's domain, hal_audio_sysbta, is a coredomain hal_audio server. system/sepolicy's
hal_audio.te gives every hal_audio domain vndbinder and plain /proc, which the full
Treble neverallows forbid for coredomain, so those two rules leave coredomain out.
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
SOURCE = pocket_paths.platform_source()
PATCH = ROOT / 'patches/android/0007-audiopolicy-sysbta-module.patch'
# Override directory under artifacts/build-overrides for each source project.
PROJECTS = {'frameworks/av': 'frameworks-av', 'system/sepolicy': 'system-sepolicy'}
SERIALIZER = 'frameworks/av/services/audiopolicy/common/managerdefinitions/src/Serializer.cpp'
HAL_AUDIO = 'system/sepolicy/private/hal_audio.te'

SWAP = '''    if (property_get_bool("persist.bluetooth.system_audio_hal.enabled", false)) {
        // System-side Bluetooth audio HAL: swap the vendor Bluetooth modules for "sysbta".
        static constexpr const char* kSysbtaFile = "/system/etc/sysbta_audio_policy_configuration.xml";
        auto sysbtaDoc = make_xmlUnique(xmlParseFile(kSysbtaFile));
        xmlNodePtr sysbtaRoot = sysbtaDoc ? xmlDocGetRootElement(sysbtaDoc.get()) : nullptr;
        std::variant<status_t, ModuleTraits::Element> sysbta = BAD_VALUE;
        if (sysbtaRoot != nullptr) sysbta = deserialize<ModuleTraits>(sysbtaRoot, config);
        if (std::holds_alternative<ModuleTraits::Element>(sysbta)) {
            for (size_t i = 0; i < modules.size();) {
                const char* name = modules[i]->getName();
                if (strcmp(name, "bluetooth") == 0 || strcmp(name, "bluetooth_qti") == 0 ||
                        strcmp(name, "a2dp") == 0 || strcmp(name, "a2dpsink") == 0) {
                    ALOGI("%s: replacing module %s with sysbta", __func__, name);
                    modules.removeAt(i);
                } else {
                    ++i;
                }
            }
            modules.add(std::get<ModuleTraits::Element>(sysbta));
        } else {
            ALOGE("%s: could not load %s, keeping the vendor Bluetooth modules", __func__,
                    kSysbtaFile);
        }
    }
'''


def edit(text, old, new):
    assert text.count(old) == 1, old[:70]
    return text.replace(old, new, 1)


def main():
    old = (SOURCE / SERIALIZER).read_text()
    new = edit(old, '#include <media/convert.h>\n', '#include <cutils/properties.h>\n#include <media/convert.h>\n')
    new = edit(new, '''    status_t status = deserializeCollection<ModuleTraits>(root, &modules, config);
    if (status != NO_ERROR) {
        return status;
    }
    config->setHwModules(modules);
''', '''    status_t status = deserializeCollection<ModuleTraits>(root, &modules, config);
    if (status != NO_ERROR) {
        return status;
    }
''' + SWAP + '''    config->setHwModules(modules);
''')
    files = {SERIALIZER: (old, new)}
    old = (SOURCE / HAL_AUDIO).read_text()
    new = edit(old, 'r_dir_file(hal_audio, proc)\n',
               '# Not for the system-side Bluetooth audio HAL: coredomain may not read plain /proc.\n'
               'r_dir_file({ hal_audio -coredomain }, proc)\n')
    new = edit(new, 'vndbinder_use(hal_audio)\n',
               '# Not for the system-side Bluetooth audio HAL: coredomain may not use vndbinder.\n'
               'vndbinder_use({ hal_audio -coredomain })\n')
    files[HAL_AUDIO] = (old, new)
    diff, hashes = [], {}
    for name, (a, b) in files.items():
        project = next(k for k in PROJECTS if name.startswith(k + '/'))
        p = ROOT / 'artifacts/build-overrides' / PROJECTS[project] / name[len(project) + 1:]
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(b)
        diff += difflib.unified_diff(a.splitlines(True), b.splitlines(True), fromfile='a/' + name, tofile='b/' + name)
        hashes[name] = {'original': hashlib.sha256(a.encode()).hexdigest(), 'modified': hashlib.sha256(b.encode()).hexdigest()}
    for project, directory in PROJECTS.items():
        for p in (ROOT / 'artifacts/build-overrides' / directory).rglob('*'):
            if p.is_file() and project + '/' + str(p.relative_to(ROOT / 'artifacts/build-overrides' / directory)) not in files:
                p.unlink()
    PATCH.write_text(''.join(diff))
    with tempfile.TemporaryDirectory(prefix='audiopolicy-patch-') as tmp:
        tree = Path(tmp)
        for name, (a, b) in files.items():
            p = tree / name
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(a)
        subprocess.run(['patch', '--batch', '--fuzz=0', '-p1', '-d', tmp, '-i', str(PATCH)], check=True, capture_output=True)
        for name, (a, b) in files.items():
            assert (tree / name).read_text() == b
    for project, directory in PROJECTS.items():
        record = {n[len(project) + 1:]: h for n, h in hashes.items() if n.startswith(project + '/')}
        out = ROOT / 'evidence/connectivity' / ('audiopolicy-patch.json' if project == 'frameworks/av' else 'audiopolicy-sepolicy-patch.json')
        out.write_text(json.dumps({'files': record, 'patch': str(PATCH.relative_to(ROOT)), 'replay_exact': True,
                                   'shared_source_modified': False, 'runtime_tested': False}, indent=2) + '\n')
    print('Audio policy sysbta patch replays exactly; shared source unchanged')


if __name__ == '__main__':
    main()
