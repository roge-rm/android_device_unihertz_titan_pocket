#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Prepare and replay-check the Pocket key hook patch for frameworks/base, without editing baseline.

PhoneWindowManager hands every key to PocketKeyHooks (packages/PocketInput/framework)
before the F13/F14 drop, PowerManagerService leaves the button light alone, and
services.core links PocketInputCore. All three only act with ro.pocket.input_policy=true.
The torch toggle goes to PocketTorch's LED, and SystemUI's flashlight controller uses the
same Settings.Global switch when no camera has a flash (FLASHLIGHT_PORT.md).
LightsService.setModes only resends a light when its level changes, so the charging LED
doesn't blink on each battery update.
PocketDisplayMode applies the display mode (mini mode) from its Settings.Global key and
at systemReady goes normal or, with Keep after reboot, to the kept mode (MINI_MODE_CONTRACT.md).
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
BASE = pocket_paths.platform_source() / 'frameworks/base'
PATCH = ROOT / 'patches/android/0004-pocket-input-framework.patch'
OUTPUT = ROOT / 'artifacts/build-overrides/frameworks-base'
HOOKS = 'services/core/java/com/android/server/policy/PocketKeyHooks.java'
TORCH = 'services/core/java/com/android/server/policy/PocketTorch.java'
DISPLAY_MODE = 'services/core/java/com/android/server/policy/PocketDisplayMode.java'
FLASH = 'packages/SystemUI/src/com/android/systemui/statusbar/policy/FlashlightControllerImpl.java'
PWM = 'services/core/java/com/android/server/policy/PhoneWindowManager.java'
PMS = 'services/core/java/com/android/server/power/PowerManagerService.java'
BP = 'services/core/Android.bp'
LIGHTS = 'services/core/java/com/android/server/lights/LightsService.java'


def edit(text, old, new):
    assert text.count(old) == 1, old[:70]
    return text.replace(old, new, 1)


def main():
    files = {}
    old = (BASE / PWM).read_text()
    new = edit(old, '    InputManager mInputManager;\n',
               '    InputManager mInputManager;\n    private PocketKeyHooks mPocketKeys;\n')
    new = edit(new, '        mInputManager = mContext.getSystemService(InputManager.class);\n',
               '        mInputManager = mContext.getSystemService(InputManager.class);\n'
               '        mPocketKeys = PocketKeyHooks.create(mContext,\n'
               '                () -> mHandler.sendEmptyMessage(MSG_TOGGLE_TORCH));\n')
    new = edit(new, '        mKeyguardDelegate.onSystemReady();\n',
               '        mKeyguardDelegate.onSystemReady();\n'
               '        if (mPocketKeys != null) mPocketKeys.systemReady(mSafeMode);\n')
    new = edit(new, '        mLineageButtons = new LineageButtons(mContext);\n',
               '        mLineageButtons = new LineageButtons(mContext);\n'
               '        if (mPocketKeys != null) mPocketKeys.systemBooted();\n')
    new = edit(new, '        // Specific device key handling\n        if (dispatchKeyToKeyHandlers(event)) {\n            return 0;\n',
               '        // Titan Pocket keyboard: light, FUNC1/FUNC2 presses and the pad key guard.\n'
               '        if (mPocketKeys != null\n'
               '                && mPocketKeys.interceptKeyBeforeQueueing(event, policyFlags, interactive)) {\n'
               '            return 0;\n'
               '        }\n\n'
               '        // Specific device key handling\n        if (dispatchKeyToKeyHandlers(event)) {\n            return 0;\n')
    new = edit(new, '    private void toggleTorch() {\n        cancelTorchOff();\n',
               '    private void toggleTorch() {\n'
               '        // Titan Pocket: no camera HAL, so the torch is PocketTorch\'s LED.\n'
               '        if (mPocketKeys != null && mPocketKeys.toggleTorch()) return;\n'
               '        cancelTorchOff();\n')
    files[PWM] = (old, new)
    old = (BASE / PMS).read_text()
    new = edit(old, '            mButtonsLight = mLightsManager.getLight(LightsManager.LIGHT_ID_BUTTONS);\n',
               '            // On the Titan Pocket the keyboard light is PocketKeyHooks\'.\n'
               '            mButtonsLight = com.android.server.policy.PocketKeyHooks.ownsButtonLight()\n'
               '                    ? null : mLightsManager.getLight(LightsManager.LIGHT_ID_BUTTONS);\n')
    files[PMS] = (old, new)
    old = (BASE / BP).read_text()
    marker = '    name: "services.core.unboosted",\n'
    assert old.count(marker) == 1
    at = old.index('    static_libs: [\n', old.index(marker))
    new = old[:at] + '    static_libs: [\n        "PocketInputCore",\n' + old[at + len('    static_libs: [\n'):]
    files[BP] = (old, new)
    old = (BASE / FLASH).read_text()
    new = edit(old, 'import android.content.pm.PackageManager;\n',
               'import android.content.ContentResolver;\nimport android.content.pm.PackageManager;\n'
               'import android.database.ContentObserver;\n')
    new = edit(new, '    private static final String ACTION_FLASHLIGHT_CHANGED =\n',
               '    // Titan Pocket: PocketTorch in system_server (Settings.Global switches).\n'
               '    private static final String POCKET_TORCH = "pocket_torch";\n'
               '    private static final String POCKET_TORCH_AVAILABLE = "pocket_torch_available";\n\n'
               '    private static final String ACTION_FLASHLIGHT_CHANGED =\n')
    new = edit(new, '            Log.e(TAG, "Couldn\'t initialize.", e);\n            return;\n        }\n\n'
               '        if (mCameraId.get() != null) {\n'
               '            mCameraManager.registerTorchCallback(mExecutor, mTorchCallback);\n        }\n    }\n',
               '            Log.e(TAG, "Couldn\'t initialize.", e);\n            tryInitPocketTorch();\n'
               '            return;\n        }\n\n'
               '        if (mCameraId.get() != null) {\n'
               '            mCameraManager.registerTorchCallback(mExecutor, mTorchCallback);\n'
               '        } else {\n            tryInitPocketTorch();\n        }\n    }\n\n'
               '    /** No camera has a flash: follow and set PocketTorch\'s switch instead. */\n'
               '    @WorkerThread\n'
               '    private void tryInitPocketTorch() {\n'
               '        ContentResolver resolver = mSecureSettings.getContentResolver();\n'
               '        if (Settings.Global.getInt(resolver, POCKET_TORCH_AVAILABLE, 0) != 1) return;\n'
               '        if (!mCameraId.compareAndSet(null, POCKET_TORCH)) return;\n'
               '        resolver.registerContentObserver(Settings.Global.getUriFor(POCKET_TORCH), false,\n'
               '                new ContentObserver(null) {\n'
               '                    @Override\n'
               '                    public void onChange(boolean selfChange) {\n'
               '                        mExecutor.execute(() -> pocketTorchChanged(resolver));\n'
               '                    }\n'
               '                });\n'
               '        pocketTorchChanged(resolver);\n'
               '    }\n\n'
               '    @WorkerThread\n'
               '    private void pocketTorchChanged(ContentResolver resolver) {\n'
               '        mTorchCallback.onTorchModeChanged(POCKET_TORCH,\n'
               '                Settings.Global.getInt(resolver, POCKET_TORCH, 0) != 0);\n'
               '    }\n')
    new = edit(new, '                if (mFlashlightEnabled != enabled) {\n                    try {\n',
               '                if (mFlashlightEnabled != enabled) {\n'
               '                    if (POCKET_TORCH.equals(mCameraId.get())) {\n'
               '                        Settings.Global.putInt(mSecureSettings.getContentResolver(),\n'
               '                                POCKET_TORCH, enabled ? 1 : 0);\n'
               '                        return;\n'
               '                    }\n'
               '                    try {\n')
    files[FLASH] = (old, new)
    old = (BASE / LIGHTS).read_text()
    new = edit(old, '                mBrightnessLevel = brightnessLevel;\n                mModesUpdate = true;\n',
               '                // Only a new level is sent again: the vendor HAL turns the LED off\n'
               '                // and on for each write, so the battery light blinked on every update.\n'
               '                if (brightnessLevel != mBrightnessLevel) mModesUpdate = true;\n'
               '                mBrightnessLevel = brightnessLevel;\n')
    files[LIGHTS] = (old, new)
    assert not any((BASE / name).exists() for name in (HOOKS, TORCH, DISPLAY_MODE))
    files[HOOKS] = ('', (pocket_paths.INPUT_PACKAGE / 'framework/PocketKeyHooks.java').read_text())
    files[TORCH] = ('', (pocket_paths.INPUT_PACKAGE / 'framework/PocketTorch.java').read_text())
    files[DISPLAY_MODE] = ('', (pocket_paths.INPUT_PACKAGE / 'framework/PocketDisplayMode.java').read_text())

    diff, hashes = [], {}
    for name, (old, new) in files.items():
        assert old != new, name
        p = OUTPUT / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(new)
        full = 'frameworks/base/' + name
        diff += list(difflib.unified_diff(old.splitlines(True), new.splitlines(True),
                                          fromfile='/dev/null' if not old else 'a/' + full,
                                          tofile='b/' + full))
        hashes[name] = {'original': hashlib.sha256(old.encode()).hexdigest() if old else None,
                        'modified': hashlib.sha256(new.encode()).hexdigest()}
    for p in OUTPUT.rglob('*'):
        if p.is_file() and str(p.relative_to(OUTPUT)) not in files:
            p.unlink()
    PATCH.write_text(''.join(diff))
    with tempfile.TemporaryDirectory(prefix='framework-patch-') as tmp:
        tree = Path(tmp)
        for name, (old, new) in files.items():
            if old:
                p = tree / 'frameworks/base' / name
                p.parent.mkdir(parents=True, exist_ok=True)
                p.write_text(old)
        subprocess.run(['patch', '--batch', '--fuzz=0', '-p1', '-d', tmp, '-i', str(PATCH)],
                       check=True, capture_output=True)
        for name, (old, new) in files.items():
            assert (tree / 'frameworks/base' / name).read_text() == new, name
    record = {'files': hashes, 'patch': str(PATCH.relative_to(ROOT)),
              'override': str(OUTPUT.relative_to(ROOT)), 'replay_exact': True,
              'shared_source_modified': False, 'runtime_tested': False,
              'used_by': 'tools/run-pocket-source-build.py',
              'limits': ['Not compiled in a product build yet', 'Not run on the device']}
    evidence = ROOT / 'evidence/kernel-upgrade/pocket-framework-patch.json'
    evidence.parent.mkdir(parents=True, exist_ok=True)
    evidence.write_text(json.dumps(record, indent=2) + '\n')
    print('frameworks/base key hook patch replays exactly; shared source unchanged')


if __name__ == '__main__':
    main()
