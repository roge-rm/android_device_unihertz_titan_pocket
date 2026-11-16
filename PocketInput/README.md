# Pocket input integration

This new Apache-2.0 code supplies a keyboard policy library, settings application/provider, IME adapter and lighting-writer interface. It does not copy Unihertz's keyboard app. No component has been installed on the test phone, and it is not a complete replacement keyboard implementation.

## Implemented behavior

`KeyboardController` requests lighting during physical key-down, extends a configurable monotonic idle deadline while typing, and turns its request off on expiry/screen-off. It supports off/scroll/cursor modes, cursor sensitivity, a typing guard, focus and sensitive-field restrictions, and explicit modifier/key shortcuts. Cursor gestures cancel on focus changes, multiple contacts, pointer changes, invalid coordinates or discontinuities. Consumed shortcut releases/repeats stay paired without retriggering actions.

`KeyboardSettingsCodec` provides bounded, versioned persistence with duplicate/unknown-field rejection. The settings app stores configuration in private preferences. Its exported provider requires the declared normal read permission and exposes configuration only; insert/update/delete are refused. The UI configures swipes, lighting, timeout, sensitivity and three optional Alt shortcuts. The source model can hold more bindings; an arbitrary shortcut editor remains future work.

`PocketInputRuntime` observes settings, schedules the timer, normalizes modifiers, and rechecks keyguard/interactive state. Its device-name filter routes the captured `aw9523-key` keyboard; that name is not hardware authentication. The fixed shortcut registry supports browser, camera and Settings actions. The LatinIME patch connects lifecycle, editor and key callbacks while retaining ordinary character handling and all locales/resources. Another IME needs its own adapter or a framework hook for these enhancements.

`EditorCursorAdapter` sends bounded DPAD press/release pairs through the owning IME's current `InputConnection`. Password variants and an explicit sensitive override block cursor actions. It neither injects global input nor accesses another IME's connection. Apps and languages still need runtime qualification, including capitalization, modifier locks, symbol/accent pickers and repeat behavior.

## Unfinished hardware/framework integration

Swipe scroll is done by the native daemon `pad/pocket_padd`, which reads `mtk-pad` and sends drags through a uinput touchscreen; `PadKeyGuard` drops letter keys during and just after a drag, in every app, from the framework hook below. See the Swipe scroll section of `TOUCHPAD_PORT.md`. The runtime's own pad entry points and scroll callback are still unused, and cursor swipes have no event route yet.

The keyboard light, FUNC1 and FUNC2 short and long presses and the pad key guard run in system_server: `framework/PocketKeyHooks.java` is added to `PhoneWindowManager` by `patches/android/0004-pocket-input-framework.patch` (staged by `tools/stage-pocket-framework.py`) and runs `PocketKeyPolicy` from `PocketInputCore`. The light goes through the lights HAL's BUTTONS light. See "Framework key hook" in `KEYBOARD_PORT.md`. `KeyboardLightWriter` and the IME runtime's light path stay unused. Optical latency and power measurements remain open.

The torch is `framework/PocketTorch.java`, run by the same hook: it writes the kernel torch LED from the `Settings.Global` switch `pocket_torch`, which the FUNC key Flashlight action and SystemUI's flashlight tile both set, since there is no camera HAL. See `FLASHLIGHT_PORT.md`.

Display modes (mini mode) are `framework/PocketDisplayMode.java`, also run by the hook: it forces the size and density of the mode in the `Settings.Global` key `pocket_display_mode`, which the settings app's Display mode tile sets. Holding FUNC1 and FUNC2 for a second, or a reboot, brings back the normal display. See `MINI_MODE_CONTRACT.md`.

The code records no typed text or private editor content. All event handling must be serialized by its owning service/IME. Reserved system shortcuts and device-disconnect lifecycle need product review before release.

## Validation and artifacts

Run `python3 -B tools/check-pocket-input.py`: **63** keyboard, 30 pad guard and 53 framework key policy host assertions pass and the Android adapter compiles against API 36. Core/light code also compiles against API 26 stubs, below the APK's API 30 minimum. These checks do not execute Android editor behavior or hardware.

`python3 -B tools/build-pocket-input-apk.py` creates aligned, signature-verified settings APKs with a disposable local test certificate. They are not platform/release signed or installed. Source/tool hashes and artifacts are recorded in `evidence/kernel-upgrade/pocket-input-apk-build.json`. `tools/stage-pocket-ime.py` generates and exact-replay-checks the LatinIME patch without changing shared source. The isolated source-build helper successfully built PocketInputSettings, PocketInputEditorAdapter and patched LatinIME. Both APK signatures verify, the LatinIME dex includes the Pocket runtime, and an immediate repeat build has no work. This is source-build validation only; no APK or image was installed. The public source export excludes APKs, keys and private evidence.
