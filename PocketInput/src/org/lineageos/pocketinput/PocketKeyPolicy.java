// SPDX-License-Identifier: Apache-2.0
package org.lineageos.pocketinput;

import java.util.Objects;

/**
 * Key policy for the Pocket keyboard in every app, run by the framework hook in
 * PhoneWindowManager.interceptKeyBeforeQueueing (PocketKeyHooks):
 * - the keyboard light goes on at a key down with the screen on, with no delay, and off
 *   after the timeout in the settings;
 * - FUNC1 (F13) and FUNC2 (F14) run their short or long press action and never reach apps;
 * - letter keys are dropped during and just after a keyboard-pad drag (PadKeyGuard);
 * - holding FUNC1 and FUNC2 together for a second restores the normal display, and runs
 *   neither key's own press.
 *
 * Times are uptimeMillis, the clock of KeyEvent.getEventTime. Not thread-safe: the owner
 * serializes every call. Sink calls are made under that serialization and must not block.
 */
public final class PocketKeyPolicy {
    /** Android's KEYCODE_F13 and KEYCODE_F14, which our layouts send for FUNC1 and FUNC2. */
    public static final int KEYCODE_F13 = 326, KEYCODE_F14 = 327;
    /** Our own pick, a little over ViewConfiguration's 400 ms so a slow tap stays short. */
    public static final long LONG_PRESS_MILLIS = 500;
    /** How long FUNC1 and FUNC2 are held together to restore the normal display. */
    public static final long RESTORE_HOLD_MILLIS = 1000;

    /** KEYBOARD is aw9523-key, KEYPAD is mtk-kpd (side key, home, volume). */
    public enum Source { KEYBOARD, KEYPAD, OTHER }

    public interface Sink {
        void setLight(boolean on);
        void runAction(String registeredActionId);
        /** FUNC1 and FUNC2 were held together: back to the normal display mode. */
        void restoreDisplay();
    }

    /** Reads sys.pocket.pad_guard; only called for guarded keyboard keys. */
    public interface PadState { String get(); }

    private final KeyboardController light;
    private final Sink sink;
    private final PadKeyGuard guard = new PadKeyGuard();
    private KeyboardSettings settings;
    private int heldKey;
    private long heldDownTime;
    private boolean longFired;
    /** FUNC1 and FUNC2 down, by keycode from either device. */
    private boolean f13Down, f14Down;
    /** Both were down together; their presses stay off until both are up. */
    private boolean chord;
    private long chordTime;
    private boolean chordFired;

    public PocketKeyPolicy(KeyboardSettings settings, KeyboardController.Clock clock, Sink sink) {
        this.settings = Objects.requireNonNull(settings);
        this.sink = Objects.requireNonNull(sink);
        // The controller is only used for its light and timeout here.
        light = new KeyboardController(settings, clock, new KeyboardController.Sink() {
            @Override public void setBacklight(boolean on) { PocketKeyPolicy.this.sink.setLight(on); }
            @Override public void moveCursor(int steps) {}
            @Override public void scroll(double delta) {}
            @Override public void runShortcut(String action) {}
        });
    }

    public static boolean isShortcutKey(int keyCode) {
        return keyCode == KEYCODE_F13 || keyCode == KEYCODE_F14;
    }

    public void setSettings(KeyboardSettings settings) {
        this.settings = Objects.requireNonNull(settings);
        light.setSettings(settings);
    }

    /** Screen on or off. Off turns the light off and forgets held and dropped keys. */
    public void setInteractive(boolean interactive) {
        light.setInteractive(interactive);
        if (!interactive) {
            heldKey = 0;
            f13Down = f14Down = chord = false;
            guard.reset();
        }
    }

    /** Returns true to drop the key down. Keys from other devices are never touched. */
    public boolean onKeyDown(Source source, int keyCode, boolean repeat, long eventTime,
            boolean interactive, PadState pad) {
        if (source == Source.OTHER) return false;
        light.setInteractive(interactive);
        if (!interactive) return false;
        if (source == Source.KEYBOARD) light.onKeyDown(true, keyCode, 0, repeat);
        if (isShortcutKey(keyCode)) {
            if (!repeat) {
                if (keyCode == KEYCODE_F13) f13Down = true; else f14Down = true;
                if (f13Down && f14Down) {
                    // The other key's press is dropped, and the hold starts now.
                    heldKey = 0;
                    chord = true;
                    chordTime = eventTime;
                    chordFired = false;
                } else if (!chord) {
                    heldKey = keyCode;
                    heldDownTime = eventTime;
                    longFired = false;
                }
            }
            return true;
        }
        if (source != Source.KEYBOARD) return false;
        String state = !repeat && PadKeyGuard.guarded(keyCode) && pad != null ? pad.get() : null;
        return guard.onKeyDown(keyCode, repeat, eventTime, state);
    }

    /** Returns true to drop the key up. A canceled short press runs nothing. */
    public boolean onKeyUp(Source source, int keyCode, boolean canceled) {
        if (source == Source.OTHER) return false;
        if (isShortcutKey(keyCode)) {
            if (keyCode == KEYCODE_F13) f13Down = false; else f14Down = false;
            if (chord) {
                if (!f13Down && !f14Down) chord = false;
                return true;
            }
            if (keyCode == heldKey) {
                heldKey = 0;
                String action = settings.pressAction(keyCode, false);
                if (!longFired && !canceled && action != null) sink.runAction(action);
            }
            return true;
        }
        return source == Source.KEYBOARD && guard.onKeyUp(keyCode);
    }

    /**
     * Runs neither the short nor the long press of the keyCode hold going on now. The key's up
     * is still dropped, and the FUNC1+FUNC2 hold still works. For the red key held at boot.
     */
    public void cancelHold(int keyCode) {
        if (heldKey == keyCode) heldKey = 0;
    }

    /** Absolute uptime of the next timer, or -1. Covers the light timeout, long press and restore hold. */
    public long nextTimerMillis() {
        long at = light.nextLightDeadlineMillis();
        if (heldKey != 0 && !longFired && settings.pressAction(heldKey, true) != null) {
            at = earliest(at, heldDownTime + LONG_PRESS_MILLIS);
        }
        if (chordPending()) at = earliest(at, chordTime + RESTORE_HOLD_MILLIS);
        return at;
    }

    private static long earliest(long a, long b) {
        return a < 0 ? b : Math.min(a, b);
    }

    private boolean chordPending() {
        return chord && f13Down && f14Down && !chordFired;
    }

    public void onTimer(long now) {
        light.onTimer();
        if (chordPending() && now >= chordTime + RESTORE_HOLD_MILLIS) {
            chordFired = true;
            sink.restoreDisplay();
        }
        if (heldKey != 0 && !longFired && now >= heldDownTime + LONG_PRESS_MILLIS) {
            String action = settings.pressAction(heldKey, true);
            if (action != null) {
                longFired = true;
                sink.runAction(action);
            }
        }
    }
}
