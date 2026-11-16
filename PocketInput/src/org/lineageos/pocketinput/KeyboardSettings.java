// SPDX-License-Identifier: Apache-2.0
package org.lineageos.pocketinput;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

/** Immutable settings; persistence/UI belongs to the eventual device integration. */
public final class KeyboardSettings {
    public enum SwipeMode { OFF, SCROLL, CURSOR }
    public static final int SHIFT = 1, ALT = 2, CTRL = 4, META = 8;
    public final SwipeMode swipeMode;
    public final boolean lightingEnabled;
    public final long lightTimeoutMillis;
    public final long typingGuardMillis;
    public final double cursorStep;
    public final Map<Chord, String> shortcuts;
    /** Short and long press actions of single keys (FUNC1 and FUNC2), run by the framework hook. */
    public final Map<Press, String> pressActions;

    public KeyboardSettings(SwipeMode mode, boolean lighting, long timeout,
            long typingGuard, double cursorStep, Map<Chord, String> shortcuts) {
        this(mode, lighting, timeout, typingGuard, cursorStep, shortcuts, Collections.emptyMap());
    }

    public KeyboardSettings(SwipeMode mode, boolean lighting, long timeout,
            long typingGuard, double cursorStep, Map<Chord, String> shortcuts,
            Map<Press, String> pressActions) {
        if (timeout < 500 || timeout > 30000 || typingGuard < 0 || typingGuard > 2000
                || !Double.isFinite(cursorStep) || cursorStep < 0.02 || cursorStep > 0.5) {
            throw new IllegalArgumentException("Keyboard setting outside supported range");
        }
        this.swipeMode = Objects.requireNonNull(mode);
        this.lightingEnabled = lighting;
        this.lightTimeoutMillis = timeout;
        this.typingGuardMillis = typingGuard;
        this.cursorStep = cursorStep;
        Map<Chord, String> copy = new HashMap<>(Objects.requireNonNull(shortcuts));
        for (Map.Entry<Chord, String> e : copy.entrySet()) {
            Objects.requireNonNull(e.getKey());
            if (e.getValue() == null || e.getValue().isEmpty()) {
                throw new IllegalArgumentException("Shortcut needs a registered action ID");
            }
        }
        this.shortcuts = Collections.unmodifiableMap(copy);
        Map<Press, String> presses = new HashMap<>(Objects.requireNonNull(pressActions));
        for (Map.Entry<Press, String> e : presses.entrySet()) {
            Objects.requireNonNull(e.getKey());
            if (e.getValue() == null || e.getValue().isEmpty()) {
                throw new IllegalArgumentException("Key press needs a registered action ID");
            }
        }
        this.pressActions = Collections.unmodifiableMap(presses);
    }

    /** The action for a short or long press of a key, or null. */
    public String pressAction(int keyCode, boolean longPress) {
        return pressActions.get(new Press(keyCode, longPress));
    }

    public static KeyboardSettings defaults() {
        return new KeyboardSettings(SwipeMode.OFF, true, 3500, 250, 0.08,
                Collections.emptyMap());
    }

    public static final class Chord {
        public final int keyCode, modifiers;
        public Chord(int keyCode, int modifiers) {
            if (keyCode <= 0 || modifiers <= 0 || (modifiers & ~15) != 0) {
                throw new IllegalArgumentException("Shortcut needs a valid key and modifier");
            }
            this.keyCode = keyCode;
            this.modifiers = modifiers;
        }
        @Override public boolean equals(Object other) {
            if (!(other instanceof Chord)) return false;
            Chord c = (Chord) other;
            return keyCode == c.keyCode && modifiers == c.modifiers;
        }
        @Override public int hashCode() { return 31 * keyCode + modifiers; }
    }

    public static final class Press {
        public final int keyCode;
        public final boolean longPress;
        public Press(int keyCode, boolean longPress) {
            if (keyCode <= 0) throw new IllegalArgumentException("Key press needs a valid key");
            this.keyCode = keyCode;
            this.longPress = longPress;
        }
        @Override public boolean equals(Object other) {
            if (!(other instanceof Press)) return false;
            Press p = (Press) other;
            return keyCode == p.keyCode && longPress == p.longPress;
        }
        @Override public int hashCode() { return 2 * keyCode + (longPress ? 1 : 0); }
    }
}
