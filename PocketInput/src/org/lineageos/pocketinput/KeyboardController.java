// SPDX-License-Identifier: Apache-2.0
package org.lineageos.pocketinput;

import java.util.Objects;
import java.util.HashSet;
import java.util.Set;

/**
 * Serialized event policy for a future device input service/IME adapter.
 * Never reads characters, records key events, injects input, or opens hardware.
 * The adapter must authenticate the physical input device and schedule onTimer.
 */
public final class KeyboardController {
    public interface Clock { long uptimeMillis(); }
    public interface Sink {
        void setBacklight(boolean on);
        void moveCursor(int characterSteps);
        void scroll(double normalizedVerticalDelta);
        void runShortcut(String registeredActionId);
    }
    private final Clock clock;
    private final Sink sink;
    private final Set<Integer> consumedKeys = new HashSet<>();
    private KeyboardSettings settings;
    private boolean interactive, editor, sensitive, unlocked, lightOn, gesture;
    private boolean lightingPermitted = true;
    private long lightDeadline = -1, lastTyped = -1;
    private int pointer;
    private double previousX, previousY, accumulatedX;

    public KeyboardController(KeyboardSettings settings, Clock clock, Sink sink) {
        this.settings = Objects.requireNonNull(settings);
        this.clock = Objects.requireNonNull(clock);
        this.sink = Objects.requireNonNull(sink);
    }
    public void setSettings(KeyboardSettings settings) {
        this.settings = Objects.requireNonNull(settings);
        resetGesture();
        if (!settings.lightingEnabled || !lightingPermitted) turnLightOff();
        else if (lightOn) lightDeadline = now() + settings.lightTimeoutMillis;
    }
    /** Ambient/manual policy supplies this; permission changes never turn light on alone. */
    public void setLightingPermitted(boolean permitted) {
        lightingPermitted = permitted;
        if (!permitted) turnLightOff();
    }
    public void setInteractive(boolean interactive) {
        this.interactive = interactive;
        resetGesture();
        if (!interactive) { turnLightOff(); consumedKeys.clear(); }
    }
    /** Call on every focus/connection change, even if these flags do not change. */
    public void setContext(boolean editor, boolean sensitive, boolean unlocked) {
        this.editor = editor;
        this.sensitive = sensitive;
        this.unlocked = unlocked;
        resetGesture();
    }
    /** Return true only for an explicitly configured, consumed shortcut. */
    public boolean onKeyDown(boolean trustedPhysicalDevice, int keyCode,
            int modifiers, boolean repeat) {
        if (!trustedPhysicalDevice || !interactive) return false;
        long time = now();
        lastTyped = time;
        resetGesture();
        if (settings.lightingEnabled && lightingPermitted) {
            if (!lightOn) { sink.setBacklight(true); lightOn = true; }
            lightDeadline = time + settings.lightTimeoutMillis;
        }
        if (consumedKeys.contains(keyCode)) return true;
        if (repeat || sensitive || !unlocked || keyCode <= 0 || modifiers <= 0
                || (modifiers & ~15) != 0) return false;
        String action = settings.shortcuts.get(new KeyboardSettings.Chord(keyCode, modifiers));
        if (action == null) return false;
        consumedKeys.add(keyCode);
        sink.runShortcut(action);
        return true;
    }
    /** Consume the release matching a consumed shortcut press. */
    public boolean onKeyUp(boolean trustedPhysicalDevice, int keyCode) {
        return trustedPhysicalDevice && consumedKeys.remove(keyCode);
    }
    public void onTimer() {
        if (lightOn && now() >= lightDeadline) turnLightOff();
    }
    /** Adapter uses this absolute monotonic deadline; -1 means no timer. */
    public long nextLightDeadlineMillis() { return lightDeadline; }
    public void onPadDown(boolean trustedPhysicalDevice, int pointer, int contacts,
            double x, double y) {
        resetGesture();
        if (!trustedPhysicalDevice || !eligible() || contacts != 1 || !valid(x, y)) return;
        this.pointer = pointer;
        previousX = x;
        previousY = y;
        gesture = true;
    }
    public void onPadMove(int pointer, int contacts, double x, double y) {
        if (!gesture) return;
        if (pointer != this.pointer || contacts != 1 || !eligible() || !valid(x, y)) {
            resetGesture();
            return;
        }
        double dx = x - previousX, dy = y - previousY;
        previousX = x;
        previousY = y;
        // Large discontinuities are a lift/palm/bad-frame signal, not cursor motion.
        if (Math.abs(dx) > 0.4 || Math.abs(dy) > 0.4) { resetGesture(); return; }
        if (settings.swipeMode == KeyboardSettings.SwipeMode.CURSOR) {
            accumulatedX += dx;
            int steps = (int) (accumulatedX / settings.cursorStep);
            if (steps != 0) {
                accumulatedX -= steps * settings.cursorStep;
                sink.moveCursor(steps);
            }
        } else if (dy != 0) {
            sink.scroll(dy);
        }
    }
    public void onPadUp() { resetGesture(); }
    private boolean eligible() {
        return interactive && unlocked && !sensitive
                && settings.swipeMode != KeyboardSettings.SwipeMode.OFF
                && (settings.swipeMode != KeyboardSettings.SwipeMode.CURSOR || editor)
                && (lastTyped < 0 || now() - lastTyped >= settings.typingGuardMillis);
    }
    private static boolean valid(double x, double y) {
        return Double.isFinite(x) && Double.isFinite(y) && x >= 0 && x <= 1 && y >= 0 && y <= 1;
    }
    private long now() {
        long value = clock.uptimeMillis();
        if (value < 0) throw new IllegalStateException("Expected nonnegative monotonic time");
        return value;
    }
    private void resetGesture() { gesture = false; accumulatedX = 0; }
    private void turnLightOff() {
        if (lightOn) { sink.setBacklight(false); lightOn = false; }
        lightDeadline = -1;
    }
}
