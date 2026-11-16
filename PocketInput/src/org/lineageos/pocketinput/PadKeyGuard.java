// SPDX-License-Identifier: Apache-2.0
package org.lineageos.pocketinput;

import java.util.HashSet;
import java.util.Set;

/**
 * Drops letter keys while a keyboard-pad drag is live and for a short time
 * after it lifts, as stock's InputReader does, so fingers brushing the keys
 * during a swipe don't type. The release of a dropped key is dropped too.
 *
 * The state is pocket_padd's sys.pocket.pad_guard: "drag START" or
 * "lift START END", times in uptimeMillis. Serialized by the owner, like KeyboardController.
 */
public final class PadKeyGuard {
    /** Stock's KEY_PRESS_DELAY wasn't read from the binary; this is our own short default. */
    public static final long KEY_PRESS_DELAY_MILLIS = 200;
    /** A "drag" older than this is treated as stale, in case the daemon died mid-drag. */
    public static final long MAX_DRAG_MILLIS = 10000;
    /** Stock's range: KEYCODE_A (29) to KEYCODE_GRAVE (68) exclusive, so 29 to 67. */
    public static final int FIRST_KEY = 29, LAST_KEY = 67;

    private final Set<Integer> dropped = new HashSet<>();

    public static boolean guarded(int keyCode) {
        return keyCode >= FIRST_KEY && keyCode <= LAST_KEY;
    }

    /**
     * True if the pad state blocks letter keys at this time. "drag S" blocks from S,
     * "lift S E" from S to E plus the delay. A key down can reach us after the lift
     * it caused (the kernel stops the pad on a key down), hence the check from S.
     * Bad or empty state blocks nothing.
     */
    public static boolean blocking(String state, long eventTimeMillis) {
        if (state == null) return false;
        String[] parts = state.trim().split(" ");
        long start, end;
        try {
            start = Long.parseLong(parts.length > 1 ? parts[1] : "-1");
            end = parts.length > 2 ? Long.parseLong(parts[2]) : -1;
        } catch (NumberFormatException e) { return false; }
        if (start < 0 || eventTimeMillis < start) return false;
        if ("drag".equals(parts[0]) && parts.length == 2) {
            return eventTimeMillis - start < MAX_DRAG_MILLIS;
        }
        if ("lift".equals(parts[0]) && parts.length == 3 && end >= start) {
            return eventTimeMillis - end < KEY_PRESS_DELAY_MILLIS;
        }
        return false;
    }

    /** Returns true to consume the key down. */
    public boolean onKeyDown(int keyCode, boolean repeat, long eventTimeMillis, String state) {
        if (dropped.contains(keyCode)) return true;
        if (repeat || !guarded(keyCode) || !blocking(state, eventTimeMillis)) return false;
        dropped.add(keyCode);
        return true;
    }

    /** Returns true to consume the release of a dropped key down. */
    public boolean onKeyUp(int keyCode) {
        return dropped.remove(keyCode);
    }

    /** Screen off, editor change or keyboard hidden: forget dropped downs. */
    public void reset() { dropped.clear(); }
}
