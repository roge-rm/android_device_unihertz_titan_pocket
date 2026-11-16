// SPDX-License-Identifier: Apache-2.0
package org.lineageos.pocketinput;

/** Letter-key suppression around keyboard-pad drags. */
public final class PadKeyGuardTest {
    private static int checks;
    private static void check(boolean value) {
        checks++;
        if (!value) throw new AssertionError("check " + checks);
    }
    public static void main(String[] args) {
        final int a = 29, z = 54, grave = 68, enter = 66, del = 67, space = 62, shift = 59, dpad = 21;
        check(PadKeyGuard.guarded(a) && PadKeyGuard.guarded(z) && PadKeyGuard.guarded(del)
                && PadKeyGuard.guarded(enter) && PadKeyGuard.guarded(space) && PadKeyGuard.guarded(shift));
        check(!PadKeyGuard.guarded(28) && !PadKeyGuard.guarded(grave) && !PadKeyGuard.guarded(dpad));

        // Live drag blocks from its start, not before, and goes stale after the cap.
        check(PadKeyGuard.blocking("drag 1000", 1000));
        check(PadKeyGuard.blocking("drag 1000", 5000));
        check(!PadKeyGuard.blocking("drag 1000", 999));
        check(!PadKeyGuard.blocking("drag 1000", 1000 + PadKeyGuard.MAX_DRAG_MILLIS));

        // After the lift: blocked for KEY_PRESS_DELAY_MILLIS, then free.
        long end = 1500, delay = PadKeyGuard.KEY_PRESS_DELAY_MILLIS;
        check(PadKeyGuard.blocking("lift 1000 1500", 1200));
        check(PadKeyGuard.blocking("lift 1000 1500", end + delay - 1));
        check(!PadKeyGuard.blocking("lift 1000 1500", end + delay));
        check(!PadKeyGuard.blocking("lift 1000 1500", 999));
        // A key down handled after the lift it caused is still dropped.
        check(PadKeyGuard.blocking("lift 1000 1500", 1499));

        // Empty, missing or broken state blocks nothing.
        check(!PadKeyGuard.blocking(null, 1000));
        check(!PadKeyGuard.blocking("", 1000));
        check(!PadKeyGuard.blocking("drag", 1000));
        check(!PadKeyGuard.blocking("drag x", 1000));
        check(!PadKeyGuard.blocking("lift 1000", 1000));
        check(!PadKeyGuard.blocking("lift 1500 1000", 1200));
        check(!PadKeyGuard.blocking("hold 1000", 1000));
        check(!PadKeyGuard.blocking("drag -5", 1000));

        // Dropped downs drop their release; other keys pass.
        PadKeyGuard guard = new PadKeyGuard();
        check(guard.onKeyDown(a, false, 1100, "drag 1000"));
        check(!guard.onKeyDown(dpad, false, 1100, "drag 1000"));
        check(!guard.onKeyUp(dpad));
        // A repeat of a dropped key stays dropped, even once the window has passed.
        check(guard.onKeyDown(a, true, 9000, "lift 1000 1200"));
        check(guard.onKeyUp(a));
        check(!guard.onKeyUp(a));
        // A key held from before the drag repeats through.
        check(!guard.onKeyDown(z, true, 1100, "drag 1000"));
        // Typing after the window types.
        check(!guard.onKeyDown(z, false, 1200 + delay, "lift 1000 1200"));
        check(!guard.onKeyUp(z));
        // Reset forgets dropped downs.
        check(guard.onKeyDown(enter, false, 1100, "drag 1000"));
        guard.reset();
        check(!guard.onKeyUp(enter));
        System.out.println(checks + " pad key guard assertions passed");
    }
}
