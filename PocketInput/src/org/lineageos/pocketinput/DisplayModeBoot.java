// SPDX-License-Identifier: Apache-2.0
package org.lineageos.pocketinput;

/**
 * Keep after reboot (MINI_MODE_CONTRACT.md), run by PocketDisplayMode at systemReady: what
 * the display does this boot, and the crash guard.
 *
 * The guard counts system_server starts that applied the kept mode, in a file that survives a
 * crash. Each such start adds one, and STABLE_MILLIS later or at a clean shutdown the count
 * goes back to 0. A start that finds MAX_STARTS already counted, so system_server has
 * started again twice within about a minute of applying the mode without a clean shutdown,
 * comes up normal and turns Keep after reboot off.
 * Safe mode and the red key skip the mode for this boot only; the setting and the kept mode
 * stay.
 *
 * Not thread safe: one thread calls everything.
 */
public final class DisplayModeBoot {
    /** Settings.Global: 1 applies the kept mode (DisplayModes.KEPT_SETTING) at boot. Default 0. */
    public static final String SETTING = "pocket_display_mode_boot";
    public static final int MAX_STARTS = 2;
    public static final long STABLE_MILLIS = 60_000;

    public enum Outcome {
        /** Keep after reboot is off or the kept mode is normal: normal, and normal is kept. */
        NORMAL,
        /** The kept mode goes on, as kept. */
        APPLY,
        /** Normal this boot only. */
        SKIP_SAFE_MODE,
        SKIP_KEY,
        /** Normal, and SETTING is turned off. */
        CRASH_GUARD,
    }

    /** The crash guard's count and the setting, kept by system_server. */
    public interface Store {
        /** Starts counted, 0 when there is no count or it can't be read. */
        int starts();
        void setStarts(int starts);
        /** Turn Keep after reboot off: SETTING to 0. */
        void disableBoot();
    }

    private final KeyboardController.Clock mClock;
    private final Store mStore;
    private long mStableAt = -1;

    public DisplayModeBoot(KeyboardController.Clock clock, Store store) {
        mClock = clock;
        mStore = store;
    }

    /**
     * Once per system_server start. bootOn is SETTING, kept the kept mode (null for normal),
     * keyHeld whether the red key was down during boot.
     */
    public Outcome start(boolean bootOn, DisplayModes.Mode kept, boolean safeMode,
            boolean keyHeld) {
        mStableAt = -1;
        Outcome outcome;
        if (!bootOn || kept == null) {
            outcome = Outcome.NORMAL;
        } else if (safeMode) {
            outcome = Outcome.SKIP_SAFE_MODE;
        } else if (keyHeld) {
            outcome = Outcome.SKIP_KEY;
        } else if (mStore.starts() >= MAX_STARTS) {
            mStore.disableBoot();
            outcome = Outcome.CRASH_GUARD;
        } else {
            mStore.setStarts(mStore.starts() + 1);
            mStableAt = mClock.uptimeMillis() + STABLE_MILLIS;
            return Outcome.APPLY;
        }
        // The mode isn't on, so nothing is left to count.
        if (mStore.starts() != 0) mStore.setStarts(0);
        return outcome;
    }

    /** A clean shutdown or reboot: it wasn't a crash, so the count goes. */
    public void shutdown() {
        mStableAt = -1;
        if (mStore.starts() != 0) mStore.setStarts(0);
    }

    /** Uptime the count is cleared at, or -1 when there's nothing to clear. */
    public long stableAt() {
        return mStableAt;
    }

    /** Clears the count once the mode has run STABLE_MILLIS. */
    public void onTimer() {
        if (mStableAt >= 0 && mClock.uptimeMillis() >= mStableAt) {
            mStableAt = -1;
            mStore.setStarts(0);
        }
    }
}
