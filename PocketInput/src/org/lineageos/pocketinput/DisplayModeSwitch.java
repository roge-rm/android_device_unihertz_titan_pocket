// SPDX-License-Identifier: Apache-2.0
package org.lineageos.pocketinput;

/**
 * Confirm or revert for display mode switches, run by PocketDisplayMode in system_server.
 * A switch applies the new mode at once and waits CONFIRM_MILLIS for Keep; Revert, the
 * timeout and the screen going off put back the last confirmed state. The key combo, a user
 * switch and a normal boot use force, which confirms straight away. Keep, a pick of the
 * confirmed state while asking and force are remembered, for Keep after reboot; a mode put on
 * at boot (boot) and a request for what's already on are not, so a boot that skips the mode
 * keeps the remembered one.
 * Modes are null for normal.
 *
 * Not thread safe: one thread calls everything. The Sink is called from inside these calls.
 */
public final class DisplayModeSwitch {
    public static final long CONFIRM_MILLIS = 10_000;

    public interface Sink {
        /** Put this mode on the display, null for normal. */
        void apply(DisplayModes.Mode mode);
        /** Write the settings keys back to this mode, so the app and tile show it. */
        void store(DisplayModes.Mode mode);
        /**
         * As store, for a revert from asked: only while the settings still hold asked, so a
         * newer pick isn't overwritten. That pick's notification then starts a new switch.
         */
        void revertStore(DisplayModes.Mode mode, DisplayModes.Mode asked);
        /** Show the Keep or Revert dialog, or show it again for a new switch. */
        void showDialog();
        void hideDialog();
        /** Save this as the kept mode, the one Keep after reboot applies. */
        void remember(DisplayModes.Mode mode);
    }

    private final KeyboardController.Clock mClock;
    private final Sink mSink;
    private DisplayModes.Mode mConfirmed;
    private DisplayModes.Mode mApplied;
    private boolean mPending;
    private long mDeadline;

    public DisplayModeSwitch(KeyboardController.Clock clock, Sink sink) {
        mClock = clock;
        mSink = sink;
    }

    /** The settings asked for this mode: switch to it and wait for Keep. */
    public void request(DisplayModes.Mode target) {
        if (DisplayModes.same(target, mApplied)) {
            // Same size and density, maybe a new ID: nothing to show or confirm.
            // Not a choice either, so the kept mode stays: after a boot skip the settings
            // notifying normal, or a custom size edited while normal, must not keep normal.
            mApplied = target;
            if (!mPending) mConfirmed = target;
            return;
        }
        if (mPending && DisplayModes.same(target, mConfirmed)) {
            // Back to the confirmed state while asking: no need to ask about that.
            mPending = false;
            mApplied = mConfirmed = target;
            mSink.apply(target);
            mSink.hideDialog();
            mSink.remember(target);
            return;
        }
        mPending = true;
        mApplied = target;
        mDeadline = mClock.uptimeMillis() + CONFIRM_MILLIS;
        mSink.apply(target);
        mSink.showDialog();
    }

    /** Apply and confirm at once, dropping any switch waiting for Keep. */
    public void force(DisplayModes.Mode target) {
        boot(target);
        mSink.remember(target);
    }

    /** As force, but the remembered mode stays: the mode Keep after reboot put on, or a skip. */
    public void boot(DisplayModes.Mode target) {
        boolean wasPending = mPending;
        mPending = false;
        mApplied = mConfirmed = target;
        mSink.apply(target);
        mSink.store(target);
        if (wasPending) mSink.hideDialog();
    }

    public void keep() {
        if (!mPending) return;
        mPending = false;
        mConfirmed = mApplied;
        mSink.hideDialog();
        mSink.remember(mConfirmed);
    }

    public void revert() {
        if (!mPending) return;
        DisplayModes.Mode asked = mApplied;
        mPending = false;
        mApplied = mConfirmed;
        mSink.apply(mConfirmed);
        mSink.revertStore(mConfirmed, asked);
        mSink.hideDialog();
    }

    /** Reverts once the deadline has passed. */
    public void onTimer() {
        if (mPending && mClock.uptimeMillis() >= mDeadline) revert();
    }

    public void screenOff() {
        revert();
    }

    public boolean pending() {
        return mPending;
    }

    /** Uptime the pending switch reverts at, or -1 when nothing is pending. */
    public long deadline() {
        return mPending ? mDeadline : -1;
    }

    /** Whole seconds left for the countdown, rounded up, 0 when nothing is pending. */
    public int secondsLeft() {
        if (!mPending) return 0;
        long left = mDeadline - mClock.uptimeMillis();
        return left <= 0 ? 0 : (int) ((left + 999) / 1000);
    }

    /** The mode on the display now, null for normal. */
    public DisplayModes.Mode applied() {
        return mApplied;
    }

    /** The mode a revert goes back to, null for normal. */
    public DisplayModes.Mode confirmed() {
        return mConfirmed;
    }
}
