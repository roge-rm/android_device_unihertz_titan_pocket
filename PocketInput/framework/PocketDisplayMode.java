/*
 * SPDX-License-Identifier: Apache-2.0
 */
package com.android.server.policy;

import android.app.ActivityManager;
import android.app.AlertDialog;
import android.content.BroadcastReceiver;
import android.content.ContentResolver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.database.ContentObserver;
import android.graphics.Point;
import android.hardware.display.DisplayManager;
import android.os.Environment;
import android.os.Handler;
import android.os.RemoteException;
import android.os.SystemClock;
import android.provider.Settings;
import android.util.AtomicFile;
import android.util.Slog;
import android.view.ContextThemeWrapper;
import android.view.Display;
import android.view.DisplayInfo;
import android.view.Gravity;
import android.view.IWindowManager;
import android.view.Window;
import android.view.WindowManager;
import android.view.WindowManagerGlobal;
import android.window.WindowContext;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;

import org.lineageos.pocketinput.DisplayModeBoot;
import org.lineageos.pocketinput.DisplayModeSwitch;
import org.lineageos.pocketinput.DisplayModes;

/**
 * Titan Pocket display modes (MINI_MODE_CONTRACT.md). Settings.Global pocket_display_mode
 * holds the active mode ID (pocket_display_mode_custom the custom size), written by the
 * Pocket keyboard app and its Quick Settings tile; this forces that mode's size and density
 * on the default display, as stock's MiniModeController does.
 *
 * Every switch from the settings asks "Keep this display mode?" in a system dialog, shown
 * once the new size is on. DisplayModeSwitch (PocketInputCore) holds the state and the 10 s
 * timer runs here, so it reverts without the dialog or the app; Revert, the timeout and
 * screen off put back the last kept mode and write the settings back to it. Boot, the key
 * combo and a user switch go to normal without asking.
 *
 * Each kept mode is saved in pocket_display_mode_kept. With pocket_display_mode_boot 1,
 * systemReady puts it on without asking instead of normal (DisplayModeBoot), unless it's safe
 * mode, the red key was held or the crash guard trips; the guard's count is a file in
 * /data/system, written with fsync so it survives a crash.
 *
 * Density is per user. When a mode first goes on, pocket_display_mode_restore keeps
 * "user saved mode": the user who turned it on, their own forced density before it (Display
 * size in Settings, 0 for none) and the density the mode set. Back to normal clears the
 * forced size and, for that user, puts the saved density back unless they changed it since,
 * then empties the key, meaning nothing to undo. Everything runs on the PocketKeyHooks
 * thread, the dialog too.
 *
 * A revert leaves the settings alone if they changed since the switch began, so a pick racing
 * the timeout starts its own switch. ACTION_SHUTDOWN clears the crash guard's count.
 */
final class PocketDisplayMode implements DisplayModeSwitch.Sink, DisplayModeBoot.Store {
    private static final String TAG = "PocketDisplayMode";
    private static final String RESTORE = "pocket_display_mode_restore";
    private static final int DISPLAY = Display.DEFAULT_DISPLAY;
    /** Above the lock screen, as the legacy power menu. */
    private static final int DIALOG_TYPE = WindowManager.LayoutParams.TYPE_KEYGUARD_DIALOG;
    /** Wait up to 20 x 100 ms for the new size before showing the dialog anyway. */
    private static final int SHOW_TRIES = 20;
    private static final long SHOW_POLL_MILLIS = 100;
    private static final String STARTS_FILE = "pocket_display_mode_starts";

    private final Context mContext;
    private final ContentResolver mResolver;
    private final Handler mHandler;
    private final DisplayModeSwitch mSwitch;
    private final Runnable mTimer = this::onTimer;
    private final Runnable mShow = this::showWhenReady;
    private final Runnable mTick = this::tick;
    private final DisplayModeBoot mBoot;
    private final Runnable mStable = this::onStable;
    private final AtomicFile mStarts;
    private AlertDialog mDialog;
    private Context mDialogContext;
    private int mShowTries;

    /** context is PhoneWindowManager's, the system UI context of the default display. */
    PocketDisplayMode(Context context, Handler handler) {
        mContext = context;
        mResolver = context.getContentResolver();
        mHandler = handler;
        mSwitch = new DisplayModeSwitch(SystemClock::uptimeMillis, this);
        mBoot = new DisplayModeBoot(SystemClock::uptimeMillis, this);
        mStarts = new AtomicFile(new File(Environment.getDataSystemDirectory(), STARTS_FILE));
    }

    /**
     * The kept mode or normal at boot, then follow the settings. Call once settings and
     * WindowManager work. keyHeld: the red key was down during boot.
     */
    void systemReady(boolean safeMode, boolean keyHeld) {
        DisplayModes.Mode kept = DisplayModes.kept(
                Settings.Global.getString(mResolver, DisplayModes.KEPT_SETTING));
        boolean bootOn = Settings.Global.getInt(mResolver, DisplayModeBoot.SETTING, 0) == 1;
        DisplayModeBoot.Outcome outcome = mBoot.start(bootOn, kept, safeMode, keyHeld);
        Slog.i(TAG, "Boot display mode: " + outcome + (bootOn ? ", kept " + kept : ""));
        if (outcome == DisplayModeBoot.Outcome.NORMAL) {
            mSwitch.force(null);
        } else {
            mSwitch.boot(outcome == DisplayModeBoot.Outcome.APPLY ? kept : null);
        }
        if (mBoot.stableAt() >= 0) mHandler.postAtTime(mStable, mBoot.stableAt());
        ContentObserver observer = new ContentObserver(mHandler) {
            @Override public void onChange(boolean selfChange) { settingsChanged(); }
        };
        mResolver.registerContentObserver(Settings.Global.getUriFor(DisplayModes.SETTING), false,
                observer);
        mResolver.registerContentObserver(
                Settings.Global.getUriFor(DisplayModes.CUSTOM_SETTING), false, observer);
        // ShutdownThread sends this on every shutdown and reboot, never on a crash.
        mContext.registerReceiver(new BroadcastReceiver() {
            @Override public void onReceive(Context context, Intent intent) {
                mHandler.removeCallbacks(mStable);
                mBoot.shutdown();
            }
        }, new IntentFilter(Intent.ACTION_SHUTDOWN), null, mHandler);
    }

    /** The key combo: normal at once, applied directly in case the observer is stuck. */
    void restoreNormal() {
        Slog.i(TAG, "Key combo, back to the normal display");
        mSwitch.force(null);
        schedule();
    }

    /** A user switch: a mode is for the user who turned it on, so back to normal. */
    void userSwitched() {
        mSwitch.force(null);
        schedule();
    }

    /** Screen off while asking reverts. */
    void screenOff() {
        mSwitch.screenOff();
        schedule();
    }

    private void onStable() {
        mBoot.onTimer();
        if (mBoot.stableAt() >= 0) mHandler.postAtTime(mStable, mBoot.stableAt());
    }

    @Override public int starts() {
        try {
            if (!mStarts.exists()) return 0;
            return Integer.parseInt(new String(mStarts.readFully(), StandardCharsets.UTF_8).trim());
        } catch (IOException | NumberFormatException e) {
            Slog.w(TAG, "Bad " + STARTS_FILE + ", counted as 0", e);
            return 0;
        }
    }

    /** AtomicFile.finishWrite syncs the file, so the count is on disk before the mode goes on. */
    @Override public void setStarts(int starts) {
        if (starts == 0) {
            mStarts.delete();
            return;
        }
        FileOutputStream out = null;
        try {
            out = mStarts.startWrite();
            out.write(Integer.toString(starts).getBytes(StandardCharsets.UTF_8));
            mStarts.finishWrite(out);
        } catch (IOException e) {
            Slog.w(TAG, "Couldn't write " + STARTS_FILE, e);
            mStarts.failWrite(out);
        }
    }

    @Override public void disableBoot() {
        Slog.w(TAG, "System server started again twice after the boot display mode, turning "
                + DisplayModeBoot.SETTING + " off");
        Settings.Global.putInt(mResolver, DisplayModeBoot.SETTING, 0);
    }

    private void settingsChanged() {
        mSwitch.request(DisplayModes.resolve(
                Settings.Global.getString(mResolver, DisplayModes.SETTING),
                Settings.Global.getString(mResolver, DisplayModes.CUSTOM_SETTING)));
        schedule();
    }

    private void schedule() {
        mHandler.removeCallbacks(mTimer);
        long at = mSwitch.deadline();
        if (at >= 0) mHandler.postAtTime(mTimer, at);
    }

    private void onTimer() {
        mSwitch.onTimer();
        if (!mSwitch.pending()) Slog.i(TAG, "Display mode not kept, reverted");
        schedule();
    }

    @Override public void apply(DisplayModes.Mode mode) {
        if (mode == null) {
            restore();
        } else {
            applyMode(mode);
        }
    }

    /** Settings back to the mode; our own observer then finds nothing to change. */
    @Override public void store(DisplayModes.Mode mode) {
        if (mode != null && DisplayModes.CUSTOM.equals(mode.id)) {
            putIfChanged(DisplayModes.CUSTOM_SETTING, DisplayModes.customValue(mode));
        }
        putIfChanged(DisplayModes.SETTING, mode != null ? mode.id : DisplayModes.NORMAL);
    }

    @Override public void revertStore(DisplayModes.Mode mode, DisplayModes.Mode asked) {
        DisplayModes.Mode now = DisplayModes.resolve(
                Settings.Global.getString(mResolver, DisplayModes.SETTING),
                Settings.Global.getString(mResolver, DisplayModes.CUSTOM_SETTING));
        boolean unchanged = asked == null ? now == null
                : now != null && now.id.equals(asked.id) && DisplayModes.same(now, asked);
        if (unchanged) {
            store(mode);
        } else {
            Slog.i(TAG, "Display mode changed while reverting, left as " + now);
        }
    }

    @Override public void remember(DisplayModes.Mode mode) {
        putIfChanged(DisplayModes.KEPT_SETTING, DisplayModes.keptValue(mode));
    }

    private void putIfChanged(String key, String value) {
        if (!value.equals(Settings.Global.getString(mResolver, key))) {
            Settings.Global.putString(mResolver, key, value);
        }
    }

    @Override public void showDialog() {
        dismissDialog();
        mShowTries = 0;
        mHandler.post(mShow);
    }

    @Override public void hideDialog() {
        dismissDialog();
    }

    /** Shows the dialog once the display has the new size and density, so it's laid out in it. */
    private void showWhenReady() {
        if (!mSwitch.pending()) return;
        if (!displayReady() && ++mShowTries < SHOW_TRIES) {
            mHandler.postDelayed(mShow, SHOW_POLL_MILLIS);
            return;
        }
        try {
            // A window context takes the display's configuration now, with the new density.
            mDialogContext = mContext.createWindowContext(DIALOG_TYPE, null);
            Context themed = new ContextThemeWrapper(mDialogContext,
                    com.android.internal.R.style.Theme_DeviceDefault_Dialog_Alert_DayNight);
            mDialog = new AlertDialog.Builder(themed)
                    .setTitle("Keep this display mode?")
                    .setMessage(countdown())
                    .setPositiveButton("Keep", (d, which) -> {
                        mSwitch.keep();
                        schedule();
                    })
                    .setNegativeButton("Revert", (d, which) -> {
                        mSwitch.revert();
                        schedule();
                    })
                    .setOnCancelListener(d -> {
                        mSwitch.revert();
                        schedule();
                    })
                    .create();
            mDialog.setCanceledOnTouchOutside(false);
            Window window = mDialog.getWindow();
            window.setType(DIALOG_TYPE);
            window.setGravity(Gravity.CENTER);
            window.addSystemFlags(WindowManager.LayoutParams.SYSTEM_FLAG_SHOW_FOR_ALL_USERS);
            mDialog.show();
            scheduleTick();
        } catch (RuntimeException e) {
            // The timer still reverts.
            Slog.w(TAG, "Couldn't show the display mode dialog", e);
            dismissDialog();
        }
    }

    /** The display has the forced (or initial) size and density WindowManager now has. */
    private boolean displayReady() {
        try {
            IWindowManager wm = WindowManagerGlobal.getWindowManagerService();
            DisplayManager displays = mContext.getSystemService(DisplayManager.class);
            Display display = displays != null ? displays.getDisplay(DISPLAY) : null;
            if (wm == null || display == null) return true;
            Point base = new Point();
            wm.getBaseDisplaySize(DISPLAY, base);
            DisplayInfo info = new DisplayInfo();
            if (!display.getDisplayInfo(info)) return true;
            return info.logicalWidth == base.x && info.logicalHeight == base.y
                    && info.logicalDensityDpi == wm.getBaseDisplayDensity(DISPLAY);
        } catch (RemoteException | RuntimeException e) {
            return true;
        }
    }

    private String countdown() {
        return "Going back in " + mSwitch.secondsLeft() + " s.";
    }

    /** Updates the countdown on each whole second left. */
    private void tick() {
        if (mDialog == null || !mSwitch.pending()) return;
        mDialog.setMessage(countdown());
        scheduleTick();
    }

    private void scheduleTick() {
        mHandler.removeCallbacks(mTick);
        int left = mSwitch.secondsLeft();
        if (left > 0) mHandler.postAtTime(mTick, mSwitch.deadline() - (left - 1) * 1000L);
    }

    private void dismissDialog() {
        mHandler.removeCallbacks(mShow);
        mHandler.removeCallbacks(mTick);
        if (mDialog != null) {
            try {
                mDialog.dismiss();
            } catch (RuntimeException e) {
                Slog.w(TAG, "Couldn't dismiss the display mode dialog", e);
            }
            mDialog = null;
        }
        if (mDialogContext instanceof WindowContext) ((WindowContext) mDialogContext).release();
        mDialogContext = null;
    }

    private void applyMode(DisplayModes.Mode mode) {
        IWindowManager wm = WindowManagerGlobal.getWindowManagerService();
        if (wm == null) return;
        int user = ActivityManager.getCurrentUser();
        int[] saved = saved();
        if (saved != null && saved[0] != user) {
            restore();
            saved = null;
        }
        Settings.Global.putString(mResolver, RESTORE, user + " "
                + (saved != null ? saved[1] : forcedDensity(user)) + " " + mode.density);
        try {
            Slog.i(TAG, "Display mode " + mode + " for user " + user);
            wm.setForcedDisplaySize(DISPLAY, mode.width, mode.height);
            wm.setForcedDisplayDensityForUser(DISPLAY, mode.density, user);
        } catch (RemoteException | RuntimeException e) {
            Slog.w(TAG, "Couldn't set display mode " + mode.id, e);
        }
    }

    /** Clear the forced size, and put back the density of the user a mode was on for. */
    private void restore() {
        IWindowManager wm = WindowManagerGlobal.getWindowManagerService();
        if (wm == null) return;
        try {
            Point base = new Point(), initial = new Point();
            wm.getBaseDisplaySize(DISPLAY, base);
            wm.getInitialDisplaySize(DISPLAY, initial);
            if (!base.equals(initial)) wm.clearForcedDisplaySize(DISPLAY);
            int[] saved = saved();
            if (saved == null) return;
            int user = saved[0];
            // A Display size picked while the mode was on stays. WindowManager stores a forced
            // density equal to the initial one as none, so 0 counts as the initial density.
            int initialDensity = wm.getInitialDisplayDensity(DISPLAY);
            int forced = forcedDensity(user);
            if ((forced > 0 ? forced : initialDensity) == saved[2]) {
                if (saved[1] > 0) {
                    wm.setForcedDisplayDensityForUser(DISPLAY, saved[1], user);
                } else {
                    wm.clearForcedDisplayDensityForUser(DISPLAY, user);
                }
            }
            Settings.Global.putString(mResolver, RESTORE, "");
            Slog.i(TAG, "Normal display for user " + user);
        } catch (RemoteException | RuntimeException e) {
            Slog.w(TAG, "Couldn't restore the normal display", e);
        }
    }

    /** {user, saved density, mode density} from RESTORE, or null when nothing is left to undo. */
    private int[] saved() {
        String value = Settings.Global.getString(mResolver, RESTORE);
        if (value == null || value.isEmpty()) return null;
        String[] parts = value.split(" ");
        try {
            if (parts.length == 3) {
                return new int[] {Integer.parseInt(parts[0]), Integer.parseInt(parts[1]),
                        Integer.parseInt(parts[2])};
            }
        } catch (NumberFormatException e) {
            // Falls through.
        }
        Slog.w(TAG, "Bad " + RESTORE + " " + value + ", dropped");
        Settings.Global.putString(mResolver, RESTORE, "");
        return null;
    }

    /** The user's forced density (Display size in Settings), 0 for none. */
    private int forcedDensity(int user) {
        String value = Settings.Secure.getStringForUser(mResolver,
                Settings.Secure.DISPLAY_DENSITY_FORCED, user);
        try {
            return value == null || value.isEmpty() ? 0 : Integer.parseInt(value);
        } catch (NumberFormatException e) {
            return 0;
        }
    }
}
