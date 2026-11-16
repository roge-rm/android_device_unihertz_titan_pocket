/*
 * SPDX-License-Identifier: Apache-2.0
 */
package com.android.server.policy;

import android.app.KeyguardManager;
import android.app.StatusBarManager;
import android.content.ActivityNotFoundException;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.database.ContentObserver;
import android.database.Cursor;
import android.hardware.input.InputManager;
import android.net.Uri;
import android.os.Handler;
import android.os.HandlerThread;
import android.os.PowerManager;
import android.os.IBinder;
import android.os.Process;
import android.os.ServiceManager;
import android.os.SystemClock;
import android.os.SystemProperties;
import android.os.UserHandle;
import android.provider.DeviceConfig;
import android.provider.Settings;
import android.util.Slog;
import android.util.SparseArray;
import android.view.InputDevice;
import android.view.KeyEvent;

import com.android.server.LocalServices;
import com.android.server.input.InputManagerService;
import com.android.server.lights.LightsManager;
import com.android.server.lights.LogicalLight;

import org.lineageos.pocketinput.KeyboardSettings;
import org.lineageos.pocketinput.KeyboardSettingsCodec;
import org.lineageos.pocketinput.PocketKeyPolicy;

import lineageos.providers.LineageSettings;

/**
 * Titan Pocket keyboard keys in every app (packages/PocketInput, KEYBOARD_PORT.md):
 * the keyboard light, FUNC1 and FUNC2 short and long presses, the pad key guard, and
 * FUNC1+FUNC2 held to restore the normal display mode (PocketDisplayMode).
 * Only made when ro.pocket.input_policy is true.
 *
 * interceptKeyBeforeQueueing runs on the input dispatcher thread and only decides under
 * the lock; the light, actions, timers and settings run on our own thread.
 */
public final class PocketKeyHooks {
    private static final String TAG = "PocketKeys";
    private static final String ENABLE_PROP = "ro.pocket.input_policy";
    private static final String PAD_GUARD_PROP = "sys.pocket.pad_guard";
    /** FUNC2, the red side key, on mtk-kpd (mtk-kpd.kl maps it to F14). */
    private static final int RED_KEY_SCAN_CODE = 250;
    private static final Uri SETTINGS =
            Uri.parse("content://org.lineageos.pocketinput.settings/configuration");

    private final Context mContext;
    private final Runnable mToggleTorch;
    private final Handler mHandler;
    private final PocketKeyPolicy mPolicy;
    /** Device ID to source, filled on first sight. IDs aren't reused while running. */
    private final SparseArray<PocketKeyPolicy.Source> mSources = new SparseArray<>();
    private final Runnable mTimer = this::onTimer;
    private final PocketTorch mTorch;
    private final PocketDisplayMode mDisplayMode;
    private LogicalLight mLight;
    /** The red key went down before systemReady. Set on the input dispatcher thread. */
    private volatile boolean mRedKeySeen;
    private volatile boolean mSystemReady;

    /** PowerManagerService leaves the button light to us when this is true. */
    public static boolean ownsButtonLight() {
        return SystemProperties.getBoolean(ENABLE_PROP, false);
    }

    static PocketKeyHooks create(Context context, Runnable toggleTorch) {
        return ownsButtonLight() ? new PocketKeyHooks(context, toggleTorch) : null;
    }

    private PocketKeyHooks(Context context, Runnable toggleTorch) {
        mContext = context;
        mToggleTorch = toggleTorch;
        HandlerThread thread = new HandlerThread(TAG, Process.THREAD_PRIORITY_DISPLAY);
        thread.start();
        mHandler = new Handler(thread.getLooper());
        mTorch = new PocketTorch(context, mHandler);
        mDisplayMode = new PocketDisplayMode(context, mHandler);
        // Defaults (light on, 3.5 s) until the settings app answers.
        mPolicy = new PocketKeyPolicy(KeyboardSettings.defaults(), SystemClock::uptimeMillis,
                new PocketKeyPolicy.Sink() {
                    @Override public void setLight(boolean on) {
                        mHandler.post(() -> writeLight(on));
                    }
                    @Override public void runAction(String action) {
                        mHandler.post(() -> run(action));
                    }
                    @Override public void restoreDisplay() {
                        mHandler.post(mDisplayMode::restoreNormal);
                    }
                });
    }

    /**
     * The boot display mode, normal or the kept one, before the launcher starts, then follow
     * its setting. safeMode is PhoneWindowManager's.
     */
    void systemReady(boolean safeMode) {
        boolean redKey = redKeyDown() || mRedKeySeen;
        mSystemReady = true;
        mHandler.post(() -> {
            try {
                mDisplayMode.systemReady(safeMode, redKey);
            } catch (RuntimeException e) {
                Slog.w(TAG, "Display mode not started", e);
            }
        });
    }

    /**
     * Whether the red key is down now, from the kernel's key state of the keypad. Input devices
     * are open by now: WindowManager waits for them when it checks for safe mode keys, earlier.
     * InputManagerService is in this process, so its binder is the service object itself.
     */
    private boolean redKeyDown() {
        try {
            IBinder binder = ServiceManager.getService(Context.INPUT_SERVICE);
            if (!(binder instanceof InputManagerService)) return false;
            InputManagerService service = (InputManagerService) binder;
            InputManager input = mContext.getSystemService(InputManager.class);
            if (input != null) {
                for (int id : input.getInputDeviceIds()) {
                    InputDevice device = input.getInputDevice(id);
                    if (device != null && "mtk-kpd".equals(device.getName())) {
                        return service.getScanCodeState(id, InputDevice.SOURCE_ANY,
                                RED_KEY_SCAN_CODE) > 0;
                    }
                }
            }
            return service.getKeyCodeState(-1, InputDevice.SOURCE_ANY, KeyEvent.KEYCODE_F14) > 0;
        } catch (RuntimeException e) {
            Slog.w(TAG, "Couldn't read the red key", e);
            return false;
        }
    }

    /**
     * Once per device: the battery light stays on green when full, as stock. Lineage turns it
     * off when full unless battery_light_full_charge_disabled is 0. A choice already made in
     * Settings is kept, and the marker stops this running again.
     */
    private void seedBatteryLight() {
        final String marker = "pocket_battery_light_seeded";
        final String key = LineageSettings.System.BATTERY_LIGHT_FULL_CHARGE_DISABLED;
        try {
            if (Settings.Global.getInt(mContext.getContentResolver(), marker, 0) == 1) return;
            if (LineageSettings.System.getStringForUser(mContext.getContentResolver(), key,
                    UserHandle.USER_SYSTEM) == null) {
                LineageSettings.System.putIntForUser(mContext.getContentResolver(), key, 0,
                        UserHandle.USER_SYSTEM);
            }
            Settings.Global.putInt(mContext.getContentResolver(), marker, 1);
        } catch (RuntimeException e) {
            Slog.w(TAG, "Battery light setting not seeded", e);
        }
    }

    /**
     * Once per device: SystemUI's falsing check wants a 1.5 in swipe to unlock, 68 % of this
     * 720 px screen, so lock screen swipes often fail. 0.5 in or 40 % of the screen is enough.
     * Values already set are kept, and the marker stops this running again.
     */
    private void seedSwipeDistance() {
        final String marker = "pocket_swipe_distance_seeded";
        try {
            if (Settings.Global.getInt(mContext.getContentResolver(), marker, 0) == 1) return;
            seedSystemUi("brightline_falsing_distance_vertical_fling_threshold_in", "0.5");
            seedSystemUi("brightline_falsing_distance_screen_fraction_max_distance", "0.4");
            Settings.Global.putInt(mContext.getContentResolver(), marker, 1);
        } catch (RuntimeException e) {
            Slog.w(TAG, "Swipe distance not seeded", e);
        }
    }

    private static void seedSystemUi(String name, String value) {
        if (DeviceConfig.getProperty(DeviceConfig.NAMESPACE_SYSTEMUI, name) == null) {
            DeviceConfig.setProperty(DeviceConfig.NAMESPACE_SYSTEMUI, name, value, false);
        }
    }

    /** Settings, screen off and user switches, once providers and broadcasts work. */
    void systemBooted() {
        mHandler.post(() -> {
            mContext.getContentResolver().registerContentObserver(SETTINGS, false,
                    new ContentObserver(mHandler) {
                        @Override public void onChange(boolean selfChange) { loadSettings(); }
                    }, UserHandle.USER_SYSTEM);
            mContext.registerReceiver(new BroadcastReceiver() {
                @Override public void onReceive(Context context, Intent intent) {
                    synchronized (mPolicy) {
                        mPolicy.setInteractive(false);
                    }
                    schedule();
                    mDisplayMode.screenOff();
                }
            }, new IntentFilter(Intent.ACTION_SCREEN_OFF), null, mHandler);
            mContext.registerReceiver(new BroadcastReceiver() {
                @Override public void onReceive(Context context, Intent intent) {
                    mDisplayMode.userSwitched();
                }
            }, new IntentFilter(Intent.ACTION_USER_SWITCHED), null, mHandler);
            loadSettings();
            mTorch.systemBooted();
            seedBatteryLight();
            seedSwipeDistance();
        });
    }

    /**
     * PhoneWindowManager's torch toggle (the flashlight action, power long press).
     * Returns false when there is no torch LED, so it falls back to the camera.
     */
    boolean toggleTorch() {
        return mTorch.toggle();
    }

    /** Returns true to drop the event. Injected and virtual keys are left alone. */
    boolean interceptKeyBeforeQueueing(KeyEvent event, int policyFlags, boolean interactive) {
        if ((policyFlags & WindowManagerPolicy.FLAG_INJECTED) != 0) return false;
        PocketKeyPolicy.Source source = source(event.getDeviceId());
        if (source == PocketKeyPolicy.Source.OTHER) return false;
        int keyCode = event.getKeyCode();
        boolean bootHold = !mSystemReady && source == PocketKeyPolicy.Source.KEYPAD
                && keyCode == KeyEvent.KEYCODE_F14 && event.getAction() == KeyEvent.ACTION_DOWN;
        if (bootHold) mRedKeySeen = true;
        boolean drop;
        synchronized (mPolicy) {
            if (event.getAction() == KeyEvent.ACTION_DOWN) {
                drop = mPolicy.onKeyDown(source, keyCode, event.getRepeatCount() != 0,
                        event.getEventTime(), interactive,
                        () -> SystemProperties.get(PAD_GUARD_PROP, ""));
                // The red key held at boot only picks a normal boot, so its press runs nothing.
                if (bootHold) mPolicy.cancelHold(keyCode);
            } else if (event.getAction() == KeyEvent.ACTION_UP) {
                drop = mPolicy.onKeyUp(source, keyCode, event.isCanceled());
            } else {
                drop = false;
            }
        }
        schedule();
        return drop;
    }

    private PocketKeyPolicy.Source source(int deviceId) {
        synchronized (mSources) {
            PocketKeyPolicy.Source known = mSources.get(deviceId);
            if (known != null) return known;
        }
        PocketKeyPolicy.Source source = PocketKeyPolicy.Source.OTHER;
        InputManager input = mContext.getSystemService(InputManager.class);
        InputDevice device = input != null ? input.getInputDevice(deviceId) : null;
        if (device == null) return source;
        if (!device.isVirtual() && !device.isExternal()) {
            if ("aw9523-key".equals(device.getName())) source = PocketKeyPolicy.Source.KEYBOARD;
            else if ("mtk-kpd".equals(device.getName())) source = PocketKeyPolicy.Source.KEYPAD;
        }
        synchronized (mSources) {
            mSources.put(deviceId, source);
        }
        return source;
    }

    /** Under the lock, so two threads can't leave a stale timer. */
    private void schedule() {
        synchronized (mPolicy) {
            long at = mPolicy.nextTimerMillis();
            mHandler.removeCallbacks(mTimer);
            if (at >= 0) mHandler.postAtTime(mTimer, at);
        }
    }

    private void onTimer() {
        synchronized (mPolicy) {
            mPolicy.onTimer(SystemClock.uptimeMillis());
        }
        schedule();
    }

    /** The lights HAL's BUTTONS light, /sys/class/leds/button-backlight on this phone. */
    private void writeLight(boolean on) {
        if (mLight == null) {
            LightsManager lights = LocalServices.getService(LightsManager.class);
            if (lights != null) mLight = lights.getLight(LightsManager.LIGHT_ID_BUTTONS);
            if (mLight == null) return;
        }
        mLight.setBrightness(on ? PowerManager.BRIGHTNESS_MAX : PowerManager.BRIGHTNESS_OFF_FLOAT);
    }

    private void loadSettings() {
        KeyboardSettings settings = null;
        try (Cursor cursor = mContext.getContentResolver().query(SETTINGS, null, null, null, null)) {
            if (cursor != null && cursor.moveToFirst()) {
                settings = KeyboardSettingsCodec.decode(cursor.getString(0));
            }
        } catch (RuntimeException e) {
            Slog.w(TAG, "Pocket keyboard settings unavailable, keeping the last ones", e);
        }
        if (settings == null) return;
        synchronized (mPolicy) {
            mPolicy.setSettings(settings);
        }
        schedule();
    }

    /** Registered action IDs, the same names the settings app saves. */
    private void run(String action) {
        if ("flashlight".equals(action)) {
            mToggleTorch.run();
            return;
        }
        KeyguardManager keyguard = mContext.getSystemService(KeyguardManager.class);
        if (keyguard == null || keyguard.isKeyguardLocked()) return;
        if ("notifications".equals(action)) {
            StatusBarManager bar = mContext.getSystemService(StatusBarManager.class);
            if (bar != null) bar.expandNotificationsPanel();
            return;
        }
        Intent intent;
        if ("browser".equals(action)) {
            intent = Intent.makeMainSelectorActivity(Intent.ACTION_MAIN, Intent.CATEGORY_APP_BROWSER);
        } else if ("camera".equals(action)) {
            // MediaStore.INTENT_ACTION_STILL_IMAGE_CAMERA; MediaStore is in an apex services.core doesn't link.
            intent = new Intent("android.media.action.STILL_IMAGE_CAMERA");
        } else if ("settings".equals(action)) {
            intent = new Intent(Settings.ACTION_SETTINGS);
        } else {
            return;
        }
        intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
        try {
            mContext.startActivityAsUser(intent, UserHandle.CURRENT);
        } catch (ActivityNotFoundException | SecurityException e) {
            Slog.w(TAG, "No activity for " + action);
        }
    }
}
