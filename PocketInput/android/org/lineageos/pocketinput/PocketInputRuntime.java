// SPDX-License-Identifier: Apache-2.0
package org.lineageos.pocketinput;

import android.app.KeyguardManager;
import android.content.Context;
import android.content.Intent;
import android.database.ContentObserver;
import android.database.Cursor;
import android.net.Uri;
import android.os.Handler;
import android.os.Looper;
import android.os.PowerManager;
import android.os.SystemClock;
import android.provider.MediaStore;
import android.provider.Settings;
import android.util.Log;
import android.view.InputDevice;
import android.view.KeyEvent;
import android.view.inputmethod.EditorInfo;
import android.view.inputmethod.InputConnection;
import java.io.IOException;

/** IME-owned runtime. Framework routing of global pad gestures is a separate hook. */
public final class PocketInputRuntime implements AutoCloseable {
    private static final String TAG = "PocketInput";
    private static final Uri SETTINGS = Uri.parse("content://org.lineageos.pocketinput.settings/configuration");
    private final Context context;
    private final Handler handler = new Handler(Looper.getMainLooper());
    private final EditorCursorAdapter editor;
    private final KeyboardController controller;
    private final ContentObserver observer;
    private final Runnable timer;
    private final KeyboardLightWriter light = new KeyboardLightWriter();
    private boolean closed;
    private InputConnection currentConnection;
    private EditorInfo currentInfo;
    private boolean currentSensitive;

    public PocketInputRuntime(Context context) {
        this.context = context;
        editor = new EditorCursorAdapter(new EditorCursorAdapter.DeviceEffects() {
            @Override public void setBacklight(boolean on) {
                try { light.set(on); } catch (IOException e) { Log.w(TAG, "Keyboard light backend unavailable"); }
            }
            @Override public void scroll(double delta) { /* Requires framework scroll routing. */ }
            @Override public void runShortcut(String action) { launch(action); }
        });
        controller = new KeyboardController(load(), SystemClock::uptimeMillis, editor);
        // The framework hook (PocketKeyHooks) owns the light, so the IME never writes it.
        controller.setLightingPermitted(false);
        timer = () -> { if (!closed) { controller.onTimer(); schedule(); } };
        observer = new ContentObserver(handler) {
            @Override public void onChange(boolean selfChange) { if (!closed) { controller.setSettings(load()); schedule(); } }
        };
        context.getContentResolver().registerContentObserver(SETTINGS, false, observer);
    }
    private KeyboardSettings load() {
        try (Cursor cursor = context.getContentResolver().query(SETTINGS, null, null, null, null)) {
            if (cursor != null && cursor.moveToFirst()) return KeyboardSettingsCodec.decode(cursor.getString(0));
        } catch (IllegalArgumentException | SecurityException e) { Log.w(TAG, "Keyboard settings unavailable; using defaults"); }
        return KeyboardSettings.defaults();
    }
    public void bindEditor(InputConnection connection, EditorInfo info, boolean sensitiveOverride) {
        currentConnection = connection;currentInfo = info;currentSensitive = sensitiveOverride;
        PowerManager power = context.getSystemService(PowerManager.class);
        KeyguardManager keyguard = context.getSystemService(KeyguardManager.class);
        controller.setInteractive(power != null && power.isInteractive());
        editor.bind(controller, connection, info, keyguard != null && !keyguard.isKeyguardLocked(), sensitiveOverride);
    }
    public void finishEditor() { currentConnection = null;currentInfo = null;editor.unbind(controller); }
    public void setLightingPermitted(boolean permitted) { controller.setLightingPermitted(permitted); schedule(); }
    public boolean onKeyDown(KeyEvent event) {
        if (closed) return false;
        // The pad key guard and the keyboard light are in the framework hook (PocketKeyHooks).
        bindEditor(currentConnection, currentInfo, currentSensitive);
        boolean consumed = controller.onKeyDown(isPocketKeyboard(event), event.getKeyCode(), modifiers(event), event.getRepeatCount() != 0);
        schedule();return consumed;
    }
    public boolean onKeyUp(KeyEvent event) {
        if (closed) return false;
        return controller.onKeyUp(isPocketKeyboard(event), event.getKeyCode());
    }
    public void onPadDown(int pointer, int contacts, double x, double y) { if (!closed) { bindEditor(currentConnection, currentInfo, currentSensitive);controller.onPadDown(true, pointer, contacts, x, y); } }
    public void onPadMove(int pointer, int contacts, double x, double y) { if (!closed && unlockedAndInteractive()) controller.onPadMove(pointer, contacts, x, y); else controller.onPadUp(); }
    public void onPadUp() { controller.onPadUp(); }
    public void startEditor(InputConnection connection, EditorInfo info, boolean sensitiveOverride) { bindEditor(connection, info, sensitiveOverride); }
    public void screenOff() { controller.setInteractive(false);schedule(); }
    private static boolean isPocketKeyboard(KeyEvent event) {
        InputDevice device = event.getDevice();
        return device != null && !device.isVirtual() && "aw9523-key".equals(device.getName());
    }
    private static int modifiers(KeyEvent event) {
        return (event.isShiftPressed() ? KeyboardSettings.SHIFT : 0)
                | (event.isAltPressed() ? KeyboardSettings.ALT : 0)
                | (event.isCtrlPressed() ? KeyboardSettings.CTRL : 0)
                | (event.isMetaPressed() ? KeyboardSettings.META : 0);
    }
    private void schedule() {
        handler.removeCallbacks(timer);
        long deadline = controller.nextLightDeadlineMillis();
        if (!closed && deadline >= 0) handler.postAtTime(timer, deadline);
    }
    private boolean unlockedAndInteractive() {
        PowerManager power = context.getSystemService(PowerManager.class);
        KeyguardManager keyguard = context.getSystemService(KeyguardManager.class);
        return power != null && power.isInteractive() && keyguard != null && !keyguard.isKeyguardLocked();
    }
    private void launch(String action) {
        if (!unlockedAndInteractive()) return;
        Intent intent;
        if ("browser".equals(action)) intent = Intent.makeMainSelectorActivity(Intent.ACTION_MAIN, Intent.CATEGORY_APP_BROWSER);
        else if ("camera".equals(action)) intent = new Intent(MediaStore.INTENT_ACTION_STILL_IMAGE_CAMERA);
        else if ("settings".equals(action)) intent = new Intent(Settings.ACTION_SETTINGS);
        else return;
        try { context.startActivity(intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)); }
        catch (android.content.ActivityNotFoundException | SecurityException e) { Log.w(TAG, "Shortcut target unavailable"); }
    }
    @Override public void close() {
        if (closed) return;
        closed = true;context.getContentResolver().unregisterContentObserver(observer);
        handler.removeCallbacks(timer);controller.setInteractive(false);editor.unbind(controller);
    }
}
