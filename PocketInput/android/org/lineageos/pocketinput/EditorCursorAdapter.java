// SPDX-License-Identifier: Apache-2.0
package org.lineageos.pocketinput;

import android.text.InputType;
import android.view.KeyEvent;
import android.view.inputmethod.EditorInfo;
import android.view.inputmethod.InputConnection;
import java.util.Objects;

/**
 * An IME-owned adapter, called on the IME event thread. It needs no input injection
 * permission. A device service must not retain another IME's connection or bypass it.
 */
public final class EditorCursorAdapter implements KeyboardController.Sink {
    public interface DeviceEffects {
        void setBacklight(boolean on);
        void scroll(double delta);
        void runShortcut(String action);
    }
    private final DeviceEffects effects;
    private InputConnection connection;
    private boolean cursorAllowed;

    public EditorCursorAdapter(DeviceEffects effects) {
        this.effects = Objects.requireNonNull(effects);
    }
    /** Pass the owning IME's current connection; call again for every editor change. */
    public void bind(KeyboardController controller, InputConnection connection,
            EditorInfo info, boolean unlocked, boolean sensitiveOverride) {
        int type = info == null ? InputType.TYPE_NULL : info.inputType;
        int cls = type & InputType.TYPE_MASK_CLASS;
        int variation = type & InputType.TYPE_MASK_VARIATION;
        boolean sensitive = sensitiveOverride
                || (cls == InputType.TYPE_CLASS_TEXT
                    && (variation == InputType.TYPE_TEXT_VARIATION_PASSWORD
                        || variation == InputType.TYPE_TEXT_VARIATION_VISIBLE_PASSWORD
                        || variation == InputType.TYPE_TEXT_VARIATION_WEB_PASSWORD))
                || (cls == InputType.TYPE_CLASS_NUMBER
                    && variation == InputType.TYPE_NUMBER_VARIATION_PASSWORD);
        boolean editor = connection != null && cls != InputType.TYPE_NULL;
        this.connection = editor ? connection : null;
        cursorAllowed = editor && unlocked && !sensitive;
        controller.setContext(editor, sensitive, unlocked);
    }
    public void unbind(KeyboardController controller) {
        connection = null;
        cursorAllowed = false;
        controller.setContext(false, false, false);
    }
    @Override public void moveCursor(int steps) {
        InputConnection target = connection;
        if (!cursorAllowed || target == null || steps == 0) return;
        int key = steps > 0 ? KeyEvent.KEYCODE_DPAD_RIGHT : KeyEvent.KEYCODE_DPAD_LEFT;
        // Bound work even if a future caller supplies an invalid large step count.
        int count = (int) Math.min(32L, Math.abs((long) steps));
        target.beginBatchEdit();
        try {
            for (int i = 0; i < count; i++) {
                boolean down = target.sendKeyEvent(new KeyEvent(KeyEvent.ACTION_DOWN, key));
                boolean up = target.sendKeyEvent(new KeyEvent(KeyEvent.ACTION_UP, key));
                if (!down || !up) break;
            }
        } finally {
            target.endBatchEdit();
        }
    }
    @Override public void setBacklight(boolean on) { effects.setBacklight(on); }
    @Override public void scroll(double delta) { effects.scroll(delta); }
    @Override public void runShortcut(String action) { effects.runShortcut(action); }
}
