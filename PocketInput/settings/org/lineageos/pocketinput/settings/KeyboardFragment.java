// SPDX-License-Identifier: Apache-2.0
package org.lineageos.pocketinput.settings;

import android.content.Context;
import android.content.Intent;
import android.os.Bundle;
import android.provider.Settings;
import android.widget.Toast;
import androidx.preference.ListPreference;
import androidx.preference.Preference;
import androidx.preference.TwoStatePreference;
import com.android.settingslib.widget.SettingsBasePreferenceFragment;
import java.util.HashMap;
import java.util.Map;
import org.lineageos.pocketinput.DisplayModes;
import org.lineageos.pocketinput.KeyboardSettings;
import org.lineageos.pocketinput.KeyboardSettingsCodec;
import org.lineageos.pocketinput.PocketKeyPolicy;

/**
 * Keyboard settings. Every change is saved at once in the provider's format; the IME and
 * PocketKeyHooks in system_server read it through KeyboardSettingsProvider.
 */
public final class KeyboardFragment extends SettingsBasePreferenceFragment
        implements Preference.OnPreferenceChangeListener {
    private static final String LIGHT = "light", TIMEOUT = "light_timeout", SWIPES = "swipes",
            CURSOR = "cursor_speed", DISPLAY = "display_mode";
    /** Alt+B, Alt+C and Alt+S (KEYCODE_B, KEYCODE_C, KEYCODE_S) and their actions. */
    private static final String[] SHORTCUT_KEYS = {"shortcut_browser", "shortcut_camera", "shortcut_settings"};
    private static final int[] SHORTCUT_CODES = {30, 31, 47};
    private static final String[] SHORTCUT_ACTIONS = {"browser", "camera", "settings"};
    /** FUNC1 and FUNC2 are F13 and F14 in our layouts. */
    private static final String[] PRESS_KEYS = {"func1_press", "func1_long_press", "func2_press", "func2_long_press"};
    private static final int[] PRESS_CODES = {PocketKeyPolicy.KEYCODE_F13, PocketKeyPolicy.KEYCODE_F13,
            PocketKeyPolicy.KEYCODE_F14, PocketKeyPolicy.KEYCODE_F14};
    private static final boolean[] PRESS_LONG = {false, true, false, true};
    private static final String NONE = "none";

    private KeyboardSettings mCurrent;

    @Override public void onCreatePreferences(Bundle state, String rootKey) {
        setPreferencesFromResource(R.xml.keyboard_settings, rootKey);
        mCurrent = load(requireContext());
        this.<TwoStatePreference>pref(LIGHT).setChecked(mCurrent.lightingEnabled);
        ListPreference timeout = pref(TIMEOUT);
        String millis = Long.toString(mCurrent.lightTimeoutMillis);
        timeout.setValue(timeout.findIndexOfValue(millis) >= 0 ? millis : "3500");
        this.<ListPreference>pref(SWIPES).setValue(mCurrent.swipeMode.name());
        double step = mCurrent.cursorStep;
        this.<ListPreference>pref(CURSOR).setValue(step >= 0.12 ? "0.16" : step <= 0.06 ? "0.04" : "0.08");
        for (int i = 0; i < SHORTCUT_KEYS.length; i++) {
            this.<TwoStatePreference>pref(SHORTCUT_KEYS[i]).setChecked(SHORTCUT_ACTIONS[i].equals(
                    mCurrent.shortcuts.get(new KeyboardSettings.Chord(SHORTCUT_CODES[i], KeyboardSettings.ALT))));
        }
        for (int i = 0; i < PRESS_KEYS.length; i++) {
            ListPreference press = pref(PRESS_KEYS[i]);
            String action = mCurrent.pressAction(PRESS_CODES[i], PRESS_LONG[i]);
            press.setValue(action != null && press.findIndexOfValue(action) >= 0 ? action : NONE);
        }
        String[] keys = {LIGHT, TIMEOUT, SWIPES, CURSOR};
        for (String key : keys) pref(key).setOnPreferenceChangeListener(this);
        for (String key : SHORTCUT_KEYS) pref(key).setOnPreferenceChangeListener(this);
        for (String key : PRESS_KEYS) pref(key).setOnPreferenceChangeListener(this);
        pref(DISPLAY).setIntent(new Intent(requireContext(), DisplayModeActivity.class));
    }

    @Override public void onResume() {
        super.onResume();
        String custom = Settings.Global.getString(requireContext().getContentResolver(),
                DisplayModes.CUSTOM_SETTING);
        pref(DISPLAY).setSummary(DisplayModes.choice(Settings.Global.getString(
                requireContext().getContentResolver(), DisplayModes.CHOICE_SETTING), custom).label);
    }

    private <T extends Preference> T pref(String key) {
        return findPreference(key);
    }

    static KeyboardSettings load(Context context) {
        try {
            return KeyboardSettingsCodec.decode(context.getSharedPreferences(KeyboardSettingsProvider.PREFS, 0)
                    .getString(KeyboardSettingsProvider.KEY, KeyboardSettingsCodec.encode(KeyboardSettings.defaults())));
        } catch (IllegalArgumentException e) {
            return KeyboardSettings.defaults();
        }
    }

    /** Saves the settings with this one change. Returning false keeps the old value on screen. */
    @Override public boolean onPreferenceChange(Preference preference, Object value) {
        String key = preference.getKey();
        KeyboardSettings.SwipeMode swipe = mCurrent.swipeMode;
        boolean light = mCurrent.lightingEnabled;
        long timeout = mCurrent.lightTimeoutMillis;
        double step = mCurrent.cursorStep;
        Map<KeyboardSettings.Chord, String> shortcuts = new HashMap<>(mCurrent.shortcuts);
        Map<KeyboardSettings.Press, String> presses = new HashMap<>(mCurrent.pressActions);
        if (LIGHT.equals(key)) light = (Boolean) value;
        else if (TIMEOUT.equals(key)) timeout = Long.parseLong((String) value);
        else if (SWIPES.equals(key)) swipe = KeyboardSettings.SwipeMode.valueOf((String) value);
        else if (CURSOR.equals(key)) step = Double.parseDouble((String) value);
        for (int i = 0; i < SHORTCUT_KEYS.length; i++) {
            if (!SHORTCUT_KEYS[i].equals(key)) continue;
            KeyboardSettings.Chord chord = new KeyboardSettings.Chord(SHORTCUT_CODES[i], KeyboardSettings.ALT);
            if ((Boolean) value) shortcuts.put(chord, SHORTCUT_ACTIONS[i]); else shortcuts.remove(chord);
        }
        for (int i = 0; i < PRESS_KEYS.length; i++) {
            if (!PRESS_KEYS[i].equals(key)) continue;
            KeyboardSettings.Press press = new KeyboardSettings.Press(PRESS_CODES[i], PRESS_LONG[i]);
            if (NONE.equals(value)) presses.remove(press); else presses.put(press, (String) value);
        }
        KeyboardSettings next = new KeyboardSettings(swipe, light, timeout, mCurrent.typingGuardMillis,
                step, shortcuts, presses);
        Context context = requireContext();
        boolean saved = context.getSharedPreferences(KeyboardSettingsProvider.PREFS, 0).edit()
                .putString(KeyboardSettingsProvider.KEY, KeyboardSettingsCodec.encode(next)).commit();
        if (!saved) {
            Toast.makeText(context, R.string.save_failed, Toast.LENGTH_SHORT).show();
            return false;
        }
        mCurrent = next;
        context.getContentResolver().notifyChange(KeyboardSettingsProvider.URI, null);
        if (SWIPES.equals(key) && !KeyboardSettingsProvider.setPadScroll(
                swipe == KeyboardSettings.SwipeMode.SCROLL)) {
            Toast.makeText(context, R.string.pad_failed, Toast.LENGTH_SHORT).show();
        }
        return true;
    }
}
