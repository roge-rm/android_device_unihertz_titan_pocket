// SPDX-License-Identifier: Apache-2.0
package org.lineageos.pocketinput.settings;

import android.content.ContentResolver;
import android.database.ContentObserver;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.provider.Settings;
import android.service.quicksettings.TileService;
import android.view.LayoutInflater;
import android.view.View;
import android.widget.EditText;
import android.widget.TextView;
import androidx.appcompat.app.AlertDialog;
import androidx.preference.TwoStatePreference;
import com.android.settingslib.widget.MainSwitchPreference;
import com.android.settingslib.widget.SelectorWithWidgetPreference;
import com.android.settingslib.widget.SettingsBasePreferenceFragment;
import org.lineageos.pocketinput.DisplayModeBoot;
import org.lineageos.pocketinput.DisplayModes;

/**
 * Display mode screen. Writes the same Settings.Global keys as the tile; PocketDisplayMode in
 * system_server applies them and asks to keep or revert. The system uid can write them.
 */
public final class DisplayModeFragment extends SettingsBasePreferenceFragment {
    private MainSwitchPreference mOn;
    private SquareGridPreference mGrid;
    private SelectorWithWidgetPreference mPortrait, mCustom;
    private TwoStatePreference mBoot;
    private final ContentObserver mObserver = new ContentObserver(new Handler(Looper.getMainLooper())) {
        @Override public void onChange(boolean selfChange) { refresh(); }
    };

    @Override public void onCreatePreferences(Bundle state, String rootKey) {
        setPreferencesFromResource(R.xml.display_mode_settings, rootKey);
        mOn = findPreference("mode_on");
        mGrid = findPreference("square_grid");
        mPortrait = findPreference("portrait_mini");
        mCustom = findPreference("custom");
        mBoot = findPreference("keep_after_reboot");
        mOn.setOnPreferenceChangeListener((preference, value) -> {
            // Same as the tile. A revert writes the key back and the observer follows it.
            put(DisplayModes.SETTING, (Boolean) value ? chosen().id : DisplayModes.NORMAL);
            TileService.requestListeningState(requireContext(), DisplayModeTileService.COMPONENT);
            return true;
        });
        mGrid.setOnPick(this::choose);
        mPortrait.setOnClickListener(p -> choose(DisplayModes.find(DisplayModes.PORTRAIT_MINI)));
        mCustom.setOnClickListener(p -> showCustomDialog());
        mBoot.setOnPreferenceChangeListener((preference, value) -> Settings.Global.putInt(
                resolver(), DisplayModeBoot.SETTING, (Boolean) value ? 1 : 0));
        DisplayModes.Mode portrait = DisplayModes.find(DisplayModes.PORTRAIT_MINI);
        mPortrait.setSummary(size(portrait));
    }

    @Override public void onResume() {
        super.onResume();
        for (String key : new String[]{DisplayModes.SETTING, DisplayModes.CHOICE_SETTING,
                DisplayModes.CUSTOM_SETTING, DisplayModeBoot.SETTING}) {
            resolver().registerContentObserver(Settings.Global.getUriFor(key), false, mObserver);
        }
        refresh();
    }

    @Override public void onPause() {
        super.onPause();
        resolver().unregisterContentObserver(mObserver);
    }

    private ContentResolver resolver() {
        return requireContext().getContentResolver();
    }

    private String get(String key) {
        return Settings.Global.getString(resolver(), key);
    }

    private void put(String key, String value) {
        Settings.Global.putString(resolver(), key, value);
    }

    private DisplayModes.Mode chosen() {
        return DisplayModes.choice(get(DisplayModes.CHOICE_SETTING), get(DisplayModes.CUSTOM_SETTING));
    }

    private String size(DisplayModes.Mode mode) {
        return getString(R.string.mode_size, mode.width, mode.height, mode.density);
    }

    private void refresh() {
        if (getContext() == null) return;
        String custom = get(DisplayModes.CUSTOM_SETTING);
        mOn.setChecked(DisplayModes.resolve(get(DisplayModes.SETTING), custom) != null);
        String id = chosen().id;
        mGrid.setSelectedId(id);
        mPortrait.setChecked(DisplayModes.PORTRAIT_MINI.equals(id));
        mCustom.setChecked(DisplayModes.CUSTOM.equals(id));
        DisplayModes.Mode mode = DisplayModes.custom(custom);
        mCustom.setSummary(mode != null ? size(mode) : getString(R.string.custom_not_set));
        mBoot.setChecked(Settings.Global.getInt(resolver(), DisplayModeBoot.SETTING, 0) == 1);
    }

    /** Sets the tile's choice and, when a mode is on, switches to it (PocketDisplayMode confirms). */
    private void choose(DisplayModes.Mode mode) {
        put(DisplayModes.CHOICE_SETTING, mode.id);
        if (DisplayModes.resolve(get(DisplayModes.SETTING), get(DisplayModes.CUSTOM_SETTING)) != null) {
            put(DisplayModes.SETTING, mode.id);
        }
        TileService.requestListeningState(requireContext(), DisplayModeTileService.COMPONENT);
        refresh();
    }

    private void showCustomDialog() {
        AlertDialog.Builder builder = new AlertDialog.Builder(requireContext());
        // Inflated in the dialog's theme, for its padding and colours.
        View view = LayoutInflater.from(builder.getContext()).inflate(R.layout.custom_mode_dialog, null);
        EditText width = view.findViewById(R.id.custom_width);
        EditText height = view.findViewById(R.id.custom_height);
        EditText density = view.findViewById(R.id.custom_density);
        TextView error = view.findViewById(R.id.custom_error);
        // Starts from the saved custom mode, or the normal display.
        DisplayModes.Mode current = DisplayModes.custom(get(DisplayModes.CUSTOM_SETTING));
        width.setText(String.valueOf(current != null ? current.width : 720));
        height.setText(String.valueOf(current != null ? current.height : 720));
        density.setText(String.valueOf(current != null ? current.density : 220));
        AlertDialog dialog = builder
                .setTitle(R.string.custom)
                .setView(view)
                .setPositiveButton(android.R.string.ok, null)
                .setNegativeButton(android.R.string.cancel, null)
                .create();
        dialog.setOnShowListener(d -> dialog.getButton(AlertDialog.BUTTON_POSITIVE).setOnClickListener(b -> {
            String problem;
            DisplayModes.Mode mode = null;
            try {
                int w = Integer.parseInt(width.getText().toString().trim());
                int h = Integer.parseInt(height.getText().toString().trim());
                int dpi = Integer.parseInt(density.getText().toString().trim());
                problem = DisplayModes.customError(w, h, dpi);
                if (problem == null) mode = DisplayModes.custom(w, h, dpi);
            } catch (NumberFormatException e) {
                problem = getString(R.string.custom_bad_number);
            }
            if (mode == null) {
                error.setText(problem);
                error.setVisibility(View.VISIBLE);
                return;
            }
            put(DisplayModes.CUSTOM_SETTING, DisplayModes.customValue(mode));
            choose(mode);
            dialog.dismiss();
        }));
        dialog.show();
    }
}
