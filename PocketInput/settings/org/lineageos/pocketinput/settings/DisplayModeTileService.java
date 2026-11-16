// SPDX-License-Identifier: Apache-2.0
package org.lineageos.pocketinput.settings;

import android.content.ComponentName;
import android.database.ContentObserver;
import android.os.Handler;
import android.os.Looper;
import android.provider.Settings;
import android.service.quicksettings.Tile;
import android.service.quicksettings.TileService;
import org.lineageos.pocketinput.DisplayModes;

/** Quick Settings tile: switches between the normal display and the chosen mode. */
public final class DisplayModeTileService extends TileService {
    static final ComponentName COMPONENT = new ComponentName(
            "org.lineageos.pocketinput.settings", DisplayModeTileService.class.getName());

    private final ContentObserver mObserver = new ContentObserver(new Handler(Looper.getMainLooper())) {
        @Override public void onChange(boolean selfChange) { update(); }
    };

    @Override public void onStartListening() {
        getContentResolver().registerContentObserver(
                Settings.Global.getUriFor(DisplayModes.SETTING), false, mObserver);
        getContentResolver().registerContentObserver(
                Settings.Global.getUriFor(DisplayModes.CHOICE_SETTING), false, mObserver);
        getContentResolver().registerContentObserver(
                Settings.Global.getUriFor(DisplayModes.CUSTOM_SETTING), false, mObserver);
        update();
    }

    @Override public void onStopListening() {
        getContentResolver().unregisterContentObserver(mObserver);
    }

    @Override public void onClick() {
        boolean on = active() != null;
        Settings.Global.putString(getContentResolver(), DisplayModes.SETTING,
                on ? DisplayModes.NORMAL : chosen().id);
        update();
    }

    private DisplayModes.Mode active() {
        return DisplayModes.resolve(
                Settings.Global.getString(getContentResolver(), DisplayModes.SETTING), custom());
    }

    private DisplayModes.Mode chosen() {
        return DisplayModes.choice(
                Settings.Global.getString(getContentResolver(), DisplayModes.CHOICE_SETTING), custom());
    }

    private String custom() {
        return Settings.Global.getString(getContentResolver(), DisplayModes.CUSTOM_SETTING);
    }

    private void update() {
        Tile tile = getQsTile();
        if (tile == null) return;
        DisplayModes.Mode active = active();
        tile.setState(active != null ? Tile.STATE_ACTIVE : Tile.STATE_INACTIVE);
        tile.setSubtitle((active != null ? active : chosen()).label);
        tile.updateTile();
    }
}
