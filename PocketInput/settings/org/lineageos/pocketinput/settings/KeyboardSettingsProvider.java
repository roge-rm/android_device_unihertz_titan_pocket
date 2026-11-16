// SPDX-License-Identifier: Apache-2.0
package org.lineageos.pocketinput.settings;

import android.content.ContentProvider;
import android.content.ContentValues;
import android.database.Cursor;
import android.database.MatrixCursor;
import android.net.Uri;
import android.util.Log;
import org.lineageos.pocketinput.KeyboardSettings;
import org.lineageos.pocketinput.KeyboardSettingsCodec;

/** Read-only configuration IPC; typed content and editor state never enter this provider. */
public final class KeyboardSettingsProvider extends ContentProvider {
    public static final Uri URI = Uri.parse("content://org.lineageos.pocketinput.settings/configuration");
    public static final String PREFS = "keyboard", KEY = "configuration";
    private static final String TAG = "PocketInput";
    /** Applies the saved swipe mode to the pad property at start, so an old Scroll choice takes effect. */
    @Override public boolean onCreate() {
        try {
            String value = getContext().getSharedPreferences(PREFS, 0).getString(KEY, null);
            if (value != null) {
                setPadScroll(KeyboardSettingsCodec.decode(value).swipeMode == KeyboardSettings.SwipeMode.SCROLL);
            }
        } catch (RuntimeException e) {
            Log.w(TAG, "Could not apply the saved pad mode", e);
        }
        return true;
    }
    /** init starts and stops pocket_padd on this property. Needs the system uid (platform key). */
    static boolean setPadScroll(boolean on) {
        try {
            Class.forName("android.os.SystemProperties").getMethod("set", String.class, String.class)
                    .invoke(null, "persist.sys.pocket.pad_scroll", on ? "1" : "0");
            return true;
        } catch (ReflectiveOperationException | RuntimeException e) {
            Log.w(TAG, "Could not set the pad scroll property", e);
            return false;
        }
    }
    @Override public Cursor query(Uri uri, String[] projection, String selection,
            String[] selectionArgs, String sortOrder) {
        if (!URI.equals(uri)) throw new IllegalArgumentException("Unknown settings URI");
        String value = getContext().getSharedPreferences(PREFS, 0).getString(KEY,
                KeyboardSettingsCodec.encode(KeyboardSettings.defaults()));
        MatrixCursor cursor = new MatrixCursor(new String[]{KEY});
        cursor.addRow(new Object[]{value});
        cursor.setNotificationUri(getContext().getContentResolver(), URI);
        return cursor;
    }
    @Override public String getType(Uri uri) { return "vnd.android.cursor.item/vnd.pocket.keyboard-settings"; }
    @Override public Uri insert(Uri uri, ContentValues values) { throw new SecurityException("Read-only provider"); }
    @Override public int update(Uri uri, ContentValues values, String selection, String[] args) { throw new SecurityException("Read-only provider"); }
    @Override public int delete(Uri uri, String selection, String[] args) { throw new SecurityException("Read-only provider"); }
}
