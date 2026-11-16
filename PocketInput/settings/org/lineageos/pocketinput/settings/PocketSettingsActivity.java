// SPDX-License-Identifier: Apache-2.0
package org.lineageos.pocketinput.settings;

import android.os.Bundle;
import com.android.settingslib.collapsingtoolbar.CollapsingToolbarBaseActivity;

/** Keyboard screen, also the entry under System in Settings. */
public final class PocketSettingsActivity extends CollapsingToolbarBaseActivity {
    @Override protected void onCreate(Bundle state) {
        super.onCreate(state);
        if (state == null) {
            getSupportFragmentManager().beginTransaction()
                    .replace(com.android.settingslib.collapsingtoolbar.R.id.content_frame,
                            new KeyboardFragment())
                    .commit();
        }
    }
}
