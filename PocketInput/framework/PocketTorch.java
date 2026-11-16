/*
 * SPDX-License-Identifier: Apache-2.0
 */
package com.android.server.policy;

import android.content.ContentResolver;
import android.content.Context;
import android.database.ContentObserver;
import android.os.Handler;
import android.provider.Settings;
import android.util.Slog;

import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

/**
 * Titan Pocket torch without a camera HAL (FLASHLIGHT_PORT.md). The kernel's torch
 * LED (pocket_torch.c) lights both MT6370 flash LEDs at the stock torch currents.
 *
 * Settings.Global pocket_torch (0 or 1) is the one switch: SystemUI's flashlight tile
 * and PhoneWindowManager's torch toggle (FUNC keys, power long press) both write it,
 * and this writes the LED on every change. pocket_torch_available tells SystemUI to
 * use it when no camera has a flash. Runs on the PocketKeyHooks thread.
 */
final class PocketTorch {
    private static final String TAG = "PocketTorch";
    // The real path: /sys/class/leds/torch is a sysfs_leds link system_server can't follow.
    private static final Path NODE = Paths.get("/sys/devices/virtual/leds/torch/brightness");
    static final String SETTING = "pocket_torch";
    static final String AVAILABLE = "pocket_torch_available";

    private final ContentResolver mResolver;
    private final Handler mHandler;
    private volatile boolean mAvailable;

    PocketTorch(Context context, Handler handler) {
        mResolver = context.getContentResolver();
        mHandler = handler;
    }

    /** Off at boot, then follow the setting. Call once settings work. */
    void systemBooted() {
        mAvailable = Files.isWritable(NODE);
        Settings.Global.putInt(mResolver, SETTING, 0);
        Settings.Global.putInt(mResolver, AVAILABLE, mAvailable ? 1 : 0);
        if (!mAvailable) {
            Slog.w(TAG, NODE + " not writable, no torch");
            return;
        }
        mResolver.registerContentObserver(Settings.Global.getUriFor(SETTING), false,
                new ContentObserver(mHandler) {
                    @Override public void onChange(boolean selfChange) { apply(); }
                });
        apply();
    }

    /** Returns false when there is no torch, so the caller can try the camera. */
    boolean toggle() {
        if (!mAvailable) return false;
        mHandler.post(() -> Settings.Global.putInt(mResolver, SETTING,
                isOn() ? 0 : 1));
        return true;
    }

    boolean isOn() {
        return Settings.Global.getInt(mResolver, SETTING, 0) != 0;
    }

    private void apply() {
        boolean on = isOn();
        try (FileOutputStream out = new FileOutputStream(NODE.toFile())) {
            out.write((on ? "1" : "0").getBytes(StandardCharsets.US_ASCII));
        } catch (IOException e) {
            Slog.w(TAG, "Couldn't turn the torch " + (on ? "on" : "off"), e);
        }
    }
}
