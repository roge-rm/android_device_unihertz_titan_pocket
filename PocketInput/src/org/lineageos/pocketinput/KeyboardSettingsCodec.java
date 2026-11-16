// SPDX-License-Identifier: Apache-2.0
package org.lineageos.pocketinput;

import java.util.HashMap;
import java.util.Map;
import java.util.TreeMap;

/** Versioned, bounded settings encoding. It never contains text typed by the user. */
public final class KeyboardSettingsCodec {
    private KeyboardSettingsCodec() {}
    public static String encode(KeyboardSettings s) {
        TreeMap<String, String> values = new TreeMap<>();
        values.put("schema", "1");
        values.put("swipe", s.swipeMode.name());
        values.put("lighting", Boolean.toString(s.lightingEnabled));
        values.put("timeout", Long.toString(s.lightTimeoutMillis));
        values.put("typing_guard", Long.toString(s.typingGuardMillis));
        values.put("cursor_step", Double.toString(s.cursorStep));
        for (Map.Entry<KeyboardSettings.Chord, String> e : s.shortcuts.entrySet()) {
            if (!e.getValue().matches("[a-z][a-z0-9_.-]{0,63}")) {
                throw new IllegalArgumentException("Invalid registered action ID");
            }
            values.put("shortcut." + e.getKey().keyCode + "." + e.getKey().modifiers, e.getValue());
        }
        for (Map.Entry<KeyboardSettings.Press, String> e : s.pressActions.entrySet()) {
            if (!e.getValue().matches("[a-z][a-z0-9_.-]{0,63}")) {
                throw new IllegalArgumentException("Invalid registered action ID");
            }
            values.put("press." + e.getKey().keyCode + "." + (e.getKey().longPress ? "long" : "short"),
                    e.getValue());
        }
        StringBuilder out = new StringBuilder();
        for (Map.Entry<String, String> e : values.entrySet()) {
            out.append(e.getKey()).append('=').append(e.getValue()).append('\n');
        }
        return out.toString();
    }
    public static KeyboardSettings decode(String text) {
        if (text == null || text.length() > 65536) throw new IllegalArgumentException("Invalid settings size");
        Map<String, String> values = new HashMap<>();
        Map<KeyboardSettings.Chord, String> shortcuts = new HashMap<>();
        Map<KeyboardSettings.Press, String> presses = new HashMap<>();
        for (String line : text.split("\n")) {
            int equal = line.indexOf('=');
            if (equal < 1) throw new IllegalArgumentException("Invalid settings record");
            String key = line.substring(0, equal), value = line.substring(equal + 1);
            if (values.put(key, value) != null) throw new IllegalArgumentException("Duplicate setting");
            if (key.startsWith("shortcut.")) {
                String[] pieces = key.split("\\.");
                if (pieces.length != 3 || !value.matches("[a-z][a-z0-9_.-]{0,63}")) {
                    throw new IllegalArgumentException("Invalid shortcut");
                }
                KeyboardSettings.Chord chord = new KeyboardSettings.Chord(
                        Integer.parseInt(pieces[1]), Integer.parseInt(pieces[2]));
                if (shortcuts.put(chord, value) != null || shortcuts.size() > 64) {
                    throw new IllegalArgumentException("Duplicate or excessive shortcuts");
                }
            } else if (key.startsWith("press.")) {
                String[] pieces = key.split("\\.");
                if (pieces.length != 3 || !pieces[2].matches("short|long")
                        || !value.matches("[a-z][a-z0-9_.-]{0,63}")) {
                    throw new IllegalArgumentException("Invalid key press");
                }
                KeyboardSettings.Press press = new KeyboardSettings.Press(
                        Integer.parseInt(pieces[1]), "long".equals(pieces[2]));
                if (presses.put(press, value) != null || presses.size() > 64) {
                    throw new IllegalArgumentException("Duplicate or excessive key presses");
                }
            } else if (!key.matches("schema|swipe|lighting|timeout|typing_guard|cursor_step")) {
                throw new IllegalArgumentException("Unknown setting");
            }
        }
        if (!"1".equals(values.get("schema"))) throw new IllegalArgumentException("Unsupported schema");
        String lighting = values.get("lighting");
        if (!"true".equals(lighting) && !"false".equals(lighting)) {
            throw new IllegalArgumentException("Invalid lighting value");
        }
        try {
            return new KeyboardSettings(KeyboardSettings.SwipeMode.valueOf(values.get("swipe")),
                    Boolean.parseBoolean(lighting), Long.parseLong(values.get("timeout")),
                    Long.parseLong(values.get("typing_guard")), Double.parseDouble(values.get("cursor_step")), shortcuts,
                    presses);
        } catch (NullPointerException e) {
            throw new IllegalArgumentException("Missing setting", e);
        }
    }
}
