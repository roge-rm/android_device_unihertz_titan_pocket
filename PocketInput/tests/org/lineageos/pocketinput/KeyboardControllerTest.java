// SPDX-License-Identifier: Apache-2.0
package org.lineageos.pocketinput;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/** Executable behavior scenarios, independent of Android and actual key capture. */
public final class KeyboardControllerTest {
    private static final class Rig implements KeyboardController.Clock, KeyboardController.Sink {
        long time = 1000;
        final List<String> events = new ArrayList<>();
        final KeyboardController controller;
        Rig(KeyboardSettings settings) {
            controller = new KeyboardController(settings, this, this);
            controller.setInteractive(true);
            controller.setContext(true, false, true);
        }
        public long uptimeMillis() { return time; }
        public void setBacklight(boolean on) { events.add("light:" + on); }
        public void moveCursor(int steps) { events.add("cursor:" + steps); }
        public void scroll(double delta) { events.add("scroll"); }
        public void runShortcut(String action) { events.add("shortcut:" + action); }
        void swipe() {
            controller.onPadDown(true, 7, 1, 0.2, 0.4);
            controller.onPadMove(7, 1, 0.4, 0.5);
            controller.onPadUp();
        }
    }
    private static int checks;
    private static void check(boolean value) {
        checks++;
        if (!value) throw new AssertionError("check " + checks);
    }
    private static KeyboardSettings mode(KeyboardSettings.SwipeMode mode) {
        return new KeyboardSettings(mode, true, 3500, 250, 0.08, new HashMap<>());
    }
    public static void main(String[] args) throws Exception {
        Rig r = new Rig(KeyboardSettings.defaults());
        r.swipe(); check(r.events.isEmpty()); // User's default is swiping off.
        check(!r.controller.onKeyDown(false, 29, 0, false));
        check(r.events.isEmpty());
        check(!r.controller.onKeyDown(true, 29, 0, false));
        check(r.events.equals(List.of("light:true"))); // Same event, no delayed-on timer.
        check(r.controller.nextLightDeadlineMillis() == 4500);
        r.time = 4499; r.controller.onTimer(); check(r.events.size() == 1);
        r.controller.onKeyDown(true, 29, 0, true); // Typing extends, never toggles light.
        check(r.controller.nextLightDeadlineMillis() == 7999);
        r.time = 7999; r.controller.onTimer(); check(r.events.equals(List.of("light:true", "light:false")));
        check(r.controller.nextLightDeadlineMillis() == -1);
        r.controller.onKeyDown(true, 29, 0, false);
        r.controller.setInteractive(false); check(r.events.get(r.events.size()-1).equals("light:false"));
        int old = r.events.size(); r.controller.onKeyDown(true, 29, 0, false);check(r.events.size()==old);
        r.controller.setInteractive(true);
        r.controller.setSettings(new KeyboardSettings(KeyboardSettings.SwipeMode.OFF, false, 500, 0, 0.1, Map.of()));
        r.controller.onKeyDown(true, 29, 0, false);check(r.events.size()==old);

        r = new Rig(mode(KeyboardSettings.SwipeMode.CURSOR));
        r.swipe(); check(r.events.equals(List.of("cursor:2")));
        r.events.clear();
        r.controller.onPadDown(true, 7, 1, 0.5, 0.5);
        r.controller.onPadMove(7, 1, 0.3, 0.5); check(r.events.equals(List.of("cursor:-2")));
        r.events.clear();r.controller.onPadMove(7, 2, 0.2, 0.5);r.controller.onPadMove(7, 1, 0.1, 0.5);check(r.events.isEmpty());
        r.controller.setContext(true, true, true);r.swipe();check(r.events.isEmpty());
        r.controller.setContext(true, false, false);r.swipe();check(r.events.isEmpty());
        r.controller.setContext(false, false, true);r.swipe();check(r.events.isEmpty());
        r.controller.setContext(true, false, true);
        r.controller.onPadDown(true,7,1,0.2,0.4);
        r.controller.setContext(true,false,true); // New editor, same flags: no leaked motion.
        r.controller.onPadMove(7,1,0.4,0.5);check(r.events.isEmpty());
        r.controller.onKeyDown(true,29,0,false);r.events.clear();r.swipe();check(r.events.isEmpty());
        r.time+=249;r.swipe();check(r.events.isEmpty());
        r.time++;r.swipe();check(r.events.equals(List.of("cursor:2")));
        r.events.clear();r.controller.onPadDown(true,7,1,0.1,0.5);r.controller.onPadMove(7,1,0.9,0.5);check(r.events.isEmpty());
        r.controller.onPadDown(false,7,1,0.1,0.5);r.controller.onPadMove(7,1,0.3,0.5);check(r.events.isEmpty());
        r.controller.onPadDown(true,7,1,Double.NaN,0.5);r.controller.onPadMove(7,1,0.3,0.5);check(r.events.isEmpty());
        r.controller.onPadDown(true,7,1,0.1,0.5);r.controller.onPadMove(8,1,0.3,0.5);check(r.events.isEmpty());
        r.controller.setSettings(mode(KeyboardSettings.SwipeMode.SCROLL));r.swipe();check(r.events.equals(List.of("scroll")));

        r = new Rig(KeyboardSettings.defaults());
        r.controller.setLightingPermitted(false);
        r.controller.onKeyDown(true,29,0,false);check(r.events.isEmpty());
        r.controller.setLightingPermitted(true);check(r.events.isEmpty());
        r.controller.onKeyDown(true,29,0,false);check(r.events.equals(List.of("light:true")));
        r.controller.setLightingPermitted(false);check(r.events.equals(List.of("light:true","light:false")));
        check(r.controller.nextLightDeadlineMillis()==-1);

        Map<KeyboardSettings.Chord,String> bindings = new HashMap<>();
        bindings.put(new KeyboardSettings.Chord(29,KeyboardSettings.ALT),"open-notes");
        KeyboardSettings s = new KeyboardSettings(KeyboardSettings.SwipeMode.OFF,true,3500,250,0.08,bindings);
        bindings.clear();check(s.shortcuts.size()==1); // Caller cannot mutate active bindings.
        r = new Rig(s);
        check(r.controller.onKeyDown(true,29,KeyboardSettings.ALT,false));
        check(r.controller.onKeyDown(true,29,KeyboardSettings.ALT,true));
        check(r.events.equals(List.of("light:true","shortcut:open-notes")));
        check(r.controller.onKeyUp(true,29));check(!r.controller.onKeyUp(true,29));
        r.controller.setContext(true,true,true);check(!r.controller.onKeyDown(true,29,KeyboardSettings.ALT,false));
        r.controller.setContext(true,false,false);check(!r.controller.onKeyDown(true,29,KeyboardSettings.ALT,false));
        r.controller.setContext(true,false,true);check(!r.controller.onKeyDown(true,29,KeyboardSettings.ALT,true));
        check(!r.controller.onKeyDown(true,29,16,false));
        for (long timeout : new long[]{-1,0,499,30001,Long.MAX_VALUE}) {
            boolean rejected=false;
            try { new KeyboardSettings(KeyboardSettings.SwipeMode.OFF,true,timeout,250,0.08,Map.of()); }
            catch(IllegalArgumentException expected) { rejected=true; }
            check(rejected);
        }
        String encoded = KeyboardSettingsCodec.encode(s);
        KeyboardSettings decoded = KeyboardSettingsCodec.decode(encoded);
        check(encoded.equals(KeyboardSettingsCodec.encode(decoded)));
        check(decoded.shortcuts.equals(s.shortcuts));
        check(KeyboardSettingsCodec.decode(KeyboardSettingsCodec.encode(KeyboardSettings.defaults())).swipeMode == KeyboardSettings.SwipeMode.OFF);
        String[] invalid = {encoded+"schema=1\n", encoded.replace("schema=1", "schema=2"),
                encoded.replace("lighting=true", "lighting=maybe"), encoded.replace("cursor_step=0.08", "cursor_step=NaN"),
                encoded+"unknown=value\n", encoded+"shortcut.29.2=other\n", "schema=1\n", "x".repeat(65537)};
        for (String value : invalid) {
            boolean rejected=false;
            try { KeyboardSettingsCodec.decode(value); } catch (IllegalArgumentException expected) { rejected=true; }
            check(rejected);
        }
        java.nio.file.Path light = java.nio.file.Files.createTempDirectory("pocket-light-");
        try {
            java.nio.file.Files.writeString(light.resolve("max_brightness"), "255\n");
            java.nio.file.Files.writeString(light.resolve("brightness"), "0");
            KeyboardLightWriter writer = new KeyboardLightWriter(light);
            writer.set(true);check(java.nio.file.Files.readString(light.resolve("brightness")).equals("255"));
            writer.set(false);check(java.nio.file.Files.readString(light.resolve("brightness")).equals("0"));
            java.nio.file.Files.writeString(light.resolve("max_brightness"), "0");
            boolean rejected=false;try { writer.set(true); } catch(java.io.IOException expected) { rejected=true; }
            check(rejected);
            java.nio.file.Files.writeString(light.resolve("max_brightness"), "255");
            java.nio.file.Files.delete(light.resolve("brightness"));
            rejected=false;try { writer.set(true); } catch(java.io.IOException expected) { rejected=true; }
            check(rejected && !java.nio.file.Files.exists(light.resolve("brightness")));
        } finally {
            java.nio.file.Files.deleteIfExists(light.resolve("brightness"));
            java.nio.file.Files.deleteIfExists(light.resolve("max_brightness"));
            java.nio.file.Files.delete(light);
        }
        System.out.println(checks+" keyboard behavior assertions passed");
    }
}
