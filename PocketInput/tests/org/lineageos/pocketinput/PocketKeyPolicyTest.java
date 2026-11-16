// SPDX-License-Identifier: Apache-2.0
package org.lineageos.pocketinput;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/** Framework key policy: light, FUNC1/FUNC2 presses, the restore combo and the pad key guard. */
public final class PocketKeyPolicyTest {
    private static final PocketKeyPolicy.Source KB = PocketKeyPolicy.Source.KEYBOARD,
            KPD = PocketKeyPolicy.Source.KEYPAD, OTHER = PocketKeyPolicy.Source.OTHER;
    private static final int F13 = PocketKeyPolicy.KEYCODE_F13, F14 = PocketKeyPolicy.KEYCODE_F14;
    private static final int A = 29, VOLUME_UP = 24, DPAD = 21;

    private static final class Rig implements KeyboardController.Clock, PocketKeyPolicy.Sink {
        long time = 1000;
        String pad = "";
        int padReads;
        final List<String> events = new ArrayList<>();
        final PocketKeyPolicy policy;
        Rig(KeyboardSettings settings) { policy = new PocketKeyPolicy(settings, this, this); }
        public long uptimeMillis() { return time; }
        public void setLight(boolean on) { events.add("light:" + on); }
        public void runAction(String action) { events.add("run:" + action); }
        public void restoreDisplay() { events.add("restore"); }
        boolean down(PocketKeyPolicy.Source s, int key) {
            return policy.onKeyDown(s, key, false, time, true, () -> { padReads++; return pad; });
        }
        boolean up(PocketKeyPolicy.Source s, int key) { return policy.onKeyUp(s, key, false); }
        void advance(long ms) {
            long end = time + ms;
            while (true) {
                long next = policy.nextTimerMillis();
                if (next < 0 || next > end) break;
                time = Math.max(time, next);
                policy.onTimer(time);
            }
            time = end;
        }
    }
    private static int checks;
    private static void check(boolean value) {
        checks++;
        if (!value) throw new AssertionError("check " + checks);
    }
    private static KeyboardSettings presses(boolean light, long timeout) {
        Map<KeyboardSettings.Press, String> p = new HashMap<>();
        p.put(new KeyboardSettings.Press(F13, false), "camera");
        p.put(new KeyboardSettings.Press(F13, true), "flashlight");
        p.put(new KeyboardSettings.Press(F14, false), "browser");
        return new KeyboardSettings(KeyboardSettings.SwipeMode.OFF, light, timeout, 250, 0.08,
                new HashMap<>(), p);
    }
    public static void main(String[] args) {
        // Light: on at the first keyboard down with no delay, timeout runs from the last key.
        Rig r = new Rig(presses(true, 1000));
        check(!r.down(KB, A) && r.events.equals(List.of("light:true")));
        check(!r.up(KB, A));
        r.advance(600);
        check(!r.down(KB, A) && r.events.size() == 1);
        r.up(KB, A);
        r.advance(999);
        check(r.events.size() == 1);
        r.advance(1);
        check(r.events.equals(List.of("light:true", "light:false")) && r.policy.nextTimerMillis() < 0);
        // The keypad and other devices don't light it; other devices pass untouched.
        check(!r.down(KPD, VOLUME_UP) && !r.up(KPD, VOLUME_UP) && r.events.size() == 2);
        check(!r.down(OTHER, F13) && !r.up(OTHER, F13) && r.events.size() == 2);
        // Screen off: nothing lights or is dropped, and the light goes off.
        check(!r.policy.onKeyDown(KB, A, false, r.time, false, () -> "drag 0") && r.events.size() == 2);
        r.down(KB, A);
        r.policy.setInteractive(false);
        check(r.events.equals(List.of("light:true", "light:false", "light:true", "light:false")));
        r.policy.setInteractive(true);
        // Light setting off.
        Rig dark = new Rig(presses(false, 1000));
        dark.down(KB, A);
        check(dark.events.isEmpty() && dark.policy.nextTimerMillis() < 0);
        // Turning the light off in the settings turns a lit light off.
        r.down(KB, A);
        r.policy.setSettings(presses(false, 1000));
        check(r.events.get(r.events.size() - 1).equals("light:false"));

        // FUNC1: short press runs at the release, long press at 500 ms and not again at release.
        r = new Rig(presses(false, 1000));
        check(r.down(KB, F13) && r.events.isEmpty());
        r.advance(PocketKeyPolicy.LONG_PRESS_MILLIS - 1);
        check(r.up(KB, F13) && r.events.equals(List.of("run:camera")));
        r.events.clear();
        check(r.down(KB, F13));
        r.advance(PocketKeyPolicy.LONG_PRESS_MILLIS);
        check(r.events.equals(List.of("run:flashlight")));
        r.advance(2000);
        check(r.up(KB, F13) && r.events.size() == 1);
        // Repeats are dropped and don't restart the press.
        r.events.clear();
        r.down(KB, F13);
        r.advance(300);
        check(r.policy.onKeyDown(KB, F13, true, r.time, true, null));
        r.advance(200);
        check(r.events.equals(List.of("run:flashlight")));
        r.up(KB, F13);
        // FUNC2 on the keypad with no long action: short at release even when held long.
        r.events.clear();
        check(r.down(KPD, F14) && r.policy.nextTimerMillis() < 0);
        r.advance(3000);
        check(r.up(KPD, F14) && r.events.equals(List.of("run:browser")));
        // A canceled hold (the red key held at boot) runs neither press; the next press does.
        Map<KeyboardSettings.Press, String> both = new HashMap<>();
        both.put(new KeyboardSettings.Press(F14, false), "browser");
        both.put(new KeyboardSettings.Press(F14, true), "flashlight");
        Rig boot = new Rig(new KeyboardSettings(KeyboardSettings.SwipeMode.OFF, false, 1000, 250, 0.08,
                new HashMap<>(), both));
        check(boot.down(KPD, F14));
        boot.policy.cancelHold(F14);
        check(boot.policy.nextTimerMillis() < 0);
        boot.advance(3000);
        check(boot.up(KPD, F14) && boot.events.isEmpty());
        boot.down(KPD, F14);
        boot.policy.cancelHold(F13);
        check(boot.up(KPD, F14) && boot.events.equals(List.of("run:browser")));
        // Canceling the red key's hold keeps the FUNC1+FUNC2 restore.
        boot.events.clear();
        boot.down(KPD, F14);
        boot.policy.cancelHold(F14);
        boot.down(KB, F13);
        boot.advance(PocketKeyPolicy.RESTORE_HOLD_MILLIS);
        check(boot.events.equals(List.of("restore")));
        boot.up(KB, F13);
        boot.up(KPD, F14);
        check(boot.events.size() == 1);
        // A canceled press runs nothing; an unbound key is still dropped.
        r.events.clear();
        r.down(KB, F13);
        check(r.policy.onKeyUp(KB, F13, true) && r.events.isEmpty());
        Rig none = new Rig(KeyboardSettings.defaults());
        check(none.down(KB, F14) && none.up(KB, F14));
        check(none.events.equals(List.of("light:true")));
        // An up with no down (pressed before the screen came on) is dropped and runs nothing.
        r.policy.setInteractive(false);
        r.policy.setInteractive(true);
        check(r.up(KB, F13) && r.events.isEmpty());

        // FUNC1 and FUNC2 held together for 1 s restore the display once, and run neither press.
        final long HOLD = PocketKeyPolicy.RESTORE_HOLD_MILLIS;
        r = new Rig(presses(false, 1000));
        check(r.down(KB, F13));
        r.advance(100);
        check(r.down(KPD, F14) && r.events.isEmpty());
        r.advance(HOLD - 1);
        check(r.events.isEmpty());
        r.advance(1);
        check(r.events.equals(List.of("restore")));
        check(r.policy.onKeyDown(KB, F13, true, r.time, true, null));
        r.advance(3000);
        check(r.events.size() == 1 && r.policy.nextTimerMillis() < 0);
        check(r.up(KB, F13) && r.up(KPD, F14) && r.events.size() == 1);
        // Afterwards each key has its own press again.
        check(r.down(KPD, F14) && r.up(KPD, F14) && r.events.equals(List.of("restore", "run:browser")));
        // Let go early: nothing runs, in either release order.
        r.events.clear();
        r.down(KB, F14);
        r.down(KB, F13);
        r.advance(HOLD - 1);
        check(r.up(KB, F13) && r.events.isEmpty() && r.policy.nextTimerMillis() < 0);
        r.advance(2000);
        check(r.up(KB, F14) && r.events.isEmpty());
        // Letting one go and pressing it again starts a new hold.
        r.down(KB, F13);
        r.down(KB, F14);
        r.advance(800);
        r.up(KB, F14);
        r.advance(100);
        r.down(KB, F14);
        r.advance(HOLD - 1);
        check(r.events.isEmpty());
        r.advance(1);
        check(r.events.equals(List.of("restore")));
        r.up(KB, F13);
        r.up(KB, F14);
        // After FUNC1's long press has run, adding FUNC2 still restores, and FUNC1's release runs nothing.
        r.events.clear();
        r.down(KB, F13);
        r.advance(PocketKeyPolicy.LONG_PRESS_MILLIS);
        r.down(KB, F14);
        r.advance(HOLD);
        check(r.up(KB, F13) && r.up(KB, F14) && r.events.equals(List.of("run:flashlight", "restore")));
        // Screen off cancels the hold.
        r.events.clear();
        r.down(KB, F13);
        r.down(KB, F14);
        r.policy.setInteractive(false);
        r.policy.setInteractive(true);
        r.advance(2 * HOLD);
        check(r.events.isEmpty());

        // Pad guard: letter keys during a drag are dropped with their release, in every app.
        r = new Rig(presses(false, 1000));
        r.pad = "drag 900";
        check(r.down(KB, A) && r.up(KB, A));
        check(!r.down(KB, DPAD) && !r.up(KB, DPAD));
        check(r.padReads == 1);
        r.pad = "lift 900 950";
        r.time = 950 + PadKeyGuard.KEY_PRESS_DELAY_MILLIS;
        check(!r.down(KB, A) && !r.up(KB, A));
        // Keypad keys never read the pad state.
        r.pad = "drag 900";
        int reads = r.padReads;
        check(!r.down(KPD, VOLUME_UP) && r.padReads == reads);
        // Screen off forgets dropped downs.
        check(r.down(KB, A));
        r.policy.setInteractive(false);
        check(!r.up(KB, A));

        // Settings codec keeps the presses and rejects bad ones.
        KeyboardSettings s = presses(true, 3500);
        KeyboardSettings back = KeyboardSettingsCodec.decode(KeyboardSettingsCodec.encode(s));
        check(back.pressActions.equals(s.pressActions) && "flashlight".equals(back.pressAction(F13, true))
                && back.pressAction(F14, true) == null);
        String base = KeyboardSettingsCodec.encode(KeyboardSettings.defaults());
        check(KeyboardSettingsCodec.decode(base).pressActions.isEmpty());
        for (String bad : new String[]{"press.326.middle=camera", "press.326=camera", "press.0.short=camera",
                "press.x.short=camera", "press.326.short=Camera"}) {
            boolean rejected = false;
            try { KeyboardSettingsCodec.decode(base + bad); } catch (IllegalArgumentException e) { rejected = true; }
            check(rejected);
        }
        boolean duplicate = false;
        try { KeyboardSettingsCodec.decode(base + "press.326.short=camera\npress.326.short=browser"); }
        catch (IllegalArgumentException e) { duplicate = true; }
        check(duplicate);
        System.out.println(checks + " framework key policy assertions passed");
    }
}
