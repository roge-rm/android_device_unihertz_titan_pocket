// SPDX-License-Identifier: Apache-2.0
package org.lineageos.pocketinput;

import java.util.ArrayList;
import java.util.List;

/** Display mode table, custom limits and the confirm or revert switch. */
public final class DisplayModesTest {
    private static final class Rig implements KeyboardController.Clock, DisplayModeSwitch.Sink {
        long time = 5000;
        boolean dialog;
        DisplayModes.Mode display, stored, kept;
        int remembered;
        final List<String> events = new ArrayList<>();
        final DisplayModeSwitch sw = new DisplayModeSwitch(this, this);
        public long uptimeMillis() { return time; }
        public void apply(DisplayModes.Mode mode) { display = mode; events.add("apply:" + name(mode)); }
        public void store(DisplayModes.Mode mode) { stored = mode; events.add("store:" + name(mode)); }
        /** Set when the app wrote this pick after the switch began, before the revert ran. */
        boolean raced;
        DisplayModes.Mode newer;
        public void revertStore(DisplayModes.Mode mode, DisplayModes.Mode asked) {
            if (raced && !DisplayModes.same(newer, asked)) {
                events.add("kept:" + name(newer));
            } else {
                store(mode);
            }
        }
        public void showDialog() { dialog = true; events.add("show"); }
        public void hideDialog() { dialog = false; events.add("hide"); }
        public void remember(DisplayModes.Mode mode) { kept = mode; remembered++; }
        void advance(long ms) {
            time += ms;
            sw.onTimer();
        }
        String take() {
            String s = String.join(",", events);
            events.clear();
            return s;
        }
    }
    private static String name(DisplayModes.Mode mode) { return mode == null ? "normal" : mode.id; }

    private static int checks;
    private static void check(boolean value) {
        checks++;
        if (!value) throw new AssertionError("check " + checks);
    }

    public static void main(String[] args) {
        // The 4 x 3 square table, densities as in MINI_MODE_CONTRACT.md.
        int[][] table = {{245, 368, 490}, {199, 298, 397}, {165, 248, 330}, {140, 211, 281}};
        check(DisplayModes.MODES.length == 13);
        for (int r = 0; r < 4; r++) {
            for (int c = 0; c < 3; c++) {
                int dp = DisplayModes.SQUARE_DP[r], render = DisplayModes.SQUARE_RENDER[c];
                DisplayModes.Mode m = DisplayModes.find(DisplayModes.squareId(dp, render));
                check(m != null && m.width == render && m.height == render && m.density == table[r][c]);
                check(Math.abs(m.widthDp() - dp) <= 3);
            }
        }
        DisplayModes.Mode mini = DisplayModes.find("portrait_mini");
        check(mini != null && mini.width == 432 && mini.height == 720 && mini.density == 160);
        // Old IDs are the 698 dp row.
        check(DisplayModes.find("square_1440").id.equals("square_698_1440"));
        check(DisplayModes.find("square_1080").id.equals("square_698_1080"));
        check(DisplayModes.find("square_720").id.equals("square_698_720"));
        check(DisplayModes.choice("square_1080", null).id.equals("square_698_1080"));
        check(DisplayModes.find(DisplayModes.DEFAULT_CHOICE) != null);
        check(DisplayModes.find("normal") == null && DisplayModes.find(null) == null
                && DisplayModes.find("square_2000") == null && DisplayModes.find("custom") == null);
        check(DisplayModes.choice(null, null).id.equals(DisplayModes.DEFAULT_CHOICE));
        check(DisplayModes.choice("bogus", null).id.equals(DisplayModes.DEFAULT_CHOICE));

        // Custom mode and its limits.
        DisplayModes.Mode custom = DisplayModes.resolve("custom", " 900 1200  240 ");
        check(custom != null && custom.id.equals("custom") && custom.width == 900
                && custom.height == 1200 && custom.density == 240);
        check(DisplayModes.customValue(custom).equals("900 1200 240"));
        check(DisplayModes.custom(DisplayModes.customValue(custom)) != null);
        check(DisplayModes.choice("custom", "900 1200 240").id.equals("custom"));
        check(DisplayModes.choice("custom", "10 10 10").id.equals(DisplayModes.DEFAULT_CHOICE));
        check(DisplayModes.resolve("custom", null) == null);
        for (String bad : new String[]{"", "900 900", "900 900 200 1", "a 900 200", "359 900 100",
                "900 2161 200", "2200 900 200", "900 900 99", "2160 2160 641",
                "640 2160 321", "360 720 181"}) {
            check(DisplayModes.custom(bad) == null);
        }
        check(DisplayModes.customError(360, 720, 180) == null);  // 360 x 160 / 180 = 320 dp
        check(DisplayModes.customError(360, 360, 181) != null);   // 318 dp
        check(DisplayModes.customError(2160, 360, 100) == null);
        check(DisplayModes.customError(360, 2160, 100) == null);
        check(DisplayModes.customError(2160, 2160, 640) == null);
        check(DisplayModes.same(DisplayModes.custom(1440, 1440, 330), DisplayModes.find("square_1440")));
        check(DisplayModes.same(null, null) && !DisplayModes.same(null, mini));

        DisplayModes.Mode a = DisplayModes.find("square_698_1440"), b = DisplayModes.find("square_470_720");

        // Normal to a mode: applied at once, dialog, Keep confirms.
        Rig rig = new Rig();
        rig.sw.force(null);
        check(rig.take().equals("apply:normal,store:normal") && !rig.dialog);
        rig.sw.request(a);
        check(rig.take().equals("apply:square_698_1440,show") && rig.dialog && rig.sw.pending());
        check(rig.sw.deadline() == 15000 && rig.sw.secondsLeft() == 10);
        rig.advance(4500);
        check(rig.sw.secondsLeft() == 6 && rig.sw.pending() && rig.take().isEmpty());
        rig.sw.keep();
        check(rig.take().equals("hide") && !rig.sw.pending() && rig.sw.confirmed() == a);
        rig.advance(20000);
        check(rig.take().isEmpty() && rig.display == a && rig.sw.deadline() == -1);

        // A to B, no answer: reverts to A at 10 s, settings written back.
        rig.sw.request(b);
        check(rig.take().equals("apply:square_470_720,show"));
        rig.advance(9999);
        check(rig.sw.pending() && rig.sw.secondsLeft() == 1);
        rig.advance(1);
        check(rig.take().equals("apply:square_698_1440,store:square_698_1440,hide")
                && !rig.sw.pending() && rig.display == a && rig.stored == a && rig.sw.applied() == a);

        // Back to normal is asked too; Revert goes back to A.
        rig.sw.request(null);
        check(rig.take().equals("apply:normal,show"));
        rig.sw.revert();
        check(rig.take().equals("apply:square_698_1440,store:square_698_1440,hide") && rig.display == a);

        // A second switch while one waits: the previous stays the confirmed A, timer restarts.
        rig.sw.request(b);
        rig.advance(6000);
        rig.sw.request(mini);
        check(rig.take().equals("apply:square_470_720,show,apply:portrait_mini,show"));
        check(rig.sw.confirmed() == a && rig.sw.deadline() == rig.time + 10000);
        rig.advance(9000);
        check(rig.sw.pending());
        rig.advance(1000);
        check(rig.take().equals("apply:square_698_1440,store:square_698_1440,hide") && rig.display == a);

        // Asking for the confirmed state while waiting goes back without asking.
        rig.sw.request(b);
        rig.take();
        rig.sw.request(a);
        check(rig.take().equals("apply:square_698_1440,hide") && !rig.sw.pending());

        // Asking again for what's on changes nothing, and doesn't restart the timer.
        rig.sw.request(b);
        long deadline = rig.sw.deadline();
        rig.take();
        rig.advance(3000);
        rig.sw.request(DisplayModes.find("square_470_720"));
        check(rig.take().isEmpty() && rig.sw.deadline() == deadline);
        rig.sw.keep();
        rig.take();
        // Same size by another ID: no dialog, the new ID is kept.
        DisplayModes.Mode same = DisplayModes.custom(720, 720, 245);
        rig.sw.request(same);
        check(rig.take().isEmpty() && rig.sw.confirmed() == same);

        // Screen off while waiting reverts; with nothing waiting it does nothing.
        rig.sw.request(a);
        rig.take();
        rig.sw.screenOff();
        check(rig.take().equals("apply:custom,store:custom,hide") && rig.display == same);
        rig.sw.screenOff();
        check(rig.take().isEmpty());

        // Force (key combo, user switch, boot) drops the waiting switch and confirms.
        rig.sw.request(mini);
        rig.take();
        rig.sw.force(null);
        check(rig.take().equals("apply:normal,store:normal,hide") && !rig.sw.pending()
                && rig.sw.confirmed() == null);
        rig.advance(20000);
        check(rig.take().isEmpty() && rig.display == null);
        // Force with nothing waiting doesn't touch the dialog, and applies again even when on.
        rig.sw.force(null);
        check(rig.take().equals("apply:normal,store:normal"));
        // Keep and Revert with nothing waiting do nothing.
        rig.sw.keep();
        rig.sw.revert();
        check(rig.take().isEmpty() && rig.sw.secondsLeft() == 0);

        keptAndBoot();
        System.out.println(checks + " display mode assertions passed");
    }

    private static final class Boot implements KeyboardController.Clock, DisplayModeBoot.Store {
        long time = 1000;
        int starts;
        boolean bootOn = true;
        final DisplayModeBoot boot = new DisplayModeBoot(this, this);
        public long uptimeMillis() { return time; }
        public int starts() { return starts; }
        public void setStarts(int value) { starts = value; }
        public void disableBoot() { bootOn = false; }
        DisplayModeBoot.Outcome start(DisplayModes.Mode kept, boolean safeMode, boolean key) {
            return boot.start(bootOn, kept, safeMode, key);
        }
    }

    /** The kept mode the switch remembers, and the boot decision with its crash guard. */
    private static DisplayModes.Mode mini() { return DisplayModes.find("portrait_mini"); }

    private static void keptAndBoot() {
        DisplayModes.Mode a = DisplayModes.find("square_698_1440"), b = DisplayModes.find("square_470_720");
        DisplayModes.Mode custom = DisplayModes.custom(900, 900, 200);

        // Kept values round trip; bad ones are normal.
        check(DisplayModes.keptValue(null).equals("normal") && DisplayModes.kept("normal") == null);
        check(DisplayModes.keptValue(a).equals("square_698_1440") && DisplayModes.kept("square_698_1440") == a);
        check(DisplayModes.kept("square_1440") == a);
        check(DisplayModes.keptValue(custom).equals("custom 900 900 200"));
        check(DisplayModes.same(DisplayModes.kept("custom 900 900 200"), custom));
        for (String bad : new String[]{null, "", "custom", "custom ", "custom 10 10 10", "bogus"}) {
            check(DisplayModes.kept(bad) == null);
        }

        // Keep remembers, Revert and the timeout don't, force does, boot doesn't.
        Rig rig = new Rig();
        rig.sw.force(null);
        check(rig.remembered == 1 && rig.kept == null);
        rig.sw.request(a);
        check(rig.remembered == 1);
        rig.sw.keep();
        check(rig.remembered == 2 && rig.kept == a);
        rig.sw.request(b);
        rig.advance(10000);
        check(rig.remembered == 2 && rig.kept == a && rig.display == a);
        rig.sw.request(b);
        rig.sw.revert();
        check(rig.remembered == 2 && rig.kept == a);
        // Back to normal and kept: normal is remembered.
        rig.sw.request(null);
        rig.sw.keep();
        check(rig.kept == null && rig.remembered == 3);
        // Back to the confirmed state while asking remembers.
        rig.sw.request(a);
        rig.sw.request(null);
        check(rig.kept == null && rig.remembered == 4);
        rig.sw.request(DisplayModes.custom(720, 720, 220));
        check(rig.remembered == 4);
        rig.sw.keep();
        check(rig.remembered == 5 && rig.kept.id.equals("custom"));
        rig.sw.request(DisplayModes.custom(720, 720, 245));
        rig.sw.keep();
        rig.take();
        // The same size by another ID isn't a choice: confirmed, not remembered.
        rig.sw.request(DisplayModes.find("square_470_720"));
        check(rig.take().isEmpty() && rig.sw.confirmed() == b && rig.kept.id.equals("custom")
                && rig.remembered == 6);
        // Boot applies and confirms without remembering; a later revert comes back to it.
        rig.sw.boot(a);
        check(rig.take().equals("apply:square_698_1440,store:square_698_1440")
                && rig.sw.confirmed() == a && rig.kept.id.equals("custom") && rig.remembered == 6);
        rig.sw.request(null);
        rig.advance(10000);
        check(rig.display == a && rig.kept.id.equals("custom") && rig.remembered == 6);
        // The key combo after a boot-applied mode: normal, and normal kept.
        rig.sw.force(null);
        check(rig.display == null && rig.kept == null);

        // A boot skip keeps the kept mode through the settings notifying normal (written by
        // the skip itself), and through a custom size edited while normal.
        rig = new Rig();
        rig.sw.force(null);
        rig.sw.request(mini());
        rig.sw.keep();
        check(rig.kept == mini() && rig.remembered == 2);
        rig.sw.boot(null);
        rig.take();
        rig.sw.request(DisplayModes.resolve("normal", null));
        rig.sw.request(DisplayModes.resolve("normal", "900 900 200"));
        check(rig.take().isEmpty() && rig.kept == mini() && rig.remembered == 2 && !rig.sw.pending());
        // A real pick after the skip asks, and Keep remembers it.
        rig.sw.request(a);
        rig.sw.keep();
        check(rig.kept == a && rig.remembered == 3);

        // A pick written just before the timeout revert ran: the settings keep the pick, and
        // its notification starts a new switch from the confirmed mode.
        rig.sw.request(b);
        rig.take();
        rig.raced = true;
        rig.newer = mini();
        rig.advance(10000);
        check(rig.take().equals("apply:square_698_1440,kept:portrait_mini,hide")
                && rig.display == a && rig.sw.confirmed() == a);
        rig.sw.request(mini());
        check(rig.take().equals("apply:portrait_mini,show") && rig.sw.pending());
        rig.sw.keep();
        check(rig.kept == mini());
        // A pick of the mode being asked about isn't newer: the revert writes back as usual.
        rig.sw.request(b);
        rig.take();
        rig.newer = b;
        rig.sw.revert();
        check(rig.take().equals("apply:portrait_mini,store:portrait_mini,hide"));
        rig.raced = false;

        // Keep after reboot off, or normal kept: normal, and the count is cleared.
        Boot boot = new Boot();
        boot.bootOn = false;
        boot.starts = 1;
        check(boot.start(a, false, false) == DisplayModeBoot.Outcome.NORMAL && boot.starts == 0);
        boot.bootOn = true;
        check(boot.start(null, false, false) == DisplayModeBoot.Outcome.NORMAL);
        check(boot.boot.stableAt() == -1);

        // On: applied, counted, and cleared after 60 s.
        check(boot.start(a, false, false) == DisplayModeBoot.Outcome.APPLY && boot.starts == 1);
        check(boot.boot.stableAt() == 61000);
        boot.time += 59999;
        boot.boot.onTimer();
        check(boot.starts == 1);
        boot.time += 1;
        boot.boot.onTimer();
        check(boot.starts == 0 && boot.boot.stableAt() == -1 && boot.bootOn);

        // Two starts again inside a minute of applying: the third comes up normal, and off.
        boot.time = 1000;
        check(boot.start(a, false, false) == DisplayModeBoot.Outcome.APPLY && boot.starts == 1);
        boot.time = 500;  // a full reboot starts uptime again
        check(boot.start(a, false, false) == DisplayModeBoot.Outcome.APPLY && boot.starts == 2);
        check(boot.start(a, false, false) == DisplayModeBoot.Outcome.CRASH_GUARD);
        check(!boot.bootOn && boot.starts == 0 && boot.boot.stableAt() == -1);
        check(boot.start(a, false, false) == DisplayModeBoot.Outcome.NORMAL);

        // Safe mode and the red key: normal this boot, the setting stays, nothing counted.
        boot.bootOn = true;
        boot.starts = 2;
        check(boot.start(a, true, false) == DisplayModeBoot.Outcome.SKIP_SAFE_MODE);
        check(boot.bootOn && boot.starts == 0);
        check(boot.start(a, true, true) == DisplayModeBoot.Outcome.SKIP_SAFE_MODE);
        check(boot.start(a, false, true) == DisplayModeBoot.Outcome.SKIP_KEY && boot.bootOn);
        check(boot.start(a, false, false) == DisplayModeBoot.Outcome.APPLY && boot.starts == 1);
        // A skip after a crash doesn't trip the guard later.
        check(boot.start(a, false, true) == DisplayModeBoot.Outcome.SKIP_KEY && boot.starts == 0);
        check(boot.start(a, false, false) == DisplayModeBoot.Outcome.APPLY && boot.starts == 1);
        // The custom mode at boot.
        check(boot.start(DisplayModes.kept("custom 900 900 200"), false, false)
                == DisplayModeBoot.Outcome.APPLY && boot.starts == 2);

        // A clean shutdown clears the count and the timer: normal reboots inside a minute
        // never trip the guard.
        boot = new Boot();
        for (int i = 0; i < 5; i++) {
            boot.time = 1000;
            check(boot.start(a, false, false) == DisplayModeBoot.Outcome.APPLY && boot.starts == 1);
            boot.time += 20000;
            boot.boot.shutdown();
            check(boot.starts == 0 && boot.boot.stableAt() == -1);
        }
        check(boot.bootOn);
        // Shutdown with nothing counted does nothing; a crash after it still counts.
        boot.boot.shutdown();
        check(boot.start(a, false, false) == DisplayModeBoot.Outcome.APPLY);
        check(boot.start(a, false, false) == DisplayModeBoot.Outcome.APPLY && boot.starts == 2);
        check(boot.start(a, false, false) == DisplayModeBoot.Outcome.CRASH_GUARD && !boot.bootOn);
    }
}
