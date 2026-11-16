// SPDX-License-Identifier: Apache-2.0
// Host test of the swipe-scroll gesture. Exits non-zero on the first failure.
#include <cstdio>
#include <cstdlib>
#include <vector>

#include "pad_gesture.h"

using pocketpad::Gesture;
using pocketpad::Output;

static int checks = 0;

static void check(bool value, const char* what) {
    checks++;
    if (!value) {
        std::fprintf(stderr, "check %d failed: %s\n", checks, what);
        std::exit(1);
    }
}

static std::vector<Output> drive(Gesture& g, const std::vector<std::vector<int>>& frames) {
    std::vector<Output> all;
    for (const auto& f : frames) {
        auto out = f.empty() ? g.onFrame(false, 0, 0) : g.onFrame(true, f[0], f[1]);
        all.insert(all.end(), out.begin(), out.end());
    }
    return all;
}

int main() {
    // A tap sends nothing.
    {
        Gesture g;
        check(drive(g, {{360, 180}, {361, 181}, {}}).empty(), "tap sends nothing");
    }
    // Middle band: 75 px across and 50 display px down (25 pad units) are still a wobble.
    {
        Gesture g;
        check(drive(g, {{300, 180}, {375, 205}, {225, 155}, {}}).empty(), "middle wobble at the limit");
    }
    // One display pixel past 50 px down starts the drag: down at the last held
    // position, then a move to the current one, moves after, up at lift.
    {
        Gesture g;
        auto out = drive(g, {{300, 180}, {300, 200}, {300, 206}, {300, 230}, {}});
        check(out.size() == 4, "drag event count");
        check(out[0].type == Output::DOWN && out[0].x == 300 && out[0].y == 200, "held down");
        check(out[1].type == Output::MOVE && out[1].y == 206, "first move");
        check(out[2].type == Output::MOVE && out[2].y == 230, "later move");
        check(out[3].type == Output::UP && out[3].y == 230, "up at lift");
    }
    // Sideways in the middle band needs more than 75 px.
    {
        Gesture g;
        check(drive(g, {{300, 180}, {375, 180}}).empty(), "75 px across held");
        check(g.held(), "still held");
        auto out = g.onFrame(true, 376, 180);
        check(out.size() == 2 && g.dragging(), "76 px across drags");
    }
    // The first frame past the threshold sends the down at the finger-down point.
    {
        Gesture g;
        auto out = drive(g, {{360, 100}, {360, 200}});
        check(out.size() == 2 && out[0].y == 100 && out[1].y == 200, "jump drags from down point");
    }
    // Near the edges (current x outside 72-648) the slop is 120 x 200 display px.
    {
        Gesture g;
        check(drive(g, {{20, 100}, {20, 200}, {20, 0}}).empty(), "edge: 200 px down held");
        check(drive(g, {{20, 201}}).size() == 2, "edge: 201 px down drags");
    }
    {
        Gesture g;
        check(drive(g, {{700, 180}, {660, 180}, {650, 180}}).empty(), "edge band across held");
        // Now at x 640 the current x is in the middle band and 60 px is under 75.
        check(drive(g, {{640, 180}}).empty(), "middle band by current x");
        check(drive(g, {{580, 180}}).size() == 2, "120 px across drags");
    }
    // A repeated frame while dragging sends no extra move.
    {
        Gesture g;
        drive(g, {{300, 100}, {300, 200}});
        check(g.onFrame(true, 300, 200).empty(), "no duplicate move");
    }
    // Cancel ends a drag with an up and a held finger with nothing.
    {
        Gesture g;
        drive(g, {{300, 100}, {300, 200}});
        auto out = g.cancel();
        check(out.size() == 1 && out[0].type == Output::UP, "cancel drag");
        drive(g, {{300, 100}});
        check(g.cancel().empty() && !g.held(), "cancel held");
        // After a cancel a lift sends nothing.
        check(g.onFrame(false, 0, 0).empty(), "lift after cancel");
    }
    // Out-of-range coordinates are clamped to the pad.
    {
        Gesture g;
        auto out = drive(g, {{300, 0}, {300, 9999}});
        check(out.size() == 2 && out[1].y == 360, "clamped");
    }
    // F11 sequence: BTN_TOOL_FINGER only, no BTN_TOUCH, no tracking id.
    {
        pocketpad::FingerTracker f;
        check(!f.down(), "tracker starts up");
        f.key(false, true, 1);
        check(f.down(), "tool finger is down");
        f.key(true, false, 0);
        f.key(false, true, 0);
        check(!f.down(), "cleared is up");
        f.trackingId(5);
        check(f.down(), "tracking id is down");
        f.trackingId(-1);
        check(!f.down(), "tracking id -1 is up");
    }
    std::printf("%d pad gesture checks passed\n", checks);
    return 0;
}
