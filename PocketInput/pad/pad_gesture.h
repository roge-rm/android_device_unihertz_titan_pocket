// SPDX-License-Identifier: Apache-2.0
// One-finger swipe scroll for the keyboard touchpad (mtk-pad).
// Pure logic, no Android or kernel headers, so the host test can run it.
#pragma once

#include <cstdint>
#include <vector>

namespace pocketpad {

// Pad and display geometry. The pad reports 0-720 x 0-360 and the panel
// is 720 x 720, so one pad unit is one display pixel across and two down.
// The virtual touchscreen uses the pad's ranges and InputReader scales it.
struct Geometry {
    int padWidth = 720;
    int padHeight = 360;
    int displayWidth = 720;
    int displayHeight = 720;
};

// Stock's move threshold, in display pixels. The middle band is x 72 to 648,
// tested against the current x, as stock's dispatchTouches does.
constexpr float kBandLeft = 72.0f;
constexpr float kBandRight = 648.0f;
constexpr float kMiddleSlopX = 75.0f;
constexpr float kMiddleSlopY = 50.0f;
constexpr float kEdgeSlopX = 120.0f;
constexpr float kEdgeSlopY = 200.0f;

// Finger-down state from the pad's key and tracking-id events. The F11 path
// sends BTN_TOOL_FINGER only, other paths BTN_TOUCH or a tracking id. Down
// while any of the three is set.
struct FingerTracker {
    bool touch = false, tool = false, tracking = false;
    void key(bool isTouch, bool isTool, int value) {
        if (isTouch) touch = value != 0;
        if (isTool) tool = value != 0;
    }
    void trackingId(int value) { tracking = value >= 0; }
    bool down() const { return touch || tool || tracking; }
};

struct Output {
    enum Type { DOWN, MOVE, UP };
    Type type;
    int x;  // pad units
    int y;
};

// Called with each SYN_REPORT frame of the pad. Holds back the finger down
// until the finger has moved past the threshold, then sends the held down at
// the last position inside the threshold, a move to the current one and every
// move after. A tap or a small wobble sends nothing.
class Gesture {
  public:
    explicit Gesture(Geometry geometry = Geometry()) : geo_(geometry) {}

    // touching false is a lift. Returns what to send to the virtual touchscreen.
    std::vector<Output> onFrame(bool touching, int x, int y);
    // SYN_DROPPED, device loss or shutdown: ends a live drag with an up.
    std::vector<Output> cancel();

    bool dragging() const { return state_ == DRAGGING; }
    bool held() const { return state_ == HELD; }

  private:
    enum State { IDLE, HELD, DRAGGING };
    bool pastThreshold(int x, int y) const;
    float toDisplayX(int x) const;
    float toDisplayY(int y) const;

    Geometry geo_;
    State state_ = IDLE;
    int downX_ = 0, downY_ = 0;  // where the finger went down
    int lastX_ = 0, lastY_ = 0;  // last frame still inside the threshold, or last sent
};

}  // namespace pocketpad
