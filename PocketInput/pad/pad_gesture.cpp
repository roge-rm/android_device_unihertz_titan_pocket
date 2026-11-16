// SPDX-License-Identifier: Apache-2.0
#include "pad_gesture.h"

#include <algorithm>
#include <cmath>

namespace pocketpad {

float Gesture::toDisplayX(int x) const {
    return static_cast<float>(x) * geo_.displayWidth / geo_.padWidth;
}

float Gesture::toDisplayY(int y) const {
    return static_cast<float>(y) * geo_.displayHeight / geo_.padHeight;
}

bool Gesture::pastThreshold(int x, int y) const {
    float cx = toDisplayX(x);
    bool middle = cx >= kBandLeft && cx <= kBandRight;
    float slopX = middle ? kMiddleSlopX : kEdgeSlopX;
    float slopY = middle ? kMiddleSlopY : kEdgeSlopY;
    // Stock sends nothing while both distances are within the slop.
    return std::fabs(cx - toDisplayX(downX_)) > slopX ||
           std::fabs(toDisplayY(y) - toDisplayY(downY_)) > slopY;
}

std::vector<Output> Gesture::onFrame(bool touching, int x, int y) {
    std::vector<Output> out;
    x = std::clamp(x, 0, geo_.padWidth);
    y = std::clamp(y, 0, geo_.padHeight);
    if (!touching) {
        if (state_ == DRAGGING) out.push_back({Output::UP, lastX_, lastY_});
        state_ = IDLE;
        return out;
    }
    switch (state_) {
        case IDLE:
            state_ = HELD;
            downX_ = lastX_ = x;
            downY_ = lastY_ = y;
            break;
        case HELD:
            if (!pastThreshold(x, y)) {
                lastX_ = x;
                lastY_ = y;
                break;
            }
            state_ = DRAGGING;
            out.push_back({Output::DOWN, lastX_, lastY_});
            out.push_back({Output::MOVE, x, y});
            lastX_ = x;
            lastY_ = y;
            break;
        case DRAGGING:
            if (x != lastX_ || y != lastY_) out.push_back({Output::MOVE, x, y});
            lastX_ = x;
            lastY_ = y;
            break;
    }
    return out;
}

std::vector<Output> Gesture::cancel() {
    std::vector<Output> out;
    if (state_ == DRAGGING) out.push_back({Output::UP, lastX_, lastY_});
    state_ = IDLE;
    return out;
}

}  // namespace pocketpad
