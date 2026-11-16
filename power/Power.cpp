// SPDX-License-Identifier: Apache-2.0
#define LOG_TAG "powerhal-pocket"

#include "Power.h"

#include <algorithm>
#include <chrono>

#include <android-base/file.h>
#include <android-base/logging.h>
#include <android-base/stringprintf.h>
#include <android/binder_enums.h>
#include <perfmgr/HintManager.h>

namespace aidl::android::hardware::power::impl::pocket {

using ::android::perfmgr::HintManager;

namespace {
// A boost with a duration from the caller is held for at most this long.
constexpr int32_t kMaxBoostMs = 5000;

ndk::ScopedAStatus unsupported() {
    return ndk::ScopedAStatus::fromExceptionCode(EX_UNSUPPORTED_OPERATION);
}

void hold(const std::string& hint, bool enabled) {
    if (enabled) {
        HintManager::GetInstance()->DoHint(hint);
    } else {
        HintManager::GetInstance()->EndHint(hint);
    }
}
}  // namespace

Power::Power() {
    for (Mode m : ndk::enum_range<Mode>()) {
        if (modeSupported(m)) mSupportInfo.modes |= 1LL << static_cast<int32_t>(m);
    }
    for (Boost b : ndk::enum_range<Boost>()) {
        if (boostSupported(b)) mSupportInfo.boosts |= 1LL << static_cast<int32_t>(b);
    }
    mSupportInfo.usesSessions = false;
    mSupportInfo.compositionData.isSupported = false;
    mSupportInfo.headroom.isCpuSupported = false;
    mSupportInfo.headroom.isGpuSupported = false;
    LOG(INFO) << "modes 0x" << std::hex << mSupportInfo.modes << " boosts 0x"
              << mSupportInfo.boosts;
}

// INTERACTIVE has no hint of its own; screen off ends the held boosts, as stock does with
// libpowerhal_UserScnDisableAll.
bool Power::modeSupported(Mode type) const {
    return type == Mode::INTERACTIVE || HintManager::GetInstance()->IsHintSupported(toString(type));
}

bool Power::boostSupported(Boost type) const {
    return HintManager::GetInstance()->IsHintSupported(toString(type));
}

ndk::ScopedAStatus Power::setMode(Mode type, bool enabled) {
    LOG(DEBUG) << "setMode " << toString(type) << " " << enabled;
    if (type == Mode::INTERACTIVE) {
        if (!enabled) {
            HintManager::GetInstance()->EndHint(toString(Mode::LAUNCH));
            HintManager::GetInstance()->EndHint(toString(Boost::INTERACTION));
        }
        return ndk::ScopedAStatus::ok();
    }
    if (HintManager::GetInstance()->IsHintSupported(toString(type))) {
        hold(toString(type), enabled);
    }
    return ndk::ScopedAStatus::ok();
}

ndk::ScopedAStatus Power::isModeSupported(Mode type, bool* _aidl_return) {
    *_aidl_return = modeSupported(type);
    return ndk::ScopedAStatus::ok();
}

ndk::ScopedAStatus Power::setBoost(Boost type, int32_t durationMs) {
    LOG(DEBUG) << "setBoost " << toString(type) << " " << durationMs;
    const std::string hint = toString(type);
    HintManager* hm = HintManager::GetInstance();
    if (!hm->IsHintSupported(hint)) return ndk::ScopedAStatus::ok();
    if (durationMs > 0) {
        hm->DoHint(hint, std::chrono::milliseconds(std::min(durationMs, kMaxBoostMs)));
    } else if (durationMs == 0) {
        // Duration from powerhint.json.
        hm->DoHint(hint);
    } else {
        hm->EndHint(hint);
    }
    return ndk::ScopedAStatus::ok();
}

ndk::ScopedAStatus Power::isBoostSupported(Boost type, bool* _aidl_return) {
    *_aidl_return = boostSupported(type);
    return ndk::ScopedAStatus::ok();
}

ndk::ScopedAStatus Power::createHintSession(int32_t, int32_t, const std::vector<int32_t>&,
                                            int64_t,
                                            std::shared_ptr<IPowerHintSession>* _aidl_return) {
    *_aidl_return = nullptr;
    return unsupported();
}

ndk::ScopedAStatus Power::createHintSessionWithConfig(
        int32_t, int32_t, const std::vector<int32_t>&, int64_t, SessionTag, SessionConfig*,
        std::shared_ptr<IPowerHintSession>* _aidl_return) {
    *_aidl_return = nullptr;
    return unsupported();
}

ndk::ScopedAStatus Power::getHintSessionPreferredRate(int64_t* outNanoseconds) {
    *outNanoseconds = -1;
    return unsupported();
}

ndk::ScopedAStatus Power::getSessionChannel(int32_t, int32_t, ChannelConfig*) {
    return unsupported();
}

ndk::ScopedAStatus Power::closeSessionChannel(int32_t, int32_t) {
    return ndk::ScopedAStatus::ok();
}

ndk::ScopedAStatus Power::getSupportInfo(SupportInfo* _aidl_return) {
    *_aidl_return = mSupportInfo;
    return ndk::ScopedAStatus::ok();
}

ndk::ScopedAStatus Power::getCpuHeadroom(const CpuHeadroomParams&, CpuHeadroomResult*) {
    return unsupported();
}

ndk::ScopedAStatus Power::getGpuHeadroom(const GpuHeadroomParams&, GpuHeadroomResult*) {
    return unsupported();
}

ndk::ScopedAStatus Power::sendCompositionData(const std::vector<CompositionData>&) {
    return ndk::ScopedAStatus::ok();
}

ndk::ScopedAStatus Power::sendCompositionUpdate(const CompositionUpdate&) {
    return ndk::ScopedAStatus::ok();
}

binder_status_t Power::dump(int fd, const char**, uint32_t) {
    HintManager* hm = HintManager::GetInstance();
    ::android::base::WriteStringToFd(
            ::android::base::StringPrintf("HintManager running: %s\n",
                                          hm->IsRunning() ? "true" : "false"),
            fd);
    hm->DumpToFd(fd);
    fsync(fd);
    return STATUS_OK;
}

}  // namespace aidl::android::hardware::power::impl::pocket
