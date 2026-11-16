// SPDX-License-Identifier: Apache-2.0
#pragma once

#include <aidl/android/hardware/power/BnPower.h>

namespace aidl::android::hardware::power::impl::pocket {

// Modes and boosts map to powerhint.json hints of the same name (toString of the enum).
// All calls arrive on the one binder thread (thread pool size 0), so no locking here;
// HintManager has its own locks.
class Power : public BnPower {
  public:
    Power();
    ndk::ScopedAStatus setMode(Mode type, bool enabled) override;
    ndk::ScopedAStatus isModeSupported(Mode type, bool* _aidl_return) override;
    ndk::ScopedAStatus setBoost(Boost type, int32_t durationMs) override;
    ndk::ScopedAStatus isBoostSupported(Boost type, bool* _aidl_return) override;
    ndk::ScopedAStatus createHintSession(int32_t tgid, int32_t uid,
                                         const std::vector<int32_t>& threadIds,
                                         int64_t durationNanos,
                                         std::shared_ptr<IPowerHintSession>* _aidl_return) override;
    ndk::ScopedAStatus createHintSessionWithConfig(
            int32_t tgid, int32_t uid, const std::vector<int32_t>& threadIds, int64_t durationNanos,
            SessionTag tag, SessionConfig* config,
            std::shared_ptr<IPowerHintSession>* _aidl_return) override;
    ndk::ScopedAStatus getHintSessionPreferredRate(int64_t* outNanoseconds) override;
    ndk::ScopedAStatus getSessionChannel(int32_t tgid, int32_t uid,
                                         ChannelConfig* _aidl_return) override;
    ndk::ScopedAStatus closeSessionChannel(int32_t tgid, int32_t uid) override;
    ndk::ScopedAStatus getSupportInfo(SupportInfo* _aidl_return) override;
    ndk::ScopedAStatus getCpuHeadroom(const CpuHeadroomParams& params,
                                      CpuHeadroomResult* _aidl_return) override;
    ndk::ScopedAStatus getGpuHeadroom(const GpuHeadroomParams& params,
                                      GpuHeadroomResult* _aidl_return) override;
    ndk::ScopedAStatus sendCompositionData(const std::vector<CompositionData>& data) override;
    ndk::ScopedAStatus sendCompositionUpdate(const CompositionUpdate& update) override;
    binder_status_t dump(int fd, const char** args, uint32_t numArgs) override;

  private:
    bool modeSupported(Mode type) const;
    bool boostSupported(Boost type) const;
    SupportInfo mSupportInfo;
};

}  // namespace aidl::android::hardware::power::impl::pocket
