// SPDX-License-Identifier: Apache-2.0
#define LOG_TAG "powerhal-pocket"

#include <condition_variable>
#include <mutex>
#include <thread>

#include <android-base/logging.h>
#include <android/binder_manager.h>
#include <android/binder_process.h>
#include <perfmgr/HintManager.h>

#include "Power.h"

using aidl::android::hardware::power::impl::pocket::Power;
using ::android::perfmgr::HintManager;

namespace {
constexpr char kConfig[] = "/system_ext/etc/powerhint.json";

// The stock vendor mtkpower service also registers IPower/default from its own thread and
// servicemanager keeps the last one added. When a remote binder takes the name, add ours
// again. The callback runs on a binder thread, where a synchronous call to servicemanager
// isn't allowed, so a worker thread does the add.
struct Reclaim {
    std::mutex lock;
    std::condition_variable cv;
    bool pending = false;
};

void onRegister(const char* instance, AIBinder* registered, void* cookie) {
    if (!AIBinder_isRemote(registered)) return;  // our own
    LOG(WARNING) << "another process registered " << instance << ", adding ours again";
    auto* r = static_cast<Reclaim*>(cookie);
    std::lock_guard<std::mutex> g(r->lock);
    r->pending = true;
    r->cv.notify_one();
}
}  // namespace

int main() {
    if (HintManager::GetFromJSON(kConfig, false) == nullptr) {
        LOG(FATAL) << "invalid config " << kConfig;
    }

    ABinderProcess_setThreadPoolMaxThreadCount(0);
    std::shared_ptr<Power> power = ndk::SharedRefBase::make<Power>();
    const std::string instance = std::string(Power::descriptor) + "/default";
    binder_status_t status = AServiceManager_addService(power->asBinder().get(), instance.c_str());
    CHECK_EQ(status, STATUS_OK);
    LOG(INFO) << "registered " << instance;

    HintManager::GetInstance()->Start();

    static Reclaim reclaim;
    std::thread([power, instance] {
        for (;;) {
            std::unique_lock<std::mutex> g(reclaim.lock);
            reclaim.cv.wait(g, [] { return reclaim.pending; });
            reclaim.pending = false;
            g.unlock();
            binder_status_t s = AServiceManager_addService(power->asBinder().get(), instance.c_str());
            LOG(INFO) << "registered " << instance << " again: " << s;
        }
    }).detach();
    AServiceManager_NotificationRegistration* note =
            AServiceManager_registerForServiceNotifications(instance.c_str(), onRegister, &reclaim);
    if (note == nullptr) LOG(ERROR) << "no registration notifications for " << instance;

    ABinderProcess_joinThreadPool();
    return EXIT_FAILURE;  // not reached
}
