// SPDX-License-Identifier: Apache-2.0
// Lineage's health service main without IFastCharge.

#include "ChargingControl.h"

#include <android-base/logging.h>
#include <android/binder_manager.h>
#include <android/binder_process.h>

using ::aidl::vendor::lineage::health::ChargingControl;

int main() {
    ABinderProcess_setThreadPoolMaxThreadCount(0);
    std::shared_ptr<ChargingControl> cc = ndk::SharedRefBase::make<ChargingControl>();

    const std::string instance = std::string(ChargingControl::descriptor) + "/default";
    binder_status_t status = AServiceManager_addService(cc->asBinder().get(), instance.c_str());
    CHECK_EQ(status, STATUS_OK);

    ABinderProcess_joinThreadPool();
    return EXIT_FAILURE;  // not reached
}
