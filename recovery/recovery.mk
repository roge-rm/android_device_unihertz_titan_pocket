# SPDX-License-Identifier: Apache-2.0
# Lineage recovery: fastbootd, USB gadget, pstore copy and adb keys. See RECOVERY.md.
PRODUCT_PACKAGES += fastbootd
PRODUCT_COPY_FILES += \
    device/unihertz/titan_pocket/recovery/init.recovery.mt6771.rc:$(TARGET_COPY_OUT_RECOVERY)/root/init.recovery.mt6771.rc

# Host adb keys for development, only in a debuggable build with POCKET_DEV_ADB_KEYS=true
# (run-pocket-product-build.py --dev-adb-keys). Release builds have none.
# Recovery adbd reads /adb_keys, which links to /product, not mounted in recovery. The rc
# copies pocket_adb_keys over the link.
ifeq ($(POCKET_DEV_ADB_KEYS),true)
ifneq ($(filter eng userdebug,$(TARGET_BUILD_VARIANT)),)
PRODUCT_ADB_KEYS := vendor/unihertz/titan_pocket/proprietary/adb_keys
PRODUCT_COPY_FILES += \
    vendor/unihertz/titan_pocket/proprietary/adb_keys:$(TARGET_COPY_OUT_RECOVERY)/root/system/etc/security/pocket_adb_keys
endif
endif
