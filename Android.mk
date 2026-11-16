# SPDX-License-Identifier: Apache-2.0
# Files releasetools.py reads from target-files RADIO/ to apply the vendor overlay in OTAs.
LOCAL_PATH := $(call my-dir)

ifeq ($(TARGET_PRODUCT),lineage_titan_pocket)
$(call add-radio-file,ota/pocket_vendor.sh)
$(call add-radio-file,ota/pocket_addond.sh)
# Target-files copies releasetools.py without depending on it, so tie it to a radio file.
$(PRODUCT_OUT)/pocket_vendor.sh: $(LOCAL_PATH)/releasetools.py
# No recovery patch: it goes in vendor, which is prebuilt (ota/no_recovery_patch.sh).
MAKE_RECOVERY_PATCH := $(LOCAL_PATH)/ota/no_recovery_patch.sh
# Private payload from tools/prepare-pocket-vendor-ota.py, staged by prepare-pocket-product-inputs.py.
LOCAL_PATH := vendor/unihertz/titan_pocket/proprietary
$(call add-radio-file,pocket_vendor_overlay.zip)
LOCAL_PATH := $(call my-dir)
endif
