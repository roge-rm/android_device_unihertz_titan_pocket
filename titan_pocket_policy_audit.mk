# SPDX-License-Identifier: Apache-2.0
# Generic-platform compile fixture; does not model stock vendor VNDK/FCM compatibility.
LINEAGE_BUILD := titan_pocket
$(call inherit-product, $(SRC_TARGET_DIR)/product/aosp_arm64.mk)
$(call inherit-product, vendor/lineage/config/lineage_sdk_common.mk)
PRODUCT_PACKAGES += PocketInputSettings
PRODUCT_NAME := titan_pocket_policy_audit
PRODUCT_DEVICE := titan_pocket
PRODUCT_BRAND := Android
PRODUCT_MANUFACTURER := Unihertz
PRODUCT_MODEL := Titan Pocket source audit only
PRODUCT_BUILD_USERDATA_IMAGE := false
