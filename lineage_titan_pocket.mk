# SPDX-License-Identifier: Apache-2.0
LINEAGE_BUILD := titan_pocket
$(call inherit-product, $(SRC_TARGET_DIR)/product/core_64_bit.mk)
$(call inherit-product, $(SRC_TARGET_DIR)/product/full_base_telephony.mk)
$(call inherit-product, vendor/lineage/config/common_full_phone.mk)
PRODUCT_NAME := lineage_titan_pocket
PRODUCT_DEVICE := titan_pocket
PRODUCT_BRAND := Unihertz
PRODUCT_MANUFACTURER := Unihertz
# The model is "Titan Pocket". TKCore checks the model teed sends against its licence byte for byte,
# so the teed shim in the vendor overlay (libpocketteed.so) gives teed the stock "Titan pocket".
PRODUCT_MODEL := Titan Pocket
PRODUCT_SHIPPING_API_LEVEL := 30
PRODUCT_USE_DYNAMIC_PARTITIONS := true
PRODUCT_BUILD_USERDATA_IMAGE := false
PRODUCT_BUILD_CACHE_IMAGE := false
PRODUCT_BUILD_SYSTEM_EXT_IMAGE := false
PRODUCT_PACKAGES += PocketInputSettings com.android.vndk.v30
# Keyboard layout for aw9523-key, so Android 16 doesn't put the US layout over its Alt layer.
PRODUCT_PACKAGES += PocketKeyboardLayout
# Hardware Home (front strip), Back and Recents, no on-screen nav bar.
PRODUCT_PACKAGES += PocketNavFrameworkOverlay PocketNavLineageOverlay
# Notification light on the MT6370 RGB LED; the charger's own indicator shows charging.
PRODUCT_PACKAGES += PocketLightsFrameworkOverlay PocketLightsLineageOverlay
# Bigger bouncer keys for the 720x720 screen.
PRODUCT_PACKAGES += PocketKeyguardOverlay
# Updater reads the owner repo's feed.
PRODUCT_PACKAGES += PocketUpdaterOverlay
# Power HAL on system_ext (libperfmgr, power/powerhint.json) for the boosts the stock
# mtkpower HAL can't do on 5.10 (POWER_PORT.md).
PRODUCT_SOONG_NAMESPACES += device/unihertz/titan_pocket/power
PRODUCT_PACKAGES += android.hardware.power-service.pocket
# Charging control (Settings > Battery) on system_ext, with the 5.10 charger's charging_enabled.
PRODUCT_PACKAGES += vendor.lineage.health-service.pocket
# OCV run logger for the battery gauge, off until persist.vendor.pocket.battlog=1.
PRODUCT_PACKAGES += pocket_battlog
# Keyboard touchpad swipe scroll, off until persist.sys.pocket.pad_scroll=1.
PRODUCT_PACKAGES += pocket_padd
# Keyboard light, FUNC1/FUNC2 presses and the pad key guard in system_server (patches/android/0004).
PRODUCT_SYSTEM_PROPERTIES += ro.pocket.input_policy=true
# Silence the audio HAL's speech messenger while there is no CCCI driver: it retries
# /dev/ccci_aud every 10 ms forever (about 100 lines a second). Drop this with CCCI.
PRODUCT_PRODUCT_PROPERTIES += log.tag.SpeechMessengerNormal=S
# Front strip fingerprint sensor in the framework (stock HIDL 2.1 HAL); face stays hidden.
PRODUCT_PACKAGES += PocketFingerprintFrameworkOverlay
PRODUCT_COPY_FILES += \
    device/unihertz/titan_pocket/rootdir/etc/permissions/pocket-no-face.xml:$(TARGET_COPY_OUT_PRODUCT)/etc/permissions/pocket-no-face.xml
# Software KeyMint on system_ext, off by default. Set POCKET_SOFTWARE_KEYMINT=true only
# together with vendor overlay v5, which keeps the TrustKernel Keymaster 4.0 HAL off
# (KEYMASTER_PORT.md). Overlay v6 and the default build use the TEE Keymaster.
ifeq ($(POCKET_SOFTWARE_KEYMINT),true)
PRODUCT_PACKAGES += android.hardware.security.keymint-service.pocket
endif
# Engineering boot: adb on and a debuggable build.
ifeq ($(POCKET_ENGINEERING_BUILD),true)
# Keep adb on at boot (ro.adb.secure stays 1, key auth) and make the build debuggable
# after Lineage's common.mk sets it not debuggable. Empty, as the build treats any text as true.
PRODUCT_PRODUCT_PROPERTIES += persist.sys.usb.config=adb
PRODUCT_NOT_DEBUGGABLE_IN_USERDEBUG :=
PRODUCT_COPY_FILES += \
    device/unihertz/titan_pocket/rootdir/etc/init/init.pocket.adbroot.rc:$(TARGET_COPY_OUT_SYSTEM)/etc/init/init.pocket.adbroot.rc
# Camera trial builds only (run-pocket-product-build.py --camera-debug): mtkcam HAL debug logs.
ifeq ($(POCKET_CAMERA_DEBUG),true)
PRODUCT_COPY_FILES += \
    device/unihertz/titan_pocket/rootdir/etc/init/init.pocket.camdebug.rc:$(TARGET_COPY_OUT_PRODUCT)/etc/init/init.pocket.camdebug.rc
endif
endif
PRODUCT_COPY_FILES += \
    device/unihertz/titan_pocket/rootdir/etc/init/init.pocket.charger.rc:$(TARGET_COPY_OUT_SYSTEM)/etc/init/init.pocket.charger.rc \
    device/unihertz/titan_pocket/rootdir/etc/init/init.pocket.usb.rc:$(TARGET_COPY_OUT_SYSTEM)/etc/init/init.pocket.usb.rc \
    device/unihertz/titan_pocket/rootdir/etc/init/init.pocket.torch.rc:$(TARGET_COPY_OUT_SYSTEM)/etc/init/init.pocket.torch.rc \
    device/unihertz/titan_pocket/rootdir/etc/init/init.pocket.power.rc:$(TARGET_COPY_OUT_SYSTEM)/etc/init/init.pocket.power.rc \
    device/unihertz/titan_pocket/rootdir/etc/init/init.pocket.battlog.rc:$(TARGET_COPY_OUT_SYSTEM_EXT)/etc/init/init.pocket.battlog.rc \
    device/unihertz/titan_pocket/rootdir/etc/fstab.mt6771:$(TARGET_COPY_OUT_RAMDISK)/first_stage_ramdisk/fstab.mt6771 \
    device/unihertz/titan_pocket/rootdir/etc/fstab.mt6771:$(TARGET_COPY_OUT_SYSTEM)/etc/fstab.mt6771 \
    device/unihertz/titan_pocket/rootdir/usr/idc/mtk-pad.idc:$(TARGET_COPY_OUT_SYSTEM)/usr/idc/mtk-pad.idc \
    device/unihertz/titan_pocket/rootdir/usr/idc/aw9523-key.idc:$(TARGET_COPY_OUT_SYSTEM)/usr/idc/aw9523-key.idc \
    device/unihertz/titan_pocket/rootdir/usr/keylayout/aw9523-key.kl:$(TARGET_COPY_OUT_SYSTEM)/usr/keylayout/aw9523-key.kl \
    device/unihertz/titan_pocket/rootdir/usr/keychars/aw9523-key.kcm:$(TARGET_COPY_OUT_SYSTEM)/usr/keychars/aw9523-key.kcm \
    device/unihertz/titan_pocket/rootdir/usr/idc/mtk-kpd.idc:$(TARGET_COPY_OUT_SYSTEM)/usr/idc/mtk-kpd.idc \
    device/unihertz/titan_pocket/rootdir/usr/keylayout/mtk-kpd.kl:$(TARGET_COPY_OUT_SYSTEM)/usr/keylayout/mtk-kpd.kl \
    device/unihertz/titan_pocket/rootdir/usr/keylayout/fingerprint_key.kl:$(TARGET_COPY_OUT_SYSTEM)/usr/keylayout/fingerprint_key.kl
# Wi-Fi, Bluetooth, GPS, FM and NFC, system side.
$(call inherit-product, device/unihertz/titan_pocket/radios.mk)
# Lineage recovery with fastbootd, adb and pstore (RECOVERY.md).
$(call inherit-product, device/unihertz/titan_pocket/recovery/recovery.mk)
$(call inherit-product-if-exists, vendor/unihertz/titan_pocket/titan_pocket-vendor.mk)
# Google apps (run-pocket-product-build.py --gapps): MindTheGapps in the source tree's
# vendor/gapps, which isn't in this repo (GAPPS.md).
ifeq ($(POCKET_GAPPS),true)
$(call inherit-product, vendor/gapps/arm64/arm64-vendor.mk)
endif
# All platform locales/carrier configuration remain available. No proprietary APKs copied.
# The isolated engineering builder enables compilation; installation remains gated.
