# SPDX-License-Identifier: Apache-2.0
# IMS and VoLTE (MODEM_PORT.md, milestone 8): stock com.mediatek.ims on Android 16.
# Inherited from radios.mk only with POCKET_IMS=true. Needs tools/prepare-pocket-ims-inputs.py
# for ImsService and mediatek-ims-base, which stay in the private vendor tree.

# Re-signed with the platform key (sharedUserId android.uid.phone), privileged, system_ext.
PRODUCT_PACKAGES += \
    ImsService \
    init.pocket-ims.rc \
    privapp-permissions-com.mediatek.ims.xml \
    PocketImsTelephonyOverlay \
    PocketImsFrameworkOverlay

# Boot jars the APK links against: stock mediatek-ims-base and our compat classes.
PRODUCT_PACKAGES += \
    mediatek-ims-base \
    pocket-ims-compat
PRODUCT_BOOT_JARS += \
    platform:mediatek-ims-base \
    platform:pocket-ims-compat

# VoLTE carrier config for Fido and Rogers. Off until IMS registers in device test 4.
ifeq ($(POCKET_IMS_FIDO_VOLTE),true)
PRODUCT_PACKAGES += PocketFidoVolteOverlay
endif
