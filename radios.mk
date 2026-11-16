# SPDX-License-Identifier: Apache-2.0
# Wi-Fi, Bluetooth, GPS, FM and NFC on the system side (WIFI_PORT.md, milestone 10).
# The HALs, supplicant, hostapd, their rc files and the Wi-Fi and framework
# overlays all stay as stock in vendor. Bluetooth profile and FM settings are in
# product.prop.

# Wi-Fi interface names, as stock system build.prop. The vendor HAL and the framework
# read them; wlan0 and p2p0 are also their defaults.
PRODUCT_SYSTEM_PROPERTIES += \
    wifi.interface=wlan0 \
    wifi.direct.interface=p2p0

# Telephony (MODEM_PORT.md, milestone 7): no props here. The stock vendor build.prop sets
# persist.radio.multisim.config=dsds, ro.telephony.sim.count=2 and the other DSDS props,
# and A16 labels them (radio_control_prop, telephony_config_prop).
# SIM hot swap without a restart prompt, as stock.
PRODUCT_PACKAGES += PocketTelephonyFrameworkOverlay

# IMS and VoLTE (milestone 8). Off until the stock APK's Android 16 gaps are closed; see ims/ims.mk.
ifeq ($(POCKET_IMS),true)
$(call inherit-product, device/unihertz/titan_pocket/ims/ims.mk)
endif

# FM: Lineage FMRadio (Apache-2.0) with its MediaTek libfmjni on /dev/fm, patched by
# patches/android/0005 for the MT6631 driver's fm_tune_parm.
PRODUCT_PACKAGES += FMRadio

# NFC: tag reader for the device test. The NFC module reads stock /vendor/etc/libnfc-nci.conf.
PRODUCT_PACKAGES += Tag

# Headset jack events from the ACCDET input device (AUDIO_PORT.md).
PRODUCT_PACKAGES += PocketAudioJackOverlay

# A2DP and hearing aid audio through a system-side Bluetooth audio HAL (AUDIO_PORT.md).
# The stock audio.bluetooth.default only reads MediaTek's bluetooth.audio 2.1 session,
# which the A16 Bluetooth stack can't start. Sources from TrebleDroid's sysbta.
PRODUCT_PACKAGES += \
    audio.sysbta.default \
    android.hardware.bluetooth.audio-service-system
PRODUCT_COPY_FILES += \
    device/unihertz/titan_pocket/bluetooth-audio/config/sysbta_audio_policy_configuration.xml:$(TARGET_COPY_OUT_SYSTEM)/etc/sysbta_audio_policy_configuration.xml
