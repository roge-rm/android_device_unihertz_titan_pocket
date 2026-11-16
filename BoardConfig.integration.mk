# SPDX-License-Identifier: Apache-2.0
# Real-device userspace integration build. This does not authorize installation.
include device/unihertz/titan_pocket/BoardConfig.hardware.mk
include vendor/lineage/config/BoardConfigSoong.mk

TARGET_NO_BOOTLOADER := true
BOARD_SHIPPING_API_LEVEL := 30
TARGET_USERIMAGES_USE_EXT4 := true
BOARD_SYSTEMIMAGE_FILE_SYSTEM_TYPE := ext4
BOARD_PRODUCTIMAGE_FILE_SYSTEM_TYPE := ext4
BOARD_VENDORIMAGE_FILE_SYSTEM_TYPE := ext4
BOARD_FLASH_BLOCK_SIZE := 131072
BOARD_SYSTEMIMAGE_PARTITION_RESERVED_SIZE := 16777216
BOARD_PRODUCTIMAGE_PARTITION_RESERVED_SIZE := 16777216
BOARD_PREBUILT_VENDORIMAGE := vendor/unihertz/titan_pocket/proprietary/vendor.img
BOARD_BUILD_VENDOR_IMAGE := true
BOARD_USES_RECOVERY_AS_BOOT := false
BOARD_USES_VENDORIMAGE := true
TARGET_RECOVERY_FSTAB := device/unihertz/titan_pocket/rootdir/etc/recovery.fstab
TARGET_COPY_OUT_VENDOR := vendor
TARGET_COPY_OUT_PRODUCT := product
TARGET_COPY_OUT_SYSTEM_EXT := system/system_ext

# Our 5.10 kernel as a prebuilt Image.gz, staged by tools/prepare-pocket-product-inputs.py
# from a recorded local source build, never an OEM kernel.
TARGET_FORCE_PREBUILT_KERNEL := true
TARGET_PREBUILT_KERNEL := vendor/unihertz/titan_pocket/proprietary/kernel
TARGET_KERNEL_CONFIG_EXT := vendor/unihertz/titan_pocket/proprietary/engineering.config
TARGET_KERNEL_ARCH := arm64
TARGET_KERNEL_CLANG_COMPILE := true
BOARD_KERNEL_IMAGE_NAME := Image.gz
# LK loads the kernel at 0x40200000 (2 MiB aligned for text_offset 0).
BOARD_KERNEL_OFFSET := 0x00200000

# Boot and recovery laid out as tools/package-pocket-boot.py does: header v2, the board dtb
# in the stock DT table at 0x54000000 and an empty recovery_dtbo in both images, since LK
# uses a header v2 recovery_dtbo on normal boot too.
BOARD_INCLUDE_DTB_IN_BOOTIMG := true
BOARD_PREBUILT_DTBIMAGE_DIR := vendor/unihertz/titan_pocket/proprietary/dtb
BOARD_INCLUDE_RECOVERY_DTBO := true
BOARD_PREBUILT_RECOVERY_DTBOIMAGE := vendor/unihertz/titan_pocket/proprietary/recovery_dtbo.img
BOARD_MKBOOTIMG_ARGS += --header_version $(BOARD_BOOT_HEADER_VERSION)
BOARD_MKBOOTIMG_ARGS += --recovery_dtbo $(BOARD_PREBUILT_RECOVERY_DTBOIMAGE)
# Stock header values, which LK hands the TEE. These come after the build's own
# --os_version and --os_patch_level, so they win.
BOARD_MKBOOTIMG_ARGS += --os_version 11.0.0 --os_patch_level 2022-09
# Stock bootargs that LK doesn't add itself (the board dtb has empty bootargs), plus our
# debug options. Same as package-pocket-boot.py CMDLINE.
BOARD_KERNEL_CMDLINE := bootopt=64S3,32N2,64N2 buildvariant=$(TARGET_BUILD_VARIANT)
BOARD_KERNEL_CMDLINE += clk_ignore_unused regulator_ignore_unused loglevel=8 printk.time=1
BOARD_KERNEL_CMDLINE += androidboot.selinux=enforcing androidboot.hardware=mt6771
BOARD_KERNEL_CMDLINE += firmware_class.path=/vendor/firmware loop.max_part=7
BOARD_KERNEL_CMDLINE += cgroup.memory=nosocket,nokmem printk.devkmsg=on panic=10 log_buf_len=4M
BOARD_KERNEL_CMDLINE += aw9523_key.start_suspended=0
# Recovery runs permissive, as the packaged recovery always has. The later --cmdline wins.
# BOARD_INCLUDE_RECOVERY_DTBO adds recovery_dtbo to recovery itself, from RECOVERY/ when
# releasetools rebuilds it, so the source path is left out here.
BOARD_RECOVERY_MKBOOTIMG_ARGS := \
    $(filter-out --recovery_dtbo $(BOARD_PREBUILT_RECOVERY_DTBOIMAGE),$(BOARD_MKBOOTIMG_ARGS)) \
    --cmdline "$(subst androidboot.selinux=enforcing,androidboot.selinux=permissive,$(strip $(BOARD_KERNEL_CMDLINE)))"
# Put the built boot.img and recovery.img in target-files as they are (BOOTABLE_IMAGES), so
# releasetools doesn't rebuild them with its own os_version order.
BOARD_CUSTOM_BOOTIMG := true

# releasetools.py: full OTAs apply our vendor overlay files to the phone's vendor partition
# and never carry vendor.img. Its inputs go in target-files RADIO/ (Android.mk).
TARGET_RELEASETOOLS_EXTENSIONS := device/unihertz/titan_pocket
# A-only: block OTAs installed by our recovery. Android 16 makes A/B the default, which makes
# the OTA tools build A/B packages and the Updater install through update_engine.
AB_OTA_UPDATER := false

BOARD_AVB_ENABLE := true
# vbmeta flags 3 (verification off), as stock ships: LK checks only vbmeta's own signature and
# fs_mgr mounts without dm-verity, which the vendor overlay writes need.
BOARD_AVB_MAKE_VBMETA_IMAGE_ARGS += --flags 3
# Boot chained from vbmeta at rollback index location 3, as stock's is. These test keys are for
# development builds; tools/sign-pocket-release.py signs releases with our AVB key.
BOARD_AVB_BOOT_KEY_PATH := external/avb/test/data/testkey_rsa2048.pem
BOARD_AVB_BOOT_ALGORITHM := SHA256_RSA2048
BOARD_AVB_BOOT_ROLLBACK_INDEX := 0
BOARD_AVB_BOOT_ROLLBACK_INDEX_LOCATION := 3
# Non-A/B recovery is signed on its own, not chained from vbmeta, as stock's is (SHA256_RSA2048,
# rollback index 0 at location 0).
BOARD_AVB_RECOVERY_KEY_PATH := external/avb/test/data/testkey_rsa2048.pem
BOARD_AVB_RECOVERY_ALGORITHM := SHA256_RSA2048
BOARD_AVB_RECOVERY_ROLLBACK_INDEX := 0
BOARD_AVB_RECOVERY_ROLLBACK_INDEX_LOCATION := 0
BOARD_AVB_VBMETA_SYSTEM := system product
BOARD_AVB_VBMETA_SYSTEM_ALGORITHM := SHA256_RSA4096
BOARD_AVB_VBMETA_SYSTEM_KEY_PATH := external/avb/test/data/testkey_rsa4096.pem
BOARD_AVB_VBMETA_SYSTEM_ROLLBACK_INDEX := 0
BOARD_AVB_VBMETA_SYSTEM_ROLLBACK_INDEX_LOCATION := 1

# These are real hardware clients, not generic audio/camera/display stubs.
BOARD_HAVE_BLUETOOTH := true
TARGET_USES_HARDWARE_QCOM_BOOTLOADER := false

# <vendor-ndk> 30 for the stock vendor's VNDK 30 matrix. PRODUCT_EXTRA_VNDK_VERSIONS would
# do the same but needs prebuilts/vndk/v30, which this tree doesn't have.
SYSTEM_EXT_MANIFEST_FILES += device/unihertz/titan_pocket/vintf/system_ext_vndk30.xml
# Stock MediaTek radio HALs only vendor processes use (WIFI_PORT.md, milestone 10).
DEVICE_FRAMEWORK_COMPATIBILITY_MATRIX_FILE += device/unihertz/titan_pocket/vintf/framework_compatibility_matrix.radios.xml
# Stock TrustKernel Keymaster 4.0 and gatekeeper 1.0 (KEYMASTER_PORT.md).
DEVICE_FRAMEWORK_COMPATIBILITY_MATRIX_FILE += device/unihertz/titan_pocket/vintf/framework_compatibility_matrix.security.xml

SYSTEM_EXT_PUBLIC_SEPOLICY_DIRS += device/unihertz/titan_pocket/sepolicy/system_ext/public
SYSTEM_EXT_PRIVATE_SEPOLICY_DIRS += device/unihertz/titan_pocket/sepolicy/system_ext/private
# Holds prebuilts/api/30.0/public, the Pocket system_ext types the API 30 vendor
# sees, so the treble tests check them against private/compat.
BOARD_SYSTEM_EXT_SEPOLICY_PREBUILT_DIRS += device/unihertz/titan_pocket/sepolicy/system_ext
# Lineage's dynamic HAL policy (service labels for vendor.lineage.*) goes in system_ext,
# as the vendor policy is the stock one; the charging control HAL needs its label.
TARGET_USES_PREBUILT_VENDOR_SEPOLICY := true

# Charging control (health/): the 5.10 charger's charging_enabled pauses charging while the
# phone keeps running from USB power, so toggle with bypass. The framework does the limit and
# time modes with it.
$(call soong_config_set,lineage_health,charging_control_charging_path,/sys/devices/platform/charger/charging_enabled)
$(call soong_config_set,lineage_health,charging_control_charging_enabled,1)
$(call soong_config_set,lineage_health,charging_control_charging_disabled,0)
$(call soong_config_set_bool,lineage_health,charging_control_supports_toggle,true)
$(call soong_config_set_bool,lineage_health,charging_control_supports_bypass,true)
