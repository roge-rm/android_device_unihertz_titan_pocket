# SPDX-License-Identifier: Apache-2.0
# The audit product builds source/policy tools only, never installable images.
ifeq ($(TARGET_PRODUCT),titan_pocket_policy_audit)
include device/generic/arm64/BoardConfig.mk
KERNEL_ARCH := arm64
TARGET_KERNEL_SOURCE := kernel/unihertz/mt6771
KERNEL_MAKE_CMD := make
include vendor/lineage/config/BoardConfigSoong.mk
else ifeq ($(TARGET_PRODUCT),lineage_titan_pocket)
ifeq ($(POCKET_ENGINEERING_BUILD),true)
include device/unihertz/titan_pocket/BoardConfig.integration.mk
else
$(error Titan Pocket image builds are gated: use the isolated engineering product builder; installation qualification remains required)
endif
else
$(error Titan Pocket image builds are gated: UFS/board boot, VNDK30/FCM5, final policy and recovery qualification remain open)
endif
