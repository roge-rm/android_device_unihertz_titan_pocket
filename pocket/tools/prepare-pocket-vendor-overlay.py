#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Apply the reviewed private overlay to the stock January vendor image.

Edits the stock ext4 filesystem in place with debugfs, so every untouched inode
keeps its exact ownership, mode, times, xattrs and SELinux label. Replaced files
get the original inode's metadata back; the one added file copies its sibling's.
The AVB hashtree/FEC footer is rebuilt with the stock geometry, salt, props and
algorithm NONE. A control repack of the unmodified filesystem must reproduce the
stock image byte for byte before the overlay is applied.

v2 is v1 with vendor_sepolicy.cil and plat_pub_versioned.cil pruned of the names
the product composition drops, using that tool's own prune(), and an engineering
/data line without encryption or checkpointing, plus a teed storage trigger for
the unsupported crypto state that line gives.

v3 is v2 with the TrustKernel Keymaster 4.0 HAL taken off the boot path for the
engineering boot, which uses the system software KeyMint: its vendor manifest
entry is dropped and its service is disabled. The manifest's kernel FCM level
goes from 5 to 6, the first one 5.10 allows.

v4 is v3 with the stock vendor_flash_recovery service disabled, so it no longer
rewrites the recovery partition from /vendor/etc/recovery.img at boot.

v5 is v4 with the six connectivity modules in /lib/modules replaced by our 5.10
builds (tools/build-pocket-connectivity-module.py), modules.dep and
modules.alias regenerated from their modinfo, and one vendor policy rule that
lets system_app (Lineage FMRadio) use /dev/fm. `--replace` rebuilds v5 in place
after the kernel or the modules change; the older versions are pinned and never
replaced.

v6 is v5 with the v3 keymaster edits reverted, for the all-TEE route: the vendor
manifest keeps its keymaster 4.0 HAL block (kernel FCM level stays 6) and the
keymaster rc is the stock file. `--replace` rebuilds v6 like v5.

v7 is v6 with the size limit of OMX.MTK.VIDEO.DECODER.VP9 in
media_codecs_mediatek_video.xml cut from 3840x2176 to 1920x1088, so apps pick
another decoder for VP9 above 1080p, and /etc/vintf/manifest/power-default.xml
deleted, so only our system_ext fragment declares IPower (the mtkpower service,
its rc and the HIDL manifest block stay). It carries the current modules.
`--replace` rebuilds v7 like v6.

v8 is v7 with one line added to /vendor/build.prop,
vendor.debug.fsc.fsc.enable=0, which turns off the camera HAL's focus scale
compensation (FSC). With FSC on, EIS video records a flat colour because FSC
returns 0 slice factors (evidence/camera/video-record-flat.md). init loads it as
vendor_init, which may set vendor_default_prop. `--replace` rebuilds v8 like v7.

v9 is v8 with the SELinux enforcing policy changes from SELINUX_ENFORCING.md (M3):
vendor CIL additions (dontaudits for known stock denials, a few allows the Android 16
platform needs, and mtk_hal_power no longer adds the AIDL power service, keeping its own hwservice type), two
vendor_file_contexts lines for the bip and wfca sockets, the two mtkpower HIDL interfaces
relabelled mtk_hal_power_hwservice in vendor_hwservice_contexts, the /dev/stune writes
dropped from init.mt6771.rc (5.10 has no schedtune), and fuelgauged made oneshot.
`--replace` rebuilds v9 like v8.

v10 is v9 with the SELinux changes from the first enforcing boot (SELINUX_ENFORCING.md M7):
one more vendor CIL dontaudit (gsm0710muxd stopping the legacy ril-daemon) and
vendor_file_contexts lines that label the 5.10 wakeup source dirs sysfs_wakeup (ueventd
relabels each one when it is added). `--replace` rebuilds v10 like v9.

v11 is v10 with the camera static metadata shim (CAMERA_PORT.md, "RAW durations"):
/bin/hw/camerahalserver-pocket and /lib64/libpocketcammeta.so added from
build/camera-shim (tools/build-pocket-camera-shim.py), camerahalserver.rc starting the
launcher, which links the shim and runs the stock camerahalserver's main() in-process,
and a vendor_file_contexts line for the launcher. No policy change: the launcher runs as
mtk_hal_camera and only maps the stock executable. `--replace` rebuilds v11 like v10.

v12 is v11 applied to the May 2024 stock vendor (SHA256 a397641c...) instead of the
January one; the overlay contents are the same. `--replace` rebuilds v12 like v11.

v13 is v12 with the teed model shim (INSTALLER_PLAN.md, milestone 0): /lib64/libpocketteed.so
added from build/teed-shim (tools/build-pocket-teed-shim.py) and /bin/teed patched to load
it as its first DT_NEEDED, so teed reads the stock "Titan pocket" for ro.product.model while
the build says "Titan Pocket". teed keeps its stock inode metadata and label, the shim takes
libteec.so's. `--replace` rebuilds v13 like v12.

v13 also keeps stock's encrypted /data (file-based encryption v2, inlinecrypt, key directory
on /metadata), without checkpoint=block and resize. The unsupported trigger in trustkernel.rc
stays but is never used with encryption on.

Inputs are never modified. Output is private and refuses to overwrite.
"""
import pocket_paths
import argparse
import hashlib
import struct
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys

ROOT = Path(__file__).resolve().parent.parent
BULK = pocket_paths.build_root()
STOCK_VENDOR = pocket_paths.private_vendor() / 'unihertz/titan_pocket/proprietary/vendor.img'
STOCK_VENDOR_SHA256 = 'd991ee39bb233c7f717d9007b1acf9f83c41b3db3e8af188a9c78d4f27b1408f'
# v12 uses the May 2024 stock vendor (lpunpack -p vendor of the factory super.img).
STOCK_VENDOR_MAY = pocket_paths.private_vendor() / 'unihertz/titan_pocket/proprietary-2024-05/vendor.img'
STOCK_VENDOR_MAY_SHA256 = 'a397641c6e621449816d625dc0f25476dddcd4286fa596065946cbb04a168c0e'


def stock_vendor_for(version):
    """Default stock image path and pinned SHA256 for an overlay version."""
    return (STOCK_VENDOR_MAY, STOCK_VENDOR_MAY_SHA256) if version in ('v12', 'v13') else (STOCK_VENDOR, STOCK_VENDOR_SHA256)
POLICY_INSTALL = ROOT / 'artifacts/m2/policy/source-contract-real-product-v14/install'
POLICY_HANDOFF = ROOT / 'evidence/kernel-upgrade/policy-source/source-port-handoff.json'
RAMDISK_FSTAB = pocket_paths.DEVICE_TREE / 'rootdir/etc/fstab.mt6771'
BOSTON = pocket_paths.platform_root()
PREBUILT_BIN = pocket_paths.platform_source() / 'prebuilts/kernel-build-tools/linux-x86/bin'
HOST_BIN = BOSTON / 'out/host/linux-x86/bin'
AVBTOOL = ROOT / 'tools/avbtool.py'
OVERLAY_DIR = pocket_paths.private_vendor_overlay()
VERSION = 'v6'
VERSIONS = ('v1', 'v2', 'v3', 'v4', 'v5', 'v6', 'v7', 'v8', 'v9', 'v10', 'v11', 'v12', 'v13')
REPLACEABLE = ('v5', 'v6', 'v7', 'v8', 'v9', 'v10', 'v11', 'v12', 'v13')
OUTPUT = OVERLAY_DIR / VERSION
COMPOSITION_TOOL = ROOT / 'tools/check-pocket-product-composition.py'
COMPOSITION_RECORD = ROOT / 'evidence/kernel-upgrade/policy-source/product-composition-20261030.json'
COMPOSITION_DIR = BULK / 'artifacts/policy/product-composition-20261030/inputs'
DROPPED_COUNT = 71
# v2 pruned files; equal to the proposal CIL the composition tool generated.
PRUNED = {'vendor_sepolicy.cil': '6ab0b851825fefce03a44e3c38f005d539432c98ff1a7a2cb63b50aad0c0ef02',
          'plat_pub_versioned.cil': 'a820928b459bdc3a295ea87372796c00d6e44b7a0222055467fb96d66dcb00b0'}
# proposal_effects keys in the composition record, per pruned file.
PRUNE_EFFECTS = {'vendor_sepolicy.cil': ('vendor_statements_removed', 'vendor_statements_changed'),
                 'plat_pub_versioned.cil': ('plat_pub_statements_removed', 'plat_pub_statements_changed')}

FSTAB = '/etc/fstab.mt6771'
INIT_RC = '/etc/init/hw/init.mt6771.rc'
SELINUX = '/etc/selinux'
# Mount points holding IMEI/calibration/TEE state; never auto-formatted.
PROTECTED = ('/mnt/vendor/protect_f', '/mnt/vendor/protect_s', '/mnt/vendor/nvdata',
             '/mnt/vendor/nvcfg', '/mnt/vendor/persist', '/mnt/vendor/apd')
LOGICAL = ('system', 'product', 'vendor')
# Android 11 fs_mgr flags the Android 16 libfstab no longer knows; it only logs
# an unknown-flag warning for them, so dropping them changes no behaviour.
OBSOLETE_FLAGS = {'/data': ('resize',)}
# v2 engineering /data: no FBE, metadata encryption or block checkpoint
# (evidence/kernel-upgrade/unencrypted-first-boot.md). Stock flag order is kept.
UNENCRYPTED_MOUNT_DROP = ('inlinecrypt',)
UNENCRYPTED_FLAG_DROP = ('checkpoint=', 'fileencryption=', 'keydirectory=')
UNENCRYPTED_DATA = ('/dev/block/by-name/userdata /data ext4 noatime,nosuid,nodev,noauto_da_alloc,errors=panic '
                    'wait,check,formattable,quota,latemount,reservedsize=128m')
# v13 on: stock's FBE and metadata key options kept, without the block checkpoint
# (an A-only device has no use for it) and without the obsolete resize.
ENCRYPTED_FLAG_DROP = ('checkpoint=',)
ENCRYPTED_DATA = ('/dev/block/by-name/userdata /data ext4 noatime,nosuid,nodev,noauto_da_alloc,errors=panic,inlinecrypt '
                  'wait,check,formattable,quota,latemount,reservedsize=128m,fileencryption=aes-256-xts:aes-256-cts:v2,'
                  'keydirectory=/metadata/vold/metadata_encryption')
# Stale stock policy binary and its hash keys; init would compile on device anyway.
REMOVE = ('precompiled_sepolicy',
          'precompiled_sepolicy.plat_sepolicy_and_mapping.sha256',
          'precompiled_sepolicy.product_sepolicy_and_mapping.sha256',
          'precompiled_sepolicy.system_ext_sepolicy_and_mapping.sha256')
KEEP = ('selinux_denial_metadata',)
ADD_REFERENCE = 'plat_sepolicy_vers.txt'
FSTAB_HEADER = ('# Pocket LineageOS vendor overlay: logical lines match the first-stage fstab,\n'
                '# provisioning filesystems have no automatic format.\n')
KEYMASTER_LINE = '    exec_start wait_for_keymaster'
USB_RC = '/etc/init/hw/init.mt6771.usb.rc'
# Android 16 sets ro.crypto.state=unsupported on an unencrypted /data; stock only
# handles "unencrypted", so teed's TA storage never gets fs.state=prepare.
TRUSTKERNEL_RC = '/etc/init/trustkernel.rc'
TK_STOCK_TRIGGER = 'on property:ro.crypto.state=unencrypted'
TK_NEW_TRIGGER = 'on property:ro.crypto.state=unsupported'
TK_COMMENT = '# Pocket overlay: Android 16 reports an unencrypted /data as unsupported'
# The 4.14 MUSB UDC name; under 5.10 the MTU3 gadget's UDC takes its parent
# device name, 11201000.usb3 (seen in the v7 diagnostic log, source-inferred).
USB_CONTROLLER_LINE = '    setprop vendor.usb.controller "musb-hdrc"'
USB_CONTROLLER_NEW = '    setprop vendor.usb.controller "11201000.usb3"'
USB_CONTROLLER_COUNT = 2
# v3: keystore2 asks km_compat for StrongBox, which calls getService on every HIDL
# keymaster in the manifest and waits for a declared one that never registers.
VINTF_MANIFEST = '/etc/vintf/manifest.xml'
KM_HAL_BLOCK = ['    <hal format="hidl">',
                '        <name>android.hardware.keymaster</name>',
                '        <transport>hwbinder</transport>',
                '        <version>4.0</version>',
                '        <interface>',
                '            <name>IKeymasterDevice</name>',
                '            <instance>default</instance>',
                '        </interface>',
                '        <fqname>@4.0::IKeymasterDevice/default</fqname>',
                '    </hal>']
KERNEL_FCM_LINE = '    <kernel target-level="5"/>'
KERNEL_FCM_NEW = '    <kernel target-level="6"/>'
KM_RC = '/etc/init/android.hardware.keymaster@4.0-service.trustkernel.rc'
KM_RC_GROUP = '    group system drmrpc'
KM_RC_ADDED = ['    # Pocket overlay: off for the engineering boot, which uses the system software KeyMint',
               '    disabled']
# v4: the stock oneshot service flashes the recovery partition at boot.
FR_RC = '/etc/init/vendor_flash_recovery.rc'
FR_RC_ANCHOR = '    oneshot'
FR_RC_ADDED = ['    # Pocket overlay: off so the recovery partition keeps the image flashed to it',
               '    disabled']
# v5: our connectivity modules, each with its build record from build-pocket-connectivity-module.py.
MODULE_DIR = '/lib/modules'
CONN_MODULES = ('wmt_drv', 'wmt_chrdev_wifi', 'wlan_drv_gen3', 'bt_drv', 'gps_drv', 'fmradio_drv')
CONN_BUILD = ROOT / 'build/connectivity'
CONN_RECORDS = ROOT / 'evidence/connectivity'
KERNEL_OUT = BULK / 'kernel-firstboot-5.10'
MODULE_VERMAGIC = '5.10.257-titanpocket-firstboot+ SMP preempt mod_unload modversions aarch64'
MODULES_DEP = MODULE_DIR + '/modules.dep'
MODULES_ALIAS = MODULE_DIR + '/modules.alias'
DEVICE_MODULE_DIR = '/vendor/lib/modules'
# v5: Lineage FMRadio runs as system_app; stock vendor policy only lets platform_app (its own FM app) at /dev/fm.
FM_RULE_ANCHOR = ('(allow platform_app_30_0 fm_device (chr_file (ioctl read write getattr lock append map open '
                  'watch watch_reads)))')
FM_RULE_ADDED = ['; Pocket overlay: Lineage FMRadio runs as system_app, stock only allowed its platform_app FM app',
                 FM_RULE_ANCHOR.replace('platform_app_30_0', 'system_app_30_0')]
# v7: the MTK VP9 decoder is software (libvp9dec_sa) and drops frames above 1080p.
CODECS_XML = '/etc/media_codecs_mediatek_video.xml'
VP9_CODEC_LINE = '        <MediaCodec name="OMX.MTK.VIDEO.DECODER.VP9" type="video/x-vnd.on2.vp9" >'
VP9_SIZE_LINE = '            <Limit name="size" min="16x16" max="3840x2176" />'
# v7: stock's AIDL IPower/default declaration, replaced by our system_ext fragment.
POWER_VINTF = '/etc/vintf/manifest/power-default.xml'
# v8: FSC off, so EIS gets real slice factors (evidence/camera/video-record-flat.md).
BUILD_PROP = '/build.prop'
FSC_PROP_ADDED = ['# Pocket overlay: camera FSC off, EIS video is a flat colour with it on',
                  'vendor.debug.fsc.fsc.enable=0']
VP9_SIZE_NEW = '            <Limit name="size" min="16x16" max="1920x1088" />'

# v9: SELinux enforcing (SELINUX_ENFORCING.md M3). Bucket ids in the comments.
HAL_POWER_SERVER_OLD = '(typeattributeset hal_power_server (hal_power_default merged_hal_service mtk_hal_power))'
HAL_POWER_SERVER_NEW = '(typeattributeset hal_power_server (hal_power_default merged_hal_service))'
_MP = '(file (read getattr map open))'
_RGO = '(file (read getattr open))'
# 2c (SELINUX_ENFORCING.md M5): the names these read fall to default_prop and none is set,
# so the default is what stock got too. Allow is a neverallow for vendor domains.
M5_DEFAULT_PROP_DOMAINS = ('mediacodec', 'mnld', 'mtk_hal_camera', 'nvram_daemon')
M5_CIL_ADDED = [
    '; 2c: unset properties that fall to default_prop (mtk.vendor.omx.core.log, ro.logsystem.usertype,',
    '; ro.mtk_gmo_ram_optimize, ro.sensorhub_support)',
] + [f'(dontaudit {d} default_prop {_MP})' for d in M5_DEFAULT_PROP_DOMAINS]
M3_CIL_ADDED = [
    '; Pocket overlay v9 (SELINUX_ENFORCING.md M3)',
    '; 3a: the Android 16 linker probes /sys/kernel/mm in every domain, nothing is there',
    '(dontaudit domain sysfs_mm (dir (search)))',
    '; 1d: inotify watch checks came with kernel 5.3',
    '(allow wlan_assistant wmtWifi_device (chr_file (watch)))',
    '(allow wlan_assistant nvdata_file (file (watch)))',
    '; 3b, 3c, 3d: Android 16 platform vs the stock vendor',
    '(allow surfaceflinger_30_0 hal_allocator_default (fd (use)))',
    f'(allow vendor_init_30_0 vts_status_prop {_MP})',
    f'(allow mediacodec aac_drc_prop {_MP})',
    f'(allow hal_face_default camera_config_prop {_MP})',
    '; 2a: libfstab probes of the kernel command line, the device tree and /metadata/gsi',
] + [l for d in ('nvram_daemon', 'fuelgauged_nvram', 'ccci_mdinit', 'mtk_hal_bluetooth') for l in (
    f'(dontaudit {d} proc_cmdline {_RGO})',
    f'(dontaudit {d} sysfs_dt_firmware_android (dir (search)))',
    f'(dontaudit {d} sysfs_dt_firmware_android {_RGO})',
    f'(dontaudit {d} gsi_metadata_file (dir (search)))')] + [
    '; 2b: read-only boot info; the modem reads stay denied as on stock',
    f'(dontaudit ccci_mdinit sysfs_boot_mode {_RGO})',
    f'(dontaudit ccci_fsd sysfs_boot_info {_RGO})',
    f'(dontaudit ccci_fsd proc_version {_RGO})',
    f'(dontaudit mediacodec sysfs_boot_mode {_RGO})',
    f'(dontaudit mtk_hal_mms sysfs_boot_mode {_RGO})',
    f'(allow mediacodec vendor_mtk_sec_video_path_support_prop {_MP})',
    '; 2e: init tunings and the TrustKernel TA scan that stock never had rules for',
    '(dontaudit system_server_30_0 tkcore_systa_file (dir (read getattr open)))',
    '(dontaudit vendor_init_30_0 nfc_data_file (dir (getattr)))',
    '(dontaudit vendor_init_30_0 proc_30_0 (file (write)))',
    '(dontaudit vendor_init_30_0 proc_dirty (file (write)))',
    '; 5: denied by a neverallow, so only silenced',
    '(dontaudit vendor_init_30_0 build_bootimage_prop (property_service (set)))',
    '(dontaudit mediacodec dalvik_dynamic_config_prop (property_service (set)))',
    f'(dontaudit rild radio_cdma_ecm_prop {_MP})',
    '(dontaudit rild vendor_default_prop (property_service (set)))',
    f'(dontaudit bip net_dns_prop {_MP})',
    '; 6b: the AOSP misc daemons stay out of the MTK misc partition (para)',
    '(dontaudit kcmdlinectrl para_block_device (blk_file (ioctl read write getattr open)))',
    '(dontaudit misctrl para_block_device (blk_file (ioctl read write getattr open)))',
    '; decision 2: mtk_hal_power leaves hal_power_server so it cannot add the AIDL power service;',
    '; the system_ext power HAL owns it. These are the hal_power_server rules it keeps. Its two MTK HIDL',
    '; interfaces move to mtk_hal_power_hwservice (see HWS_CHANGED), since hal_power_hwservice add is a neverallow now.',
    '(allow mtk_hal_power mtk_hal_power_hwservice (hwservice_manager (add find)))',
    '(allow hal_power_client mtk_hal_power_hwservice (hwservice_manager (find)))',
    '(allow hal_power_client mtk_hal_power (binder (call transfer)))',
    '(allow mtk_hal_power hal_power_client (binder (call transfer)))',
    '(allow hal_power_client mtk_hal_power (fd (use)))',
    '(allow mtk_hal_power hal_power_client (fd (use)))',
    '(allow mtk_hal_power hidl_base_hwservice_30_0 (hwservice_manager (add)))',
    '(allow mtk_hal_power servicemanager_30_0 (binder (call transfer)))',
    '(allow servicemanager_30_0 mtk_hal_power (binder (transfer)))',
    '(allow mtk_hal_power servicemanager_30_0 (fd (use)))',
    '(dontaudit mtk_hal_power hal_power_service_30_0 (service_manager (add)))',
    '(allow dumpstate_30_0 mtk_hal_power (process (signal)))',
    '(allow mtk_hal_power dumpstate_30_0 (fifo_file (write)))',
    '(allow mtk_hal_power dumpstate_30_0 (fd (use)))',
    '(allow system_server_30_0 mtk_hal_power (process (signal)))',
] + M5_CIL_ADDED
HWSERVICE_CONTEXTS = SELINUX + '/vendor_hwservice_contexts'
HWS_CHANGED = [
    ('vendor.mediatek.hardware.mtkpower::IMtkPerf u:object_r:hal_power_hwservice:s0',
     'vendor.mediatek.hardware.mtkpower::IMtkPerf u:object_r:mtk_hal_power_hwservice:s0'),
    ('vendor.mediatek.hardware.mtkpower::IMtkPower u:object_r:hal_power_hwservice:s0',
     'vendor.mediatek.hardware.mtkpower::IMtkPower u:object_r:mtk_hal_power_hwservice:s0')]
# 2d: init makes /dev/socket/bip_socket and /dev/socket/wfca_rds, which the stock patterns miss.
FILE_CONTEXTS = SELINUX + '/vendor_file_contexts'
FC_ADDED = ['# Pocket overlay: sockets made by init.bip.rc and init.wfca.rc',
            '/dev/socket/bip_socket u:object_r:bip_socket:s0',
            '/dev/socket/wfca_rds u:object_r:wfca_socket:s0']
# v10 (SELINUX_ENFORCING.md M7).
# 5: gsm0710muxd sets ctl.stop$ril-daemon once the mux is up. No service has that name (the RIL is
# vendor.ril-daemon-mtk), stock policy had no rule either, and muxd carries on either way.
M7_CIL_ADDED = [
    '; Pocket overlay v10 (SELINUX_ENFORCING.md M7)',
    '; 5: gsm0710muxd stops the legacy ril-daemon, which does not exist here',
    '(dontaudit gsm0710muxd ctl_stop_prop_30_0 (property_service (set)))',
]
# 1b: each wakeup source with a parent device gets a dir under that device, which takes the parent's
# genfs label (sysfs, sysfs_batteryinfo). ueventd restorecons a wakeupN dir when it is added, so these
# label it sysfs_wakeup for system_suspend. Regexes, since the i2c bus numbers change with the kernel's
# probe order (the board DT has no i2c aliases). The system_ext genfs lines cover the other five parents.
FC_M7_ADDED = [
    '# Pocket overlay: 5.10 wakeup sources under their parent device',
    r'/sys/devices/platform/mt_charger/power_supply/(charger|usb)/wakeup[0-9]+(/.*)?  u:object_r:sysfs_wakeup:s0',
    r'/sys/devices/platform/1000d000\.pwrap/1000d000\.pwrap:mt6358-pmic/mt6358-rtc/wakeup/wakeup[0-9]+(/.*)?  u:object_r:sysfs_wakeup:s0',
    r'/sys/devices/platform/10238000\.gce/wakeup/wakeup[0-9]+(/.*)?  u:object_r:sysfs_wakeup:s0',
    r'/sys/devices/platform/fingerprint/wakeup/wakeup[0-9]+(/.*)?  u:object_r:sysfs_wakeup:s0',
    r'/sys/devices/platform/11201000\.usb3/wakeup/wakeup[0-9]+(/.*)?  u:object_r:sysfs_wakeup:s0',
    r'/sys/devices/platform/11008000\.i2c/i2c-[0-9]+/[0-9]+-0058/wakeup/wakeup[0-9]+(/.*)?  u:object_r:sysfs_wakeup:s0',
    r'/sys/devices/platform/1100f000\.i2c/i2c-[0-9]+/[0-9]+-0008/wakeup/wakeup[0-9]+(/.*)?  u:object_r:sysfs_wakeup:s0',
    r'/sys/devices/platform/11017000\.i2c/i2c-[0-9]+/[0-9]+-0034/wakeup/wakeup[0-9]+(/.*)?  u:object_r:sysfs_wakeup:s0',
    r'/sys/devices/platform/11005000\.i2c/i2c-[0-9]+/[0-9]+-002f/wakeup/wakeup[0-9]+(/.*)?  u:object_r:sysfs_wakeup:s0',
]
# v11: camera 0's RAW durations (CAMERA_PORT.md, "RAW durations"). init can't preload into
# camerahalserver (its domain transition sets AT_SECURE) and hal_camera_server may not exec
# without a transition, so a launcher linked with the shim runs the stock main() in-process.
CAM_RC = '/etc/init/camerahalserver.rc'
CAM_RC_LINE = 'service camerahalserver /vendor/bin/hw/camerahalserver'
CAM_RC_NEW = 'service camerahalserver /vendor/bin/hw/camerahalserver-pocket'
CAM_RC_COMMENT = '# Pocket overlay: the launcher runs the stock server with libpocketcammeta.so linked in'
CAM_SHIM_BUILD = ROOT / 'build/camera-shim'
# Added path: (build output name, stock file whose metadata and label it takes).
CAM_ADDED = {'/bin/hw/camerahalserver-pocket': ('camerahalserver-pocket', '/bin/hw/camerahalserver'),
             '/lib64/libpocketcammeta.so': ('libpocketcammeta.so', '/lib64/libmtkcam_metastore.so')}
FC_CAM_ADDED = [
    '# Pocket overlay: launcher that preloads the camera metadata shim',
    r'/(vendor|system/vendor)/bin/hw/camerahalserver-pocket u:object_r:mtk_hal_camera_exec:s0',
]
# v13: teed loads libpocketteed.so first, which answers "Titan pocket" for ro.product.model.
# init can't preload into teed (the tee domain has no noatsecure), so the shim is a DT_NEEDED.
TEED = '/bin/teed'
TEED_SHIM = '/lib64/libpocketteed.so'
TEED_SHIM_REF = '/lib64/libteec.so'
TEED_SHIM_BUILD = ROOT / 'build/teed-shim'
TEED_TOOL = ROOT / 'tools/build-pocket-teed-shim.py'
# 6a: 5.10 has no schedtune, so these writes make stray regular files in /dev/stune.
STUNE_DROP = ['    chown system system /dev/stune/foreground/schedtune.prefer_idle',
              '    chown system system /dev/stune/top-app/schedtune.prefer_idle',
              '    chown system system /dev/stune/rt/schedtune.prefer_idle',
              '    write /dev/stune/foreground/schedtune.prefer_idle 0',
              '    write /dev/stune/top-app/schedtune.prefer_idle 0',
              '    write /dev/stune/rt/schedtune.prefer_idle 0']
# 6c: fuelgauged has no GM3.0 to talk to and exits 0 at once, so it restarted about every 12 s.
FG_RC = '/etc/init/fuelgauged_init.rc'
FG_RC_ANCHOR = '    group system'
FG_RC_ADDED = ['    # Pocket overlay: exits at once, so do not restart it',
               '    oneshot']


def sha256(path):
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        for block in iter(lambda: f.read(1 << 20), b''):
            h.update(block)
    return h.hexdigest()


def sha256_bytes(data):
    return hashlib.sha256(data).hexdigest()


def run(cmd, env=None, check=True):
    p = subprocess.run([str(c) for c in cmd], capture_output=True, text=True, env=env)
    if check and p.returncode:
        raise SystemExit(f'{cmd[0]} failed ({p.returncode}):\n{p.stdout}\n{p.stderr}')
    return p


def tool_env():
    env = dict(os.environ)
    env['PATH'] = f'{PREBUILT_BIN}:{env["PATH"]}'
    return env


def debugfs(image, commands, write=False, fake_time=None, allow_missing=False):
    """Run a debugfs command batch; return {command: output}. Any error line fails."""
    script = Path(str(image) + '.debugfs')
    script.write_text(''.join(c + '\n' for c in commands))
    env = dict(os.environ)
    if fake_time is not None:
        env['E2FSPROGS_FAKE_TIME'] = str(fake_time)
    cmd = [HOST_BIN / 'debugfs'] + (['-w'] if write else []) + ['-f', script, image]
    p = run(cmd, env=env)
    script.unlink()
    errors = [l for l in p.stderr.splitlines() if l.strip() and not l.startswith('debugfs 1.')
              and not (allow_missing and 'File not found by ext2_lookup' in l)]
    if errors:
        raise SystemExit('debugfs reported errors:\n' + '\n'.join(errors))
    chunks, current = [], None
    for line in p.stdout.splitlines():
        if line.startswith('debugfs: '):
            current = [line[len('debugfs: '):], []]
            chunks.append(current)
        elif current is not None:
            current[1].append(line)
    return [(c, '\n'.join(o)) for c, o in chunks]


TIME = re.compile(r'^\s*(ctime|atime|mtime|crtime): 0x([0-9a-f]+):([0-9a-f]+)')


def parse_stat(text):
    """Parse debugfs stat output into comparable metadata."""
    if 'File not found' in text or 'Inode:' not in text:
        return None
    meta = {'xattrs': []}
    m = re.search(r'Inode: (\d+)\s+Type: (\S+)\s+Mode:\s+(\d+)\s+Flags: (0x[0-9a-f]+)', text)
    meta.update(inode=int(m[1]), type=m[2], mode=m[3], flags=m[4])
    meta['generation'] = int(re.search(r'Generation: (\d+)', text)[1])
    m = re.search(r'User:\s+(\d+)\s+Group:\s+(\d+)\s+Project:\s+(\d+)\s+Size: (\d+)', text)
    meta.update(uid=int(m[1]), gid=int(m[2]), project=int(m[3]), size=int(m[4]))
    meta['links'] = int(re.search(r'Links: (\d+)', text)[1])
    m = re.search(r'Size of extra inode fields: (\d+)', text)
    meta['extra_isize'] = int(m[1]) if m else None
    for line in text.splitlines():
        t = TIME.match(line)
        if t:
            meta[t[1]] = [int(t[2], 16), int(t[3], 16)]
    m = re.search(r'Fast link dest: "(.*)"', text)
    if m:
        meta['link'] = m[1]
    in_xattr = False
    for line in text.splitlines():
        if line.startswith('Extended attributes:'):
            in_xattr = True
        elif in_xattr and line.startswith('  '):
            meta['xattrs'].append(line.strip())
        elif in_xattr:
            in_xattr = False
    return meta


def stat_paths(image, paths, allow_missing=False):
    out = debugfs(image, [f'stat "{p}"' for p in paths], allow_missing=allow_missing)
    metas = {p: parse_stat(o) for p, (_, o) in zip(paths, out)}
    # stat truncates xattr values of 40 bytes or more; ea_get prints them whole.
    wanted = [(p, re.match(r'(\S+) \(', x)[1]) for p, m in metas.items() if m for x in m['xattrs']]
    values = debugfs(image, [f'ea_get "{p}" {n}' for p, n in wanted]) if wanted else []
    for m in metas.values():
        if m:
            m['xattrs'] = []
    for (p, n), (_, text) in zip(wanted, values):
        metas[p]['xattrs'].append(text.strip())
    return metas


def dump(image, path, dest):
    debugfs(image, [f'dump "{path}" "{dest}"'])
    return dest.read_bytes()


def footer(image):
    """Read the stock AVB footer through avbtool's own parser."""
    text = run([sys.executable, AVBTOOL, 'info_image', '--image', image]).stdout
    get = lambda key: re.search(rf'^\s*{re.escape(key)}:\s+(.*)$', text, re.M)[1].strip()
    props = re.findall(r"^\s*Prop: (\S+) -> '(.*)'$", text, re.M)
    info = {
        'image_size': int(get('Image size').split()[0]),
        'original_image_size': int(get('Original image size').split()[0]),
        'algorithm': get('Algorithm'),
        'release_string': get('Release String').strip("'"),
        'rollback_index': int(get('Rollback Index')),
        'flags': int(get('Flags')),
        'partition_name': get('Partition Name'),
        'hash_algorithm': get('Hash Algorithm'),
        'salt': get('Salt'),
        'root_digest': get('Root Digest'),
        'fec_num_roots': int(get('FEC num roots')),
        'data_block_size': int(get('Data Block Size').split()[0]),
        'hash_block_size': int(get('Hash Block Size').split()[0]),
        'tree_size': int(get('Tree Size').split()[0]),
        'fec_size': int(get('FEC size').split()[0]),
        'props': props,
    }
    if text.count('Hashtree descriptor:') != 1 or 'Hash descriptor:' in text:
        raise SystemExit('unexpected AVB descriptor set')
    return info


def add_footer(image, info):
    cmd = [sys.executable, AVBTOOL, 'add_hashtree_footer', '--image', image,
           '--partition_size', info['image_size'], '--partition_name', info['partition_name'],
           '--hash_algorithm', info['hash_algorithm'], '--salt', info['salt'],
           '--block_size', info['data_block_size'], '--fec_num_roots', info['fec_num_roots'],
           '--algorithm', info['algorithm'], '--rollback_index', info['rollback_index'],
           '--flags', info['flags'], '--internal_release_string', info['release_string']]
    for k, v in info['props']:
        cmd += ['--prop', f'{k}:{v}']
    run(cmd, env=tool_env())


def extract_fs(source, dest, size):
    with open(source, 'rb') as src, open(dest, 'wb') as dst:
        remaining = size
        while remaining:
            block = src.read(min(1 << 20, remaining))
            if not block:
                raise SystemExit('stock image shorter than its filesystem')
            dst.write(block)
            remaining -= len(block)


def fstab_fields(line):
    fields = line.split()
    return fields if fields and not fields[0].startswith('#') else None


def overlay_fstab(stock_text, ramdisk_text, unencrypted=False, encrypted=False):
    ramdisk = {f[0]: line for line in ramdisk_text.splitlines()
               if (f := fstab_fields(line)) and f[0] in LOGICAL}
    if set(ramdisk) != set(LOGICAL):
        raise SystemExit('first-stage fstab lacks a logical entry')
    out, seen, edits = [], set(), []
    for line in stock_text.splitlines():
        f = fstab_fields(line)
        if f and f[0] in LOGICAL:
            if f[0] in seen:
                raise SystemExit(f'duplicate stock entry {f[0]}')
            seen.add(f[0])
            if line != ramdisk[f[0]]:
                edits.append({'entry': f[0], 'from': line, 'to': ramdisk[f[0]]})
            line = ramdisk[f[0]]
        elif f and f[1] in PROTECTED:
            if f[1] in seen:
                raise SystemExit(f'duplicate stock entry {f[1]}')
            seen.add(f[1])
            flags = f[4].split(',')
            if 'formattable' not in flags:
                raise SystemExit(f'stock {f[1]} was expected to be formattable')
            f[4] = ','.join(x for x in flags if x != 'formattable')
            new = ' '.join(f)
            edits.append({'entry': f[1], 'from': line, 'to': new})
            line = new
        elif f and f[1] in OBSOLETE_FLAGS:
            flags = f[4].split(',')
            drop = OBSOLETE_FLAGS[f[1]]
            if not all(x in flags for x in drop):
                raise SystemExit(f'stock {f[1]} lacks an expected obsolete flag')
            f[4] = ','.join(x for x in flags if x not in drop)
            if unencrypted and f[1] == '/data':
                mount = f[3].split(',')
                if not all(x in mount for x in UNENCRYPTED_MOUNT_DROP) or \
                   not all(any(x.startswith(d) for x in flags) for d in UNENCRYPTED_FLAG_DROP):
                    raise SystemExit('stock /data lacks an expected encryption or checkpoint flag')
                f[3] = ','.join(x for x in mount if x not in UNENCRYPTED_MOUNT_DROP)
                f[4] = ','.join(x for x in f[4].split(',') if not x.startswith(UNENCRYPTED_FLAG_DROP))
            if encrypted and f[1] == '/data':
                if not all(any(x.startswith(d) for x in f[4].split(',')) for d in ENCRYPTED_FLAG_DROP):
                    raise SystemExit('stock /data lacks an expected checkpoint flag')
                f[4] = ','.join(x for x in f[4].split(',') if not x.startswith(ENCRYPTED_FLAG_DROP))
            new = ' '.join(f)
            if unencrypted and f[1] == '/data' and new != UNENCRYPTED_DATA:
                raise SystemExit(f'unencrypted /data line differs from the reviewed one:\n{new}')
            if encrypted and f[1] == '/data' and new != ENCRYPTED_DATA:
                raise SystemExit(f'encrypted /data line differs from the reviewed one:\n{new}')
            edits.append({'entry': f[1], 'from': line, 'to': new})
            line = new
        elif f and (f[0] == 'system_ext' or f[1] == '/system_ext'):
            raise SystemExit('stock fstab unexpectedly has a system_ext entry')
        out.append(line)
    missing = (set(LOGICAL) | set(PROTECTED)) - seen
    if missing:
        raise SystemExit(f'stock fstab lacks {sorted(missing)}')
    return FSTAB_HEADER + '\n'.join(out) + '\n', edits


def overlay_init(stock_text):
    lines = stock_text.split('\n')
    hits = [i for i, l in enumerate(lines) if l.rstrip() == KEYMASTER_LINE.rstrip()]
    if len(hits) != 1:
        raise SystemExit(f'expected one wait_for_keymaster line, found {len(hits)}')
    section = next(l for l in reversed(lines[:hits[0]]) if l.startswith('on '))
    if section.strip() != 'on late-fs':
        raise SystemExit(f'wait_for_keymaster is under {section!r}, not on late-fs')
    removed = lines.pop(hits[0])
    return '\n'.join(lines), {'section': section.strip(), 'line': hits[0] + 1, 'removed': removed}


def overlay_usb(stock_text):
    lines = stock_text.split('\n')
    hits = [i for i, l in enumerate(lines) if l == USB_CONTROLLER_LINE]
    if len(hits) != USB_CONTROLLER_COUNT:
        raise SystemExit(f'expected {USB_CONTROLLER_COUNT} vendor.usb.controller lines, found {len(hits)}')
    for i in hits:
        lines[i] = USB_CONTROLLER_NEW
    return '\n'.join(lines), {'lines': [i + 1 for i in hits], 'from': USB_CONTROLLER_LINE,
                              'to': USB_CONTROLLER_NEW}


def trustkernel_block(lines, trigger):
    """Return (start, end) of the section under `trigger`, up to its first blank line."""
    hits = [i for i, l in enumerate(lines) if l == trigger]
    if len(hits) != 1:
        raise SystemExit(f'expected one {trigger!r} section, found {len(hits)}')
    end = hits[0] + 1
    while end < len(lines) and lines[end].strip():
        end += 1
    return hits[0], end


def overlay_trustkernel(stock_text):
    """Add a copy of the stock unencrypted block under the unsupported trigger, right after it."""
    lines = stock_text.split('\n')
    if any(l.strip() == TK_NEW_TRIGGER for l in lines):
        raise SystemExit('stock trustkernel.rc already handles ro.crypto.state=unsupported')
    start, end = trustkernel_block(lines, TK_STOCK_TRIGGER)
    body = lines[start + 1:end]
    if not body or lines[end] != '':
        raise SystemExit('stock unencrypted block is empty or not followed by a blank line')
    added = [TK_COMMENT, TK_NEW_TRIGGER] + body + ['']
    lines[end + 1:end + 1] = added
    return '\n'.join(lines), {'after_line': end + 1, 'added': added}


def policy_plan(stock_names, install_dir, handoff):
    expected = {k.split('/')[-1]: v for k, v in handoff['install_files'].items()
                if k.startswith('vendor/etc/selinux/')}
    actual = {p.name: sha256(p) for p in install_dir.iterdir()}
    if expected != actual:
        raise SystemExit('policy install files do not match the frozen handoff hashes')
    plan = {'replace': [], 'add': [], 'unchanged': [], 'remove': list(REMOVE), 'keep': list(KEEP)}
    for name in sorted(actual):
        if name not in stock_names:
            plan['add'].append(name)
        elif stock_names[name] != actual[name]:
            plan['replace'].append(name)
        else:
            plan['unchanged'].append(name)
    extra = set(stock_names) - set(actual) - set(REMOVE) - set(KEEP)
    if extra or not set(REMOVE) <= set(stock_names):
        raise SystemExit(f'unexpected stock policy files: {sorted(extra)}')
    return plan


def composition_tool():
    spec = importlib.util.spec_from_file_location('composition', COMPOSITION_TOOL)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def dropped_names(record_path=COMPOSITION_RECORD):
    record = json.loads(Path(record_path).read_text())
    names = {n for n, v in record['missing_names']['names'].items() if v['decision'].startswith('drop')}
    if len(names) != DROPPED_COUNT or record['missing_names']['dropped'] != DROPPED_COUNT:
        raise SystemExit(f'composition record drops {len(names)} names, expected {DROPPED_COUNT}')
    return names, record['proposal_effects']


def pruned_policy(install_dir, record_path=COMPOSITION_RECORD):
    """Return {name: bytes} of the pruned v2 CIL, checked against the record and pins."""
    cp = composition_tool()
    dropped, effects = dropped_names(record_path)
    out = {}
    for name, (rkey, ckey) in PRUNE_EFFECTS.items():
        doc, removed, changed = cp.prune(cp.load(Path(install_dir) / name), dropped)
        if (removed, changed) != (effects[rkey], effects[ckey]):
            raise SystemExit(f'{name}: prune removed {removed}, changed {changed}; record has '
                             f'{effects[rkey]}, {effects[ckey]}')
        data = ('\n'.join(cp.C.encode(s) for s in doc) + '\n').encode()
        if sha256_bytes(data) != PRUNED[name]:
            raise SystemExit(f'{name}: pruned output differs from the pinned proposal hash')
        out[name] = data
    return out, dropped


def overlay_manifest_keep_km(stock_text):
    """Set the kernel FCM level to 6 and keep every HAL block (v6)."""
    lines = stock_text.split('\n')
    fcm = [i for i, l in enumerate(lines) if l == KERNEL_FCM_LINE]
    if len(fcm) != 1 or sum(lines[i:i + len(KM_HAL_BLOCK)] == KM_HAL_BLOCK for i in range(len(lines))) != 1:
        raise SystemExit('unexpected kernel FCM line count or keymaster HAL block count')
    lines[fcm[0]] = KERNEL_FCM_NEW
    return '\n'.join(lines), {'kernel_fcm_line': fcm[0] + 1, 'from': KERNEL_FCM_LINE, 'to': KERNEL_FCM_NEW,
                              'keymaster_block_kept': True}


def overlay_manifest(stock_text):
    """Drop the TrustKernel keymaster 4.0 HAL block and set the kernel FCM level to 6."""
    lines = stock_text.split('\n')
    hits = [i for i in range(len(lines)) if lines[i:i + len(KM_HAL_BLOCK)] == KM_HAL_BLOCK]
    if len(hits) != 1:
        raise SystemExit(f'expected one keymaster 4.0 HAL block, found {len(hits)}')
    del lines[hits[0]:hits[0] + len(KM_HAL_BLOCK)]
    fcm = [i for i, l in enumerate(lines) if l == KERNEL_FCM_LINE]
    if len(fcm) != 1 or any('android.hardware.keymaster' in l for l in lines):
        raise SystemExit('unexpected kernel FCM line count or a keymaster HAL left in the manifest')
    lines[fcm[0]] = KERNEL_FCM_NEW
    return '\n'.join(lines), {'removed_at_line': hits[0] + 1, 'removed': KM_HAL_BLOCK,
                              'kernel_fcm_line': fcm[0] + 1, 'from': KERNEL_FCM_LINE, 'to': KERNEL_FCM_NEW}


def overlay_km_rc(stock_text):
    """Add `disabled` to the TrustKernel keymaster service, after its group line."""
    lines = stock_text.split('\n')
    hits = [i for i, l in enumerate(lines) if l == KM_RC_GROUP]
    if len(hits) != 1 or not lines[0].startswith('service vendor.keymaster-4-0-trustkernel '):
        raise SystemExit('stock keymaster rc is not the expected one-service file')
    lines[hits[0] + 1:hits[0] + 1] = KM_RC_ADDED
    return '\n'.join(lines), {'after_line': hits[0] + 1, 'added': KM_RC_ADDED}


def overlay_fr_rc(stock_text):
    """Add `disabled` to the vendor_flash_recovery service, after its oneshot line."""
    lines = stock_text.split('\n')
    hits = [i for i, l in enumerate(lines) if l == FR_RC_ANCHOR]
    if len(hits) != 1 or not lines[0].startswith('service vendor_flash_recovery '):
        raise SystemExit('stock flash recovery rc is not the expected one-service file')
    lines[hits[0] + 1:hits[0] + 1] = FR_RC_ADDED
    return '\n'.join(lines), {'after_line': hits[0] + 1, 'added': FR_RC_ADDED}


def overlay_codecs(stock_text):
    """Cap the MTK VP9 decoder's size limit at 1920x1088 (v7)."""
    lines = stock_text.split('\n')
    hits = [i for i, l in enumerate(lines) if l == VP9_CODEC_LINE]
    if len(hits) != 1 or lines[hits[0] + 1] != VP9_SIZE_LINE:
        raise SystemExit('stock media_codecs_mediatek_video.xml has no single expected VP9 decoder block')
    lines[hits[0] + 1] = VP9_SIZE_NEW
    return '\n'.join(lines), {'line': hits[0] + 2, 'from': VP9_SIZE_LINE, 'to': VP9_SIZE_NEW}


def overlay_build_prop(stock_text):
    """Append the FSC off property to the vendor build.prop (v8)."""
    if not stock_text.endswith('\n') or 'vendor.debug.fsc.' in stock_text:
        raise SystemExit('stock vendor build.prop is not the expected file')
    lines = stock_text[:-1].split('\n')
    return '\n'.join(lines + FSC_PROP_ADDED) + '\n', {'after_line': len(lines), 'added': FSC_PROP_ADDED}


def overlay_m3_policy(text, m7=False):
    """v9: mtk_hal_power leaves hal_power_server, then the M3 block is appended (v10: and the M7 block)."""
    lines = text.split('\n')
    hits = [i for i, l in enumerate(lines) if l == HAL_POWER_SERVER_OLD]
    if len(hits) != 1 or any(l in M3_CIL_ADDED for l in lines if not l.startswith(';')):
        raise SystemExit('vendor policy has no single hal_power_server line, or already has an M3 line')
    lines[hits[0]] = HAL_POWER_SERVER_NEW
    end = len(lines) - 1 if lines[-1] == '' else len(lines)
    added = M3_CIL_ADDED + (M7_CIL_ADDED if m7 else [])
    lines[end:end] = added
    return '\n'.join(lines), {'hal_power_server_line': hits[0] + 1, 'from': HAL_POWER_SERVER_OLD,
                              'to': HAL_POWER_SERVER_NEW, 'added': added}


def overlay_hwservice_contexts(stock_text):
    """Relabel the two mtkpower HIDL interfaces to mtk_hal_power_hwservice (v9)."""
    lines = stock_text.split('\n')
    for old, new in HWS_CHANGED:
        hits = [i for i, l in enumerate(lines) if l == old]
        if len(hits) != 1:
            raise SystemExit('stock vendor_hwservice_contexts lacks the line ' + old)
        lines[hits[0]] = new
    return '\n'.join(lines), {'changed': HWS_CHANGED}


def overlay_file_contexts(stock_text, m7=False, cam=False):
    """Append the bip and wfca socket labels (v9), the wakeup source labels (v10) and the camera launcher (v11)."""
    if (not stock_text.endswith('\n') or 'wfca_rds' in stock_text or 'bip_socket u:' in stock_text
            or 'sysfs_wakeup' in stock_text or 'camerahalserver-pocket' in stock_text):
        raise SystemExit('stock vendor_file_contexts is not the expected file')
    added = FC_ADDED + (FC_M7_ADDED if m7 else []) + (FC_CAM_ADDED if cam else [])
    return stock_text + '\n'.join(added) + '\n', {'added': added}


def overlay_stune(text):
    """Drop the schedtune writes from init.mt6771.rc (v9)."""
    lines = text.split('\n')
    gone = [i for i, l in enumerate(lines) if l in STUNE_DROP]
    if [lines[i] for i in gone] != STUNE_DROP:
        raise SystemExit('init.mt6771.rc has not exactly the expected schedtune lines')
    return '\n'.join(l for l in lines if l not in STUNE_DROP), {'lines': [i + 1 for i in gone], 'removed': STUNE_DROP}


def overlay_fg_rc(stock_text):
    """Add oneshot to the fuelgauged service, after its group line (v9)."""
    lines = stock_text.split('\n')
    hits = [i for i, l in enumerate(lines) if l == FG_RC_ANCHOR]
    if len(hits) != 1 or not lines[0].startswith('service fuelgauged ') or 'oneshot' in stock_text:
        raise SystemExit('stock fuelgauged rc is not the expected one-service file')
    lines[hits[0] + 1:hits[0] + 1] = FG_RC_ADDED
    return '\n'.join(lines), {'after_line': hits[0] + 1, 'added': FG_RC_ADDED}


def overlay_cam_rc(stock_text):
    """Start camerahalserver through the launcher (v11)."""
    lines = stock_text.split('\n')
    if lines[0] != CAM_RC_LINE or sum(l.startswith('service ') for l in lines) != 1:
        raise SystemExit('stock camerahalserver.rc is not the expected one-service file')
    return '\n'.join([CAM_RC_COMMENT, CAM_RC_NEW] + lines[1:]), {'from': CAM_RC_LINE, 'to': CAM_RC_NEW,
                                                                 'added': [CAM_RC_COMMENT]}


def camera_shim(build=CAM_SHIM_BUILD):
    """The launcher and shim, checked against their build record and current sources (v11)."""
    rec = json.loads((build / 'record.json').read_text())
    out = {}
    for path, (name, ref) in CAM_ADDED.items():
        o = rec['outputs'].get(name, {})
        f = build / name
        stale = [s for s, h in o.get('sources', {}).items() if sha256(Path(s)) != h]
        if not f.exists() or sha256(f) != o.get('sha256') or stale or not o.get('sources'):
            raise SystemExit(f'{f} differs from its build record or its sources changed; '
                             'rebuild with tools/build-pocket-camera-shim.py')
        out[path] = {'path': f, 'sha256': o['sha256'], 'metadata_from': ref, 'sources': o['sources']}
    return out


def teed_tool():
    spec = importlib.util.spec_from_file_location('build_pocket_teed_shim', TEED_TOOL)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def teed_shim(build=TEED_SHIM_BUILD):
    """The shim, checked against its build record and current sources (v13)."""
    tool = teed_tool()
    rec = json.loads((build / 'record.json').read_text())
    o = rec['outputs'].get(tool.NAME, {})
    f = build / tool.NAME
    stale = [s for s, h in o.get('sources', {}).items() if sha256(Path(s)) != h]
    if not f.exists() or sha256(f) != o.get('sha256') or stale or not o.get('sources'):
        raise SystemExit(f'{f} differs from its build record or its sources changed; '
                         'rebuild with tools/build-pocket-teed-shim.py')
    return {'path': f, 'sha256': o['sha256'], 'metadata_from': TEED_SHIM_REF, 'sources': o['sources']}


def overlay_teed(stock):
    """Stock teed with the shim as its first DT_NEEDED, and the checked change list (v13)."""
    tool = teed_tool()
    if sha256_bytes(stock) != tool.TEED_SHA256:
        raise SystemExit('stock teed is not the pinned file')
    patched, changes = tool.add_needed(stock, tool.NAME)
    regions = tool.check_patched(stock, patched, tool.NAME)
    return patched, {'stock_sha256': tool.TEED_SHA256, 'sha256': sha256_bytes(patched),
                     'needed': tool.needed(patched), 'changes': changes, 'changed_regions': regions}


def modinfo(data):
    """{key: [values]} from the .modinfo section of an AArch64 module."""
    if data[:6] != b'\x7fELF\x02\x01':
        raise SystemExit('module is not a 64-bit little-endian ELF')
    shoff, = struct.unpack_from('<Q', data, 0x28)
    shentsize, shnum, shstrndx = struct.unpack_from('<HHH', data, 0x3a)
    sections = [struct.unpack_from('<IIQQQQ', data, shoff + i * shentsize) for i in range(shnum)]
    strtab = sections[shstrndx]
    name = lambda off: data[strtab[4] + off:data.index(b'\0', strtab[4] + off)].decode()
    hits = [s for s in sections if name(s[0]) == '.modinfo']
    if len(hits) != 1:
        raise SystemExit('module has no single .modinfo section')
    out = {}
    for entry in data[hits[0][4]:hits[0][4] + hits[0][5]].split(b'\0'):
        if b'=' in entry:
            k, v = entry.decode().split('=', 1)
            out.setdefault(k, []).append(v)
    return out


def connectivity_modules(build=CONN_BUILD, records=CONN_RECORDS, kernel_out=KERNEL_OUT):
    """Our six modules, each checked against its build record and the current kernel Module.symvers."""
    symvers = kernel_out / 'Module.symvers'
    symvers_sha = sha256(symvers)
    release = (kernel_out / 'include/config/kernel.release').read_text().strip()
    if not MODULE_VERMAGIC.startswith(release + ' '):
        raise SystemExit(f'kernel release {release} is not the one in MODULE_VERMAGIC')
    out = {}
    for m in CONN_MODULES:
        ko = build / m / f'{m}.ko'
        rec = json.loads((records / f'build-{m}.json').read_text())
        data = ko.read_bytes()
        info = modinfo(data)
        problems = [why for bad, why in (
            (rec.get('returncode') != 0, 'its build failed'),
            (rec.get('ko', {}).get('sha256') != sha256_bytes(data), 'it differs from its build record'),
            (rec.get('module_symvers_sha256') != symvers_sha, 'it was built against another Module.symvers'),
            (ko.stat().st_mtime < symvers.stat().st_mtime, 'it is older than the kernel Module.symvers'),
            (info.get('vermagic') != [MODULE_VERMAGIC], f'vermagic is {info.get("vermagic")}'),
            (info.get('name') != [m], f'modinfo name is {info.get("name")}'),
            (info.get('softdep'), 'it has a softdep, which this tool does not write')) if bad]
        if problems:
            raise SystemExit(f'{m}: ' + '; '.join(problems) + '. Rebuild it with tools/build-pocket-connectivity-module.py')
        deps = [d for d in info.get('depends', [''])[0].split(',') if d]
        out[m] = {'path': ko, 'sha256': sha256_bytes(data), 'bytes': len(data), 'vermagic': info['vermagic'][0],
                  'depends': deps, 'alias': info.get('alias', []), 'build_record': str(records / f'build-{m}.json')}
    return out, symvers_sha


def dep_order(name, mods):
    """depmod order: every module before the ones it needs, so the last entry loads first."""
    seen, post = set(), []

    def visit(n):
        for d in mods[n]['depends']:
            if d not in mods:
                raise SystemExit(f'{n} depends on {d}, which is not one of the replaced modules')
            if d not in seen:
                seen.add(d)
                visit(d)
                post.append(d)
    visit(name)
    return list(reversed(post))


def overlay_modules_dep(stock_text, mods):
    """Rewrite the six modules' modules.dep lines from their modinfo; other lines stay."""
    lines = stock_text.split('\n')
    done = set()
    for i, l in enumerate(lines):
        m = re.match(rf'^{re.escape(DEVICE_MODULE_DIR)}/(\w+)\.ko:', l)
        if m and m[1] in mods:
            deps = ' '.join(f'{DEVICE_MODULE_DIR}/{d}.ko' for d in dep_order(m[1], mods))
            lines[i] = f'{DEVICE_MODULE_DIR}/{m[1]}.ko:' + (' ' + deps if deps else '')
            done.add(m[1])
    if done != set(mods):
        raise SystemExit(f'modules.dep lacks lines for {sorted(set(mods) - done)}')
    return '\n'.join(lines)


def overlay_modules_alias(stock_text, mods):
    """modules.alias with the six modules' aliases from their modinfo. Stock text if the set is unchanged."""
    lines = stock_text.split('\n')
    rest = [l for l in lines if not (l.startswith('alias ') and l.rsplit(' ', 1)[1] in mods)]
    ours = [f'alias {a} {m}' for m in mods for a in mods[m]['alias']]
    if sorted(l for l in lines if l) == sorted(l for l in rest + ours if l):
        return stock_text
    tail = [''] if rest and rest[-1] == '' else []
    return '\n'.join(rest[:len(rest) - len(tail)] + ours + tail)


def overlay_fm_policy(stock_text):
    """Add the system_app /dev/fm rule after stock's platform_app one."""
    lines = stock_text.split('\n')
    hits = [i for i, l in enumerate(lines) if l == FM_RULE_ANCHOR]
    if len(hits) != 1 or any(l == FM_RULE_ADDED[1] for l in lines):
        raise SystemExit('vendor policy has no single platform_app fm_device rule, or already has the system_app one')
    lines[hits[0] + 1:hits[0] + 1] = FM_RULE_ADDED
    return '\n'.join(lines), {'after_line': hits[0] + 1, 'added': FM_RULE_ADDED}


def restore_commands(path, meta, xattr_files):
    """debugfs commands that give `path` the metadata of `meta`."""
    cmds = [f'sif "{path}" mode 0{int(meta["mode"], 8) | 0o100000:o}',
            f'sif "{path}" uid {meta["uid"]}', f'sif "{path}" gid {meta["gid"]}',
            f'sif "{path}" flags {meta["flags"]}', f'sif "{path}" generation {meta["generation"]}']
    for t in ('atime', 'ctime', 'mtime', 'crtime'):
        cmds += [f'sif "{path}" {t} @{meta[t][0]}', f'sif "{path}" {t}_extra {meta[t][1]}']
    for name, file in xattr_files:
        cmds.append(f'ea_set -f "{file}" "{path}" {name}')
    return cmds


def xattr_names(meta):
    return [re.match(r'(\S+) \(', x)[1] for x in meta['xattrs']]


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument('--stock-vendor', type=Path)
    ap.add_argument('--policy-install', type=Path, default=POLICY_INSTALL)
    ap.add_argument('--policy-handoff', type=Path, default=POLICY_HANDOFF)
    ap.add_argument('--ramdisk-fstab', type=Path, default=RAMDISK_FSTAB)
    ap.add_argument('--version', choices=VERSIONS, default=VERSION)
    ap.add_argument('--composition-record', type=Path, default=COMPOSITION_RECORD)
    ap.add_argument('--output', type=Path)
    ap.add_argument('--replace', action='store_true',
                    help='delete an existing output first; only for ' + ', '.join(REPLACEABLE) + ' in the default place')
    args = ap.parse_args()
    args.output = args.output or OVERLAY_DIR / args.version
    args.stock_vendor = args.stock_vendor or stock_vendor_for(args.version)[0]
    stock_sha = stock_vendor_for(args.version)[1]

    replacing = args.output.exists() and args.replace
    if replacing and (args.version not in REPLACEABLE or args.output != OVERLAY_DIR / args.version):
        raise SystemExit(f'--replace only rebuilds {", ".join(REPLACEABLE)} in {OVERLAY_DIR}')
    if args.output.exists() and not replacing:
        raise SystemExit(f'{args.output} exists; refusing to overwrite (v5 to v13 take --replace)')
    v5 = args.version in ('v5', 'v6', 'v7', 'v8', 'v9', 'v10', 'v11', 'v12', 'v13')
    mods, symvers_sha = connectivity_modules() if v5 else ({}, None)
    if sha256(args.stock_vendor) != stock_sha:
        raise SystemExit('stock vendor image hash differs from the pinned image')
    handoff = json.loads(args.policy_handoff.read_text())
    if replacing:
        shutil.rmtree(args.output)
    v2 = args.version in ('v2', 'v3', 'v4', 'v5', 'v6', 'v7', 'v8', 'v9', 'v10', 'v11', 'v12', 'v13')
    out = args.output
    work = out / 'work'
    work.mkdir(parents=True)
    info = footer(args.stock_vendor)
    if info['algorithm'] != 'NONE':
        raise SystemExit('stock vendor footer is signed; this tool only handles AVB NONE')

    # Control: the unmodified filesystem must repack to the exact stock image.
    control = work / 'control.img'
    extract_fs(args.stock_vendor, control, info['original_image_size'])
    add_footer(control, info)
    control_sha = sha256(control)
    control.unlink()
    if control_sha != stock_sha:
        raise SystemExit(f'control repack differs from stock ({control_sha})')

    fs = work / 'vendor.ext4'
    extract_fs(args.stock_vendor, fs, info['original_image_size'])
    # Keep the superblock write time and write counter at their stock values.
    # The stock build stamped every time field with the root inode's mtime.
    sb = debugfs(fs, ['show_super_stats -h'])[0][1]
    kbytes = re.search(r'Lifetime writes:\s+(\d+) kB', sb)
    kbytes = int(kbytes[1]) if kbytes else None
    fake_time = stat_paths(fs, ['/'])['/']['mtime'][0]

    # Unpack the stock files to edit and build the overlay tree.
    stock_dir = out / 'stock-files'
    overlay = out / 'overlay/vendor'
    for d in (stock_dir, overlay / 'etc/init/hw', overlay / 'etc/selinux'):
        d.mkdir(parents=True, exist_ok=True)
    stock_fstab = dump(fs, FSTAB, stock_dir / 'fstab.mt6771').decode()
    stock_init = dump(fs, INIT_RC, stock_dir / 'init.mt6771.rc').decode()
    new_fstab, fstab_edits = overlay_fstab(stock_fstab, args.ramdisk_fstab.read_text(),
                                             unencrypted=v2 and args.version != 'v13',
                                             encrypted=args.version == 'v13')
    new_init, init_edit = overlay_init(stock_init)
    v9 = args.version in ('v9', 'v10', 'v11', 'v12', 'v13')
    v10 = args.version in ('v10', 'v11', 'v12', 'v13')
    v11 = args.version in ('v11', 'v12', 'v13')
    cam = camera_shim() if v11 else {}
    cam_rc_edit = None
    v13 = args.version == 'v13'
    teed = teed_shim() if v13 else None
    teed_edit = None
    stune_edit = fg_edit = fc_edit = m3_edit = hws_edit = None
    if v9:
        new_init, stune_edit = overlay_stune(new_init)
    stock_usb = dump(fs, USB_RC, stock_dir / 'init.mt6771.usb.rc').decode()
    new_usb, usb_edit = overlay_usb(stock_usb)
    (overlay / 'etc/init/hw/init.mt6771.usb.rc').write_text(new_usb)
    tk_edit = None
    if v2:
        stock_tk = dump(fs, TRUSTKERNEL_RC, stock_dir / 'trustkernel.rc').decode()
        new_tk, tk_edit = overlay_trustkernel(stock_tk)
        (overlay / 'etc/init/trustkernel.rc').write_text(new_tk)
    manifest_edit = km_rc_edit = fr_rc_edit = codecs_edit = None
    if args.version in ('v3', 'v4', 'v5', 'v6', 'v7', 'v8', 'v9', 'v10', 'v11', 'v12', 'v13'):
        (overlay / 'etc/vintf').mkdir(parents=True)
        stock_manifest = dump(fs, VINTF_MANIFEST, stock_dir / 'manifest.xml').decode()
        new_manifest, manifest_edit = (overlay_manifest_keep_km if args.version in ('v6', 'v7', 'v8', 'v9', 'v10', 'v11', 'v12', 'v13') else overlay_manifest)(stock_manifest)
        (overlay / 'etc/vintf/manifest.xml').write_text(new_manifest)
    if args.version in ('v3', 'v4', 'v5'):
        stock_km = dump(fs, KM_RC, stock_dir / KM_RC.rsplit('/', 1)[1]).decode()
        new_km, km_rc_edit = overlay_km_rc(stock_km)
        (overlay / 'etc/init' / KM_RC.rsplit('/', 1)[1]).write_text(new_km)
    if args.version in ('v4', 'v5', 'v6', 'v7', 'v8', 'v9', 'v10', 'v11', 'v12', 'v13'):
        stock_fr = dump(fs, FR_RC, stock_dir / FR_RC.rsplit('/', 1)[1]).decode()
        new_fr, fr_rc_edit = overlay_fr_rc(stock_fr)
        (overlay / 'etc/init' / FR_RC.rsplit('/', 1)[1]).write_text(new_fr)
    build_prop_edit = None
    if args.version in ('v8', 'v9', 'v10', 'v11', 'v12', 'v13'):
        new_prop, build_prop_edit = overlay_build_prop(dump(fs, BUILD_PROP, stock_dir / 'build.prop').decode())
        (overlay / 'build.prop').write_text(new_prop)
    if v9:
        new_fg, fg_edit = overlay_fg_rc(dump(fs, FG_RC, stock_dir / FG_RC.rsplit('/', 1)[1]).decode())
        (overlay / 'etc/init' / FG_RC.rsplit('/', 1)[1]).write_text(new_fg)
        new_fc, fc_edit = overlay_file_contexts(dump(fs, FILE_CONTEXTS, stock_dir / 'vendor_file_contexts').decode(), m7=v10, cam=v11)
        (overlay / 'etc/selinux/vendor_file_contexts').write_text(new_fc)
        new_hws, hws_edit = overlay_hwservice_contexts(dump(fs, HWSERVICE_CONTEXTS, stock_dir / 'vendor_hwservice_contexts').decode())
        (overlay / 'etc/selinux/vendor_hwservice_contexts').write_text(new_hws)
    if args.version in ('v7', 'v8', 'v9', 'v10', 'v11', 'v12', 'v13'):
        name = CODECS_XML.rsplit('/', 1)[1]
        new_codecs, codecs_edit = overlay_codecs(dump(fs, CODECS_XML, stock_dir / name).decode())
        (overlay / 'etc' / name).write_text(new_codecs)
    if v11:
        new_cam_rc, cam_rc_edit = overlay_cam_rc(dump(fs, CAM_RC, stock_dir / CAM_RC.rsplit('/', 1)[1]).decode())
        (overlay / 'etc/init' / CAM_RC.rsplit('/', 1)[1]).write_text(new_cam_rc)
        for path, c in cam.items():
            (overlay / path.lstrip('/')).parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(c['path'], overlay / path.lstrip('/'))
    if v13:
        patched, teed_edit = overlay_teed(dump(fs, TEED, stock_dir / 'teed'))
        (overlay / 'bin').mkdir(parents=True, exist_ok=True)
        (overlay / 'bin/teed').write_bytes(patched)
        (overlay / 'lib64').mkdir(parents=True, exist_ok=True)
        shutil.copy2(teed['path'], overlay / TEED_SHIM.lstrip('/'))
    (overlay / 'etc/fstab.mt6771').write_text(new_fstab)
    (overlay / 'etc/init/hw/init.mt6771.rc').write_text(new_init)

    listing = debugfs(fs, [f'ls -p {SELINUX}'])[0][1]
    names = [l.split('/')[5] for l in listing.splitlines() if l.startswith('/') and l.split('/')[5] not in ('.', '..')]
    stock_policy = {}
    for n in names:
        stock_policy[n] = sha256_bytes(dump(fs, f'{SELINUX}/{n}', stock_dir / n))
    install_dir = args.policy_install / 'vendor/etc/selinux'
    plan = policy_plan(stock_policy, install_dir, handoff)
    for n in plan['replace'] + plan['add']:
        shutil.copy2(install_dir / n, overlay / 'etc/selinux' / n)
    pruned = {}
    if v2:
        pruned, dropped = pruned_policy(install_dir, args.composition_record)
        if not set(pruned) <= set(plan['replace']):
            raise SystemExit('a pruned policy file is not among the replaced stock files')
        for n, data in pruned.items():
            (overlay / 'etc/selinux' / n).write_bytes(data)
    fm_policy_edit = None
    module_files = []
    if v5:
        new_cil, fm_policy_edit = overlay_fm_policy(pruned['vendor_sepolicy.cil'].decode())
        if v9:
            new_cil, m3_edit = overlay_m3_policy(new_cil, m7=v10)
        (overlay / 'etc/selinux/vendor_sepolicy.cil').write_text(new_cil)
        (overlay / 'lib/modules').mkdir(parents=True)
        for m, mod in mods.items():
            shutil.copy2(mod['path'], overlay / f'lib/modules/{m}.ko')
            module_files.append((f'{MODULE_DIR}/{m}.ko', overlay / f'lib/modules/{m}.ko', f'{MODULE_DIR}/{m}.ko'))
        for path, edit in ((MODULES_DEP, overlay_modules_dep), (MODULES_ALIAS, overlay_modules_alias)):
            name = path.rsplit('/', 1)[1]
            stock = dump(fs, path, stock_dir / name).decode()
            new = edit(stock, mods)
            if new != stock:
                (overlay / 'lib/modules' / name).write_text(new)
                module_files.append((path, overlay / 'lib/modules' / name, path))

    # In-place edit plan: (image path, overlay file, metadata reference path).
    replace = [(FSTAB, overlay / 'etc/fstab.mt6771', FSTAB),
               (INIT_RC, overlay / 'etc/init/hw/init.mt6771.rc', INIT_RC),
               (USB_RC, overlay / 'etc/init/hw/init.mt6771.usb.rc', USB_RC)]
    if tk_edit:
        replace.append((TRUSTKERNEL_RC, overlay / 'etc/init/trustkernel.rc', TRUSTKERNEL_RC))
    if manifest_edit:
        replace.append((VINTF_MANIFEST, overlay / 'etc/vintf/manifest.xml', VINTF_MANIFEST))
    if km_rc_edit:
        replace.append((KM_RC, overlay / 'etc/init' / KM_RC.rsplit('/', 1)[1], KM_RC))
    if fr_rc_edit:
        replace.append((FR_RC, overlay / 'etc/init' / FR_RC.rsplit('/', 1)[1], FR_RC))
    if codecs_edit:
        replace.append((CODECS_XML, overlay / 'etc' / CODECS_XML.rsplit('/', 1)[1], CODECS_XML))
    if fg_edit:
        replace.append((FG_RC, overlay / 'etc/init' / FG_RC.rsplit('/', 1)[1], FG_RC))
        replace.append((FILE_CONTEXTS, overlay / 'etc/selinux/vendor_file_contexts', FILE_CONTEXTS))
        replace.append((HWSERVICE_CONTEXTS, overlay / 'etc/selinux/vendor_hwservice_contexts', HWSERVICE_CONTEXTS))
    if build_prop_edit:
        replace.append((BUILD_PROP, overlay / 'build.prop', BUILD_PROP))
    if cam_rc_edit:
        replace.append((CAM_RC, overlay / 'etc/init' / CAM_RC.rsplit('/', 1)[1], CAM_RC))
    if teed_edit:
        replace.append((TEED, overlay / 'bin/teed', TEED))
    replace += [(f'{SELINUX}/{n}', overlay / 'etc/selinux' / n, f'{SELINUX}/{n}') for n in plan['replace']]
    replace += module_files
    add = [(f'{SELINUX}/{n}', overlay / 'etc/selinux' / n, f'{SELINUX}/{ADD_REFERENCE}') for n in plan['add']]
    add += [(path, overlay / path.lstrip('/'), c['metadata_from']) for path, c in cam.items()]
    if teed:
        add.append((TEED_SHIM, overlay / TEED_SHIM.lstrip('/'), teed['metadata_from']))
    remove = [f'{SELINUX}/{n}' for n in plan['remove']] + ([POWER_VINTF] if args.version in ('v7', 'v8', 'v9', 'v10', 'v11', 'v12', 'v13') else [])
    refs = sorted({r for _, _, r in replace + add})
    before = stat_paths(fs, refs + remove)
    if any(v is None for v in before.values()):
        raise SystemExit('a stock path to edit is missing')
    parents = sorted({p.rsplit('/', 1)[0] or '/' for p, _, _ in replace + add} | {p.rsplit('/', 1)[0] or '/' for p in remove})
    parent_before = stat_paths(fs, parents)

    xdir = work / 'xattrs'
    xdir.mkdir()
    xattrs = {}
    for ref in refs:
        files = []
        for i, name in enumerate(xattr_names(before[ref])):
            f = xdir / f'{before[ref]["inode"]}-{i}.bin'
            debugfs(fs, [f'ea_get -f "{f}" "{ref}" {name}'])
            files.append((name, f))
        xattrs[ref] = files

    cmds = [f'rm "{p}"' for p in remove]
    for path, src, ref in replace + add:
        d, base = path.rsplit('/', 1)
        d = d or '/'
        if (path, src, ref) in replace:
            cmds.append(f'rm "{path}"')
        cmds += [f'cd "{d}"', f'write "{src}" "{base}"', 'cd /']
        cmds += restore_commands(path, before[ref], xattrs[ref])
    for p in parents:
        m = parent_before[p]
        for t in ('atime', 'ctime', 'mtime', 'crtime'):
            cmds += [f'sif "{p}" {t} @{m[t][0]}', f'sif "{p}" {t}_extra {m[t][1]}']
    debugfs(fs, cmds, write=True, fake_time=fake_time)
    if kbytes is not None:
        debugfs(fs, [f'ssv kbytes_written {kbytes}'], write=True, fake_time=fake_time)

    # Verify the written metadata against the references before packing.
    after = stat_paths(fs, [p for p, _, _ in replace + add] + parents)
    ignore = {'inode', 'size'}
    for path, src, ref in replace + add:
        a, b = after[path], before[ref]
        diff = {k for k in b if k not in ignore and a.get(k) != b.get(k)}
        if diff:
            raise SystemExit(f'{path}: metadata differs after write: {sorted(diff)}')
        if dump(fs, path, work / 'verify.bin') != src.read_bytes():
            raise SystemExit(f'{path}: content differs after write')
    for p in parents:
        diff = {k for k in parent_before[p] if k != 'size' and after[p].get(k) != parent_before[p].get(k)}
        if diff:
            raise SystemExit(f'{p}: directory metadata changed: {sorted(diff)}')
    (work / 'verify.bin').unlink()
    if any(stat_paths(fs, remove, allow_missing=True).values()):
        raise SystemExit('a removed file is still present')

    fsck = run([PREBUILT_BIN / 'e2fsck', '-fn', fs], check=False)
    if fsck.returncode != 0:
        raise SystemExit(f'e2fsck -fn failed ({fsck.returncode}):\n{fsck.stdout}{fsck.stderr}')

    image = out / 'vendor.img'
    os.replace(fs, image)
    add_footer(image, info)
    new_info = footer(image)
    shutil.rmtree(work)

    record = {
        'schema': 1,
        'version': args.version,
        'status': 'Private engineering vendor overlay; not installed, not boot-tested',
        'stock_vendor': {'path': str(args.stock_vendor), 'sha256': stock_sha},
        'control_repack_sha256': control_sha,
        'control_repack_identical': True,
        'image': {'path': str(image), 'sha256': sha256(image), 'bytes': image.stat().st_size},
        'footer': {'stock_root_digest': info['root_digest'], 'root_digest': new_info['root_digest'],
                   'salt': new_info['salt'], 'algorithm': new_info['algorithm'],
                   'fec_num_roots': new_info['fec_num_roots'], 'props': new_info['props']},
        'fstab_edits': fstab_edits,
        'init_edit': init_edit,
        'usb_edit': usb_edit,
        'trustkernel_edit': tk_edit,
        'manifest_edit': manifest_edit,
        'keymaster_rc_edit': km_rc_edit,
        'flash_recovery_rc_edit': fr_rc_edit,
        'codecs_edit': codecs_edit,
        'build_prop_edit': build_prop_edit,
        'fm_policy_edit': fm_policy_edit,
        'm3_policy_edit': m3_edit,
        'file_contexts_edit': fc_edit,
        'hwservice_contexts_edit': hws_edit,
        'stune_edit': stune_edit,
        'fuelgauged_rc_edit': fg_edit,
        'camera_rc_edit': cam_rc_edit,
        'teed_edit': teed_edit,
        'teed_shim': {k: (str(v) if k == 'path' else v) for k, v in teed.items()} if teed else None,
        'camera_shim': {p: {k: (str(v) if k == 'path' else v) for k, v in c.items()} for p, c in cam.items()},
        'modules': {m: {k: (str(v) if k == 'path' else v) for k, v in i.items()} for m, i in mods.items()},
        'kernel_module_symvers_sha256': symvers_sha,
        'policy_plan': plan,
        'pruned': {n: {'sha256': sha256_bytes(d), 'dropped_names': sorted(dropped)} for n, d in pruned.items()},
        'replaced': [p for p, _, _ in replace],
        'added': [{'path': p, 'metadata_from': r} for p, _, r in add],
        'removed': remove,
        'overlay_files': {str(p.relative_to(out)): sha256(p) for p in sorted(overlay.rglob('*')) if p.is_file()},
        'inputs': {str(args.policy_handoff): sha256(args.policy_handoff),
                   **({str(args.composition_record): sha256(args.composition_record),
                       str(COMPOSITION_TOOL): sha256(COMPOSITION_TOOL)} if pruned else {}),
                   str(args.ramdisk_fstab): sha256(args.ramdisk_fstab),
                   **{str(i['path']): i['sha256'] for i in mods.values()},
                   **{str(c['path']): c['sha256'] for c in cam.values()},
                   **({str(teed['path']): teed['sha256'], str(TEED_TOOL): sha256(TEED_TOOL)} if teed else {}),
                   **{str(install_dir / n): sha256(install_dir / n) for n in plan['replace'] + plan['add']}},
        'tools': {str(t): sha256(t) for t in (Path(__file__).resolve(), AVBTOOL, HOST_BIN / 'debugfs',
                                              PREBUILT_BIN / 'e2fsck', PREBUILT_BIN / 'fec')},
        'e2fsck': fsck.stdout.strip().splitlines()[-1:],
        'device_accessed': False,
    }
    (out / 'record.json').write_text(json.dumps(record, indent=1) + '\n')
    print(json.dumps({'image': record['image'], 'record': str(out / 'record.json')}, indent=1))


if __name__ == '__main__':
    main()
