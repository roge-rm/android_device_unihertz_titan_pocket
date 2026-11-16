#!/usr/bin/env python3
"""Checks the camera HAL contract and the camera scaffolding in the 5.10 tree (CAMERA_PORT.md milestone C0).

HAL scan: every BL to ioctl or ion_custom_ioctl in the stock camera libs (aarch64, NDK llvm-objdump), with the
request number recovered from w1 by a linear walk of the function (mov, movk, orr). For ion_custom_ioctl the first
u32 of the struct x2 points at (mm_cmd or sys_cmd) is recovered from constant stores to that stack slot. A call whose
value isn't a constant in the walk is "unresolved" and is listed by call site.

Header tables: every _IO* macro in T's camera headers, evaluated by the NDK clang for aarch64 with empty stand-ins
for the kernel-only headers (CONFIG_COMPAT is off, so only the native 64-bit numbers come out; the HAL is 64-bit).

Contract: evidence/camera/hal-contract.md must name every resolved request number (as 0x%08x), every unresolved
call site (lib and address) and every ION sub-command, and each resolved number must be in a T header table or in
the file's list of numbers that aren't camera driver ioctls.

Scaffolding (C0): the stub headers, the MTK I2C shim and their Kconfig/Makefile glue exist in the 5.10 tree, and
when a build of this tree is present, System.map has the shim's symbols. Later milestones add their checks here.

Sensor path (C1): U's imgsensor, seninf, lens and cam_cal headers give the same numbers as T's, native and compat
(29 + 8 + 16 + 5), and the uapi headers are T's bytes; the node names and compat_ioctl handlers are in the source;
the build has the C1 config and the probe and ioctl symbols; both board dtbs have the camera nodes okay as stock.

Flashlight (C2) and ISP raw, DIP and WPE (C3): the same for their headers (ISP 35 + 13, DIP 13 + 7, WPE 16 + 8),
ISP_mmap and WPE_mmap and their base and range defines are T's, SOF timestamps stay ktime_get, and both boards have
the engines okay with stock's IRQs.

CCU (C5): ccu_drv.h gives T's 21 numbers, the CCU files are T's bytes except the 5.10 changes listed in C5_CHANGED,
the CCU I2C hooks are real (i2c-mt65xx's CCU channel through the shim's T names), the kernel loads no CCU firmware
and lib3a.ccudrv names the vendor files it maps, and both boards have /ccu and the ccu_sensor children okay.

JPEG (C6): jpeg_drv.h gives T's 24 native and 6 compat numbers, the JPEG files are T's bytes except the proc_ops change
(stock has no JPEG_DEV, so /proc/mtk_jpeg, which both libJpgEncPipe builds open), the encoder-only mt6771 build, and
venc_jpg is the one JPEG node both boards have okay.

Host only: no build and no phone access. Writes evidence/camera/camera-contract-check.json.
"""
import pocket_paths
import hashlib, json, os, re, struct, subprocess, sys, tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
BULK = pocket_paths.build_root()
BUILD = BULK / 'kernel-firstboot-5.10'
U = Path(os.environ.get('POCKET_KERNEL_SOURCE', str(ROOT / 'tools/kernel-source/upgrade-5.10')))
T = ROOT / 'tools/kernel-source/android_kernel_unihertz_titan_pocket-3335ddf5dd7fac4fdba5d5fd451ad6649c51250c'
VENDOR = ROOT / 'firmware/analysis/rootfs/vendor'
CONTRACT = ROOT / 'evidence/camera/hal-contract.md'
OUT = ROOT / 'evidence/camera/camera-contract-check.json'
LLVM = Path(os.environ.get('ANDROID_SDK_ROOT', str(Path.home() / 'Android/Sdk'))) / \
    'ndk/27.1.12297006/toolchains/llvm/prebuilt/linux-x86_64/bin'
MM = 'drivers/misc/mediatek/'

# Stock camera libs that send ioctls to camera, ION, M4U or GZ nodes (vendor/lib64, by their open strings).
LIBS = ['libcam.halsensor.so', 'libcameracustom.so', 'libcam.hal3a.v3.so', 'libcamdrv_isp.so', 'libdip_drv.so',
        'lib3a.ccudrv.so', 'lib3a.ccuif.so', 'libmtkcam_fdvt.so', 'libmtkcam_rsc.so', 'libJpgEncPipe.so',
        'libvpu.so', 'libcamalgo.vpunr.so', 'libcamdrv_imem.so', 'libdip_imem.so', 'libmtkcam_imem.so',
        'libmtkcam_imgbuf.so']
# Wrappers that pass their w1 straight to ioctl as the request: (this, cmd, ...).
WRAPPERS = {'libcam.hal3a.v3.so': ['<_ZN23StrobeDrvFlashlightFops11sendCommandEiiii',
                                   '<_ZN23StrobeDrvFlashlightFops14sendCommandRetEiiiPi']}
# T header -> extra include dirs (relative to T); kernel-only headers are empty stand-ins.
HEADERS = {
    MM + 'imgsensor/inc/kd_imgsensor.h': ([MM + 'imgsensor/inc'], ['kd_imgsensor_define.h']),
    MM + 'imgsensor/inc/kd_seninf.h': ([MM + 'imgsensor/inc'], []),
    MM + 'cam_cal/inc/cam_cal.h': ([MM + 'cam_cal/inc', MM + 'imgsensor/inc'], ['cam_cal_define.h']),
    MM + 'lens/main/inc/lens_info.h': ([MM + 'lens/main/inc'], []),
    MM + 'flashlight/flashlight.h': ([], []),
    MM + 'cameraisp/src/isp_50/inc/camera_isp.h': ([], []),
    MM + 'cameraisp/dip/isp_50/camera_dip.h': ([], []),
    MM + 'cameraisp/wpe/isp_50/inc/camera_wpe.h': ([], []),
    MM + 'cameraisp/fdvt/4.0/inc/camera_fdvt.h': ([], []),
    MM + 'cameraisp/rsc/isp_50/camera_rsc.h': ([], []),
    MM + 'ccu/src/2.0/ccu_drv.h': ([MM + 'ccu/src/2.0', MM + 'ccu/src/mt6771/ccu_ext_interface'], []),
    MM + 'jpeg/v2/jpeg_drv.h': ([], []),
    MM + 'vpu/3.0/vpu_drv.h': ([MM + 'vpu/2.0/mt6771', MM + 'vpu/2.0'], []),
    'drivers/staging/android/uapi/ion.h': ([], []),
    'include/uapi/linux/dma-buf.h': ([], []),
}
STANDINS = ['linux/fs.h', 'linux/compat.h', 'linux/notifier.h', 'linux/clk.h', 'linux/device.h', 'linux/cdev.h',
            'linux/semaphore.h', 'linux/wait.h', 'linux/mutex.h', 'linux/spinlock.h', 'linux/list.h',
            'linux/interrupt.h', 'linux/kernel.h', 'linux/slab.h', 'linux/sched.h', 'linux/i2c.h',
            'linux/platform_device.h', 'linux/time.h', 'linux/printk.h', 'linux/module.h', 'linux/uaccess.h',
            'linux/io.h', 'linux/delay.h', 'linux/regulator/consumer.h', 'linux/gpio.h', 'vpu_dvfs.h',
            'linux/pm_qos.h', 'mmdvfs_pmqos.h', 'linux/dma-mapping.h', 'linux/kref.h', 'linux/wakelock.h',
            'linux/pm_wakeup.h', 'linux/atomic.h']
TYPES = '''typedef unsigned char u8, __u8; typedef signed char s8, __s8; typedef unsigned short u16, __u16;
typedef short s16, __s16; typedef unsigned int u32, __u32; typedef int s32, __s32;
typedef unsigned long long u64, __u64; typedef long long s64, __s64; typedef unsigned long size_t, uintptr_t;
typedef long ssize_t, intptr_t; typedef _Bool bool; typedef unsigned int compat_uptr_t, compat_uint_t;
typedef int compat_int_t; typedef int compat_long_t; typedef unsigned int compat_ulong_t; typedef unsigned int __bitwise, dma_addr_t32;
typedef unsigned long dma_addr_t, phys_addr_t; typedef unsigned short umode_t; typedef int pid_t;
typedef long long ktime_t; typedef unsigned char uint8_t; typedef unsigned short uint16_t;
typedef unsigned int uint32_t; typedef unsigned long long uint64_t; typedef signed char int8_t; typedef short int16_t;
typedef int int32_t; typedef long long int64_t; typedef unsigned int gfp_t; typedef unsigned long long __aligned_u64;
#define __user
#define __iomem
#define __bitwise
#define __force
#define true 1
#define false 0
#define NULL ((void *)0)
struct notifier_block { void *p; }; struct file; struct inode; struct device; struct platform_device; struct clk;
struct timeval { long tv_sec; long tv_usec; };
struct list_head { struct list_head *next, *prev; };
typedef struct { long counter; } atomic_t;
typedef struct { int raw; } spinlock_t;
typedef struct { void *x; } wait_queue_head_t;
'''
# Numbers the HAL sends that aren't camera driver ioctls: who serves them in U.
NOT_DRIVER = {
    0xc0104906: 'ION_IOC_CUSTOM (libion_mtk ion_custom_ioctl), legacy MTK ION in U (0022)',
    0xc0084905: 'ION_IOC_IMPORT, legacy MTK ION in U (0022)',
    0x40086200: 'DMA_BUF_IOCTL_SYNC, dma-buf core',
    0xc1007c01: 'MEDIA_IOC_ENUM_ENTITIES on /dev/media* (V4L2 strobe/lens probe in hal3a), no media device in U or stock',
    0xc1007c00: 'MEDIA_IOC_DEVICE_INFO on /dev/media* (V4L2 lens probe in hal3a), no media device in U or stock',
    0x40084e08: 'FDVT_IOC_SETMETA_CMD, defined only with MTK_SECURE_FD_SUPPORT=1; stock built FDVT with 0 (no GZ)',
    0x00004101: '/dev/laser (LaserDrv in hal3a); no laser driver in T or stock kallsyms',
    0x80044102: '/dev/laser (LaserDrv), offset calibration get',
    0x80044103: '/dev/laser (LaserDrv), crosstalk calibration get',
    0x40044104: '/dev/laser (LaserDrv), offset calibration set',
    0x40044105: '/dev/laser (LaserDrv), crosstalk calibration set',
    0x800c410a: '/dev/laser (LaserDrv), laser info',
    0x40046732: 'MTK_M4U_T_SEC_INIT on /proc/m4u (secure init, initSecureM4U)',
    0x4004673c: 'MTK_M4U_T_GZ_SEC_INIT on /proc/m4u (GenieZone secure init)',
}
GZ_MAGIC = 'T'  # /dev/gz_kree, GenieZone; off in our build (secure buffers only)
ION_CMD = {0: 'ION_CMD_SYSTEM', 1: 'ION_CMD_MULTIMEDIA'}
ION_SYS = {0: 'ION_SYS_CACHE_SYNC', 1: 'ION_SYS_GET_PHYS', 4: 'ION_SYS_SET_CLIENT_NAME', 5: 'ION_SYS_DMA_OP'}
ION_MM = {0: 'ION_MM_CONFIG_BUFFER', 1: 'ION_MM_SET_DEBUG_INFO', 5: 'ION_MM_CONFIG_BUFFER_EXT', 8: 'ION_MM_GET_IOVA'}

# C0 scaffolding in U: file -> strings it must contain. The AEE, MET and mmprofile stubs are the display port's;
# the camera drivers need only their names. The MTK PM QoS classes are in include/linux/pm_qos.h already.
SCAFFOLD = {
    MM + 'include/mt-plat/aee.h': ['aee_kernel_warning', 'aee_kernel_exception', 'DB_OPT_DEFAULT'],
    MM + 'include/mt-plat/met_drv.h': ['met_tag_oneshot'],
    MM + 'mmp/mmprofile.h': ['mmprofile_log_ex'],
    MM + 'mmdvfs/mmdvfs_pmqos.h': ['mm_qos_add_request', 'mm_qos_set_request', 'mm_qos_set_bw_request',
                                  'mm_qos_set_hrt_request', 'mm_qos_update_all_request',
                                  'mm_qos_remove_all_request', 'mm_qos_update_all_request_zero',
                                  'mmdvfs_qos_get_freq_steps', 'mmdvfs_qos_get_freq(', 'mmdvfs_qos_limit_config',
                                  'BW_COMP_NONE', 'struct mm_qos_request'],
    'include/linux/pm_qos.h': ['PM_QOS_CAM_FREQ', 'PM_QOS_MM_MEMORY_BANDWIDTH', 'PM_QOS_EMI_OPP',
                               'PM_QOS_VCORE_OPP', 'PM_QOS_VENC_FREQ'],
    'drivers/i2c/busses/i2c-mtk.h': ['mtk_i2c_transfer', 'hw_trig_i2c_enable', 'hw_trig_i2c_disable',
                                     'hw_trig_i2c_transfer', 'i2c_ccu_enable', 'i2c_ccu_disable',
                                     'I2C_A_FILTER_MSG', 'MAX_DMA_TRANS_SIZE'],
    MM + 'i2c_shim/mtk_i2c_shim.c': ['EXPORT_SYMBOL(mtk_i2c_transfer)', 'EXPORT_SYMBOL(hw_trig_i2c_enable)',
                                     'EXPORT_SYMBOL(hw_trig_i2c_disable)', 'EXPORT_SYMBOL(hw_trig_i2c_transfer)',
                                     'EXPORT_SYMBOL(i2c_ccu_enable)', 'EXPORT_SYMBOL(i2c_ccu_disable)',
                                     'i2c_transfer(adap, msgs, num)'],
    MM + 'i2c_shim/Makefile': ['obj-$(CONFIG_MTK_I2C_SHIM) += mtk_i2c_shim.o'],
    MM + 'i2c_shim/Kconfig': ['config MTK_I2C_SHIM', 'depends on I2C_MT65XX'],
    MM + 'Kconfig': ['source "drivers/misc/mediatek/i2c_shim/Kconfig"'],
    MM + 'Makefile': ['obj-$(CONFIG_MTK_I2C_SHIM) += i2c_shim/'],
}
SHIM_SYMBOLS = ['mtk_i2c_transfer', 'hw_trig_i2c_enable', 'hw_trig_i2c_disable', 'hw_trig_i2c_transfer',
                'i2c_ccu_enable', 'i2c_ccu_disable']

# C1 sensor path. Header -> (native, compat) ioctl counts; U's numbers must equal T's, compat ones included.
C1_HEADERS = {
    MM + 'imgsensor/inc/kd_imgsensor.h': (23, 6),
    MM + 'imgsensor/inc/kd_seninf.h': (8, 0),
    MM + 'lens/main/inc/lens_info.h': (16, 0),
    MM + 'cam_cal/inc/cam_cal.h': (3, 2),
}
C1_SUB_LENS = MM + 'lens/sub/inc/lens_info.h'
# The uapi headers and struct definitions the HAL builds against: byte for byte T's.
C1_SAME_AS_T = [MM + 'imgsensor/inc/' + f for f in ('kd_imgsensor.h', 'kd_imgsensor_define.h', 'kd_seninf.h',
                                                    'kd_seninf_define.h', 'kd_camera_feature.h',
                                                    'kd_camera_feature_enum.h', 'kd_camera_feature_id.h',
                                                    'kd_camera_typedef.h')] + \
               [MM + 'cam_cal/inc/cam_cal.h', MM + 'cam_cal/inc/cam_cal_define.h',
                MM + 'lens/main/inc/lens_info.h', MM + 'lens/sub/inc/lens_info.h']
# Source file -> strings it must contain: the node name and a compat_ioctl handler.
C1_NODES = {
    MM + 'imgsensor/src/mt6771/camera_hw/imgsensor_cfg_table.h': ['#define IMGSENSOR_DEV_NAME "kd_camera_hw"'],
    MM + 'imgsensor/src/common/v1_1/imgsensor.c': ['.compat_ioctl   = imgsensor_compat_ioctl'],
    MM + 'imgsensor/src/common/v1_1/seninf.h': ['#define SENINF_DEV_NAME "seninf"'],
    MM + 'imgsensor/src/common/v1_1/seninf.c': ['.compat_ioctl   = seninf_ioctl_compat'],
    MM + 'cam_cal/src/common/v1/eeprom_driver.c': ['#define CAM_CAL_DRV_NAME "CAM_CAL_DRV"',
                                                   '.compat_ioctl = EEPROM_drv_compat_ioctl'],
    MM + 'lens/main/main_lens.c': ['#define AF_DRVNAME "MAINAF"', '.compat_ioctl = AF_Ioctl_Compat',
                                   '{1, AFDRV_AK7371AF, AK7371AF_SetI2Cclient'],
    MM + 'lens/sub/sub_lens.c': ['#define AF_DRVNAME "SUBAF"', '.compat_ioctl = AF_Ioctl_Compat'],
}
C1_CONFIG = ['CONFIG_MTK_IMGSENSOR=y', 'CONFIG_CUSTOM_KERNEL_IMGSENSOR="ov16880_mipi_raw ov8865_mipi_raw"',
             'CONFIG_MTK_CAM_CAL=y', 'CONFIG_MTK_LENS=y', '# CONFIG_MTK_LENS_USE_MODULE is not set']
# Probe, open and sensor entry points that must be in the image.
C1_SYMBOLS = ['imgsensor_probe', 'imgsensor_compat_ioctl', 'seninf_probe', 'seninf_ioctl_compat',
              'seninf_clk_init', 'EEPROM_HW_probe', 'EEPROM_HW_i2c_probe', 'EEPROM_HW_i2c_probe2',
              'EEPROM_HW_i2c_probe3', 'EEPROM_drv_compat_ioctl', 'AF_i2c_probe', 'AF_Ioctl_Compat',
              'AK7371AF_Ioctl_Main', 'OV16880MIPISensorInit', 'OV8865_MIPI_RAW_SensorInit']
# Board DT (both boards): okay as stock. The CCU sensor children stay disabled.
C1_BOARDS = [BULK / 'artifacts/firstboot-5.10/board/keyboard.dtb',
             BULK / 'artifacts/firstboot-5.10/board/keyboard-modem-on.dtb']
C1_DT_OKAY = ['/kd_camera_hw1@1a040000', '/seninf_top@1a040000', '/i2c@11009000', '/i2c@11009000/camera_main@1a',
              '/i2c@11009000/camera_main_af@72', '/i2c@11009000/camera_main_eeprom@50', '/i2c@11008000/camera_sub@35',
              '/i2c@11008000/camera_sub_eeprom@54', '/i2c@11008000/camera_main_two_eeprom@51']

# C2 flashlight: the core's header (FLASH_IOC_*) is T's, stock's file names, the stubs and the DT nodes.
C2_HEADER = MM + 'flashlight/flashlight.h'
C2_SAME_AS_T = [MM + 'flashlight/' + f for f in ('flashlight.h', 'flashlight-core.h', 'flashlight-core.c', 'flashlight-device.c',
                                                  'flashlight-dt.h')]
C2_NODES = {
    MM + 'flashlight/flashlight-core.c': ['.compat_ioctl = flashlight_compat_ioctl', 'FLASHLIGHT_DEVNAME'],
    MM + 'flashlight/flashlights-mt6370.c': ['pocket_torch_camera_claim();', 'pocket_torch_camera_off(',
                                             '#define RT_FLED_DEVICE_CH1  "mt-flash-led1"'],
    MM + 'flashlight/flashlight.h': ['#define FLASHLIGHT_DEVNAME          "flashlight"'],
    MM + 'flashlight/richtek/pocket_torch.c': ['pocket_torch_camera_claim', 'pocket_torch_camera = true',
                                               'value ? -EBUSY : 0', 'led_set_brightness(&pocket_torch_led, LED_OFF)'],
}
C2_CONFIG = ['CONFIG_MTK_FLASHLIGHT=y', 'CONFIG_MTK_FLASHLIGHT_MT6370=y', 'CONFIG_MTK_FLASHLIGHT_PT=y',
             'CONFIG_MTK_FLASHLIGHT_PT_STRICT=y', 'CONFIG_MTK_FLASHLIGHT_DLPT=y', 'CONFIG_RT_FLASHLIGHT=y',
             'CONFIG_POCKET_TORCH=y']
C2_SYMBOLS = ['flashlight_probe', 'flashlight_compat_ioctl', 'mt6370_probe', 'pocket_torch_camera_claim',
              'pocket_torch_camera_release', 'pocket_torch_camera_off', 'pocket_torch_update']
C2_DT_OKAY = ['/flashlight_core', '/flashlights_mt6370']
C2_DT_OFF = ['/i2c@11000000/flashlights_lm3643_i2c@63', '/i2c@1100f000/flashlights_lm3643_i2c@63']

# C3 ISP raw (P1), DIP (P2) and WPE. Header -> (native, compat) ioctl counts; U's numbers must equal T's.
C3_ISP = MM + 'cameraisp/src/isp_50/'
C3_DIP = MM + 'cameraisp/dip/isp_50/'
C3_WPE = MM + 'cameraisp/wpe/isp_50/'
C3_HEADERS = {C3_ISP + 'inc/camera_isp.h': (35, 13), C3_DIP + 'camera_dip.h': (13, 7), C3_WPE + 'inc/camera_wpe.h': (16, 8)}
C3_SAME_AS_T = list(C3_HEADERS) + [C3_ISP + 'inc/cam_regs.h', MM + 'timer/timesync/archcounter_timesync.h']
# Driver -> its mmap handler, whose body (the base and range switch) must be T's, and the header with the bases.
C3_MMAP = {C3_ISP + 'camera_isp.c': ('ISP_mmap', C3_ISP + 'inc/camera_isp.h'),
           C3_WPE + 'camera_wpe.c': ('WPE_mmap', C3_WPE + 'inc/camera_wpe.h')}
C3_NODES = {
    C3_ISP + 'camera_isp.c': ['#define ISP_DEV_NAME                "camera-isp"', '.compat_ioctl = ISP_ioctl_compat',
                              '.mmap = ISP_mmap', 'archcounter_timesync_to_monotonic('],
    C3_DIP + 'camera_dip.c': ['#define DIP_DEV_NAME        "camera-dip"', '.compat_ioctl = DIP_ioctl_compat',
                              '/*  .mmap = DIP_mmap, */'],
    C3_WPE + 'camera_wpe.c': ['#define WPE_DEV_NAME                "camera-wpe"', '.compat_ioctl = WPE_ioctl_compat',
                              '.mmap = WPE_mmap'],
}
C3_CONFIG = ['CONFIG_MTK_ARCHCOUNTER_TIMESYNC=y', 'CONFIG_MTK_CAMERA_ISP=y', 'CONFIG_MTK_CAMERA_ISP_WPE_SUPPORT=y']
# Stock has these on; our build keeps secure camera buffers off, so they must not be set.
C3_CONFIG_OFF = ['CONFIG_MTK_CAM_SECURITY_SUPPORT', 'CONFIG_MTK_CAM_GENIEZONE_SUPPORT']
C3_SYMBOLS = ['ISP_probe', 'ISP_ioctl_compat', 'ISP_mmap', 'DIP_probe', 'DIP_ioctl_compat', 'WPE_probe',
              'WPE_ioctl_compat', 'WPE_mmap', 'archcounter_timesync_to_monotonic', 'archcounter_timesync_init']
# Nodes the drivers bind, okay on both boards with stock's live IRQs (SPI, level low); camsys and imgsys give the clocks.
C3_DT_IRQ = {'/cam1@1a003000': 0xfd, '/cam2@1a004000': 0xfe, '/cam3@1a006000': 0xff, '/cam4@1a008000': 0x100,
             '/camsv1@1a050000': 0x102, '/camsv2@1a051000': 0x103, '/camsv3@1a052000': 0x104, '/camsv4@1a053000': 0x105,
             '/camsv5@1a054000': None, '/camsv6@1a055000': None, '/dip1@15022000': 0x10c, '/wpe_a@1502a000': 0x111,
             '/wpe_b@1502d000': 0x112}
C3_DT_OKAY = ['/camsys@1a000000', '/imgsys@15020000', '/smi_larb2@1502f000', '/smi_larb3@1a002000',
              '/smi_larb5@15021000', '/smi_larb6@1a001000']
C3_DT_OFF = ['/dip2@15023000', '/dip3@15024000', '/dip4@15025000', '/dip5@15026000', '/dip6@15027000']

# C4 FDVT 4.0 and RSC (isp_50) with engine_request. Header -> (native, compat) ioctl counts; U's numbers must equal T's.
C4_FDVT = MM + 'cameraisp/fdvt/4.0/'
C4_RSC = MM + 'cameraisp/rsc/'
C4_HEADERS = {C4_FDVT + 'inc/camera_fdvt.h': (7, 7), C4_RSC + 'isp_50/camera_rsc.h': (13, 4)}
C4_SAME_AS_T = list(C4_HEADERS) + [C4_RSC + 'engine_request.h', C4_RSC + 'engine_request.c']
C4_NODES = {
    C4_FDVT + 'camera_fdvt.c': ['#define FDVT_DEVNAME     "camera-fdvt"', '.compat_ioctl        = compat_FD_ioctl',
                                '"mediatek,fdvt"'],
    C4_RSC + 'isp_50/camera_rsc.c': ['#define RSC_DEV_NAME "camera-rsc"', '.compat_ioctl = RSC_ioctl_compat',
                                     '"mediatek,imgsyscq"', '"mediatek,rsc"', '/* .mmap = RSC_mmap, */'],
}
C4_CONFIG = ['CONFIG_MTK_CAMERA_ISP_RSC_SUPPORT=y', 'CONFIG_MTK_CAMERA_ISP_FD_SUPPORT=y']
# Stock leaves these off or unbuilt for the engines the HAL never opens (hal-contract.md: OWE, MFB, DPE absent).
C4_CONFIG_OFF = ['CONFIG_MTK_CAMERA_ISP_OWE_SUPPORT', 'CONFIG_MTK_CAMERA_ISP_MFB_SUPPORT', 'CONFIG_MTK_CAMERA_ISP_DPE_SUPPORT',
                 'CONFIG_MTK_CAMERA_ISP_TSF_SUPPORT']
C4_SYMBOLS = ['FDVT_probe', 'compat_FD_ioctl', 'RSC_probe', 'RSC_ioctl_compat', 'init_ring_ctl', 'enque_request']
# camera_rsc counts its devices by probe order and registers /dev/camera-rsc on the second: imgsyscq (reg only) then rsc.
C4_DT_IRQ = {'/imgsyscq@15020000': None, '/rsc@15029000': 0x10f, '/fdvt@1502b000': 0x10d}
C4_DT_OFF = ['/owe@1502c000', '/mfb@1502e000', '/dpe@15028000', '/fdvt_dma@1502b000']

# C5 CCU 2.0 with the mt6771 platform code. ccu_drv.h's numbers are int-sized, so compat uses the native ones.
C5_SRC = MM + 'ccu/src/'
C5_HEADER = C5_SRC + '2.0/ccu_drv.h'
C5_NATIVE = 21
# U file -> (T text, U text) pairs: the only differences from T. Every other file under ccu/src is T's bytes.
C5_CHANGED = {
    C5_SRC + '2.0/ccu_drv.c': [('struct wakeup_source ccu_wake_lock;', 'struct wakeup_source *ccu_wake_lock;'),
                               ('wakeup_source_init(&ccu_wake_lock, "ccu_lock_wakelock");',
                                'ccu_wake_lock = wakeup_source_register(NULL, "ccu_lock_wakelock");')],
    C5_SRC + 'mt6771/ccu_mva.c': [('\tstruct sg_table *sg_table;\n', '\tstruct sg_table *sg_table = NULL;\n')],
}
# Rewritten for 5.10, checked by content: the Kconfig help keyword, the platform-free Makefile and ccu_i2c.c's
# struct mt_i2c accesses, now i2c-mt65xx's CCU calls.
C5_NODES = {
    C5_SRC + 'Kconfig': ['config MTK_CCU', '\thelp\n'],
    C5_SRC + 'Makefile': ['subdir-ccflags-y += -DMTK_VPU_KERNEL', 'subdir-ccflags-y += -DCCU_AF_ENABLE',
                          'obj-y += mt6771/', 'obj-y += 2.0/'],
    C5_SRC + '2.0/ccu_drv.c': ['#define CCU_DEV_NAME            "ccu"', '.mmap = ccu_mmap', '.compat_ioctl = ccu_compat_ioctl',
                               '{.compatible = "mediatek,ccu",}'],
    C5_SRC + '2.0/ccu_i2c.c': ['#define I2C_BASE_OFS_CH1 (0x200)', 'i2c_ccu_enable(pClient->adapter,', 'i2c_ccu_disable(',
                               'mtk_i2c_ccu_dma_buf(pClient->adapter, va, &pa)', '*i2c_id = mtk_i2c_hw_id(pClient->adapter);',
                               'i2c_writew(2, pClient->adapter, 0x240);', 'mtk_i2c_ccu_writew(adap, value, offset);',
                               '"mediatek,ccu_sensor_i2c_2_hw"', '"mediatek,ccu_sensor_i2c_4_hw"'],
    'drivers/i2c/busses/i2c-mt65xx.c': ['EXPORT_SYMBOL(mtk_i2c_hw_id)', 'EXPORT_SYMBOL(mtk_i2c_ccu_dma_buf)',
                                        'EXPORT_SYMBOL(mtk_i2c_ccu_enable)', 'EXPORT_SYMBOL(mtk_i2c_ccu_disable)',
                                        'EXPORT_SYMBOL(mtk_i2c_ccu_writew)', 'mtk_i2c_setup_chan_at(i2c, i2c->chan, control);',
                                        'i2c_lock_bus(adap, I2C_LOCK_ROOT_ADAPTER);', 'ch_offset == i2c->ch_offset',
                                        'of_property_read_u32(pdev->dev.of_node, "id", &hw_id)',
                                        'dmam_alloc_coherent(&pdev->dev, PAGE_SIZE,'],
    'drivers/i2c/busses/i2c-mt65xx-ccu.h': ['int mtk_i2c_hw_id(struct i2c_adapter *adap);', 'int mtk_i2c_ccu_enable(',
                                           'int mtk_i2c_ccu_disable(', 'int mtk_i2c_ccu_writew(', 'int mtk_i2c_ccu_dma_buf('],
    'drivers/i2c/busses/i2c-mtk.h': ['#include "i2c-mt65xx-ccu.h"', '#define I2C_MAX_CHANNEL\t\t10'],
    MM + 'i2c_shim/mtk_i2c_shim.c': ['mtk_i2c_ccu_enable(adap, ch_offset)', 'mtk_i2c_ccu_disable(adap)'],
    MM + 'i2c_shim/Kconfig': ['depends on I2C_MT65XX=y'],
    MM + 'imgsensor/src/common/v1_1/imgsensor.c': ['mtk_i2c_hw_id(pi2c_client->adapter)'],
    MM + 'Kconfig': ['source "drivers/misc/mediatek/ccu/src/Kconfig"'],
    MM + 'Makefile': ['obj-$(CONFIG_MTK_CCU) += ccu/src/'],
}
C5_CONFIG = ['CONFIG_MTK_CCU=y', 'CONFIG_I2C_MT65XX=y', 'CONFIG_MTK_I2C_SHIM=y']
C5_SYMBOLS = ['ccu_probe', 'ccu_ioctl', 'ccu_compat_ioctl', 'ccu_mmap', 'ccu_init_hw', 'ccu_i2c_register_driver',
              'mtk_i2c_hw_id', 'mtk_i2c_ccu_dma_buf', 'mtk_i2c_ccu_enable', 'mtk_i2c_ccu_disable', 'mtk_i2c_ccu_writew']
# The CCU binary blobs the HAL maps into /dev/ccu (lib3a.ccudrv, observed strings), on the stock vendor partition.
C5_FIRMWARE = ['lib3a.ccu.pm', 'lib3a.ccu.dm', 'lib3a.ccu.ddr']
C5_DT_OKAY = {'/ccu@1a0a0000': 0x108, '/i2c@11009000/ccu_sensor_i2c_2_hw@33': None,
              '/i2c@11008000/ccu_sensor_i2c_4_hw@36': None}
C5_DT_OFF = ['/i2c@1101a000/ccu_sensor_i2c_7_hw@43']
# The AP channel of the two CCU buses; the CCU takes 0x200 (ccu_i2c.c I2C_BASE_OFS_CH1).
C5_BUSES = ['/i2c@11009000', '/i2c@11008000']

# C6 JPEG v2, built for mt6771 as T does: encoder only (JPEG_ENC_DRIVER), /proc/mtk_jpeg (JPEG_DEV is not defined).
C6_SRC = MM + 'jpeg/'
C6_HEADER = C6_SRC + 'v2/jpeg_drv.h'
C6_NATIVE = 24
C6_COMPAT = 6
C6_HAL_LIBS = ['lib64/libJpgEncPipe.so', 'lib/libJpgEncPipe.so']
C6_FOPS_T = (
    'static struct file_operations const jpeg_fops = {\n\t.owner = THIS_MODULE,\n\t/* .ioctl          = jpeg_ioctl, */\n'
    '\t.unlocked_ioctl = jpeg_unlocked_ioctl,\n#ifdef CONFIG_COMPAT\n\t.compat_ioctl = compat_jpeg_ioctl,\n#endif\n'
    '\t.open = jpeg_open,\n\t.release = jpeg_release,\n\t.flush = jpeg_flush,\n\t.read = jpeg_read,\n'
    '#ifdef JPEG_HYBRID_DEC_DRIVER\n\t.mmap = jpeg_mmap,\n#endif\n};\n')
C6_FOPS_U = (
    'static struct proc_ops const jpeg_fops = {\n\t.proc_ioctl = jpeg_unlocked_ioctl,\n#ifdef CONFIG_COMPAT\n'
    '\t.proc_compat_ioctl = compat_jpeg_ioctl,\n#endif\n\t.proc_open = jpeg_open,\n\t.proc_release = jpeg_release,\n'
    '\t.proc_read = jpeg_read,\n#ifdef JPEG_HYBRID_DEC_DRIVER\n\t.proc_mmap = jpeg_mmap,\n#endif\n};\n')
# U file -> (T text, U text) pairs: the only differences from T. Every other file under jpeg/ is T's bytes (jpeg_cmdq.* is
# not built by T and not ported).
C6_CHANGED = {
    C6_SRC + 'v2/jpeg_drv.c': [
        ('/* Kernel interface */\n' + C6_FOPS_T,
         '/* Kernel interface: /proc/mtk_jpeg (proc_ops has no flush, jpeg_release calls jpeg_flush) */\n' + C6_FOPS_U),
        ('static int jpeg_release(struct inode *inode, struct file *file)\n{\n',
         'static int jpeg_flush(struct file *a_pstFile, fl_owner_t a_id);\n\nstatic int jpeg_release(struct inode *inode, struct file *file)\n{\n'
         '\t/* proc_ops has no flush, so the per-file cleanup runs here */\n\tjpeg_flush(file, NULL);\n\n')],
}
C6_NODES = {
    C6_SRC + 'v2/jpeg_drv.c': ['#define JPEG_DEVNAME "mtk_jpeg"', 'proc_create("mtk_jpeg", 0x644, NULL, &jpeg_fops);',
                               '{.compatible = "mediatek,venc_jpg",}', '.proc_compat_ioctl = compat_jpeg_ioctl',
                               'smi_bus_prepare_enable(SMI_LARB4, "JPEG");', 'smi_bus_disable_unprepare(SMI_LARB4, "JPEG");',
                               'of_clk_get_by_name(node, "MT_CG_VENC_JPGENC")', 'request_irq(gJpegqDev.encIrqId,'],
    C6_SRC + 'v2/Makefile': ['ccflags-y += -DPLATFORM_MT6771', 'ccflags-y += -DJPEG_ENC_DRIVER'],
    MM + 'Kconfig': ['source "drivers/misc/mediatek/jpeg/Kconfig"'],
    MM + 'Makefile': ['obj-$(CONFIG_MTK_JPEG) += jpeg/'],
}
C6_CONFIG = ['CONFIG_MTK_JPEG=y', 'CONFIG_MACH_MT6771=y', 'CONFIG_MTK_SMI_EXT=y', 'CONFIG_COMPAT=y']
C6_SYMBOLS = ['jpeg_probe', 'jpeg_unlocked_ioctl', 'compat_jpeg_ioctl', 'jpeg_drv_enc_power_on', 'jpeg_drv_enc_power_off',
              'jpeg_drv_enc_start', 'jpeg_drv_enc_reset', 'jpeg_open', 'jpeg_release']
C6_DT_OKAY = {'/venc_jpg@17030000': 0xf9}

checks = []


def check(name, ok, detail=''):
    checks.append({'check': name, 'ok': bool(ok), 'detail': detail})
    print(('OK   ' if ok else 'FAIL ') + name + (f': {detail}' if detail else ''))


def decode(v):
    d = {0: '_IO', 1: '_IOW', 2: '_IOR', 3: '_IOWR'}[(v >> 30) & 3]
    t = (v >> 8) & 0xff
    return f"{d}('{chr(t) if 32 < t < 127 else hex(t)}',{v & 0xff},{(v >> 16) & 0x3fff})"


def imm(s):
    return int(s.strip().lstrip('#'), 0)


def scan(lib, wrappers=()):
    """[(addr, function, import, w1 or None, first u32 at x2 or None)] for ioctl and ion_custom_ioctl calls, and for
    calls to the lib's own wrappers that take the request in w1 (counted as ioctl)."""
    asm = subprocess.run([str(LLVM / 'llvm-objdump'), '-d', '--no-show-raw-insn', str(lib)],
                         capture_output=True, text=True, check=True).stdout
    funcs, cur = [], None
    for line in asm.splitlines():
        m = re.match(r'^([0-9a-f]+) <(.*)>:', line)
        if m:
            cur = (m.group(2), []); funcs.append(cur); continue
        m = re.match(r'\s+([0-9a-f]+):\s+(\S+)\s*(.*)', line)
        if m and cur:
            cur[1].append((int(m.group(1), 16), m.group(2), m.group(3).split('//')[0].strip()))
    out = []
    for name, body in funcs:
        regs, slots, x2 = {}, {}, None
        for addr, op, args in body:
            ops = [x.strip() for x in re.split(r',(?![^\[]*\])', args)] if args else []
            dst = ops[0][1:] if ops and re.match(r'[wx]\d+$', ops[0]) else None
            if op == 'bl' and re.search(r'<(ioctl|ion_custom_ioctl)@plt>', args):
                imp = re.search(r'<(\w+)@plt>', args).group(1)
                out.append((addr, name, imp, regs.get('1'), slots.get(x2) if x2 else None))
            elif op == 'bl' and any(w in args for w in wrappers):
                out.append((addr, name, 'ioctl', regs.get('1'), None))
            if op in ('mov', 'movz') and dst and len(ops) == 2:
                if re.match(r'#-?(0x)?[0-9a-f]+$', ops[1]):
                    regs[dst] = imm(ops[1]) & (0xffffffff if ops[0][0] == 'w' else (1 << 64) - 1)
                elif ops[1] in ('wzr', 'xzr'):
                    regs[dst] = 0
                elif re.match(r'[wx]\d+$', ops[1]) and ops[1][1:] in regs:
                    regs[dst] = regs[ops[1][1:]]
                else:
                    regs.pop(dst, None)
            elif op == 'movk' and dst and dst in regs:
                m = re.match(r'#(0x[0-9a-f]+|\d+)(?:, lsl #(\d+))?', ', '.join(ops[1:]))
                sh = int(m.group(2) or 0)
                regs[dst] = (regs[dst] & ~(0xffff << sh)) | (int(m.group(1), 0) << sh)
            elif op in ('add', 'sub') and dst and len(ops) == 3 and ops[1][1:] in regs and \
                    re.match(r'[wx]\d+$', ops[1]) and re.match(r'#(0x[0-9a-f]+|\d+)$', ops[2]):
                mask = 0xffffffff if ops[0][0] == 'w' else (1 << 64) - 1
                regs[dst] = (regs[ops[1][1:]] + (imm(ops[2]) if op == 'add' else -imm(ops[2]))) & mask
            elif op in ('str', 'stur', 'stp') and ops:
                m = re.match(r'\[(sp|x29)(?:, #(-?(?:0x)?[0-9a-f]+))?\]!?$', ops[-1])
                if m:
                    base, off = m.group(1), int(m.group(2) or '0', 0)
                    width = 4 if ops[0][0] == 'w' else 8
                    for n, s in enumerate(ops[:-1]):
                        slots[(base, off + n * width)] = 0 if s in ('wzr', 'xzr') else regs.get(s[1:])
            elif op == 'bl' or op == 'blr':
                for r in range(19):
                    regs.pop(str(r), None)
            elif dst and op not in ('cmp', 'cmn', 'tst', 'cbz', 'cbnz', 'tbz', 'tbnz', 'str', 'stur', 'stp', 'strb',
                                    'strh', 'sturb', 'sturh', 'ccmp'):
                regs.pop(dst, None)
                if op == 'ldp' and len(ops) > 1 and re.match(r'[wx]\d+$', ops[1]):
                    regs.pop(ops[1][1:], None)
            if dst == '2' and op == 'add' and len(ops) == 3 and ops[1] in ('sp', 'x29'):
                x2 = (ops[1], imm(ops[2]))
            elif dst == '2' and op == 'sub' and len(ops) == 3 and ops[1] == 'x29':
                x2 = ('x29', -imm(ops[2]))
            elif dst == '2' and op == 'mov' and ops[1] == 'sp':
                x2 = ('sp', 0)
            elif dst == '2' and op not in ('str', 'stur', 'stp'):
                x2 = None
    return out


def header_table(header, spec, base=T, compat=False):
    """{name: value} for every _IO* macro the header under base (T by default) defines, native aarch64.
    With compat, CONFIG_COMPAT is on and only the COMPAT_ numbers come out, sized by the 32-bit structs."""
    incs, pre = spec
    text = (base / header).read_text(errors='replace')
    names = sorted(set(re.findall(r'#define\s+(\w+)\s*\\?\s*\n?\s*_IO(?:W|R|WR)?\s*\(', text)))
    names = [n for n in names if n.startswith('COMPAT_') == compat]
    with tempfile.TemporaryDirectory() as d:
        shim = Path(d) / 'shim'
        for s in STANDINS:
            (shim / s).parent.mkdir(parents=True, exist_ok=True)
            (shim / s).write_text('')
        (shim / 'linux/types.h').write_text('#pragma once\n#include "../ktypes.h"\n')
        (shim / 'ktypes.h').write_text('#pragma once\n' + TYPES)
        (shim / 'linux/ioctl.h').write_text('#pragma once\n#include <asm-generic/ioctl.h>\n')
        (shim / 'asm-generic').mkdir()
        (shim / 'asm-generic/ioctl.h').write_text((T / 'include/uapi/asm-generic/ioctl.h').read_text())
        c = Path(d) / 'probe.c'
        c.write_text(('#define CONFIG_COMPAT 1\n' if compat else '') +
                     '#include "ktypes.h"\n#include <linux/ioctl.h>\n' + ''.join(f'#include "{x}"\n' for x in pre) +
                     '#include "' + str(base / header) + '"\nconst unsigned int probe_values[] = {\n' +
                     ''.join(f'#ifdef {n}\n  (unsigned int)({n}),\n#else\n  0xffffffffu,\n#endif\n' for n in names) +
                     '};\n')
        s = Path(d) / 'probe.s'
        cmd = [str(LLVM / 'clang'), '--target=aarch64-linux-android30', '-ffreestanding', '-nostdinc', '-w',
               '-isystem', str(next((LLVM.parent / 'lib/clang').glob('*/include'))), '-I', str(shim),
               '-I', str((base / header).parent)] + [a for i in incs for a in ('-I', str(base / i))] + \
              ['-S', '-O0', '-o', str(s), str(c)]
        r = subprocess.run(cmd, capture_output=True, text=True)
        if r.returncode:
            raise RuntimeError(header + ': ' + ' | '.join(l for l in r.stderr.splitlines() if 'error' in l)[:600])
        asm = s.read_text()
    body = asm[asm.index('probe_values:'):]
    words = [int(m.group(2), 0) & 0xffffffff for m in re.finditer(r'\.(long|word)\s+(-?\w+)', body)][:len(names)]
    return {n: v for n, v in zip(names, words) if v != 0xffffffff}


def main():
    # 1. HAL scan
    calls = {}
    for lib in LIBS:
        calls[lib] = scan(VENDOR / 'lib64' / lib, WRAPPERS.get(lib, ()))
    total = sum(len(v) for v in calls.values())
    check('HAL scan found calls in every lib', all(calls.values()), f'{total} calls in {len(LIBS)} libs')

    # 2. T header tables
    tables = {}
    for h, incs in HEADERS.items():
        try:
            tables[h] = header_table(h, incs)
        except RuntimeError as e:
            check('T header compiles: ' + h, False, str(e)[:300])
    by_value = {}
    for h, tab in tables.items():
        for n, v in tab.items():
            by_value.setdefault(v, []).append((n, h))
    check('T header tables built', len(tables) == len(HEADERS),
          ', '.join(f'{Path(h).name} {len(t)}' for h, t in tables.items()))

    # 3. Contract file
    text = CONTRACT.read_text() if CONTRACT.exists() else ''
    check('hal-contract.md exists', bool(text))
    contract_numbers = {int(x, 16) for x in re.findall(r'\b0x([0-9a-f]{8})\b', text)}
    resolved, unresolved, ion = {}, [], set()
    for lib, cs in calls.items():
        for addr, func, imp, w1, sub in cs:
            if imp == 'ioctl':
                if w1 is None:
                    unresolved.append((lib, addr, func))
                else:
                    resolved.setdefault(w1, set()).add(lib)
            else:
                if w1 is None or sub is None:
                    unresolved.append((lib, addr, func))
                else:
                    ion.add((w1, sub))
    record = []
    for v, libs in sorted(resolved.items()):
        names = by_value.get(v, [])
        known = bool(names) or v in NOT_DRIVER or chr((v >> 8) & 0xff) == GZ_MAGIC
        check(f'0x{v:08x} {decode(v)} in contract', v in contract_numbers, ', '.join(sorted(libs)))
        check(f'0x{v:08x} matches a T header or a listed non-driver node', known,
              '; '.join(f'{n} ({Path(h).name})' for n, h in names) or NOT_DRIVER.get(v) or
              ('GenieZone /dev/gz_kree (off)' if known else 'no match'))
        record.append({'value': f'0x{v:08x}', 'decoded': decode(v), 'libs': sorted(libs),
                       'names': [f'{n} ({h})' for n, h in names], 'other': NOT_DRIVER.get(v)})
    for lib, addr, func in unresolved:
        check(f'unresolved call {lib} 0x{addr:x} in contract',
              re.search(re.escape(lib) + r'[^\n]*0x' + f'{addr:x}' + r'\b', text) is not None, func[:80])
    for cmd, sub in sorted(ion):
        sub_name = (ION_MM if cmd == 1 else ION_SYS).get(sub, f'unknown {sub}')
        check(f'ION {ION_CMD.get(cmd, cmd)} / {sub_name} in contract', sub_name in text)

    # 4. C0 scaffolding in U
    for path, needles in SCAFFOLD.items():
        p = U / path
        body = p.read_text() if p.exists() else ''
        missing = [n for n in needles if n not in body]
        check('U has ' + path, p.exists() and not missing, ('missing ' + ', '.join(missing)) if missing else '')
    smap = BUILD / 'System.map'
    config = BUILD / '.config'
    if smap.exists() and config.exists():
        sm = smap.read_text()
        have = [s for s in SHIM_SYMBOLS if re.search(r' [tT] ' + s + r'$', sm, re.M)]
        cfg = config.read_text()
        check('build has CONFIG_MTK_I2C_SHIM=y', 'CONFIG_MTK_I2C_SHIM=y' in cfg)
        check('System.map has the I2C shim', len(have) == len(SHIM_SYMBOLS),
              ', '.join(sorted(set(SHIM_SYMBOLS) - set(have))) or f'{len(have)} symbols')

    # 5. C1 sensor path in U
    c1_values = set()
    for h, (native, compat) in C1_HEADERS.items():
        spec = HEADERS[h]
        try:
            tn, tc = header_table(h, spec), header_table(h, spec, compat=True)
            un, uc = header_table(h, spec, U), header_table(h, spec, U, True)
        except RuntimeError as e:
            check('C1 header compiles: ' + h, False, str(e)[:300]); continue
        c1_values |= set(un.values())
        check(f'C1 {Path(h).name}: {native} ioctls, as T', len(un) == native and un == tn, f'U {len(un)}, T {len(tn)}')
        check(f'C1 {Path(h).name}: {compat} compat ioctls, as T', len(uc) == compat and uc == tc,
              ', '.join(f'{n} 0x{v:08x}' for n, v in sorted(uc.items())) or 'none')
    spec = ([MM + 'lens/sub/inc'], [])
    try:
        check('C1 sub lens_info.h numbers as T', header_table(C1_SUB_LENS, spec, U) == header_table(C1_SUB_LENS, spec))
    except RuntimeError as e:
        check('C1 sub lens_info.h compiles', False, str(e)[:300])
    check('C1 numbers total 29 + 8 + 16 + 5', sum(sum(c) for c in C1_HEADERS.values()) == 58)
    hal_c1 = sorted(v for v, _ in resolved.items() if any(Path(h).name in ('kd_imgsensor.h', 'kd_seninf.h',
                    'cam_cal.h', 'lens_info.h') for _, h in by_value.get(v, [])))
    check('C1 every HAL number for these nodes is in U', hal_c1 and all(v in c1_values for v in hal_c1),
          f'{len(hal_c1)} numbers')
    for path in C1_SAME_AS_T:
        same = (U / path).exists() and (U / path).read_bytes() == (T / path).read_bytes()
        check('C1 U ' + path + ' is T\'s', same)
    for path, needles in C1_NODES.items():
        body = (U / path).read_text() if (U / path).exists() else ''
        missing = [n for n in needles if n not in body]
        check('C1 U has ' + path, body and not missing, ('missing ' + ', '.join(missing)) if missing else '')
    if smap.exists() and config.exists():
        missing = [c for c in C1_CONFIG if c not in cfg.splitlines()]
        check('C1 build config', not missing, ', '.join(missing))
        missing = [s for s in C1_SYMBOLS if not re.search(r' [tT] ' + s + r'$', sm, re.M)]
        check('C1 System.map has the probe and ioctl entry points', not missing,
              ', '.join(missing) or f'{len(C1_SYMBOLS)} symbols')
    os.environ.setdefault('POCKET_DIAGNOSTIC_VARIANT', 'v4')
    tree = None
    for board in C1_BOARDS:
        if not board.exists():
            check('C1 board ' + board.name + ' exists', False); continue
        tree = tree or __import__('runpy').run_path(str(ROOT / 'tools/prepare-pocket-diagnostic-tree.py'),
                                                    run_name='camera_contract_helpers')
        nodes = tree['DECODE'](board.read_bytes())['nodes']
        off = [p for p in C1_DT_OKAY if p not in nodes or not tree['enabled'](nodes, p)]
        check('C1 board ' + board.name + ' has the camera nodes okay', not off, ', '.join(off))
        bus = nodes.get('/i2c@11009000', {})
        check('C1 board ' + board.name + ' i2c-2 is mt6771-i2c with ch-offset 0x100',
              tree['text'](bus.get('compatible', b'\0')) == ['mediatek,mt6771-i2c'] and
              'mediatek,ch-offset' in bus and tree['values'](bus['mediatek,ch-offset']) == [0x100])

    # 6. C2 flashlight core
    spec = HEADERS[C2_HEADER]
    try:
        tn, uc2 = header_table(C2_HEADER, spec), header_table(C2_HEADER, spec, U)
        names = {n: v for n, v in uc2.items() if n.startswith('FLASH_IOC_')}
        check('C2 flashlight.h: FLASH_IOC and FLASHLIGHTIOC numbers as T', uc2 == tn and len(uc2) == 41,
              f'U {len(uc2)}, T {len(tn)}')
        check('C2 FLASH_IOC numbers are _IOR/_IOWR(S, nr, int)', all(chr((v >> 8) & 0xff) == 'S' and (v >> 16) & 0x3fff == 4
                                                                  for v in uc2.values()))
        hal_fl = sorted(v for v in resolved if any(Path(h).name == 'flashlight.h' for _, h in by_value.get(v, [])))
        check('C2 every HAL flashlight number is in U', hal_fl and all(v in uc2.values() for v in hal_fl),
              f'{len(hal_fl)} numbers, names ' + ', '.join(sorted(n for n, v in uc2.items() if v in hal_fl))[:200])
        check('C2 no compat-only flashlight numbers (ints only, same for 32 and 64-bit)',
              header_table(C2_HEADER, spec, U, True) == {})
    except RuntimeError as e:
        check('C2 flashlight.h compiles', False, str(e)[:300])
    for path in C2_SAME_AS_T:
        same = (U / path).exists() and (U / path).read_bytes() == (T / path).read_bytes()
        check('C2 U ' + path + ' is T\'s', same)
    for path, needles in C2_NODES.items():
        body = (U / path).read_text() if (U / path).exists() else ''
        missing = [n for n in needles if n not in body]
        check('C2 U has ' + path, body and not missing, ('missing ' + ', '.join(missing)) if missing else '')
    # No double registration of the FLED channels: the Richtek class registers mt-flash-led1 and 2 once (rtfled.c),
    # flashlights-mt6370 and pocket_torch only look them up; nothing else registers a flashlight device or a core client.
    reg = []
    for f in sorted((U / MM / 'flashlight').rglob('*.c')) + sorted((U / MM / 'pmic').rglob('*.c')):
        t = f.read_text(errors='replace')
        reg += [(f.name, m) for m in re.findall(r'\b(flashlight_device_register|flashlight_dev_register(?:_by_device_id)?)\s*\(', t)]
    dev_reg = [f for f, m in reg if m == 'flashlight_device_register' and f != 'rt-flashlight.c']
    check('C2 FLEDs registered once: only rtfled.c calls flashlight_device_register; mt6370 and pocket_torch look up',
          dev_reg == ['rtfled.c'] and 'flashlight_device_register' not in (U / MM / 'flashlight/richtek/pocket_torch.c').read_text()
          and 'flashlight_device_register' not in (U / MM / 'flashlight/flashlights-mt6370.c').read_text(), ', '.join(dev_reg))
    check('C2 one core client: flashlights-mt6370 is the only flashlight_dev_register caller',
          sorted({f for f, m in reg if m.startswith('flashlight_dev_register')} - {'flashlight-core.c'}) == ['flashlights-mt6370.c'])
    pt = (U / MM / 'flashlight/richtek/pocket_torch.c').read_text()
    check('C2 pocket_torch does not touch the FLED channels without its lock',
          pt.count('flashlight_set_mode(') == pt.count('flashlight_set_mode(') and
          all(re.search(r'mutex_lock\(&pocket_torch_lock\)', pt[:m.start()][-900:]) for m in re.finditer(r'flashlight_set_mode\(', pt)))
    if smap.exists() and config.exists():
        missing = [c for c in C2_CONFIG if c not in cfg.splitlines()]
        check('C2 build config', not missing, ', '.join(missing))
        missing = [s for s in C2_SYMBOLS if not re.search(r' [tT] ' + s + r'$', sm, re.M)]
        check('C2 System.map has the core, mt6370 and pocket_torch entry points', not missing,
              ', '.join(missing) or f'{len(C2_SYMBOLS)} symbols')
    for board in C1_BOARDS:
        if not board.exists():
            check('C2 board ' + board.name + ' exists', False); continue
        nodes = tree['DECODE'](board.read_bytes())['nodes']
        off = [p for p in C2_DT_OKAY if p not in nodes or not tree['enabled'](nodes, p)]
        check('C2 board ' + board.name + ' has /flashlight_core and /flashlights_mt6370 okay', not off, ', '.join(off))
        ch = [tuple(tree['values'](nodes[f'/flashlights_mt6370/channel@{n}'][k])[0] for k in ('type', 'ct', 'part')) for n in '12']
        check('C2 board ' + board.name + ' channels are stock (0,0,0) and (0,1,0), couple mode',
              ch == [(0, 0, 0), (0, 1, 0)] and tree['values'](nodes['/flashlights_mt6370']['decouple']) == [0])
        on = [p for p in nodes if p.endswith('flashlights_lm3643_i2c@63') and tree['enabled'](nodes, p)]
        check('C2 board ' + board.name + ' keeps the lm3643 node disabled', not on, ', '.join(on))

    # 7. C3 ISP, DIP and WPE
    c3_values = set()
    for h, (native, compat) in C3_HEADERS.items():
        spec = HEADERS[h]
        try:
            tn, tc = header_table(h, spec), header_table(h, spec, compat=True)
            un, uc = header_table(h, spec, U), header_table(h, spec, U, True)
        except RuntimeError as e:
            check('C3 header compiles: ' + h, False, str(e)[:300]); continue
        c3_values |= set(un.values()) | set(uc.values())
        check(f'C3 {Path(h).name}: {native} ioctls, as T', len(un) == native and un == tn, f'U {len(un)}, T {len(tn)}')
        check(f'C3 {Path(h).name}: {compat} compat ioctls, as T', len(uc) == compat and uc == tc, f'U {len(uc)}, T {len(tc)}')
    check('C3 ISP 48, DIP 20 and WPE 24 numbers', [sum(c) for c in C3_HEADERS.values()] == [48, 20, 24])
    hal_c3 = sorted(v for v in resolved if any(Path(h).name in ('camera_isp.h', 'camera_dip.h', 'camera_wpe.h')
                                               for _, h in by_value.get(v, [])))
    check('C3 every HAL number for camera-isp, camera-dip and camera-wpe is in U', hal_c3 and all(v in c3_values for v in hal_c3),
          f'{len(hal_c3)} numbers')
    for path in C3_SAME_AS_T:
        same = (U / path).exists() and (U / path).read_bytes() == (T / path).read_bytes()
        check('C3 U ' + path + ' is T\'s', same)
    for path, (func, header) in C3_MMAP.items():
        def body(base):
            t = (base / path).read_text(errors='replace')
            m = re.search(r'\n(static [^\n]*?' + func + r'\((?:.|\n)*?\n}\n)', t)
            return m.group(1) if m else None
        def ranges(base):
            t = (base / path).read_text(errors='replace') + (base / header).read_text(errors='replace')
            return sorted(set(re.findall(r'#define\s+\w*(?:BASE_HW|REG_RANGE|_RANGE)\w*\s+[^\n]*', t)))
        ub, tb = body(U), body(T)
        check(f'C3 {func} is T\'s (same bases and lengths)', ub is not None and ub == tb, f'{len(ub or "")} bytes')
        check(f'C3 {Path(path).name} and {Path(header).name} base and range defines are T\'s', ranges(U) == ranges(T) and ranges(U),
              f'{len(ranges(U))} defines')
    for path, needles in C3_NODES.items():
        body = (U / path).read_text() if (U / path).exists() else ''
        missing = [n for n in needles if n not in body]
        check('C3 U has ' + path, body and not missing, ('missing ' + ', '.join(missing)) if missing else '')
    isp = (U / C3_ISP / 'camera_isp.c').read_text()
    check('C3 SOF timestamps stay ktime_get (TS_BOOT_T not defined)', not re.search(r'^\s*#define\s+TS_BOOT_T', isp, re.M))
    if smap.exists() and config.exists():
        missing = [c for c in C3_CONFIG if c not in cfg.splitlines()]
        missing += [c + '=y' for c in C3_CONFIG_OFF if c + '=y' in cfg.splitlines()]
        check('C3 build config (secure camera off)', not missing, ', '.join(missing))
        missing = [s for s in C3_SYMBOLS if not re.search(r' [tT] ' + s + r'$', sm, re.M)]
        check('C3 System.map has the probe, ioctl, mmap and timesync entry points', not missing,
              ', '.join(missing) or f'{len(C3_SYMBOLS)} symbols')
    for board in C1_BOARDS:
        if not board.exists():
            check('C3 board ' + board.name + ' exists', False); continue
        nodes = tree['DECODE'](board.read_bytes())['nodes']
        off = [p for p in list(C3_DT_IRQ) + C3_DT_OKAY if p not in nodes or not tree['enabled'](nodes, p)]
        check('C3 board ' + board.name + ' has the ISP, DIP, WPE, camsys, imgsys and larb nodes okay', not off, ', '.join(off))
        bad = [p for p, irq in C3_DT_IRQ.items() if p in nodes and
               (tree['values'](nodes[p]['interrupts']) != [0, irq, 8] if irq is not None else 'interrupts' in nodes[p])]
        check('C3 board ' + board.name + ' ISP, DIP and WPE IRQs are stock', not bad, ', '.join(bad))
        on = [p for p in C3_DT_OFF if p in nodes and tree['enabled'](nodes, p)]
        check('C3 board ' + board.name + ' keeps dip2..6 disabled', not on, ', '.join(on))

    # 8. C4 FDVT and RSC
    c4_values = set()
    for h, (native, compat) in C4_HEADERS.items():
        spec = HEADERS[h]
        try:
            tn, tc = header_table(h, spec), header_table(h, spec, compat=True)
            un, uc = header_table(h, spec, U), header_table(h, spec, U, True)
        except RuntimeError as e:
            check('C4 header compiles: ' + h, False, str(e)[:300]); continue
        c4_values |= set(un.values()) | set(uc.values())
        check(f'C4 {Path(h).name}: {native} ioctls, as T', len(un) == native and un == tn, f'U {len(un)}, T {len(tn)}')
        check(f'C4 {Path(h).name}: {compat} compat ioctls, as T', len(uc) == compat and uc == tc, f'U {len(uc)}, T {len(tc)}')
    hal_c4 = sorted(v for v in resolved if any(Path(h).name in ('camera_fdvt.h', 'camera_rsc.h') for _, h in by_value.get(v, [])))
    check('C4 every HAL number for camera-fdvt and camera-rsc is in U (SETMETA is the secure-only one)',
          hal_c4 and all(v in c4_values or v in NOT_DRIVER for v in hal_c4), f'{len(hal_c4)} numbers')
    for path in C4_SAME_AS_T:
        same = (U / path).exists() and (U / path).read_bytes() == (T / path).read_bytes()
        check('C4 U ' + path + ' is T\'s', same)
    for path, needles in C4_NODES.items():
        body = (U / path).read_text() if (U / path).exists() else ''
        missing = [n for n in needles if n not in body]
        check('C4 U has ' + path, body and not missing, ('missing ' + ', '.join(missing)) if missing else '')
    fm = (U / C4_FDVT / '../Makefile').resolve().read_text()
    check('C4 FDVT built with larb 5 and no secure FD (no GenieZone)', 'MTK_FD_LARB=5' in fm and 'MTK_SECURE_FD_SUPPORT=0' in fm)
    check('C4 no OWE, MFB or DPE driver in U (the HAL does not open them)',
          not any((U / MM / 'cameraisp' / d).exists() for d in ('owe', 'mfb', 'dpe', 'tsf')))
    if smap.exists() and config.exists():
        missing = [c for c in C4_CONFIG if c not in cfg.splitlines()]
        missing += [c + '=y' for c in C4_CONFIG_OFF if c + '=y' in cfg.splitlines()]
        check('C4 build config (OWE, MFB, DPE, TSF off)', not missing, ', '.join(missing))
        missing = [s for s in C4_SYMBOLS if not re.search(r' [tT] ' + s + r'$', sm, re.M)]
        check('C4 System.map has the FDVT, RSC and engine_request entry points', not missing,
              ', '.join(missing) or f'{len(C4_SYMBOLS)} symbols')
    for board in C1_BOARDS:
        if not board.exists():
            check('C4 board ' + board.name + ' exists', False); continue
        nodes = tree['DECODE'](board.read_bytes())['nodes']
        off = [p for p in C4_DT_IRQ if p not in nodes or not tree['enabled'](nodes, p)]
        check('C4 board ' + board.name + ' has imgsyscq, rsc and fdvt okay', not off, ', '.join(off))
        bad = [p for p, irq in C4_DT_IRQ.items() if p in nodes and
               (tree['values'](nodes[p]['interrupts']) != [0, irq, 8] if irq is not None else 'interrupts' in nodes[p])]
        check('C4 board ' + board.name + ' RSC and FDVT IRQs are stock', not bad, ', '.join(bad))
        order = list(nodes)
        check('C4 board ' + board.name + ' imgsyscq comes before rsc in DT order (probe order)',
              order.index('/imgsyscq@15020000') < order.index('/rsc@15029000'))
        on = [p for p in C4_DT_OFF if p in nodes and tree['enabled'](nodes, p)]
        check('C4 board ' + board.name + ' keeps owe, mfb, dpe and fdvt_dma disabled', not on, ', '.join(on))

    # 9. C5 CCU
    spec = HEADERS[C5_HEADER]
    try:
        tn, un = header_table(C5_HEADER, spec), header_table(C5_HEADER, spec, U)
        check(f'C5 ccu_drv.h: {C5_NATIVE} ioctls, as T', len(un) == C5_NATIVE and un == tn, f'U {len(un)}, T {len(tn)}')
        check('C5 ccu_drv.h: no compat-only numbers (int-sized, the compat handler takes the native ones)',
              header_table(C5_HEADER, spec, U, True) == {} == header_table(C5_HEADER, spec, compat=True))
        hal_c5 = sorted(v for v in resolved if any(Path(h).name == 'ccu_drv.h' for _, h in by_value.get(v, [])))
        check('C5 every HAL /dev/ccu number is in U', hal_c5 and all(v in un.values() for v in hal_c5), f'{len(hal_c5)} numbers')
    except RuntimeError as e:
        check('C5 ccu_drv.h compiles', False, str(e)[:300])
    rewritten = {C5_SRC + 'Kconfig', C5_SRC + 'Makefile', C5_SRC + '2.0/ccu_i2c.c'}
    files = sorted(str(f.relative_to(U)) for f in (U / C5_SRC).rglob('*') if f.is_file())
    tfiles = {str(f.relative_to(T)) for f in (T / C5_SRC).rglob('*') if f.is_file()}
    same = [f for f in files if f not in C5_CHANGED and f not in rewritten]
    bad = [f for f in same if f not in tfiles or (U / f).read_bytes() != (T / f).read_bytes()]
    check('C5 U ccu/src files are T\'s bytes', same and not bad, ', '.join(bad) or f'{len(same)} files')
    check('C5 U ccu/src has only 2.0 and mt6771 (no other CCU version or platform)',
          {f.split('/')[5] for f in files if f.count('/') > 5} == {'2.0', 'mt6771'})
    for path, pairs in C5_CHANGED.items():
        t = (T / path).read_text(errors='replace')
        for a, b in pairs:
            t = t.replace(a, b)
        check('C5 U ' + path + ' is T\'s with only the 5.10 changes', (U / path).read_text(errors='replace') == t,
              '; '.join(b for _, b in pairs)[:200])
    for path, needles in C5_NODES.items():
        body = (U / path).read_text() if (U / path).exists() else ''
        missing = [n for n in needles if n not in body]
        check('C5 U has ' + path, body and not missing, ('missing ' + ', '.join(missing)) if missing else '')
    ci = (U / C5_SRC / '2.0/ccu_i2c.c').read_text()
    check('C5 ccu_i2c.c no longer reaches into struct mt_i2c', not re.search(r'struct mt_i2c\s*\*|i2c->(?:dma_buf|base|id)\b', ci))
    shim = (U / MM / 'i2c_shim/mtk_i2c_shim.c').read_text()
    check('C5 shim CCU hooks are no longer -EOPNOTSUPP stubs', 'EOPNOTSUPP' not in shim)
    req = [str(f.relative_to(U)) for f in (U / C5_SRC).rglob('*.c') if 'request_firmware' in f.read_text(errors='replace')]
    check('C5 the kernel loads no CCU firmware (no request_firmware in ccu/src)', not req, ', '.join(req))
    drv = VENDOR / 'lib64/lib3a.ccudrv.so'
    st = subprocess.run(['strings', '-a', str(drv)], capture_output=True, text=True).stdout.splitlines() if drv.exists() else []
    check('C5 lib3a.ccudrv opens /dev/ccu and names /system/vendor/bin/lib3a.ccu.{pm,dm,ddr}',
          '/dev/ccu' in st and all('/system/vendor/bin/' + f in st for f in C5_FIRMWARE))
    missing = [f for f in C5_FIRMWARE if not (VENDOR / 'bin' / f).is_file()]
    check('C5 the CCU blobs are on the stock vendor partition (vendor/bin)', not missing, ', '.join(missing))
    if smap.exists() and config.exists():
        missing = [c for c in C5_CONFIG if c not in cfg.splitlines()]
        check('C5 build config', not missing, ', '.join(missing))
        missing = [s for s in C5_SYMBOLS if not re.search(r' [tT] ' + s + r'$', sm, re.M)]
        check('C5 System.map has the CCU and i2c-mt65xx CCU entry points', not missing,
              ', '.join(missing) or f'{len(C5_SYMBOLS)} symbols')
    for board in C1_BOARDS:
        if not board.exists():
            check('C5 board ' + board.name + ' exists', False); continue
        nodes = tree['DECODE'](board.read_bytes())['nodes']
        off = [p for p in C5_DT_OKAY if p not in nodes or not tree['enabled'](nodes, p)]
        check('C5 board ' + board.name + ' has /ccu and the ccu_sensor children of i2c-2 and i2c-4 okay', not off, ', '.join(off))
        bad = [p for p, irq in C5_DT_OKAY.items() if p in nodes and irq is not None and
               tree['values'](nodes[p]['interrupts']) != [0, irq, 8]]
        check('C5 board ' + board.name + ' CCU IRQ is stock (SPI 264)', not bad, ', '.join(bad))
        on = [p for p in C5_DT_OFF if p in nodes and tree['enabled'](nodes, p)]
        check('C5 board ' + board.name + ' keeps ccu_sensor_i2c_7_hw disabled', not on, ', '.join(on))
        bad = [p for p in C5_BUSES if tree['values'](nodes[p].get('mediatek,ch-offset', b'\0\0\0\0')) != [0x100]
               or tree['values'](nodes[p]['id']) != [int(p == '/i2c@11009000') * 2 or 4]]
        check('C5 board ' + board.name + ' CCU buses: AP channel 0x100 (CCU 0x200), ids 2 and 4', not bad, ', '.join(bad))

    # 10. C6 JPEG
    spec = HEADERS[C6_HEADER]
    try:
        tn, un = header_table(C6_HEADER, spec), header_table(C6_HEADER, spec, U)
        tc, uc = header_table(C6_HEADER, spec, T, True), header_table(C6_HEADER, spec, U, True)
        check(f'C6 jpeg_drv.h: {C6_NATIVE} native ioctls, as T', len(un) == C6_NATIVE and un == tn, f'U {len(un)}, T {len(tn)}')
        check(f'C6 jpeg_drv.h: {C6_COMPAT} compat ioctls (32-bit struct sizes), as T', len(uc) == C6_COMPAT and uc == tc,
              f'U {len(uc)}, T {len(tc)}')
        hal_c6 = sorted(v for v in resolved if any(Path(h).name == 'jpeg_drv.h' for _, h in by_value.get(v, [])))
        check('C6 every HAL /proc/mtk_jpeg number is in U', hal_c6 and all(v in un.values() for v in hal_c6),
              f'{len(hal_c6)} numbers')
    except RuntimeError as e:
        check('C6 jpeg_drv.h compiles', False, str(e)[:300])
    files = sorted(str(f.relative_to(U)) for f in (U / C6_SRC).rglob('*') if f.is_file())
    tfiles = {str(f.relative_to(T)) for f in (T / C6_SRC).rglob('*') if f.is_file()}
    same = [f for f in files if f not in C6_CHANGED]
    bad = [f for f in same if f not in tfiles or (U / f).read_bytes() != (T / f).read_bytes()]
    check('C6 U jpeg files are T\'s bytes (headers, Makefiles, Kconfig, encoder, decoder, registers)', same and not bad,
          ', '.join(bad) or f'{len(same)} files')
    check('C6 U jpeg has only v2 and no jpeg_cmdq (T does not build it)',
          {f.split('/')[4] for f in files if f.count('/') > 4} == {'v2'} and not any('cmdq' in f for f in files))
    for path, pairs in C6_CHANGED.items():
        t = (T / path).read_text(errors='replace')
        for a, b in pairs:
            check('C6 T ' + path + ' has the text the 5.10 change replaces', t.count(a) == 1)
            t = t.replace(a, b)
        check('C6 U ' + path + ' is T\'s with only the 5.10 changes', (U / path).read_text(errors='replace') == t,
              'proc_ops, flush from release')
    for path, needles in C6_NODES.items():
        body = (U / path).read_text() if (U / path).exists() else ''
        missing = [n for n in needles if n not in body]
        check('C6 U has ' + path, body and not missing, ('missing ' + ', '.join(missing)) if missing else '')
    jd = (U / C6_SRC / 'v2/jpeg_drv.c').read_text()
    check('C6 JPEG_DEV is not defined anywhere (stock: /proc/mtk_jpeg, no /dev node)',
          not any(re.search(r'#\s*define\s+JPEG_DEV\b', (U / f).read_text(errors='replace')) for f in files if f.endswith(('.c', '.h')))
          and 'static struct file_operations' not in jd.replace('/* Kernel interface */', '').split('#if 0')[0])
    for lib in C6_HAL_LIBS:
        so = VENDOR / lib
        st = subprocess.run(['strings', '-a', str(so)], capture_output=True, text=True).stdout.splitlines() if so.exists() else []
        check('C6 ' + lib + ' opens /proc/mtk_jpeg (not /dev/mtk_jpeg)', '/proc/mtk_jpeg' in st and '/dev/mtk_jpeg' not in st)
    rc = (VENDOR / 'etc/init/hw/init.mt6771.rc').read_text(errors='replace')
    check('C6 init.mt6771.rc chowns /proc/mtk_jpeg system:graphics, 0660',
          'chown system graphics /proc/mtk_jpeg' in rc and 'chmod 0660 /proc/mtk_jpeg' in rc)
    if smap.exists() and config.exists():
        missing = [c for c in C6_CONFIG if c not in cfg.splitlines()]
        check('C6 build config', not missing, ', '.join(missing))
        missing = [s for s in C6_SYMBOLS if not re.search(r' [tT] ' + s + r'$', sm, re.M)]
        check('C6 System.map has the JPEG encoder entry points', not missing, ', '.join(missing) or f'{len(C6_SYMBOLS)} symbols')
        check('C6 the decoder is not built (no jpeg_drv_dec_power_on or hybrid symbols)',
              not re.search(r' [tT] (jpeg_drv_dec_power_on|jpeg_hybrid_dec_ioctl)$', sm, re.M))
    for board in C1_BOARDS:
        if not board.exists():
            check('C6 board ' + board.name + ' exists', False); continue
        nodes = tree['DECODE'](board.read_bytes())['nodes']
        off = [p for p in C6_DT_OKAY if p not in nodes or not tree['enabled'](nodes, p)]
        check('C6 board ' + board.name + ' has /venc_jpg okay', not off, ', '.join(off))
        bad = [p for p, irq in C6_DT_OKAY.items() if p in nodes and tree['values'](nodes[p]['interrupts']) != [0, irq, 8]]
        check('C6 board ' + board.name + ' JPEG IRQ is stock (SPI 249)', not bad, ', '.join(bad))
        ok = [p for p, v in nodes.items() if 'compatible' in v and tree['enabled'](nodes, p) and
              any(c in ('mediatek,venc_jpg', 'mediatek,jpgdec') for c in tree['text'](v['compatible']))]
        check('C6 board ' + board.name + ' has no other JPEG node okay', ok == list(C6_DT_OKAY), ', '.join(ok))
        gc = nodes['/venc_gcon@17000000']
        check('C6 board ' + board.name + ' /venc_jpg takes venc_gcon clock 3 (JPGENC)',
              tree['values'](nodes['/venc_jpg@17030000']['clocks']) == [tree['values'](gc['phandle'])[0], 3] and tree['enabled'](nodes, '/venc_gcon@17000000'))

    # Trial cam1 fixes. imgsensor_custom_config against the shipped stock Image (boot partition kernel): 6 rows of
    # sensor idx, i2c dev and 12 (pin, hw id) pairs, 104 bytes each, ending with the IMGSENSOR_SENSOR_IDX_NONE row.
    img = ROOT / 'firmware/installed-20230105/boot/Image'
    data = img.read_bytes() if img.exists() else b''
    check('Stock boot Image is the shipped one', hashlib.sha256(data).hexdigest().startswith('a67fcf44a821963e'))
    cfg_h = (U / MM / 'imgsensor/src/mt6771/camera_hw/imgsensor_cfg_table.h').read_text()
    feat_h = (U / MM / 'imgsensor/inc/kd_camera_feature.h').read_text()

    def enum_values(text, name):
        body = re.search(r'enum ' + name + r' \{(.*?)\};', text, re.S).group(1)
        body = re.sub(r'#ifdef MIPI_SWITCH.*?#endif', '', body, flags=re.S)
        out, nxt = {}, 0
        for item in [x.strip() for x in re.sub(r'/\*.*?\*/', '', body, flags=re.S).split(',') if x.strip()]:
            k, _, v = [t.strip() for t in item.partition('=')]
            nxt = (int(v) if re.fullmatch(r'-?\d+', v) else out[v]) if v else nxt
            out[k] = nxt
            nxt += 1
        return out
    names = {}
    for text, name in ((cfg_h, 'IMGSENSOR_HW_PIN'), (cfg_h, 'IMGSENSOR_HW_ID'), (cfg_h, 'IMGSENSOR_I2C_DEV'),
                       (feat_h, 'IMGSENSOR_SENSOR_IDX')):
        names.update(enum_values(text, name))
    src = (U / MM / 'imgsensor/src/mt6771/camera_hw/imgsensor_cfg_table.c').read_text()
    table = src[src.index('imgsensor_custom_config[] = {'):src.index('platform_power_sequence[]')]
    ours = []
    for m in re.finditer(r'\{\s*(IMGSENSOR_SENSOR_IDX_\w+)\s*(?:,\s*(IMGSENSOR_I2C_DEV_\d)\s*,\s*\{(.*?)\}\s*,\s*\})?',
                         table, re.S):
        pins = re.findall(r'\{(IMGSENSOR_HW_PIN_\w+),\s*(IMGSENSOR_HW_ID_\w+)', m.group(3) or '')
        row = [names[m.group(1)], names[m.group(2)] if m.group(2) else 0]
        for i in range(12):
            row += [names[pins[i][0]], names[pins[i][1]]] if i < len(pins) else [0, 0]
        ours.append(row)
    stock = [list(struct.unpack_from('<26i', data, 0x1921168 + 104 * i)) for i in range(len(ours))] if data else []
    diff = [i for i, (a, b) in enumerate(zip(ours, stock)) if a != b]
    check('imgsensor_custom_config equals the shipped stock table (Image 0x1921168)',
          data and len(ours) == 6 and ours == stock, f'{len(ours)} rows, differing rows {diff}')
    main_row = dict(zip(ours[0][2::2], ours[0][3::2])) if ours else {}
    check('MAIN AVDD on GPIO and DVDD on regulator, as stock',
          main_row.get(names['IMGSENSOR_HW_PIN_AVDD']) == names['IMGSENSOR_HW_ID_GPIO'] and
          main_row.get(names['IMGSENSOR_HW_PIN_DVDD']) == names['IMGSENSOR_HW_ID_REGULATOR'])
    # ISP clock steps without mmdvfs: stock's cam_freq steps from the live stock DT, step 0 first.
    live = (ROOT / 'evidence/device-tree/stock-dt-match/dts/live-fdt-20230105.dts').read_text()
    steps = [int(re.search(r'\b' + n + r' = <(0x[0-9a-f]+) ', live).group(1), 16) for n in ('cam_step0', 'cam_step1')]
    isp = (U / MM / 'cameraisp/src/isp_50/camera_isp.c').read_text()
    m = re.search(r'isp_stock_cam_steps\[\] = \{([^}]*)\}', isp)
    check('ISP clock list equals stock cam_freq steps (live DT)', m and [int(x) for x in m.group(1).split(',')] == steps,
          f'stock {steps}')
    # The shipped stock Image has no "cqcnt" string; T's SOF gate on SPARE2 against the virtual CQ count masked
    # every SOF on the phone (trial cam1, camc7), as the HAL never sends ISP_SET_VIR_CQCNT.
    stock_img = data
    check('Stock Image has no cqcnt SOF gate', stock_img and b'cqcnt' not in stock_img)
    check('ISP SOF path has no SPARE2 vs virtual CQ count gate',
          'CTL_SPARE2' not in isp and 'PHY cqcnt' not in isp)
    check('ISP_GET_SUPPORTED_ISP_CLOCKS falls back to the stock list',
          'ARRAY_SIZE(isp_stock_cam_steps)' in isp and '__clk_lookup("cam_sel")' in isp)

    failed = [c for c in checks if not c['ok']]
    OUT.write_text(json.dumps({
        'resolved': record,
        'unresolved': [{'lib': l, 'callsite': f'0x{a:x}', 'function': f} for l, a, f in unresolved],
        'ion': [{'cmd': ION_CMD.get(c, c), 'sub': (ION_MM if c == 1 else ION_SYS).get(s, s)} for c, s in sorted(ion)],
        'header_tables': {h: {n: f'0x{v:08x}' for n, v in sorted(t.items(), key=lambda x: x[1])}
                          for h, t in tables.items()},
        'checks': checks, 'failures': len(failed), 'phone_accessed': False}, indent=2) + '\n')
    print(f'checks {len(checks)} failures {len(failed)} report {OUT}')
    return 1 if failed else 0


if __name__ == '__main__':
    sys.exit(main())
