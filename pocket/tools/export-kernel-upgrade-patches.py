#!/usr/bin/env python3
"""Export and replay-check the isolated forward-port patches against the pin."""
import pocket_paths
import difflib
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parent.parent
BASE = Path(os.environ['POCKET_KERNEL_DONOR']) if os.environ.get('POCKET_KERNEL_DONOR') else pocket_paths.platform_source()/'kernel/motorola/sm6450'
WORK = Path(os.environ.get('POCKET_KERNEL_SOURCE',str(ROOT/'tools/kernel-source/upgrade-5.10')))
GROUPS = {
    '0009-pocket-ramoops-guard.patch': ['fs/pstore/ram.c','fs/pstore/ram-pocket-diagnostic.h'],
    '0010-mt6771-watchdog-handoff.patch': ['drivers/watchdog/mtk_wdt.c', 'include/linux/soc/mediatek/mtk-wdt.h'],
    '0008-debug-regulator-handoff.patch': ['drivers/regulator/core.c'],
    '0001-mt6771-pinctrl-forward-port.patch': [
        'drivers/pinctrl/mediatek/pinctrl-mt6771.c', 'drivers/pinctrl/mediatek/pinctrl-mtk-mt6771.h',
        'drivers/pinctrl/mediatek/pinctrl-mtk-common-v2.c', 'drivers/pinctrl/mediatek/pinctrl-mtk-common-v2.h',
        'drivers/pinctrl/mediatek/Kconfig', 'drivers/pinctrl/mediatek/Makefile'],
    '0002-mt6771-clock-forward-port.patch': [
        'drivers/clk/mediatek/clk-mt6771-pg.h',
        'drivers/clk/mediatek/clk-mt6771.c', 'include/dt-bindings/clock/mt6771-clk.h',
        'include/dt-bindings/reset/mt6771-resets.h',
        'drivers/clk/mediatek/clk-mt6358-ufs.c', 'drivers/clk/mediatek/clk-mt6358-ufs.h',
        'drivers/clk/mediatek/Kconfig'],
    '0003-mt6771-pwrap-handoff.patch': [
        'drivers/soc/mediatek/mtk-pmic-wrap.c'],
    '0004-mt6771-ufs-phy.patch': [
        'drivers/phy/mediatek/phy-mtk-ufs.c'],
    '0005-mt6771-usb-phy.patch': [
        'drivers/phy/mediatek/phy-mt6771-core.c',
        'drivers/phy/mediatek/phy-mtk-mt6771.c',
        'drivers/phy/mediatek/phy-mtk.h',
        'drivers/phy/mediatek/phy-mtk-ssusb-reg.h',
        'include/linux/phy/mediatek/mtk_usb_phy.h',
        'drivers/phy/mediatek/Kconfig', 'drivers/phy/mediatek/Makefile'],
    '0006-mt6771-mtu3-binding.patch': [
        'drivers/usb/mtu3/mtu3_plat.c', 'drivers/usb/mtu3/mtu3_core.c', 'drivers/usb/mtu3/mtu3.h'],
    '0007-mt6771-ufs-firmware-guard.patch': [
        'drivers/scsi/ufs/ufs-mediatek.c', 'drivers/scsi/ufs/ufs-mediatek-fw.h',
        'drivers/scsi/ufs/ufs-mediatek.h', 'drivers/scsi/ufs/ufs-mt6771-hie.h'],
    '0011-trustkernel-forward-port.patch': [
        'drivers/misc/mediatek/tkcore/Kconfig',
        'drivers/misc/mediatek/tkcore/Makefile',
        'drivers/misc/mediatek/tkcore/armtz/Makefile',
        'drivers/misc/mediatek/tkcore/armtz/handle.c',
        'drivers/misc/mediatek/tkcore/armtz/handle.h',
        'drivers/misc/mediatek/tkcore/armtz/tee_mem.c',
        'drivers/misc/mediatek/tkcore/armtz/tee_mem.h',
        'drivers/misc/mediatek/tkcore/armtz/tee_smc_xfer.c',
        'drivers/misc/mediatek/tkcore/armtz/tee_smc_xfer.h',
        'drivers/misc/mediatek/tkcore/armtz/tee_tz_drv.c',
        'drivers/misc/mediatek/tkcore/armtz/tee_tz_op.h',
        'drivers/misc/mediatek/tkcore/armtz/tee_tz_priv.h',
        'drivers/misc/mediatek/tkcore/core/Makefile',
        'drivers/misc/mediatek/tkcore/core/pm.c',
        'drivers/misc/mediatek/tkcore/core/pm.h',
        'drivers/misc/mediatek/tkcore/core/tee_clkmgr.c',
        'drivers/misc/mediatek/tkcore/core/tee_clkmgr_priv.h',
        'drivers/misc/mediatek/tkcore/core/tee_context.c',
        'drivers/misc/mediatek/tkcore/core/tee_core.c',
        'drivers/misc/mediatek/tkcore/core/tee_core_priv.h',
        'drivers/misc/mediatek/tkcore/core/tee_fp.c',
        'drivers/misc/mediatek/tkcore/core/tee_fp_priv.h',
        'drivers/misc/mediatek/tkcore/core/tee_kernel_api.c',
        'drivers/misc/mediatek/tkcore/core/tee_procfs.c',
        'drivers/misc/mediatek/tkcore/core/tee_procfs.h',
        'drivers/misc/mediatek/tkcore/core/tee_session.c',
        'drivers/misc/mediatek/tkcore/core/tee_shm.c',
        'drivers/misc/mediatek/tkcore/core/tee_shm.h',
        'drivers/misc/mediatek/tkcore/core/tee_supp_com.c',
        'drivers/misc/mediatek/tkcore/core/tee_supp_com.h',
        'drivers/misc/mediatek/tkcore/core/tee_sysfs.c',
        'drivers/misc/mediatek/tkcore/core/tee_sysfs.h',
        'drivers/misc/mediatek/tkcore/core/tee_ta_mgmt.c',
        'drivers/misc/mediatek/tkcore/core/tee_ta_mgmt.h',
        'drivers/misc/mediatek/tkcore/core/tee_tui.c',
        'drivers/misc/mediatek/tkcore/core/tee_tui.h',
        'drivers/misc/mediatek/tkcore/core/tee_tui_hal.c',
        'drivers/misc/mediatek/tkcore/core/tee_tui_hal.h',
        'drivers/misc/mediatek/tkcore/core/tee_wait_queue.c',
        'drivers/misc/mediatek/tkcore/core/tee_wait_queue.h',
        'drivers/misc/mediatek/tkcore/include/arm_common/teesmc.h',
        'drivers/misc/mediatek/tkcore/include/arm_common/teesmc_st.h',
        'drivers/misc/mediatek/tkcore/include/linux/tee_client_api.h',
        'drivers/misc/mediatek/tkcore/include/linux/tee_clkmgr.h',
        'drivers/misc/mediatek/tkcore/include/linux/tee_core.h',
        'drivers/misc/mediatek/tkcore/include/linux/tee_fp.h',
        'drivers/misc/mediatek/tkcore/include/linux/tee_ioc.h',
        'drivers/misc/mediatek/tkcore/include/linux/tee_kernel_api.h',
        'drivers/misc/mediatek/tkcore/include/linux/tee_kernel_lowlevel_api.h',
        'drivers/misc/mediatek/tkcore/include/linux/tee_pm_sec_call.h',
        'drivers/misc/mediatek/tkcore/include/linux/tee_rpmb.h',
        'drivers/misc/mediatek/tkcore/version.h',
    ],
    '0012-mt6358-ufs-clock-child.patch': [
        'drivers/mfd/mt6397-core.c',
    ],
    '0013-mt6771-i2c.patch': [
        'drivers/i2c/busses/i2c-mt65xx.c',
        'drivers/i2c/busses/i2c-mt65xx-ccu.h',
    ],
    '0014-mediatek-display-port-glue.patch': [
        'drivers/misc/Kconfig',
        'drivers/misc/Makefile',
        'drivers/misc/mediatek/Makefile',
        'drivers/misc/mediatek/include/mt-plat/aee.h',
        'drivers/misc/mediatek/include/mt-plat/met_drv.h',
        'drivers/misc/mediatek/include/mt-plat/mmpath.h',
        'drivers/misc/mediatek/include/mt-plat/mtk_boot.h',
        'drivers/misc/mediatek/include/mt-plat/mtk_boot_common.h',
        'drivers/misc/mediatek/include/mt-plat/mtk_boot_reason.h',
        'drivers/misc/mediatek/include/mt-plat/mtk_ccci_common.h',
        'drivers/misc/mediatek/include/mt-plat/mtk_chip.h',
        'drivers/misc/mediatek/include/mt-plat/mtk_cirq.h',
        'drivers/misc/mediatek/include/mt-plat/mtk_devinfo.h',
        'drivers/misc/mediatek/include/mt-plat/mtk_gpu_utility.h',
        'drivers/misc/mediatek/include/mt-plat/mtk_io.h',
        'drivers/misc/mediatek/include/mt-plat/mtk_lpae.h',
        'drivers/misc/mediatek/include/mt-plat/mtk_meminfo.h',
        'drivers/misc/mediatek/include/mt-plat/mtk_pwm.h',
        'drivers/misc/mediatek/include/mt-plat/mtk_ram_console.h',
        'drivers/misc/mediatek/include/mt-plat/mtk_rtc.h',
        'drivers/misc/mediatek/include/mt-plat/mtk_secure_api.h',
        'drivers/misc/mediatek/include/mt-plat/mtk_smi.h',
        'drivers/misc/mediatek/include/mt-plat/sync_write.h',
        'drivers/misc/mediatek/include/mt-plat/upmu_common.h',
        'drivers/misc/mediatek/include/mt-plat/mt6771/include/mach/mtk_pwm_hal.h',
        'drivers/misc/mediatek/include/mt-plat/mt6771/include/mach/upmu_hw.h',
        'drivers/misc/mediatek/include/mt-plat/mt6771/include/mach/upmu_sw.h',
        'drivers/misc/mediatek/mmp/mmprofile.h',
        'drivers/misc/mediatek/mmp/mmprofile_function.h',
        'drivers/misc/mediatek/mmp/mmprofile_static_event.h',
    ],
    '0015-mt6771-power-gate-clocks.patch': [
        'drivers/clk/mediatek/Makefile',
        'drivers/clk/mediatek/clk-mt6771-pg.c',
        'drivers/clk/mediatek/clk-mtk-v1.c',
        'drivers/clk/mediatek/clk-mtk-v1.h',
        'drivers/misc/mediatek/Kconfig',
        'drivers/misc/mediatek/base/Makefile',
        'drivers/misc/mediatek/base/power/Makefile',
        'drivers/misc/mediatek/base/power/include/mtk_idle.h',
        'drivers/misc/mediatek/base/power/include/mtk_spm_idle.h',
        'drivers/misc/mediatek/base/power/include/mtk_spm_reg.h',
        'drivers/misc/mediatek/base/power/include/spm_v4/mtk_idle.h',
        'drivers/misc/mediatek/base/power/include/spm_v4/mtk_spm.h',
        'drivers/misc/mediatek/base/power/include/spm_v4/mtk_spm_early_porting.h',
        'drivers/misc/mediatek/base/power/include/spm_v4/mtk_spm_idle.h',
        'drivers/misc/mediatek/base/power/include/spm_v4/mtk_spm_internal.h',
        'drivers/misc/mediatek/base/power/include/spm_v4/mtk_spm_reg_mt6771.h',
        'drivers/misc/mediatek/base/power/include/spm_v4/mtk_spm_sleep.h',
        'drivers/misc/mediatek/base/power/include/spm_v4/pcm_def_mt6771.h',
        'drivers/misc/mediatek/base/power/include/spm_v4/sleep_def_mt6771.h',
        'drivers/misc/mediatek/base/power/spm_v4/Makefile',
        'drivers/misc/mediatek/base/power/spm_v4/mtk_spm_hooks.c',
    ],
    '0016-pocket-keyboard.patch': [
        'include/linux/input/pocket-touchpad.h',
        'drivers/input/keyboard/Kconfig',
        'drivers/input/keyboard/Makefile',
        'drivers/input/keyboard/aw9523-key.c',
        'drivers/leds/Kconfig',
        'drivers/leds/Makefile',
        'drivers/leds/leds-mt65xx-button.c',
    ],
    '0017-pocket-touchpad.patch': [
        'drivers/input/misc/Kconfig',
        'drivers/input/misc/Makefile',
        'drivers/input/misc/pocket-touchpad-report.h',
        'drivers/input/misc/pocket-touchpad.c',
    ],
    '0018-mt6358-power-off.patch': [
        'drivers/power/reset/Kconfig',
        'drivers/power/reset/Makefile',
        'drivers/power/reset/mt6358-poweroff.c',
        'drivers/rtc/rtc-mt6397.c',
    ],
    '0019-mt6370-mfd.patch': [
        'drivers/misc/mediatek/flashlight/richtek/Kconfig',
        'drivers/misc/mediatek/flashlight/richtek/Makefile',
        'drivers/misc/mediatek/flashlight/richtek/pocket_torch.c',
        'drivers/misc/mediatek/flashlight/richtek/rt-flashlight.c',
        'drivers/misc/mediatek/flashlight/richtek/rt-flashlight.h',
        'drivers/misc/mediatek/flashlight/richtek/rtfled.c',
        'drivers/misc/mediatek/flashlight/richtek/rtfled.h',
        'drivers/misc/mediatek/include/mt-plat/rt-regmap.h',
        'drivers/misc/mediatek/pmic/Kconfig',
        'drivers/misc/mediatek/pmic/Makefile',
        'drivers/misc/mediatek/pmic/mt6370/inc/mt6370_pmu_bled.h',
        'drivers/misc/mediatek/pmic/mt6370/inc/mt6370_pmu_charger.h',
        'drivers/misc/mediatek/pmic/mt6370/inc/mt6370_pmu_core.h',
        'drivers/misc/mediatek/pmic/mt6370/inc/mt6370_pmu_debugfs.h',
        'drivers/misc/mediatek/pmic/mt6370/inc/mt6370_pmu_dsv_debugfs.h',
        'drivers/misc/mediatek/pmic/mt6370/inc/mt6370_pmu_fled.h',
        'drivers/misc/mediatek/pmic/mt6370/inc/mt6370_pmu.h',
        'drivers/misc/mediatek/pmic/mt6370/inc/mt6370_pmu_rgbled.h',
        'drivers/misc/mediatek/pmic/mt6370/Kconfig',
        'drivers/misc/mediatek/pmic/mt6370/Makefile',
        'drivers/misc/mediatek/pmic/mt6370/mt6370_pmu_bled.c',
        'drivers/misc/mediatek/pmic/mt6370/mt6370_pmu_core.c',
        'drivers/misc/mediatek/pmic/mt6370/mt6370_pmu_dsv.c',
        'drivers/misc/mediatek/pmic/mt6370/mt6370_pmu_dsv_debugfs.c',
        'drivers/misc/mediatek/pmic/mt6370/mt6370_pmu_fled.c',
        'drivers/misc/mediatek/pmic/mt6370/mt6370_pmu_i2c.c',
        'drivers/misc/mediatek/pmic/mt6370/mt6370_pmu_irq.c',
        'drivers/misc/mediatek/pmic/mt6370/mt6370_pmu_ldo.c',
        'drivers/misc/mediatek/pmic/mt6370/mt6370_pmu_regmap.c',
        'drivers/misc/mediatek/pmic/mt6370/mt6370_pmu_rgbled.c',
        'drivers/misc/mediatek/pmic/mt6370/mt6370_pmu_subdevs.c',
        'drivers/misc/mediatek/rt-regmap/Kconfig',
        'drivers/misc/mediatek/rt-regmap/Makefile',
        'drivers/misc/mediatek/rt-regmap/rt-regmap.c',
    ],
    '0020-pocket-touchscreen.patch': [
        'drivers/input/touchscreen/Kconfig',
        'drivers/input/touchscreen/Makefile',
        'drivers/input/touchscreen/pocket-gt1151-report.h',
        'drivers/input/touchscreen/pocket-gt1151.c',
    ],
    '0021-mt6771-smi-m4u.patch': [
        'drivers/misc/mediatek/freqhopping/mt6771/mtk_freqhopping.h',
        'drivers/memory/Makefile',
        'drivers/memory/mtk-smi-debug.c',
        'drivers/memory/mtk-smi.c',
        'include/soc/mediatek/smi.h',
        'drivers/misc/mediatek/atf/Makefile',
        'drivers/misc/mediatek/atf/mt_secure_call.c',
        'drivers/misc/mediatek/base/power/include/mtk_vcorefs_manager.h',
        'drivers/misc/mediatek/base/power/include/vcorefs_v3/mtk_vcorefs_governor.h',
        'drivers/misc/mediatek/base/power/include/vcorefs_v3/mtk_vcorefs_manager.h',
        'drivers/misc/mediatek/cmo/Kconfig',
        'drivers/misc/mediatek/cmo/Makefile',
        'drivers/misc/mediatek/cmo/cmo-mtk.c',
        'drivers/misc/mediatek/cmo/cmo-mtk.h',
        'drivers/misc/mediatek/dramc/mt6771/mtk_dramc.h',
        'drivers/misc/mediatek/emi/mt6771/mt_emi_api.h',
        'drivers/misc/mediatek/freqhopping/mtk_freqhopping_drv.h',
        'drivers/misc/mediatek/m4u/Kconfig',
        'drivers/misc/mediatek/m4u/Makefile',
        'drivers/misc/mediatek/m4u/2.4/Makefile',
        'drivers/misc/mediatek/m4u/2.4/m4u.c',
        'drivers/misc/mediatek/m4u/2.4/m4u_debug.c',
        'drivers/misc/mediatek/m4u/2.4/m4u_debug.h',
        'drivers/misc/mediatek/m4u/2.4/m4u_mva.c',
        'drivers/misc/mediatek/m4u/2.4/m4u_mva.h',
        'drivers/misc/mediatek/m4u/2.4/m4u_pgtable.c',
        'drivers/misc/mediatek/m4u/2.4/m4u_pgtable.h',
        'drivers/misc/mediatek/m4u/2.4/m4u_v2.h',
        'drivers/misc/mediatek/m4u/2.4/m4u_v2_ext.h',
        'drivers/misc/mediatek/m4u/2.4/m4u_vpu_ut.c',
        'drivers/misc/mediatek/m4u/mt6771/Makefile',
        'drivers/misc/mediatek/m4u/mt6771/m4u.h',
        'drivers/misc/mediatek/m4u/mt6771/m4u_hw.c',
        'drivers/misc/mediatek/m4u/mt6771/m4u_hw.h',
        'drivers/misc/mediatek/m4u/mt6771/m4u_platform.h',
        'drivers/misc/mediatek/m4u/mt6771/m4u_port.h',
        'drivers/misc/mediatek/m4u/mt6771/m4u_priv.h',
        'drivers/misc/mediatek/m4u/mt6771/m4u_reg.h',
        'drivers/misc/mediatek/mmdvfs/mmdvfs_pmqos.h',
        'drivers/misc/mediatek/smi/Kconfig',
        'drivers/misc/mediatek/smi/Makefile',
        'drivers/misc/mediatek/smi/mmdvfs_config_mt6771.h',
        'drivers/misc/mediatek/smi/mmdvfs_config_util.h',
        'drivers/misc/mediatek/smi/mmdvfs_internal.h',
        'drivers/misc/mediatek/smi/mmdvfs_mgr.h',
        'drivers/misc/mediatek/smi/mmdvfs_mgr_util.c',
        'drivers/misc/mediatek/smi/mmdvfs_mgr_v3.c',
        'drivers/misc/mediatek/smi/mmdvfs_profile_adaptor.c',
        'drivers/misc/mediatek/smi/mt6771/smi_conf.h',
        'drivers/misc/mediatek/smi/mt6771/smi_hw.h',
        'drivers/misc/mediatek/smi/mt6771/smi_port.h',
        'drivers/misc/mediatek/smi/smi_conf_dbg.h',
        'drivers/misc/mediatek/smi/smi_drv.c',
        'drivers/misc/mediatek/smi/smi_pmqos.h',
        'drivers/misc/mediatek/smi/smi_public.h',
        'drivers/misc/mediatek/smi/smi_reg.h',
    ],
    '0022-mtk-legacy-ion.patch': [
        'arch/arm64/include/asm/cacheflush.h',
        'arch/arm64/mm/Makefile',
        'arch/arm64/mm/cache-mtk-user.S',
        'drivers/dma-buf/dma-buf.c',
        'include/linux/dma-buf.h',
        'drivers/staging/android/ion/Kconfig',
        'drivers/staging/android/ion/Makefile',
        'drivers/staging/android/ion/compat_ion.c',
        'drivers/staging/android/ion/compat_ion.h',
        'drivers/staging/android/ion/ion-ioctl.c',
        'drivers/staging/android/ion/ion.c',
        'drivers/staging/android/ion/ion.h',
        'drivers/staging/android/ion/ion_carveout_heap.c',
        'drivers/staging/android/ion/ion_chunk_heap.c',
        'drivers/staging/android/ion/ion_cma_heap.c',
        'drivers/staging/android/ion/ion_heap.c',
        'drivers/staging/android/ion/ion_page_pool.c',
        'drivers/staging/android/ion/ion_priv.h',
        'drivers/staging/android/ion/ion_system_heap.c',
        'drivers/staging/android/ion/mtk/Kconfig',
        'drivers/staging/android/ion/mtk/Makefile',
        'drivers/staging/android/ion/mtk/ion_comm.c',
        'drivers/staging/android/ion/mtk/ion_drv.c',
        'drivers/staging/android/ion/mtk/ion_drv.h',
        'drivers/staging/android/ion/mtk/ion_drv_priv.h',
        'drivers/staging/android/ion/mtk/ion_fb_heap.c',
        'drivers/staging/android/ion/mtk/ion_fb_heap.h',
        'drivers/staging/android/ion/mtk/ion_history.c',
        'drivers/staging/android/ion/mtk/ion_mm_heap.c',
        'drivers/staging/android/ion/mtk/ion_profile.c',
        'drivers/staging/android/ion/mtk/ion_profile.h',
        'drivers/staging/android/ion/mtk/ion_sec_heap.c',
        'drivers/staging/android/ion/mtk/ion_sec_heap.h',
        'drivers/staging/android/ion/mtk/mtk_ion.h',
        'drivers/staging/android/uapi/ion.h',
    ],
    '0023-mt6771-cmdq.patch': [
        'drivers/mailbox/mtk-cmdq-mailbox.c',
        'drivers/soc/mediatek/mtk-cmdq-helper.c',
        'include/linux/mailbox/mtk-cmdq-mailbox.h',
        'include/linux/soc/mediatek/mtk-cmdq.h',
        'include/linux/pm_qos.h',
        'kernel/power/qos_mtk.c',
        'kernel/power/Makefile',
        'drivers/misc/mediatek/cmdq/bridge/cmdq-bdg.h',
        'drivers/misc/mediatek/cmdq/Kconfig',
        'drivers/misc/mediatek/cmdq/Makefile',
        'drivers/misc/mediatek/cmdq/mdp_sync/Makefile',
        'drivers/misc/mediatek/cmdq/mdp_sync/mdp_fence.c',
        'drivers/misc/mediatek/cmdq/v3/cmdq_core.h',
        'drivers/misc/mediatek/cmdq/v3/cmdq_def.h',
        'drivers/misc/mediatek/cmdq/v3/cmdq_device.c',
        'drivers/misc/mediatek/cmdq/v3/cmdq_device.h',
        'drivers/misc/mediatek/cmdq/v3/cmdq_driver.c',
        'drivers/misc/mediatek/cmdq/v3/cmdq_driver.h',
        'drivers/misc/mediatek/cmdq/v3/cmdq_event_common.c',
        'drivers/misc/mediatek/cmdq/v3/cmdq_event_common.h',
        'drivers/misc/mediatek/cmdq/v3/cmdq_helper_ext.c',
        'drivers/misc/mediatek/cmdq/v3/cmdq_helper_ext.h',
        'drivers/misc/mediatek/cmdq/v3/cmdq_mdp_common.c',
        'drivers/misc/mediatek/cmdq/v3/cmdq_mdp_common.h',
        'drivers/misc/mediatek/cmdq/v3/cmdq_mdp_pmqos.h',
        'drivers/misc/mediatek/cmdq/v3/cmdq_record.c',
        'drivers/misc/mediatek/cmdq/v3/cmdq_record.h',
        'drivers/misc/mediatek/cmdq/v3/cmdq_record_private.h',
        'drivers/misc/mediatek/cmdq/v3/cmdq_reg.h',
        'drivers/misc/mediatek/cmdq/v3/cmdq_sec.h',
        'drivers/misc/mediatek/cmdq/v3/cmdq_struct.h',
        'drivers/misc/mediatek/cmdq/v3/cmdq_subsys_common.c',
        'drivers/misc/mediatek/cmdq/v3/cmdq_subsys_common.h',
        'drivers/misc/mediatek/cmdq/v3/cmdq_test.c',
        'drivers/misc/mediatek/cmdq/v3/cmdq_virtual.c',
        'drivers/misc/mediatek/cmdq/v3/cmdq_virtual.h',
        'drivers/misc/mediatek/cmdq/v3/inc/cmdq_sec_dr/cmdq_sec_iwc_common.h',
        'drivers/misc/mediatek/cmdq/v3/Makefile',
        'drivers/misc/mediatek/cmdq/v3/mt6771/cmdq_engine.h',
        'drivers/misc/mediatek/cmdq/v3/mt6771/cmdq_mdp.c',
        'drivers/misc/mediatek/cmdq/v3/mt6771/Makefile',
        'drivers/misc/mediatek/cmdq/v3/mt6771/mdp_base.h',
        'drivers/misc/mediatek/mdp/Makefile',
        'drivers/misc/mediatek/mdp/mdp_def_ex.h',
        'drivers/misc/mediatek/mdp/mdp_ioctl_ex.c',
        'drivers/misc/mediatek/mdp/mdp_ioctl_ex.h',
        'drivers/misc/mediatek/mdp/mdp_m4u.c',
        'drivers/misc/mediatek/mdp/mdp_m4u.h',
        'drivers/misc/mediatek/sync/Kconfig',
        'drivers/misc/mediatek/sync/Makefile',
        'drivers/misc/mediatek/sync/mtk_sync.c',
        'drivers/misc/mediatek/sync/mtk_sync.h',
    ],
    '0024-mt6771-disp.patch': [
        'drivers/misc/mediatek/hdmi/inc/hdmi_drv.h',
        'drivers/misc/mediatek/video/Kconfig',
        'drivers/misc/mediatek/video/Makefile',
        'drivers/misc/mediatek/video/common/Makefile',
        'drivers/misc/mediatek/video/common/aal30/Makefile',
        'drivers/misc/mediatek/video/common/aal30/ddp_aal.c',
        'drivers/misc/mediatek/video/common/color20/Makefile',
        'drivers/misc/mediatek/video/common/color20/ddp_color.c',
        'drivers/misc/mediatek/video/common/corr10/Makefile',
        'drivers/misc/mediatek/video/common/corr10/ddp_dither.c',
        'drivers/misc/mediatek/video/common/corr10/ddp_gamma.c',
        'drivers/misc/mediatek/video/common/layering_rule_base/Makefile',
        'drivers/misc/mediatek/video/common/layering_rule_base/v1.1/Makefile',
        'drivers/misc/mediatek/video/common/layering_rule_base/v1.1/layering_rule_base.c',
        'drivers/misc/mediatek/video/common/layering_rule_base/v1.1/layering_rule_base.h',
        'drivers/misc/mediatek/video/common/mtkfb_fence.h',
        'drivers/misc/mediatek/video/common/pwm10/Makefile',
        'drivers/misc/mediatek/video/common/pwm10/ddp_pwm.c',
        'drivers/misc/mediatek/video/common/rdma20/ddp_rdma.h',
        'drivers/misc/mediatek/video/common/wdma20/ddp_wdma.h',
        'drivers/misc/mediatek/video/include/DpDataType.h',
        'drivers/misc/mediatek/video/include/ddp_aal.h',
        'drivers/misc/mediatek/video/include/ddp_color.h',
        'drivers/misc/mediatek/video/include/ddp_dither.h',
        'drivers/misc/mediatek/video/include/ddp_gamma.h',
        'drivers/misc/mediatek/video/include/ddp_od.h',
        'drivers/misc/mediatek/video/include/ddp_pq.h',
        'drivers/misc/mediatek/video/include/ddp_pwm.h',
        'drivers/misc/mediatek/video/include/ddp_pwm_mux.h',
        'drivers/misc/mediatek/video/include/disp_gettimeofday.h',
        'drivers/misc/mediatek/video/include/disp_session.h',
        'drivers/misc/mediatek/video/include/fbconfig_kdebug.h',
        'drivers/misc/mediatek/video/include/mtkfb.h',
        'drivers/misc/mediatek/video/include/mtkfb_info.h',
        'drivers/misc/mediatek/video/include/mtkfb_vsync.h',
        'drivers/misc/mediatek/video/mt6771/Makefile',
        'drivers/misc/mediatek/video/mt6771/dispsys/Makefile',
        'drivers/misc/mediatek/video/mt6771/dispsys/ddp_clkmgr.c',
        'drivers/misc/mediatek/video/mt6771/dispsys/ddp_clkmgr.h',
        'drivers/misc/mediatek/video/mt6771/dispsys/ddp_color_format.c',
        'drivers/misc/mediatek/video/mt6771/dispsys/ddp_dbi.c',
        'drivers/misc/mediatek/video/mt6771/dispsys/ddp_dbi.h',
        'drivers/misc/mediatek/video/mt6771/dispsys/ddp_debug.c',
        'drivers/misc/mediatek/video/mt6771/dispsys/ddp_debug.h',
        'drivers/misc/mediatek/video/mt6771/dispsys/ddp_dpi.c',
        'drivers/misc/mediatek/video/mt6771/dispsys/ddp_dpi.h',
        'drivers/misc/mediatek/video/mt6771/dispsys/ddp_dpi_reg.h',
        'drivers/misc/mediatek/video/mt6771/dispsys/ddp_drv.c',
        'drivers/misc/mediatek/video/mt6771/dispsys/ddp_drv.h',
        'drivers/misc/mediatek/video/mt6771/dispsys/ddp_dsi.c',
        'drivers/misc/mediatek/video/mt6771/dispsys/ddp_dsi.h',
        'drivers/misc/mediatek/video/mt6771/dispsys/ddp_dump.c',
        'drivers/misc/mediatek/video/mt6771/dispsys/ddp_dump.h',
        'drivers/misc/mediatek/video/mt6771/dispsys/ddp_hal.h',
        'drivers/misc/mediatek/video/mt6771/dispsys/ddp_info.c',
        'drivers/misc/mediatek/video/mt6771/dispsys/ddp_info.h',
        'drivers/misc/mediatek/video/mt6771/dispsys/ddp_irq.c',
        'drivers/misc/mediatek/video/mt6771/dispsys/ddp_irq.h',
        'drivers/misc/mediatek/video/mt6771/dispsys/ddp_log.h',
        'drivers/misc/mediatek/video/mt6771/dispsys/ddp_m4u.c',
        'drivers/misc/mediatek/video/mt6771/dispsys/ddp_m4u.h',
        'drivers/misc/mediatek/video/mt6771/dispsys/ddp_manager.c',
        'drivers/misc/mediatek/video/mt6771/dispsys/ddp_manager.h',
        'drivers/misc/mediatek/video/mt6771/dispsys/ddp_matrix_para.h',
        'drivers/misc/mediatek/video/mt6771/dispsys/ddp_met.c',
        'drivers/misc/mediatek/video/mt6771/dispsys/ddp_met.h',
        'drivers/misc/mediatek/video/mt6771/dispsys/ddp_mmp.c',
        'drivers/misc/mediatek/video/mt6771/dispsys/ddp_mmp.h',
        'drivers/misc/mediatek/video/mt6771/dispsys/ddp_mutex.c',
        'drivers/misc/mediatek/video/mt6771/dispsys/ddp_mutex.h',
        'drivers/misc/mediatek/video/mt6771/dispsys/ddp_ovl.c',
        'drivers/misc/mediatek/video/mt6771/dispsys/ddp_ovl.h',
        'drivers/misc/mediatek/video/mt6771/dispsys/ddp_path.c',
        'drivers/misc/mediatek/video/mt6771/dispsys/ddp_path.h',
        'drivers/misc/mediatek/video/mt6771/dispsys/ddp_pwm_mux.c',
        'drivers/misc/mediatek/video/mt6771/dispsys/ddp_rdma_ex.c',
        'drivers/misc/mediatek/video/mt6771/dispsys/ddp_rdma_ex.h',
        'drivers/misc/mediatek/video/mt6771/dispsys/ddp_reg.h',
        'drivers/misc/mediatek/video/mt6771/dispsys/ddp_reg_dbi.h',
        'drivers/misc/mediatek/video/mt6771/dispsys/ddp_reg_dma.h',
        'drivers/misc/mediatek/video/mt6771/dispsys/ddp_reg_dpi.h',
        'drivers/misc/mediatek/video/mt6771/dispsys/ddp_reg_dsi.h',
        'drivers/misc/mediatek/video/mt6771/dispsys/ddp_reg_mipi.h',
        'drivers/misc/mediatek/video/mt6771/dispsys/ddp_reg_mmsys.h',
        'drivers/misc/mediatek/video/mt6771/dispsys/ddp_reg_mutex.h',
        'drivers/misc/mediatek/video/mt6771/dispsys/ddp_reg_ovl.h',
        'drivers/misc/mediatek/video/mt6771/dispsys/ddp_reg_pq.h',
        'drivers/misc/mediatek/video/mt6771/dispsys/ddp_reg_rsz.h',
        'drivers/misc/mediatek/video/mt6771/dispsys/ddp_rsz.c',
        'drivers/misc/mediatek/video/mt6771/dispsys/ddp_rsz.h',
        'drivers/misc/mediatek/video/mt6771/dispsys/ddp_wdma_ex.c',
        'drivers/misc/mediatek/video/mt6771/dispsys/ddp_wdma_ex.h',
        'drivers/misc/mediatek/video/mt6771/dispsys/disp_event.h',
        'drivers/misc/mediatek/video/mt6771/dispsys/display_recorder.c',
        'drivers/misc/mediatek/video/mt6771/dispsys/display_recorder.h',
        'drivers/misc/mediatek/video/mt6771/videox/Makefile',
        'drivers/misc/mediatek/video/mt6771/videox/compat_mtk_disp_mgr.c',
        'drivers/misc/mediatek/video/mt6771/videox/compat_mtk_disp_mgr.h',
        'drivers/misc/mediatek/video/mt6771/videox/compat_mtkfb.h',
        'drivers/misc/mediatek/video/mt6771/videox/debug.c',
        'drivers/misc/mediatek/video/mt6771/videox/debug.h',
        'drivers/misc/mediatek/video/mt6771/videox/disp_arr.c',
        'drivers/misc/mediatek/video/mt6771/videox/disp_arr.h',
        'drivers/misc/mediatek/video/mt6771/videox/disp_assert_layer.c',
        'drivers/misc/mediatek/video/mt6771/videox/disp_assert_layer.h',
        'drivers/misc/mediatek/video/mt6771/videox/disp_drv_ddp.h',
        'drivers/misc/mediatek/video/mt6771/videox/disp_drv_log.h',
        'drivers/misc/mediatek/video/mt6771/videox/disp_drv_platform.h',
        'drivers/misc/mediatek/video/mt6771/videox/disp_dts_gpio.c',
        'drivers/misc/mediatek/video/mt6771/videox/disp_dts_gpio.h',
        'drivers/misc/mediatek/video/mt6771/videox/disp_helper.c',
        'drivers/misc/mediatek/video/mt6771/videox/disp_helper.h',
        'drivers/misc/mediatek/video/mt6771/videox/disp_lcm.c',
        'drivers/misc/mediatek/video/mt6771/videox/disp_lcm.h',
        'drivers/misc/mediatek/video/mt6771/videox/disp_lowpower.c',
        'drivers/misc/mediatek/video/mt6771/videox/disp_lowpower.h',
        'drivers/misc/mediatek/video/mt6771/videox/disp_partial.c',
        'drivers/misc/mediatek/video/mt6771/videox/disp_partial.h',
        'drivers/misc/mediatek/video/mt6771/videox/disp_recovery.c',
        'drivers/misc/mediatek/video/mt6771/videox/disp_recovery.h',
        'drivers/misc/mediatek/video/mt6771/videox/disp_rect.c',
        'drivers/misc/mediatek/video/mt6771/videox/disp_rect.h',
        'drivers/misc/mediatek/video/mt6771/videox/disp_utils.c',
        'drivers/misc/mediatek/video/mt6771/videox/disp_utils.h',
        'drivers/misc/mediatek/video/mt6771/videox/fbconfig_kdebug.c',
        'drivers/misc/mediatek/video/mt6771/videox/frame_queue.c',
        'drivers/misc/mediatek/video/mt6771/videox/frame_queue.h',
        'drivers/misc/mediatek/video/mt6771/videox/layering_rule.c',
        'drivers/misc/mediatek/video/mt6771/videox/layering_rule.h',
        'drivers/misc/mediatek/video/mt6771/videox/mtk_disp_mgr.c',
        'drivers/misc/mediatek/video/mt6771/videox/mtk_disp_mgr.h',
        'drivers/misc/mediatek/video/mt6771/videox/mtk_ovl.c',
        'drivers/misc/mediatek/video/mt6771/videox/mtk_ovl.h',
        'drivers/misc/mediatek/video/mt6771/videox/mtkfb.c',
        'drivers/misc/mediatek/video/mt6771/videox/mtkfb_console.c',
        'drivers/misc/mediatek/video/mt6771/videox/mtkfb_console.h',
        'drivers/misc/mediatek/video/mt6771/videox/mtkfb_fence.c',
        'drivers/misc/mediatek/video/mt6771/videox/mtkfb_fence.h',
        'drivers/misc/mediatek/video/mt6771/videox/mtkfb_vsync.c',
        'drivers/misc/mediatek/video/mt6771/videox/primary_display.c',
        'drivers/misc/mediatek/video/mt6771/videox/primary_display.h',
        'drivers/misc/mediatek/lcm/Kconfig',
        'drivers/misc/mediatek/lcm/Makefile',
        'drivers/misc/mediatek/lcm/R63308_CASCADEMDZ40/Makefile',
        'drivers/misc/mediatek/lcm/R63308_CASCADEMDZ40/R63308_CASCADEMDZ40.c',
        'drivers/misc/mediatek/lcm/inc/lcm_define.h',
        'drivers/misc/mediatek/lcm/inc/lcm_drv.h',
        'drivers/misc/mediatek/lcm/lcm_common.c',
        'drivers/misc/mediatek/lcm/lcm_gpio.c',
        'drivers/misc/mediatek/lcm/lcm_i2c.c',
        'drivers/misc/mediatek/lcm/lcm_pmic.c',
        'drivers/misc/mediatek/lcm/lcm_util.c',
        'drivers/misc/mediatek/lcm/mt65xx_lcm_list.c',
        'drivers/misc/mediatek/lcm/mt65xx_lcm_list.h',
        'drivers/misc/mediatek/leds/Kconfig',
        'drivers/misc/mediatek/leds/Makefile',
        'drivers/misc/mediatek/leds/mt6771/Makefile',
        'drivers/misc/mediatek/leds/mt6771/mtk_leds.c',
        'drivers/misc/mediatek/leds/mt6771/mtk_leds_hal.h',
        'drivers/misc/mediatek/leds/mt6771/mtk_leds_sw.h',
        'drivers/misc/mediatek/leds/mtk_leds_drv.c',
        'drivers/misc/mediatek/leds/mtk_leds_drv.h',
        'drivers/misc/mediatek/ext_disp/Kconfig',
        'drivers/misc/mediatek/ext_disp/Makefile',
        'drivers/misc/mediatek/ext_disp/include/mtk_extd_mgr.h',
        'drivers/misc/mediatek/ext_disp/mt6771/Makefile',
        'drivers/misc/mediatek/ext_disp/mt6771/extd_epd.c',
        'drivers/misc/mediatek/ext_disp/mt6771/extd_hdmi.c',
        'drivers/misc/mediatek/ext_disp/mt6771/extd_hdmi.h',
        'drivers/misc/mediatek/ext_disp/mt6771/extd_hdmi_types.h',
        'drivers/misc/mediatek/ext_disp/mt6771/extd_info.h',
        'drivers/misc/mediatek/ext_disp/mt6771/extd_log.h',
        'drivers/misc/mediatek/ext_disp/mt6771/extd_multi_control.c',
        'drivers/misc/mediatek/ext_disp/mt6771/extd_multi_control.h',
        'drivers/misc/mediatek/ext_disp/mt6771/extd_platform.h',
        'drivers/misc/mediatek/ext_disp/mt6771/extd_utils.c',
        'drivers/misc/mediatek/ext_disp/mt6771/extd_utils.h',
        'drivers/misc/mediatek/ext_disp/mt6771/external_display.c',
        'drivers/misc/mediatek/ext_disp/mt6771/external_display.h',
        'drivers/misc/mediatek/boot/Kconfig',
        'drivers/misc/mediatek/boot/Makefile',
        'drivers/misc/mediatek/boot/mtk_boot_common.c',
        'drivers/misc/mediatek/ccci_util/Makefile',
        'drivers/misc/mediatek/ccci_util/ccci_util_dummy.c',
        'drivers/misc/mediatek/base/power/include/mtk_spm.h',
        'drivers/misc/mediatek/base/power/include/mtk_vcorefs_governor.h',
        'drivers/pinctrl/mediatek/pinctrl-paris.c',
    ],
    '0026-oz8806-gauge.patch': [
        'drivers/power/supply/Kconfig',
        'drivers/power/supply/Makefile',
        'drivers/power/supply/oz8806.c',
        'drivers/power/supply/oz8806_battery.c',
        'drivers/power/supply/oz8806_bmulib.c',
        'drivers/power/supply/oz8806_bmulib.h',
        'drivers/power/supply/oz8806_ntc.h',
        'drivers/power/supply/oz8806_ocv.h',
        'drivers/power/supply/oz8806_ocv_generic.h',
        'include/linux/power/oz8806.h',
    ],
    '0025-mt6771-gpu.patch': [
        'drivers/misc/mediatek/base/power/include/leakage_table_v2/mtk_static_power.h',
        'drivers/misc/mediatek/base/power/include/leakage_table_v2/mtk_static_power_mt6771.h',
        'drivers/misc/mediatek/base/power/mt6771/Makefile',
        'drivers/misc/mediatek/base/power/mt6771/mtk_gpu_bw.h',
        'drivers/misc/mediatek/base/power/mt6771/mtk_gpu_log.c',
        'drivers/misc/mediatek/base/power/mt6771/mtk_gpu_log.h',
        'drivers/misc/mediatek/base/power/mt6771/mtk_gpufreq.h',
        'drivers/misc/mediatek/base/power/mt6771/mtk_gpufreq_cooling.c',
        'drivers/misc/mediatek/base/power/mt6771/mtk_gpufreq_core.c',
        'drivers/misc/mediatek/base/power/mt6771/mtk_gpufreq_core.h',
        'drivers/misc/mediatek/base/power/mt6771/mtk_gpufreq_stubs.c',
        'drivers/misc/mediatek/freqhopping/Kconfig',
        'drivers/misc/mediatek/freqhopping/Makefile',
        'drivers/misc/mediatek/freqhopping/mt6771/Makefile',
        'drivers/misc/mediatek/freqhopping/mt6771/mtk_fhreg.h',
        'drivers/misc/mediatek/freqhopping/mt6771/mtk_freqhopping.c',
        'drivers/misc/mediatek/freqhopping/mtk_freqhopping_drv.c',
        'drivers/misc/mediatek/gpu/Kconfig',
        'drivers/misc/mediatek/gpu/Makefile',
        'drivers/misc/mediatek/gpu/ged/Makefile',
        'drivers/misc/mediatek/gpu/ged/include/config_kernel_user.h',
        'drivers/misc/mediatek/gpu/ged/include/ged.h',
        'drivers/misc/mediatek/gpu/ged/include/ged_base.h',
        'drivers/misc/mediatek/gpu/ged/include/ged_bridge.h',
        'drivers/misc/mediatek/gpu/ged/include/ged_bridge_id.h',
        'drivers/misc/mediatek/gpu/ged/include/ged_debugFS.h',
        'drivers/misc/mediatek/gpu/ged/include/ged_dvfs.h',
        'drivers/misc/mediatek/gpu/ged/include/ged_global.h',
        'drivers/misc/mediatek/gpu/ged/include/ged_gpu_tuner.h',
        'drivers/misc/mediatek/gpu/ged/include/ged_hal.h',
        'drivers/misc/mediatek/gpu/ged/include/ged_hashtable.h',
        'drivers/misc/mediatek/gpu/ged/include/ged_kpi.h',
        'drivers/misc/mediatek/gpu/ged/include/ged_log.h',
        'drivers/misc/mediatek/gpu/ged/include/ged_monitor_3D_fence.h',
        'drivers/misc/mediatek/gpu/ged/include/ged_notify_sw_vsync.h',
        'drivers/misc/mediatek/gpu/ged/include/ged_sysfs.h',
        'drivers/misc/mediatek/gpu/ged/include/ged_type.h',
        'drivers/misc/mediatek/gpu/ged/src/ged.c',
        'drivers/misc/mediatek/gpu/ged/src/ged_base.c',
        'drivers/misc/mediatek/gpu/ged/src/ged_bridge.c',
        'drivers/misc/mediatek/gpu/ged/src/ged_debugFS.c',
        'drivers/misc/mediatek/gpu/ged/src/ged_dvfs.c',
        'drivers/misc/mediatek/gpu/ged/src/ged_ge.c',
        'drivers/misc/mediatek/gpu/ged/src/ged_ge.h',
        'drivers/misc/mediatek/gpu/ged/src/ged_gpu_tuner.c',
        'drivers/misc/mediatek/gpu/ged/src/ged_hal.c',
        'drivers/misc/mediatek/gpu/ged/src/ged_hashtable.c',
        'drivers/misc/mediatek/gpu/ged/src/ged_kpi.c',
        'drivers/misc/mediatek/gpu/ged/src/ged_log.c',
        'drivers/misc/mediatek/gpu/ged/src/ged_main.c',
        'drivers/misc/mediatek/gpu/ged/src/ged_monitor_3D_fence.c',
        'drivers/misc/mediatek/gpu/ged/src/ged_notify_sw_vsync.c',
        'drivers/misc/mediatek/gpu/ged/src/ged_sysfs.c',
        'drivers/misc/mediatek/gpu/ged/src/ged_thread.c',
        'drivers/misc/mediatek/gpu/ged/src/ged_thread.h',
        'drivers/misc/mediatek/gpu/gpu_mali/Makefile',
        'drivers/misc/mediatek/gpu/gpu_mali/mali_bifrost/Makefile',
        'drivers/misc/mediatek/gpu/gpu_mali/mali_bifrost/mali-r25p0/drivers/gpu/arm/midgard/Kbuild',
        'drivers/misc/mediatek/gpu/gpu_mali/mali_bifrost/mali-r25p0/drivers/gpu/arm/midgard/Kbuild-mtk-custom-env',
        'drivers/misc/mediatek/gpu/gpu_mali/mali_bifrost/mali-r25p0/drivers/gpu/arm/midgard/Makefile',
        'drivers/misc/mediatek/gpu/gpu_mali/mali_bifrost/mali-r25p0/drivers/gpu/arm/midgard/backend/gpu/Kbuild',
        'drivers/misc/mediatek/gpu/gpu_mali/mali_bifrost/mali-r25p0/drivers/gpu/arm/midgard/backend/gpu/mali_kbase_backend_config.h',
        'drivers/misc/mediatek/gpu/gpu_mali/mali_bifrost/mali-r25p0/drivers/gpu/arm/midgard/backend/gpu/mali_kbase_cache_policy_backend.c',
        'drivers/misc/mediatek/gpu/gpu_mali/mali_bifrost/mali-r25p0/drivers/gpu/arm/midgard/backend/gpu/mali_kbase_cache_policy_backend.h',
        'drivers/misc/mediatek/gpu/gpu_mali/mali_bifrost/mali-r25p0/drivers/gpu/arm/midgard/backend/gpu/mali_kbase_clk_rate_trace_mgr.c',
        'drivers/misc/mediatek/gpu/gpu_mali/mali_bifrost/mali-r25p0/drivers/gpu/arm/midgard/backend/gpu/mali_kbase_clk_rate_trace_mgr.h',
        'drivers/misc/mediatek/gpu/gpu_mali/mali_bifrost/mali-r25p0/drivers/gpu/arm/midgard/backend/gpu/mali_kbase_debug_job_fault_backend.c',
        'drivers/misc/mediatek/gpu/gpu_mali/mali_bifrost/mali-r25p0/drivers/gpu/arm/midgard/backend/gpu/mali_kbase_devfreq.h',
        'drivers/misc/mediatek/gpu/gpu_mali/mali_bifrost/mali-r25p0/drivers/gpu/arm/midgard/backend/gpu/mali_kbase_device_hw.c',
        'drivers/misc/mediatek/gpu/gpu_mali/mali_bifrost/mali-r25p0/drivers/gpu/arm/midgard/backend/gpu/mali_kbase_device_internal.h',
        'drivers/misc/mediatek/gpu/gpu_mali/mali_bifrost/mali-r25p0/drivers/gpu/arm/midgard/backend/gpu/mali_kbase_gpuprops_backend.c',
        'drivers/misc/mediatek/gpu/gpu_mali/mali_bifrost/mali-r25p0/drivers/gpu/arm/midgard/backend/gpu/mali_kbase_instr_backend.c',
        'drivers/misc/mediatek/gpu/gpu_mali/mali_bifrost/mali-r25p0/drivers/gpu/arm/midgard/backend/gpu/mali_kbase_instr_defs.h',
        'drivers/misc/mediatek/gpu/gpu_mali/mali_bifrost/mali-r25p0/drivers/gpu/arm/midgard/backend/gpu/mali_kbase_instr_internal.h',
        'drivers/misc/mediatek/gpu/gpu_mali/mali_bifrost/mali-r25p0/drivers/gpu/arm/midgard/backend/gpu/mali_kbase_irq_internal.h',
        'drivers/misc/mediatek/gpu/gpu_mali/mali_bifrost/mali-r25p0/drivers/gpu/arm/midgard/backend/gpu/mali_kbase_irq_linux.c',
        'drivers/misc/mediatek/gpu/gpu_mali/mali_bifrost/mali-r25p0/drivers/gpu/arm/midgard/backend/gpu/mali_kbase_jm_as.c',
        'drivers/misc/mediatek/gpu/gpu_mali/mali_bifrost/mali-r25p0/drivers/gpu/arm/midgard/backend/gpu/mali_kbase_jm_defs.h',
        'drivers/misc/mediatek/gpu/gpu_mali/mali_bifrost/mali-r25p0/drivers/gpu/arm/midgard/backend/gpu/mali_kbase_jm_hw.c',
        'drivers/misc/mediatek/gpu/gpu_mali/mali_bifrost/mali-r25p0/drivers/gpu/arm/midgard/backend/gpu/mali_kbase_jm_internal.h',
        'drivers/misc/mediatek/gpu/gpu_mali/mali_bifrost/mali-r25p0/drivers/gpu/arm/midgard/backend/gpu/mali_kbase_jm_rb.c',
        'drivers/misc/mediatek/gpu/gpu_mali/mali_bifrost/mali-r25p0/drivers/gpu/arm/midgard/backend/gpu/mali_kbase_jm_rb.h',
        'drivers/misc/mediatek/gpu/gpu_mali/mali_bifrost/mali-r25p0/drivers/gpu/arm/midgard/backend/gpu/mali_kbase_js_backend.c',
        'drivers/misc/mediatek/gpu/gpu_mali/mali_bifrost/mali-r25p0/drivers/gpu/arm/midgard/backend/gpu/mali_kbase_js_internal.h',
        'drivers/misc/mediatek/gpu/gpu_mali/mali_bifrost/mali-r25p0/drivers/gpu/arm/midgard/backend/gpu/mali_kbase_l2_mmu_config.c',
        'drivers/misc/mediatek/gpu/gpu_mali/mali_bifrost/mali-r25p0/drivers/gpu/arm/midgard/backend/gpu/mali_kbase_l2_mmu_config.h',
        'drivers/misc/mediatek/gpu/gpu_mali/mali_bifrost/mali-r25p0/drivers/gpu/arm/midgard/backend/gpu/mali_kbase_pm_always_on.c',
        'drivers/misc/mediatek/gpu/gpu_mali/mali_bifrost/mali-r25p0/drivers/gpu/arm/midgard/backend/gpu/mali_kbase_pm_always_on.h',
        'drivers/misc/mediatek/gpu/gpu_mali/mali_bifrost/mali-r25p0/drivers/gpu/arm/midgard/backend/gpu/mali_kbase_pm_backend.c',
        'drivers/misc/mediatek/gpu/gpu_mali/mali_bifrost/mali-r25p0/drivers/gpu/arm/midgard/backend/gpu/mali_kbase_pm_ca.c',
        'drivers/misc/mediatek/gpu/gpu_mali/mali_bifrost/mali-r25p0/drivers/gpu/arm/midgard/backend/gpu/mali_kbase_pm_ca.h',
        'drivers/misc/mediatek/gpu/gpu_mali/mali_bifrost/mali-r25p0/drivers/gpu/arm/midgard/backend/gpu/mali_kbase_pm_coarse_demand.c',
        'drivers/misc/mediatek/gpu/gpu_mali/mali_bifrost/mali-r25p0/drivers/gpu/arm/midgard/backend/gpu/mali_kbase_pm_coarse_demand.h',
        'drivers/misc/mediatek/gpu/gpu_mali/mali_bifrost/mali-r25p0/drivers/gpu/arm/midgard/backend/gpu/mali_kbase_pm_defs.h',
        'drivers/misc/mediatek/gpu/gpu_mali/mali_bifrost/mali-r25p0/drivers/gpu/arm/midgard/backend/gpu/mali_kbase_pm_driver.c',
        'drivers/misc/mediatek/gpu/gpu_mali/mali_bifrost/mali-r25p0/drivers/gpu/arm/midgard/backend/gpu/mali_kbase_pm_internal.h',
        'drivers/misc/mediatek/gpu/gpu_mali/mali_bifrost/mali-r25p0/drivers/gpu/arm/midgard/backend/gpu/mali_kbase_pm_l2_states.h',
        'drivers/misc/mediatek/gpu/gpu_mali/mali_bifrost/mali-r25p0/drivers/gpu/arm/midgard/backend/gpu/mali_kbase_pm_metrics.c',
        'drivers/misc/mediatek/gpu/gpu_mali/mali_bifrost/mali-r25p0/drivers/gpu/arm/midgard/backend/gpu/mali_kbase_pm_policy.c',
        'drivers/misc/mediatek/gpu/gpu_mali/mali_bifrost/mali-r25p0/drivers/gpu/arm/midgard/backend/gpu/mali_kbase_pm_policy.h',
        'drivers/misc/mediatek/gpu/gpu_mali/mali_bifrost/mali-r25p0/drivers/gpu/arm/midgard/backend/gpu/mali_kbase_pm_shader_states.h',
        'drivers/misc/mediatek/gpu/gpu_mali/mali_bifrost/mali-r25p0/drivers/gpu/arm/midgard/backend/gpu/mali_kbase_time.c',
        'drivers/misc/mediatek/gpu/gpu_mali/mali_bifrost/mali-r25p0/drivers/gpu/arm/midgard/context/backend/mali_kbase_context_jm.c',
        'drivers/misc/mediatek/gpu/gpu_mali/mali_bifrost/mali-r25p0/drivers/gpu/arm/midgard/context/mali_kbase_context.c',
        'drivers/misc/mediatek/gpu/gpu_mali/mali_bifrost/mali-r25p0/drivers/gpu/arm/midgard/context/mali_kbase_context.h',
        'drivers/misc/mediatek/gpu/gpu_mali/mali_bifrost/mali-r25p0/drivers/gpu/arm/midgard/context/mali_kbase_context_internal.h',
        'drivers/misc/mediatek/gpu/gpu_mali/mali_bifrost/mali-r25p0/drivers/gpu/arm/midgard/debug/backend/mali_kbase_debug_ktrace_jm.c',
        'drivers/misc/mediatek/gpu/gpu_mali/mali_bifrost/mali-r25p0/drivers/gpu/arm/midgard/debug/backend/mali_kbase_debug_ktrace_jm.h',
        'drivers/misc/mediatek/gpu/gpu_mali/mali_bifrost/mali-r25p0/drivers/gpu/arm/midgard/debug/mali_kbase_debug_ktrace.c',
        'drivers/misc/mediatek/gpu/gpu_mali/mali_bifrost/mali-r25p0/drivers/gpu/arm/midgard/debug/mali_kbase_debug_ktrace.h',
        'drivers/misc/mediatek/gpu/gpu_mali/mali_bifrost/mali-r25p0/drivers/gpu/arm/midgard/debug/mali_kbase_debug_ktrace_defs.h',
        'drivers/misc/mediatek/gpu/gpu_mali/mali_bifrost/mali-r25p0/drivers/gpu/arm/midgard/debug/mali_kbase_debug_ktrace_internal.h',
        'drivers/misc/mediatek/gpu/gpu_mali/mali_bifrost/mali-r25p0/drivers/gpu/arm/midgard/debug/mali_kbase_debug_linux_ktrace.h',
        'drivers/misc/mediatek/gpu/gpu_mali/mali_bifrost/mali-r25p0/drivers/gpu/arm/midgard/device/backend/mali_kbase_device_jm.c',
        'drivers/misc/mediatek/gpu/gpu_mali/mali_bifrost/mali-r25p0/drivers/gpu/arm/midgard/device/mali_kbase_device.c',
        'drivers/misc/mediatek/gpu/gpu_mali/mali_bifrost/mali-r25p0/drivers/gpu/arm/midgard/device/mali_kbase_device.h',
        'drivers/misc/mediatek/gpu/gpu_mali/mali_bifrost/mali-r25p0/drivers/gpu/arm/midgard/device/mali_kbase_device_internal.h',
        'drivers/misc/mediatek/gpu/gpu_mali/mali_bifrost/mali-r25p0/drivers/gpu/arm/midgard/gpu/backend/mali_kbase_gpu_fault_jm.c',
        'drivers/misc/mediatek/gpu/gpu_mali/mali_bifrost/mali-r25p0/drivers/gpu/arm/midgard/gpu/backend/mali_kbase_gpu_regmap_jm.h',
        'drivers/misc/mediatek/gpu/gpu_mali/mali_bifrost/mali-r25p0/drivers/gpu/arm/midgard/gpu/mali_kbase_gpu.c',
        'drivers/misc/mediatek/gpu/gpu_mali/mali_bifrost/mali-r25p0/drivers/gpu/arm/midgard/gpu/mali_kbase_gpu_coherency.h',
        'drivers/misc/mediatek/gpu/gpu_mali/mali_bifrost/mali-r25p0/drivers/gpu/arm/midgard/gpu/mali_kbase_gpu_fault.h',
        'drivers/misc/mediatek/gpu/gpu_mali/mali_bifrost/mali-r25p0/drivers/gpu/arm/midgard/gpu/mali_kbase_gpu_id.h',
        'drivers/misc/mediatek/gpu/gpu_mali/mali_bifrost/mali-r25p0/drivers/gpu/arm/midgard/gpu/mali_kbase_gpu_regmap.h',
        'drivers/misc/mediatek/gpu/gpu_mali/mali_bifrost/mali-r25p0/drivers/gpu/arm/midgard/include/linux/memory_group_manager.h',
        'drivers/misc/mediatek/gpu/gpu_mali/mali_bifrost/mali-r25p0/drivers/gpu/arm/midgard/ipa/mali_kbase_ipa.h',
        'drivers/misc/mediatek/gpu/gpu_mali/mali_bifrost/mali-r25p0/drivers/gpu/arm/midgard/jm/mali_base_jm_kernel.h',
        'drivers/misc/mediatek/gpu/gpu_mali/mali_bifrost/mali-r25p0/drivers/gpu/arm/midgard/jm/mali_kbase_jm_defs.h',
        'drivers/misc/mediatek/gpu/gpu_mali/mali_bifrost/mali-r25p0/drivers/gpu/arm/midgard/jm/mali_kbase_jm_ioctl.h',
        'drivers/misc/mediatek/gpu/gpu_mali/mali_bifrost/mali-r25p0/drivers/gpu/arm/midgard/jm/mali_kbase_jm_js.h',
        'drivers/misc/mediatek/gpu/gpu_mali/mali_bifrost/mali-r25p0/drivers/gpu/arm/midgard/jm/mali_kbase_js_defs.h',
        'drivers/misc/mediatek/gpu/gpu_mali/mali_bifrost/mali-r25p0/drivers/gpu/arm/midgard/mali_base_hwconfig_features.h',
        'drivers/misc/mediatek/gpu/gpu_mali/mali_bifrost/mali-r25p0/drivers/gpu/arm/midgard/mali_base_hwconfig_issues.h',
        'drivers/misc/mediatek/gpu/gpu_mali/mali_bifrost/mali-r25p0/drivers/gpu/arm/midgard/mali_base_kernel.h',
        'drivers/misc/mediatek/gpu/gpu_mali/mali_bifrost/mali-r25p0/drivers/gpu/arm/midgard/mali_base_mem_priv.h',
        'drivers/misc/mediatek/gpu/gpu_mali/mali_bifrost/mali-r25p0/drivers/gpu/arm/midgard/mali_gpu_mem_trace.h',
        'drivers/misc/mediatek/gpu/gpu_mali/mali_bifrost/mali-r25p0/drivers/gpu/arm/midgard/mali_gputrace.c',
        'drivers/misc/mediatek/gpu/gpu_mali/mali_bifrost/mali-r25p0/drivers/gpu/arm/midgard/mali_kbase.h',
        'drivers/misc/mediatek/gpu/gpu_mali/mali_bifrost/mali-r25p0/drivers/gpu/arm/midgard/mali_kbase_as_fault_debugfs.c',
        'drivers/misc/mediatek/gpu/gpu_mali/mali_bifrost/mali-r25p0/drivers/gpu/arm/midgard/mali_kbase_as_fault_debugfs.h',
        'drivers/misc/mediatek/gpu/gpu_mali/mali_bifrost/mali-r25p0/drivers/gpu/arm/midgard/mali_kbase_bits.h',
        'drivers/misc/mediatek/gpu/gpu_mali/mali_bifrost/mali-r25p0/drivers/gpu/arm/midgard/mali_kbase_cache_policy.c',
        'drivers/misc/mediatek/gpu/gpu_mali/mali_bifrost/mali-r25p0/drivers/gpu/arm/midgard/mali_kbase_cache_policy.h',
        'drivers/misc/mediatek/gpu/gpu_mali/mali_bifrost/mali-r25p0/drivers/gpu/arm/midgard/mali_kbase_caps.h',
        'drivers/misc/mediatek/gpu/gpu_mali/mali_bifrost/mali-r25p0/drivers/gpu/arm/midgard/mali_kbase_ccswe.c',
        'drivers/misc/mediatek/gpu/gpu_mali/mali_bifrost/mali-r25p0/drivers/gpu/arm/midgard/mali_kbase_ccswe.h',
        'drivers/misc/mediatek/gpu/gpu_mali/mali_bifrost/mali-r25p0/drivers/gpu/arm/midgard/mali_kbase_config.c',
        'drivers/misc/mediatek/gpu/gpu_mali/mali_bifrost/mali-r25p0/drivers/gpu/arm/midgard/mali_kbase_config.h',
        'drivers/misc/mediatek/gpu/gpu_mali/mali_bifrost/mali-r25p0/drivers/gpu/arm/midgard/mali_kbase_config_defaults.h',
        'drivers/misc/mediatek/gpu/gpu_mali/mali_bifrost/mali-r25p0/drivers/gpu/arm/midgard/mali_kbase_core_linux.c',
        'drivers/misc/mediatek/gpu/gpu_mali/mali_bifrost/mali-r25p0/drivers/gpu/arm/midgard/mali_kbase_cs_experimental.h',
        'drivers/misc/mediatek/gpu/gpu_mali/mali_bifrost/mali-r25p0/drivers/gpu/arm/midgard/mali_kbase_ctx_sched.c',
        'drivers/misc/mediatek/gpu/gpu_mali/mali_bifrost/mali-r25p0/drivers/gpu/arm/midgard/mali_kbase_ctx_sched.h',
        'drivers/misc/mediatek/gpu/gpu_mali/mali_bifrost/mali-r25p0/drivers/gpu/arm/midgard/mali_kbase_debug.c',
        'drivers/misc/mediatek/gpu/gpu_mali/mali_bifrost/mali-r25p0/drivers/gpu/arm/midgard/mali_kbase_debug.h',
        'drivers/misc/mediatek/gpu/gpu_mali/mali_bifrost/mali-r25p0/drivers/gpu/arm/midgard/mali_kbase_debug_job_fault.c',
        'drivers/misc/mediatek/gpu/gpu_mali/mali_bifrost/mali-r25p0/drivers/gpu/arm/midgard/mali_kbase_debug_job_fault.h',
        'drivers/misc/mediatek/gpu/gpu_mali/mali_bifrost/mali-r25p0/drivers/gpu/arm/midgard/mali_kbase_debug_mem_view.c',
        'drivers/misc/mediatek/gpu/gpu_mali/mali_bifrost/mali-r25p0/drivers/gpu/arm/midgard/mali_kbase_debug_mem_view.h',
        'drivers/misc/mediatek/gpu/gpu_mali/mali_bifrost/mali-r25p0/drivers/gpu/arm/midgard/mali_kbase_debugfs_helper.c',
        'drivers/misc/mediatek/gpu/gpu_mali/mali_bifrost/mali-r25p0/drivers/gpu/arm/midgard/mali_kbase_debugfs_helper.h',
        'drivers/misc/mediatek/gpu/gpu_mali/mali_bifrost/mali-r25p0/drivers/gpu/arm/midgard/mali_kbase_defs.h',
        'drivers/misc/mediatek/gpu/gpu_mali/mali_bifrost/mali-r25p0/drivers/gpu/arm/midgard/mali_kbase_disjoint_events.c',
        'drivers/misc/mediatek/gpu/gpu_mali/mali_bifrost/mali-r25p0/drivers/gpu/arm/midgard/mali_kbase_dma_fence.h',
        'drivers/misc/mediatek/gpu/gpu_mali/mali_bifrost/mali-r25p0/drivers/gpu/arm/midgard/mali_kbase_dummy_job_wa.c',
        'drivers/misc/mediatek/gpu/gpu_mali/mali_bifrost/mali-r25p0/drivers/gpu/arm/midgard/mali_kbase_dummy_job_wa.h',
        'drivers/misc/mediatek/gpu/gpu_mali/mali_bifrost/mali-r25p0/drivers/gpu/arm/midgard/mali_kbase_event.c',
        'drivers/misc/mediatek/gpu/gpu_mali/mali_bifrost/mali-r25p0/drivers/gpu/arm/midgard/mali_kbase_fence.c',
        'drivers/misc/mediatek/gpu/gpu_mali/mali_bifrost/mali-r25p0/drivers/gpu/arm/midgard/mali_kbase_fence.h',
        'drivers/misc/mediatek/gpu/gpu_mali/mali_bifrost/mali-r25p0/drivers/gpu/arm/midgard/mali_kbase_fence_defs.h',
        'drivers/misc/mediatek/gpu/gpu_mali/mali_bifrost/mali-r25p0/drivers/gpu/arm/midgard/mali_kbase_gator.h',
        'drivers/misc/mediatek/gpu/gpu_mali/mali_bifrost/mali-r25p0/drivers/gpu/arm/midgard/mali_kbase_gator_api.c',
        'drivers/misc/mediatek/gpu/gpu_mali/mali_bifrost/mali-r25p0/drivers/gpu/arm/midgard/mali_kbase_gator_api.h',
        'drivers/misc/mediatek/gpu/gpu_mali/mali_bifrost/mali-r25p0/drivers/gpu/arm/midgard/mali_kbase_gator_hwcnt_names.h',
        'drivers/misc/mediatek/gpu/gpu_mali/mali_bifrost/mali-r25p0/drivers/gpu/arm/midgard/mali_kbase_gator_hwcnt_names_tbex.h',
        'drivers/misc/mediatek/gpu/gpu_mali/mali_bifrost/mali-r25p0/drivers/gpu/arm/midgard/mali_kbase_gator_hwcnt_names_tgox.h',
        'drivers/misc/mediatek/gpu/gpu_mali/mali_bifrost/mali-r25p0/drivers/gpu/arm/midgard/mali_kbase_gator_hwcnt_names_thex.h',
        'drivers/misc/mediatek/gpu/gpu_mali/mali_bifrost/mali-r25p0/drivers/gpu/arm/midgard/mali_kbase_gator_hwcnt_names_tmix.h',
        'drivers/misc/mediatek/gpu/gpu_mali/mali_bifrost/mali-r25p0/drivers/gpu/arm/midgard/mali_kbase_gator_hwcnt_names_tnax.h',
        'drivers/misc/mediatek/gpu/gpu_mali/mali_bifrost/mali-r25p0/drivers/gpu/arm/midgard/mali_kbase_gator_hwcnt_names_tnox.h',
        'drivers/misc/mediatek/gpu/gpu_mali/mali_bifrost/mali-r25p0/drivers/gpu/arm/midgard/mali_kbase_gator_hwcnt_names_tsix.h',
        'drivers/misc/mediatek/gpu/gpu_mali/mali_bifrost/mali-r25p0/drivers/gpu/arm/midgard/mali_kbase_gator_hwcnt_names_ttrx.h',
        'drivers/misc/mediatek/gpu/gpu_mali/mali_bifrost/mali-r25p0/drivers/gpu/arm/midgard/mali_kbase_gpu_memory_debugfs.c',
        'drivers/misc/mediatek/gpu/gpu_mali/mali_bifrost/mali-r25p0/drivers/gpu/arm/midgard/mali_kbase_gpu_memory_debugfs.h',
        'drivers/misc/mediatek/gpu/gpu_mali/mali_bifrost/mali-r25p0/drivers/gpu/arm/midgard/mali_kbase_gpuprops.c',
        'drivers/misc/mediatek/gpu/gpu_mali/mali_bifrost/mali-r25p0/drivers/gpu/arm/midgard/mali_kbase_gpuprops.h',
        'drivers/misc/mediatek/gpu/gpu_mali/mali_bifrost/mali-r25p0/drivers/gpu/arm/midgard/mali_kbase_gpuprops_types.h',
        'drivers/misc/mediatek/gpu/gpu_mali/mali_bifrost/mali-r25p0/drivers/gpu/arm/midgard/mali_kbase_hw.c',
        'drivers/misc/mediatek/gpu/gpu_mali/mali_bifrost/mali-r25p0/drivers/gpu/arm/midgard/mali_kbase_hw.h',
        'drivers/misc/mediatek/gpu/gpu_mali/mali_bifrost/mali-r25p0/drivers/gpu/arm/midgard/mali_kbase_hwaccess_backend.h',
        'drivers/misc/mediatek/gpu/gpu_mali/mali_bifrost/mali-r25p0/drivers/gpu/arm/midgard/mali_kbase_hwaccess_defs.h',
        'drivers/misc/mediatek/gpu/gpu_mali/mali_bifrost/mali-r25p0/drivers/gpu/arm/midgard/mali_kbase_hwaccess_gpuprops.h',
        'drivers/misc/mediatek/gpu/gpu_mali/mali_bifrost/mali-r25p0/drivers/gpu/arm/midgard/mali_kbase_hwaccess_instr.h',
        'drivers/misc/mediatek/gpu/gpu_mali/mali_bifrost/mali-r25p0/drivers/gpu/arm/midgard/mali_kbase_hwaccess_jm.h',
        'drivers/misc/mediatek/gpu/gpu_mali/mali_bifrost/mali-r25p0/drivers/gpu/arm/midgard/mali_kbase_hwaccess_pm.h',
        'drivers/misc/mediatek/gpu/gpu_mali/mali_bifrost/mali-r25p0/drivers/gpu/arm/midgard/mali_kbase_hwaccess_time.h',
        'drivers/misc/mediatek/gpu/gpu_mali/mali_bifrost/mali-r25p0/drivers/gpu/arm/midgard/mali_kbase_hwcnt.c',
        'drivers/misc/mediatek/gpu/gpu_mali/mali_bifrost/mali-r25p0/drivers/gpu/arm/midgard/mali_kbase_hwcnt_accumulator.h',
        'drivers/misc/mediatek/gpu/gpu_mali/mali_bifrost/mali-r25p0/drivers/gpu/arm/midgard/mali_kbase_hwcnt_backend.h',
        'drivers/misc/mediatek/gpu/gpu_mali/mali_bifrost/mali-r25p0/drivers/gpu/arm/midgard/mali_kbase_hwcnt_backend_jm.c',
        'drivers/misc/mediatek/gpu/gpu_mali/mali_bifrost/mali-r25p0/drivers/gpu/arm/midgard/mali_kbase_hwcnt_backend_jm.h',
        'drivers/misc/mediatek/gpu/gpu_mali/mali_bifrost/mali-r25p0/drivers/gpu/arm/midgard/mali_kbase_hwcnt_context.h',
        'drivers/misc/mediatek/gpu/gpu_mali/mali_bifrost/mali-r25p0/drivers/gpu/arm/midgard/mali_kbase_hwcnt_gpu.c',
        'drivers/misc/mediatek/gpu/gpu_mali/mali_bifrost/mali-r25p0/drivers/gpu/arm/midgard/mali_kbase_hwcnt_gpu.h',
        'drivers/misc/mediatek/gpu/gpu_mali/mali_bifrost/mali-r25p0/drivers/gpu/arm/midgard/mali_kbase_hwcnt_legacy.c',
        'drivers/misc/mediatek/gpu/gpu_mali/mali_bifrost/mali-r25p0/drivers/gpu/arm/midgard/mali_kbase_hwcnt_legacy.h',
        'drivers/misc/mediatek/gpu/gpu_mali/mali_bifrost/mali-r25p0/drivers/gpu/arm/midgard/mali_kbase_hwcnt_reader.h',
        'drivers/misc/mediatek/gpu/gpu_mali/mali_bifrost/mali-r25p0/drivers/gpu/arm/midgard/mali_kbase_hwcnt_types.c',
        'drivers/misc/mediatek/gpu/gpu_mali/mali_bifrost/mali-r25p0/drivers/gpu/arm/midgard/mali_kbase_hwcnt_types.h',
        'drivers/misc/mediatek/gpu/gpu_mali/mali_bifrost/mali-r25p0/drivers/gpu/arm/midgard/mali_kbase_hwcnt_virtualizer.c',
        'drivers/misc/mediatek/gpu/gpu_mali/mali_bifrost/mali-r25p0/drivers/gpu/arm/midgard/mali_kbase_hwcnt_virtualizer.h',
        'drivers/misc/mediatek/gpu/gpu_mali/mali_bifrost/mali-r25p0/drivers/gpu/arm/midgard/mali_kbase_ioctl.h',
        'drivers/misc/mediatek/gpu/gpu_mali/mali_bifrost/mali-r25p0/drivers/gpu/arm/midgard/mali_kbase_jd.c',
        'drivers/misc/mediatek/gpu/gpu_mali/mali_bifrost/mali-r25p0/drivers/gpu/arm/midgard/mali_kbase_jd_debugfs.c',
        'drivers/misc/mediatek/gpu/gpu_mali/mali_bifrost/mali-r25p0/drivers/gpu/arm/midgard/mali_kbase_jd_debugfs.h',
        'drivers/misc/mediatek/gpu/gpu_mali/mali_bifrost/mali-r25p0/drivers/gpu/arm/midgard/mali_kbase_jm.c',
        'drivers/misc/mediatek/gpu/gpu_mali/mali_bifrost/mali-r25p0/drivers/gpu/arm/midgard/mali_kbase_jm.h',
        'drivers/misc/mediatek/gpu/gpu_mali/mali_bifrost/mali-r25p0/drivers/gpu/arm/midgard/mali_kbase_js.c',
        'drivers/misc/mediatek/gpu/gpu_mali/mali_bifrost/mali-r25p0/drivers/gpu/arm/midgard/mali_kbase_js.h',
        'drivers/misc/mediatek/gpu/gpu_mali/mali_bifrost/mali-r25p0/drivers/gpu/arm/midgard/mali_kbase_js_ctx_attr.c',
        'drivers/misc/mediatek/gpu/gpu_mali/mali_bifrost/mali-r25p0/drivers/gpu/arm/midgard/mali_kbase_js_ctx_attr.h',
        'drivers/misc/mediatek/gpu/gpu_mali/mali_bifrost/mali-r25p0/drivers/gpu/arm/midgard/mali_kbase_kinstr_jm.c',
        'drivers/misc/mediatek/gpu/gpu_mali/mali_bifrost/mali-r25p0/drivers/gpu/arm/midgard/mali_kbase_kinstr_jm.h',
        'drivers/misc/mediatek/gpu/gpu_mali/mali_bifrost/mali-r25p0/drivers/gpu/arm/midgard/mali_kbase_kinstr_jm_reader.h',
        'drivers/misc/mediatek/gpu/gpu_mali/mali_bifrost/mali-r25p0/drivers/gpu/arm/midgard/mali_kbase_linux.h',
        'drivers/misc/mediatek/gpu/gpu_mali/mali_bifrost/mali-r25p0/drivers/gpu/arm/midgard/mali_kbase_mem.c',
        'drivers/misc/mediatek/gpu/gpu_mali/mali_bifrost/mali-r25p0/drivers/gpu/arm/midgard/mali_kbase_mem.h',
        'drivers/misc/mediatek/gpu/gpu_mali/mali_bifrost/mali-r25p0/drivers/gpu/arm/midgard/mali_kbase_mem_linux.c',
        'drivers/misc/mediatek/gpu/gpu_mali/mali_bifrost/mali-r25p0/drivers/gpu/arm/midgard/mali_kbase_mem_linux.h',
        'drivers/misc/mediatek/gpu/gpu_mali/mali_bifrost/mali-r25p0/drivers/gpu/arm/midgard/mali_kbase_mem_lowlevel.h',
        'drivers/misc/mediatek/gpu/gpu_mali/mali_bifrost/mali-r25p0/drivers/gpu/arm/midgard/mali_kbase_mem_pool.c',
        'drivers/misc/mediatek/gpu/gpu_mali/mali_bifrost/mali-r25p0/drivers/gpu/arm/midgard/mali_kbase_mem_pool_debugfs.c',
        'drivers/misc/mediatek/gpu/gpu_mali/mali_bifrost/mali-r25p0/drivers/gpu/arm/midgard/mali_kbase_mem_pool_debugfs.h',
        'drivers/misc/mediatek/gpu/gpu_mali/mali_bifrost/mali-r25p0/drivers/gpu/arm/midgard/mali_kbase_mem_pool_group.c',
        'drivers/misc/mediatek/gpu/gpu_mali/mali_bifrost/mali-r25p0/drivers/gpu/arm/midgard/mali_kbase_mem_pool_group.h',
        'drivers/misc/mediatek/gpu/gpu_mali/mali_bifrost/mali-r25p0/drivers/gpu/arm/midgard/mali_kbase_mem_profile_debugfs.c',
        'drivers/misc/mediatek/gpu/gpu_mali/mali_bifrost/mali-r25p0/drivers/gpu/arm/midgard/mali_kbase_mem_profile_debugfs.h',
        'drivers/misc/mediatek/gpu/gpu_mali/mali_bifrost/mali-r25p0/drivers/gpu/arm/midgard/mali_kbase_mem_profile_debugfs_buf_size.h',
        'drivers/misc/mediatek/gpu/gpu_mali/mali_bifrost/mali-r25p0/drivers/gpu/arm/midgard/mali_kbase_mipe_gen_header.h',
        'drivers/misc/mediatek/gpu/gpu_mali/mali_bifrost/mali-r25p0/drivers/gpu/arm/midgard/mali_kbase_mipe_proto.h',
        'drivers/misc/mediatek/gpu/gpu_mali/mali_bifrost/mali-r25p0/drivers/gpu/arm/midgard/mali_kbase_native_mgm.c',
        'drivers/misc/mediatek/gpu/gpu_mali/mali_bifrost/mali-r25p0/drivers/gpu/arm/midgard/mali_kbase_native_mgm.h',
        'drivers/misc/mediatek/gpu/gpu_mali/mali_bifrost/mali-r25p0/drivers/gpu/arm/midgard/mali_kbase_pm.c',
        'drivers/misc/mediatek/gpu/gpu_mali/mali_bifrost/mali-r25p0/drivers/gpu/arm/midgard/mali_kbase_pm.h',
        'drivers/misc/mediatek/gpu/gpu_mali/mali_bifrost/mali-r25p0/drivers/gpu/arm/midgard/mali_kbase_regs_history_debugfs.c',
        'drivers/misc/mediatek/gpu/gpu_mali/mali_bifrost/mali-r25p0/drivers/gpu/arm/midgard/mali_kbase_regs_history_debugfs.h',
        'drivers/misc/mediatek/gpu/gpu_mali/mali_bifrost/mali-r25p0/drivers/gpu/arm/midgard/mali_kbase_reset_gpu.h',
        'drivers/misc/mediatek/gpu/gpu_mali/mali_bifrost/mali-r25p0/drivers/gpu/arm/midgard/mali_kbase_smc.c',
        'drivers/misc/mediatek/gpu/gpu_mali/mali_bifrost/mali-r25p0/drivers/gpu/arm/midgard/mali_kbase_smc.h',
        'drivers/misc/mediatek/gpu/gpu_mali/mali_bifrost/mali-r25p0/drivers/gpu/arm/midgard/mali_kbase_softjobs.c',
        'drivers/misc/mediatek/gpu/gpu_mali/mali_bifrost/mali-r25p0/drivers/gpu/arm/midgard/mali_kbase_strings.c',
        'drivers/misc/mediatek/gpu/gpu_mali/mali_bifrost/mali-r25p0/drivers/gpu/arm/midgard/mali_kbase_strings.h',
        'drivers/misc/mediatek/gpu/gpu_mali/mali_bifrost/mali-r25p0/drivers/gpu/arm/midgard/mali_kbase_sync.h',
        'drivers/misc/mediatek/gpu/gpu_mali/mali_bifrost/mali-r25p0/drivers/gpu/arm/midgard/mali_kbase_sync_common.c',
        'drivers/misc/mediatek/gpu/gpu_mali/mali_bifrost/mali-r25p0/drivers/gpu/arm/midgard/mali_kbase_sync_file.c',
        'drivers/misc/mediatek/gpu/gpu_mali/mali_bifrost/mali-r25p0/drivers/gpu/arm/midgard/mali_kbase_trace_gpu_mem.c',
        'drivers/misc/mediatek/gpu/gpu_mali/mali_bifrost/mali-r25p0/drivers/gpu/arm/midgard/mali_kbase_trace_gpu_mem.h',
        'drivers/misc/mediatek/gpu/gpu_mali/mali_bifrost/mali-r25p0/drivers/gpu/arm/midgard/mali_kbase_utility.h',
        'drivers/misc/mediatek/gpu/gpu_mali/mali_bifrost/mali-r25p0/drivers/gpu/arm/midgard/mali_kbase_vinstr.c',
        'drivers/misc/mediatek/gpu/gpu_mali/mali_bifrost/mali-r25p0/drivers/gpu/arm/midgard/mali_kbase_vinstr.h',
        'drivers/misc/mediatek/gpu/gpu_mali/mali_bifrost/mali-r25p0/drivers/gpu/arm/midgard/mali_linux_trace.h',
        'drivers/misc/mediatek/gpu/gpu_mali/mali_bifrost/mali-r25p0/drivers/gpu/arm/midgard/mali_malisw.h',
        'drivers/misc/mediatek/gpu/gpu_mali/mali_bifrost/mali-r25p0/drivers/gpu/arm/midgard/mali_power_gpu_frequency_trace.c',
        'drivers/misc/mediatek/gpu/gpu_mali/mali_bifrost/mali-r25p0/drivers/gpu/arm/midgard/mali_power_gpu_frequency_trace.h',
        'drivers/misc/mediatek/gpu/gpu_mali/mali_bifrost/mali-r25p0/drivers/gpu/arm/midgard/mmu/backend/mali_kbase_mmu_jm.c',
        'drivers/misc/mediatek/gpu/gpu_mali/mali_bifrost/mali-r25p0/drivers/gpu/arm/midgard/mmu/mali_kbase_mmu.c',
        'drivers/misc/mediatek/gpu/gpu_mali/mali_bifrost/mali-r25p0/drivers/gpu/arm/midgard/mmu/mali_kbase_mmu.h',
        'drivers/misc/mediatek/gpu/gpu_mali/mali_bifrost/mali-r25p0/drivers/gpu/arm/midgard/mmu/mali_kbase_mmu_hw.h',
        'drivers/misc/mediatek/gpu/gpu_mali/mali_bifrost/mali-r25p0/drivers/gpu/arm/midgard/mmu/mali_kbase_mmu_hw_direct.c',
        'drivers/misc/mediatek/gpu/gpu_mali/mali_bifrost/mali-r25p0/drivers/gpu/arm/midgard/mmu/mali_kbase_mmu_internal.h',
        'drivers/misc/mediatek/gpu/gpu_mali/mali_bifrost/mali-r25p0/drivers/gpu/arm/midgard/mmu/mali_kbase_mmu_mode_aarch64.c',
        'drivers/misc/mediatek/gpu/gpu_mali/mali_bifrost/mali-r25p0/drivers/gpu/arm/midgard/mmu/mali_kbase_mmu_mode_lpae.c',
        'drivers/misc/mediatek/gpu/gpu_mali/mali_bifrost/mali-r25p0/drivers/gpu/arm/midgard/platform/mt6771/Kbuild',
        'drivers/misc/mediatek/gpu/gpu_mali/mali_bifrost/mali-r25p0/drivers/gpu/arm/midgard/platform/mt6771/mali_kbase_config_mt6771.c',
        'drivers/misc/mediatek/gpu/gpu_mali/mali_bifrost/mali-r25p0/drivers/gpu/arm/midgard/platform/mt6771/mali_kbase_config_platform.h',
        'drivers/misc/mediatek/gpu/gpu_mali/mali_bifrost/mali-r25p0/drivers/gpu/arm/midgard/platform/mt6771/mali_kbase_cpu_mt6771.c',
        'drivers/misc/mediatek/gpu/gpu_mali/mali_bifrost/mali-r25p0/drivers/gpu/arm/midgard/platform/mt6771/mali_kbase_cpu_mt6771.h',
        'drivers/misc/mediatek/gpu/gpu_mali/mali_bifrost/mali-r25p0/drivers/gpu/arm/midgard/platform/mtk_mfg_counter.h',
        'drivers/misc/mediatek/gpu/gpu_mali/mali_bifrost/mali-r25p0/drivers/gpu/arm/midgard/platform/mtk_platform_common.h',
        'drivers/misc/mediatek/gpu/gpu_mali/mali_bifrost/mali-r25p0/drivers/gpu/arm/midgard/platform/mtk_platform_common/Kbuild',
        'drivers/misc/mediatek/gpu/gpu_mali/mali_bifrost/mali-r25p0/drivers/gpu/arm/midgard/platform/mtk_platform_common/mtk_mfg_counter.c',
        'drivers/misc/mediatek/gpu/gpu_mali/mali_bifrost/mali-r25p0/drivers/gpu/arm/midgard/platform/mtk_platform_common/mtk_platform_common.c',
        'drivers/misc/mediatek/gpu/gpu_mali/mali_bifrost/mali-r25p0/drivers/gpu/arm/midgard/protected_mode_switcher.h',
        'drivers/misc/mediatek/gpu/gpu_mali/mali_bifrost/mali-r25p0/drivers/gpu/arm/midgard/thirdparty/mali_kbase_mmap.c',
        'drivers/misc/mediatek/gpu/gpu_mali/mali_bifrost/mali-r25p0/drivers/gpu/arm/midgard/tl/backend/mali_kbase_timeline_jm.c',
        'drivers/misc/mediatek/gpu/gpu_mali/mali_bifrost/mali-r25p0/drivers/gpu/arm/midgard/tl/mali_kbase_timeline.c',
        'drivers/misc/mediatek/gpu/gpu_mali/mali_bifrost/mali-r25p0/drivers/gpu/arm/midgard/tl/mali_kbase_timeline.h',
        'drivers/misc/mediatek/gpu/gpu_mali/mali_bifrost/mali-r25p0/drivers/gpu/arm/midgard/tl/mali_kbase_timeline_io.c',
        'drivers/misc/mediatek/gpu/gpu_mali/mali_bifrost/mali-r25p0/drivers/gpu/arm/midgard/tl/mali_kbase_timeline_priv.h',
        'drivers/misc/mediatek/gpu/gpu_mali/mali_bifrost/mali-r25p0/drivers/gpu/arm/midgard/tl/mali_kbase_tl_serialize.h',
        'drivers/misc/mediatek/gpu/gpu_mali/mali_bifrost/mali-r25p0/drivers/gpu/arm/midgard/tl/mali_kbase_tlstream.c',
        'drivers/misc/mediatek/gpu/gpu_mali/mali_bifrost/mali-r25p0/drivers/gpu/arm/midgard/tl/mali_kbase_tlstream.h',
        'drivers/misc/mediatek/gpu/gpu_mali/mali_bifrost/mali-r25p0/drivers/gpu/arm/midgard/tl/mali_kbase_tracepoints.c',
        'drivers/misc/mediatek/gpu/gpu_mali/mali_bifrost/mali-r25p0/drivers/gpu/arm/midgard/tl/mali_kbase_tracepoints.h',
        'drivers/misc/mediatek/gpu/hal/Makefile',
        'drivers/misc/mediatek/gpu/hal/mtk_gpu_utility.c',
        'drivers/misc/mediatek/gpu/hal/mtk_gpu_utility.h',
        'drivers/misc/mediatek/include/mt-plat/fpsgo_common.h',
        'drivers/misc/mediatek/include/mt-plat/mt6771/include/mach/mtk_cpufreq_api.h',
        'drivers/misc/mediatek/include/mt-plat/mt6771/include/mach/mtk_pbm.h',
        'drivers/misc/mediatek/include/mt-plat/mt6771/include/mach/mtk_pmic.h',
        'drivers/misc/mediatek/include/mt-plat/mtk_cpufreq_common_api.h',
        'drivers/misc/mediatek/include/mt-plat/mtk_pmic_wrap.h',
        'drivers/misc/mediatek/include/mt-plat/mtk_thermal_typedefs.h',
        'drivers/misc/mediatek/thermal/mt6771/inc/mach/mtk_thermal.h',
        'drivers/watchdog/mediatek/include/ext_wd_drv.h',
        'drivers/watchdog/mediatek/wdt/common/wdt_v2/mtk_wdt.h',
        'include/trace/events/gpu.h',
    ],
    '0027-mt6771-zone-movable-cma.patch': [
        'drivers/misc/mediatek/zone_movable_cma/Makefile',
        'drivers/misc/mediatek/zone_movable_cma/single_cma.c',
        'drivers/misc/mediatek/zone_movable_cma/single_cma.h',
        'drivers/misc/mediatek/zone_movable_cma/zmc_notify.c',
        'include/linux/cma.h',
        'include/linux/gfp.h',
        'mm/Kconfig',
        'mm/cma.c',
    ],
    '0028-mtk-charger.patch': [
        'drivers/iio/adc/mt6577_auxadc.c',
        'drivers/misc/mediatek/include/mt-plat/charger_class.h',
        'drivers/misc/mediatek/include/mt-plat/charger_type.h',
        'drivers/misc/mediatek/include/mt-plat/mtk_battery.h',
        'drivers/misc/mediatek/include/mt-plat/mtk_charger.h',
        'drivers/misc/mediatek/include/mt-plat/prop_chgalgo_class.h',
        'drivers/misc/mediatek/pmic/mt6370/mt6370_pmu_charger.c',
        'drivers/misc/mediatek/power/Makefile',
        'drivers/misc/mediatek/power/mt6771/Makefile',
        'drivers/misc/mediatek/power/mt6771/mtk_battery_intf.c',
        'drivers/power/supply/mediatek/Makefile',
        'drivers/power/supply/mediatek/battery/Kconfig',
        'drivers/power/supply/mediatek/charger/Kconfig',
        'drivers/power/supply/mediatek/charger/Makefile',
        'drivers/power/supply/mediatek/charger/adapter_class.c',
        'drivers/power/supply/mediatek/charger/adapter_class.h',
        'drivers/power/supply/mediatek/charger/charger_class.c',
        'drivers/power/supply/mediatek/charger/mtk_charger.c',
        'drivers/power/supply/mediatek/charger/mtk_charger_glue.c',
        'drivers/power/supply/mediatek/charger/mtk_charger_init.h',
        'drivers/power/supply/mediatek/charger/mtk_charger_intf.h',
        'drivers/power/supply/mediatek/charger/mtk_chg_type_det.c',
        'drivers/power/supply/mediatek/charger/mtk_pdc_intf.h',
        'drivers/power/supply/mediatek/charger/mtk_pe20_intf.h',
        'drivers/power/supply/mediatek/charger/mtk_pe40_intf.h',
        'drivers/power/supply/mediatek/charger/mtk_pe50_intf.h',
        'drivers/power/supply/mediatek/charger/mtk_pe_intf.h',
        'drivers/power/supply/mediatek/charger/mtk_smartcharging.h',
        'drivers/power/supply/mediatek/charger/mtk_switch_charging.c',
        'drivers/power/supply/mediatek/charger/mtk_switch_charging.h',
        'drivers/power/supply/mediatek/misc/Makefile',
        'drivers/power/supply/mediatek/misc/mtk_gauge_time_service.c',
        'drivers/power/supply/mediatek/misc/mtk_gauge_time_service.h',
    ],
    '0029-mtk-kpd.patch': [
        'drivers/input/keyboard/mediatek/Kconfig',
        'drivers/input/keyboard/mediatek/Makefile',
        'drivers/input/keyboard/mediatek/kpd-mt6358.c',
        'drivers/input/keyboard/mediatek/kpd.c',
        'drivers/input/keyboard/mediatek/kpd.h',
        'drivers/input/keyboard/mediatek/mt6771/hal_kpd.c',
        'drivers/input/keyboard/mediatek/mt6771/hal_kpd.h',
    ],
    '0030-mt6771-thermal.patch': [
        'drivers/thermal/cpufreq_cooling.c',
        'drivers/thermal/mtk_thermal.c',
    ],
    '0031-mt6771-cpufreq.patch': [
        'drivers/cpufreq/cpufreq-dt-platdev.c',
        'drivers/cpufreq/mediatek-cpufreq.c',
    ],
    '0032-mtk-vibrator.patch': [
        'drivers/misc/mediatek/vibrator/Kconfig',
        'drivers/misc/mediatek/vibrator/Makefile',
        'drivers/misc/mediatek/vibrator/vibrator_drv.c',
    ],
    '0035-psci-s2idle-only.patch': [
        'drivers/firmware/psci/Kconfig',
        'drivers/firmware/psci/psci.c',
    ],
    '0036-mt6771-scp.patch': [
        'drivers/misc/mediatek/scp/Kconfig',
        'drivers/misc/mediatek/scp/Makefile',
        'drivers/misc/mediatek/scp/mt6771/Makefile',
        'drivers/misc/mediatek/scp/mt6771/scp_awake.c',
        'drivers/misc/mediatek/scp/mt6771/scp_dvfs.c',
        'drivers/misc/mediatek/scp/mt6771/scp_dvfs.h',
        'drivers/misc/mediatek/scp/mt6771/scp_excep.h',
        'drivers/misc/mediatek/scp/mt6771/scp_feature_define.h',
        'drivers/misc/mediatek/scp/mt6771/scp_feature_table.c',
        'drivers/misc/mediatek/scp/mt6771/scp_helper.h',
        'drivers/misc/mediatek/scp/mt6771/scp_ipi.h',
        'drivers/misc/mediatek/scp/mt6771/scp_reg.h',
        'drivers/misc/mediatek/scp/mt6771/scp_reservedmem_define.h',
        'drivers/misc/mediatek/scp/v01/Makefile',
        'drivers/misc/mediatek/scp/v01/scp_excep.c',
        'drivers/misc/mediatek/scp/v01/scp_helper.c',
        'drivers/misc/mediatek/scp/v01/scp_ipi.c',
        'drivers/misc/mediatek/scp/v01/scp_irq.c',
    ],
    '0037-mtk-sensor-hub.patch': [
        'drivers/staging/Kconfig',
        'drivers/staging/Makefile',
        'drivers/misc/mediatek/sensors-1.0/Kconfig',
        'drivers/misc/mediatek/sensors-1.0/Makefile',
        'drivers/misc/mediatek/sensors-1.0/accelerometer/Kconfig',
        'drivers/misc/mediatek/sensors-1.0/accelerometer/Makefile',
        'drivers/misc/mediatek/sensors-1.0/accelerometer/accel.c',
        'drivers/misc/mediatek/sensors-1.0/accelerometer/accel_factory.c',
        'drivers/misc/mediatek/sensors-1.0/accelerometer/accelhub/Kconfig',
        'drivers/misc/mediatek/sensors-1.0/accelerometer/accelhub/Makefile',
        'drivers/misc/mediatek/sensors-1.0/accelerometer/accelhub/accelhub.c',
        'drivers/misc/mediatek/sensors-1.0/accelerometer/accelhub/accelhub.h',
        'drivers/misc/mediatek/sensors-1.0/accelerometer/inc/accel.h',
        'drivers/misc/mediatek/sensors-1.0/accelerometer/inc/accel_factory.h',
        'drivers/misc/mediatek/sensors-1.0/accelerometer/inc/cust_acc.h',
        'drivers/misc/mediatek/sensors-1.0/accelgyro/inc/cust_accelgyro.h',
        'drivers/misc/mediatek/sensors-1.0/alsps/Kconfig',
        'drivers/misc/mediatek/sensors-1.0/alsps/Makefile',
        'drivers/misc/mediatek/sensors-1.0/alsps/aal_control.c',
        'drivers/misc/mediatek/sensors-1.0/alsps/alsps.c',
        'drivers/misc/mediatek/sensors-1.0/alsps/alsps_factory.c',
        'drivers/misc/mediatek/sensors-1.0/alsps/alspshub/Kconfig',
        'drivers/misc/mediatek/sensors-1.0/alsps/alspshub/Makefile',
        'drivers/misc/mediatek/sensors-1.0/alsps/alspshub/alspshub.c',
        'drivers/misc/mediatek/sensors-1.0/alsps/alspshub/alspshub.h',
        'drivers/misc/mediatek/sensors-1.0/alsps/inc/aal_control.h',
        'drivers/misc/mediatek/sensors-1.0/alsps/inc/alsps.h',
        'drivers/misc/mediatek/sensors-1.0/alsps/inc/alsps_factory.h',
        'drivers/misc/mediatek/sensors-1.0/alsps/inc/cust_alsps.h',
        'drivers/misc/mediatek/sensors-1.0/barometer/inc/cust_baro.h',
        'drivers/misc/mediatek/sensors-1.0/gyroscope/inc/cust_gyro.h',
        'drivers/misc/mediatek/sensors-1.0/hwmon/Kconfig',
        'drivers/misc/mediatek/sensors-1.0/hwmon/Makefile',
        'drivers/misc/mediatek/sensors-1.0/hwmon/hwmsen/Makefile',
        'drivers/misc/mediatek/sensors-1.0/hwmon/hwmsen/hwmsen_helper.c',
        'drivers/misc/mediatek/sensors-1.0/hwmon/include/hwmsen_helper.h',
        'drivers/misc/mediatek/sensors-1.0/hwmon/include/hwmsensor.h',
        'drivers/misc/mediatek/sensors-1.0/hwmon/include/sensor_attr.h',
        'drivers/misc/mediatek/sensors-1.0/hwmon/include/sensor_event.h',
        'drivers/misc/mediatek/sensors-1.0/hwmon/include/sensor_list.h',
        'drivers/misc/mediatek/sensors-1.0/hwmon/include/sensor_performance.h',
        'drivers/misc/mediatek/sensors-1.0/hwmon/include/sensors_io.h',
        'drivers/misc/mediatek/sensors-1.0/hwmon/sensor_attributes/Makefile',
        'drivers/misc/mediatek/sensors-1.0/hwmon/sensor_attributes/sensor_attr.c',
        'drivers/misc/mediatek/sensors-1.0/hwmon/sensor_dts/Makefile',
        'drivers/misc/mediatek/sensors-1.0/hwmon/sensor_dts/sensor_dts.c',
        'drivers/misc/mediatek/sensors-1.0/hwmon/sensor_event/Makefile',
        'drivers/misc/mediatek/sensors-1.0/hwmon/sensor_event/sensor_event.c',
        'drivers/misc/mediatek/sensors-1.0/hwmon/sensor_list/Makefile',
        'drivers/misc/mediatek/sensors-1.0/hwmon/sensor_list/sensor_list.c',
        'drivers/misc/mediatek/sensors-1.0/hwmon/sensor_performance/Makefile',
        'drivers/misc/mediatek/sensors-1.0/hwmon/sensor_performance/sensor_performance.c',
        'drivers/misc/mediatek/sensors-1.0/magnetometer/inc/cust_mag.h',
        'drivers/misc/mediatek/sensors-1.0/sensorHub/Kconfig',
        'drivers/misc/mediatek/sensors-1.0/sensorHub/Makefile',
        'drivers/misc/mediatek/sensors-1.0/sensorHub/SCP_nanoHub/Makefile',
        'drivers/misc/mediatek/sensors-1.0/sensorHub/SCP_nanoHub/SCP_nanoHub.c',
        'drivers/misc/mediatek/sensors-1.0/sensorHub/SCP_power_monitor/Makefile',
        'drivers/misc/mediatek/sensors-1.0/sensorHub/SCP_power_monitor/SCP_power_monitor.c',
        'drivers/misc/mediatek/sensors-1.0/sensorHub/inc_v1/SCP_power_monitor.h',
        'drivers/misc/mediatek/sensors-1.0/sensorHub/inc_v1/SCP_sensorHub.h',
        'drivers/misc/mediatek/sensors-1.0/sensorHub/inc_v1/cust_sensorHub.h',
        'drivers/staging/nanohub/Kconfig',
        'drivers/staging/nanohub/Makefile',
        'drivers/staging/nanohub/bl.c',
        'drivers/staging/nanohub/bl.h',
        'drivers/staging/nanohub/comms.c',
        'drivers/staging/nanohub/comms.h',
        'drivers/staging/nanohub/main.c',
        'drivers/staging/nanohub/main.h',
        'drivers/staging/nanohub/nanohub-mtk.c',
        'drivers/staging/nanohub/nanohub-mtk.h',
        'include/linux/platform_data/nanohub.h',
    ],
    '0038-mtk-audio-scaffolding.patch': [
        'sound/soc/mediatek/Kconfig',
        'sound/soc/mediatek/Makefile',
        'sound/soc/mediatek/codec/mt6358/Makefile',
        'sound/soc/mediatek/codec/mt6358/mtk-auddrv-ana.h',
        'sound/soc/mediatek/codec/mt6358/mtk-soc-analog-type.h',
        'sound/soc/mediatek/codec/mt6358/mtk-soc-codec-63xx.h',
        'sound/soc/mediatek/common/mtk-mmap-ion.h',
        'sound/soc/mediatek/common_int/Makefile',
        'sound/soc/mediatek/common_int/mtk-auddrv-clk.h',
        'sound/soc/mediatek/common_int/mtk-auddrv-common-func.h',
        'sound/soc/mediatek/common_int/mtk-auddrv-common.h',
        'sound/soc/mediatek/common_int/mtk-auddrv-def.h',
        'sound/soc/mediatek/common_int/mtk-auddrv-devtree-parser.h',
        'sound/soc/mediatek/common_int/mtk-auddrv-gpio.h',
        'sound/soc/mediatek/common_int/mtk-auddrv-kernel.h',
        'sound/soc/mediatek/common_int/mtk-auddrv-type-def.h',
        'sound/soc/mediatek/common_int/mtk-soc-afe-connection.h',
        'sound/soc/mediatek/common_int/mtk-soc-afe-control.h',
        'sound/soc/mediatek/common_int/mtk-soc-digital-type.h',
        'sound/soc/mediatek/common_int/mtk-soc-pcm-common.h',
        'sound/soc/mediatek/common_int/mtk-soc-speaker-amp.h',
        'sound/soc/mediatek/mt6771/Makefile',
        'sound/soc/mediatek/mt6771/mtk-auddrv-afe.h',
        'sound/soc/mediatek/mt6771/mtk-soc-pcm-platform.h',
        'drivers/misc/mediatek/base/power/include/mtk_spm_resource_req.h',
        'drivers/misc/mediatek/base/power/include/spm_v4/mtk_spm_resource_req.h',
    ],
    '0039-regmap-syscon-no-debugfs.patch': [
        'include/linux/regmap.h',
        'drivers/base/regmap/regmap.c',
        'drivers/mfd/syscon.c',
        'drivers/clk/clk.c',
    ],
    '0040-mtk-connectivity-adapter.patch': [
        'drivers/misc/mediatek/connectivity/Kconfig',
        'drivers/misc/mediatek/connectivity/Makefile',
        'drivers/misc/mediatek/connectivity/common/connectivity_build_in_adapter.c',
        'drivers/misc/mediatek/connectivity/common/connectivity_build_in_adapter.h',
        'drivers/misc/mediatek/connectivity/common/connectivity_platform_stubs.c',
        'drivers/misc/mediatek/connectivity/common/wmt_build_in_adapter.c',
        'drivers/misc/mediatek/connectivity/common/wmt_build_in_adapter.h',
        'drivers/misc/mediatek/include/mt-plat/mtk_wcn_cmb_stub.h',
        'drivers/misc/mediatek/base/power/include/clkbuf_v1/mtk_clkbuf_ctl.h',
        'drivers/misc/mediatek/base/power/include/clkbuf_v1/mt6771/mtk_clkbuf_hw.h',
    ],
    '0041-mtk-btif.patch': [
        'drivers/misc/mediatek/btif/Kconfig',
        'drivers/misc/mediatek/btif/Makefile',
        'drivers/misc/mediatek/btif/common/Makefile',
        'drivers/misc/mediatek/btif/common/btif_dma_plat.c',
        'drivers/misc/mediatek/btif/common/btif_plat.c',
        'drivers/misc/mediatek/btif/common/mtk_btif.c',
        'drivers/misc/mediatek/btif/common/mtk_btif_exp.c',
        'drivers/misc/mediatek/btif/common/inc/mtk_btif.h',
        'drivers/misc/mediatek/btif/common/inc/mtk_btif_exp.h',
        'drivers/misc/mediatek/btif/common/plat_inc/btif_dma_priv.h',
        'drivers/misc/mediatek/btif/common/plat_inc/btif_dma_pub.h',
        'drivers/misc/mediatek/btif/common/plat_inc/btif_priv.h',
        'drivers/misc/mediatek/btif/common/plat_inc/btif_pub.h',
        'drivers/misc/mediatek/btif/common/plat_inc/plat_common.h',
    ],
    '0042-mtk-audio-afe.patch': [
        'sound/soc/mediatek/common/Makefile',
        'sound/soc/mediatek/common/mtk-mmap-ion.c',
        'sound/soc/mediatek/common_int/mtk-auddrv-afe.c',
        'sound/soc/mediatek/common_int/mtk-auddrv-devtree-parser.c',
        'sound/soc/mediatek/common_int/mtk-auddrv-gpio.c',
        'sound/soc/mediatek/common_int/mtk-auddrv-power.h',
        'sound/soc/mediatek/common_int/mtk-soc-afe-control.c',
        'sound/soc/mediatek/common_int/mtk-soc-codec-dummy.c',
        'sound/soc/mediatek/common_int/mtk-soc-dai-routing.c',
        'sound/soc/mediatek/common_int/mtk-soc-dai-stub.c',
        'sound/soc/mediatek/common_int/mtk-soc-pcm-common.c',
        'sound/soc/mediatek/common_int/mtk-soc-pcm-component.c',
        'sound/soc/mediatek/common_int/mtk-soc-pcm-component.h',
        'sound/soc/mediatek/common_int/mtk-soc-pcm-dl1.c',
        'sound/soc/mediatek/common_int/mtk-soc-pcm-dl1-i2s0.c',
        'sound/soc/mediatek/common_int/mtk-soc-pcm-routing.c',
        'sound/soc/mediatek/common_int/mtk-soc-speaker-amp.c',
        'sound/soc/mediatek/mt6771/mt6771-sound.c',
        'sound/soc/mediatek/mt6771/mtk-auddrv-clk.c',
        'sound/soc/mediatek/mt6771/mtk-soc-afe-connection.c',
    ],
    '0043-mt6358-battery-oc.patch': [
        'drivers/mfd/Kconfig',
        'drivers/mfd/Makefile',
        'drivers/mfd/mt6358-battery-oc.c',
    ],
    '0044-mtk-audio-pcm-codec-machine.patch': [
        # The legacy MT6358 PMIC calls the codec makes (AUXADC, OTP lock), shared with accdet in 0053
        'drivers/misc/mediatek/include/mt-plat/mt6358_pmic_legacy.h',
        'drivers/misc/mediatek/pmic/mt6358/Makefile',
        'drivers/misc/mediatek/pmic/mt6358/pmic_legacy.c',
        'include/linux/soc/mediatek/pmic_wrap.h',
        'sound/soc/mediatek/codec/mt6358/mtk-auddrv-ana.c',
        'sound/soc/mediatek/codec/mt6358/mtk-soc-codec-6358.c',
        'sound/soc/mediatek/common_int/mtk-soc-machine.c',
        'sound/soc/mediatek/common_int/mtk-soc-pcm-bt-dai.c',
        'sound/soc/mediatek/common_int/mtk-soc-pcm-capture.c',
        'sound/soc/mediatek/common_int/mtk-soc-pcm-capture2.c',
        'sound/soc/mediatek/common_int/mtk-soc-pcm-deep-buffer-dl.c',
        'sound/soc/mediatek/common_int/mtk-soc-pcm-dl1-awb.c',
        'sound/soc/mediatek/common_int/mtk-soc-pcm-dl1-bt.c',
        'sound/soc/mediatek/common_int/mtk-soc-pcm-dl1-i2s0Dl1.c',
        'sound/soc/mediatek/common_int/mtk-soc-pcm-dl2.c',
        'sound/soc/mediatek/common_int/mtk-soc-pcm-dummy.c',
        'sound/soc/mediatek/common_int/mtk-soc-pcm-fm-i2s.c',
        'sound/soc/mediatek/common_int/mtk-soc-pcm-fm-i2s-awb.c',
        'sound/soc/mediatek/common_int/mtk-soc-pcm-fmtx.c',
        'sound/soc/mediatek/common_int/mtk-soc-pcm-hp-impedance.c',
        'sound/soc/mediatek/common_int/mtk-soc-pcm-i2s0-awb.c',
        'sound/soc/mediatek/common_int/mtk-soc-pcm-i2s2-adc2.c',
        'sound/soc/mediatek/common_int/mtk-soc-pcm-mrgrx.c',
        'sound/soc/mediatek/common_int/mtk-soc-pcm-mrgrx-awb.c',
        'sound/soc/mediatek/common_int/mtk-soc-pcm-uldlloopback.c',
        'sound/soc/mediatek/common_int/mtk-soc-pcm-voice-md1.c',
        'sound/soc/mediatek/common_int/mtk-soc-pcm-voice-md1-bt.c',
        'sound/soc/mediatek/common_int/mtk-soc-pcm-voice-md2.c',
        'sound/soc/mediatek/common_int/mtk-soc-pcm-voice-md2-bt.c',
        'sound/soc/mediatek/common_int/mtk-soc-pcm-voice-usb.c',
        'sound/soc/mediatek/common_int/mtk-soc-pcm-voice-usb-echoref.c',
        'sound/soc/mediatek/common_int/mtk-soc-tdm-capture.c',
        'drivers/misc/mediatek/include/mt-plat/mtk_auxadc_intf.h',
        'drivers/misc/mediatek/base/power/mcdi/include/mtk_mcdi_api.h',
    ],
    # T's st21nfc on 5.10 with stock's three changes, built in
    '0045-mtk-st21nfc.patch': [
        'drivers/misc/mediatek/nfc/Kconfig',
        'drivers/misc/mediatek/nfc/Makefile',
        'drivers/misc/mediatek/nfc/st21nfc/Makefile',
        'drivers/misc/mediatek/nfc/st21nfc/st21nfc.c',
        'drivers/misc/mediatek/nfc/st21nfc/st21nfc.h',
    ],
    # the raw I2C misc device /dev/smartpa_i2c for the FS16xx amp, built in
    '0046-fs16xx-smartpa-i2c.patch': [
        'drivers/misc/mediatek/smartpa/Kconfig',
        'drivers/misc/mediatek/smartpa/Makefile',
        'drivers/misc/mediatek/smartpa/fs16xx_i2c.c',
    ],
    # gyro, mag, step counter, situation and fusion hub drivers
    '0047-mtk-sensor-hub-rest.patch': [
        'drivers/misc/mediatek/sensors-1.0/gyroscope/Kconfig',
        'drivers/misc/mediatek/sensors-1.0/gyroscope/Makefile',
        'drivers/misc/mediatek/sensors-1.0/gyroscope/gyro_factory.c',
        'drivers/misc/mediatek/sensors-1.0/gyroscope/gyrohub/Kconfig',
        'drivers/misc/mediatek/sensors-1.0/gyroscope/gyrohub/Makefile',
        'drivers/misc/mediatek/sensors-1.0/gyroscope/gyrohub/gyrohub.c',
        'drivers/misc/mediatek/sensors-1.0/gyroscope/gyrohub/gyrohub.h',
        'drivers/misc/mediatek/sensors-1.0/gyroscope/gyroscope.c',
        'drivers/misc/mediatek/sensors-1.0/gyroscope/inc/gyro_factory.h',
        'drivers/misc/mediatek/sensors-1.0/gyroscope/inc/gyroscope.h',
        'drivers/misc/mediatek/sensors-1.0/magnetometer/Kconfig',
        'drivers/misc/mediatek/sensors-1.0/magnetometer/Makefile',
        'drivers/misc/mediatek/sensors-1.0/magnetometer/inc/mag.h',
        'drivers/misc/mediatek/sensors-1.0/magnetometer/inc/mag_factory.h',
        'drivers/misc/mediatek/sensors-1.0/magnetometer/mag.c',
        'drivers/misc/mediatek/sensors-1.0/magnetometer/mag_factory.c',
        'drivers/misc/mediatek/sensors-1.0/magnetometer/maghub/Kconfig',
        'drivers/misc/mediatek/sensors-1.0/magnetometer/maghub/Makefile',
        'drivers/misc/mediatek/sensors-1.0/magnetometer/maghub/maghub.c',
        'drivers/misc/mediatek/sensors-1.0/magnetometer/maghub/maghub.h',
        'drivers/misc/mediatek/sensors-1.0/sensorfusion/Kconfig',
        'drivers/misc/mediatek/sensors-1.0/sensorfusion/Makefile',
        'drivers/misc/mediatek/sensors-1.0/sensorfusion/fusion.c',
        'drivers/misc/mediatek/sensors-1.0/sensorfusion/fusion.h',
        'drivers/misc/mediatek/sensors-1.0/sensorfusion/gamerotvechub/Kconfig',
        'drivers/misc/mediatek/sensors-1.0/sensorfusion/gamerotvechub/Makefile',
        'drivers/misc/mediatek/sensors-1.0/sensorfusion/gamerotvechub/gamerotvechub.c',
        'drivers/misc/mediatek/sensors-1.0/sensorfusion/gamerotvechub/gamerotvechub.h',
        'drivers/misc/mediatek/sensors-1.0/sensorfusion/gmagrotvechub/Kconfig',
        'drivers/misc/mediatek/sensors-1.0/sensorfusion/gmagrotvechub/Makefile',
        'drivers/misc/mediatek/sensors-1.0/sensorfusion/gmagrotvechub/gmagrotvechub.c',
        'drivers/misc/mediatek/sensors-1.0/sensorfusion/gmagrotvechub/gmagrotvechub.h',
        'drivers/misc/mediatek/sensors-1.0/sensorfusion/gravityhub/Kconfig',
        'drivers/misc/mediatek/sensors-1.0/sensorfusion/gravityhub/Makefile',
        'drivers/misc/mediatek/sensors-1.0/sensorfusion/gravityhub/gravityhub.c',
        'drivers/misc/mediatek/sensors-1.0/sensorfusion/gravityhub/gravityhub.h',
        'drivers/misc/mediatek/sensors-1.0/sensorfusion/linearacchub/Kconfig',
        'drivers/misc/mediatek/sensors-1.0/sensorfusion/linearacchub/Makefile',
        'drivers/misc/mediatek/sensors-1.0/sensorfusion/linearacchub/linearacchub.c',
        'drivers/misc/mediatek/sensors-1.0/sensorfusion/linearacchub/linearacchub.h',
        'drivers/misc/mediatek/sensors-1.0/sensorfusion/orienthub/Kconfig',
        'drivers/misc/mediatek/sensors-1.0/sensorfusion/orienthub/Makefile',
        'drivers/misc/mediatek/sensors-1.0/sensorfusion/orienthub/orienthub.c',
        'drivers/misc/mediatek/sensors-1.0/sensorfusion/orienthub/orienthub.h',
        'drivers/misc/mediatek/sensors-1.0/sensorfusion/rotatvechub/Kconfig',
        'drivers/misc/mediatek/sensors-1.0/sensorfusion/rotatvechub/Makefile',
        'drivers/misc/mediatek/sensors-1.0/sensorfusion/rotatvechub/rotatvechub.c',
        'drivers/misc/mediatek/sensors-1.0/sensorfusion/rotatvechub/rotatvechub.h',
        'drivers/misc/mediatek/sensors-1.0/sensorfusion/uncali_acchub/Kconfig',
        'drivers/misc/mediatek/sensors-1.0/sensorfusion/uncali_acchub/Makefile',
        'drivers/misc/mediatek/sensors-1.0/sensorfusion/uncali_acchub/uncali_acchub.c',
        'drivers/misc/mediatek/sensors-1.0/sensorfusion/uncali_acchub/uncali_acchub.h',
        'drivers/misc/mediatek/sensors-1.0/sensorfusion/uncali_gyrohub/Kconfig',
        'drivers/misc/mediatek/sensors-1.0/sensorfusion/uncali_gyrohub/Makefile',
        'drivers/misc/mediatek/sensors-1.0/sensorfusion/uncali_gyrohub/uncali_gyrohub.c',
        'drivers/misc/mediatek/sensors-1.0/sensorfusion/uncali_gyrohub/uncali_gyrohub.h',
        'drivers/misc/mediatek/sensors-1.0/sensorfusion/uncali_maghub/Kconfig',
        'drivers/misc/mediatek/sensors-1.0/sensorfusion/uncali_maghub/Makefile',
        'drivers/misc/mediatek/sensors-1.0/sensorfusion/uncali_maghub/uncali_maghub.c',
        'drivers/misc/mediatek/sensors-1.0/sensorfusion/uncali_maghub/uncali_maghub.h',
        'drivers/misc/mediatek/sensors-1.0/situation/Kconfig',
        'drivers/misc/mediatek/sensors-1.0/situation/Makefile',
        'drivers/misc/mediatek/sensors-1.0/situation/answercall/Kconfig',
        'drivers/misc/mediatek/sensors-1.0/situation/answercall/Makefile',
        'drivers/misc/mediatek/sensors-1.0/situation/answercall/ancallhub.c',
        'drivers/misc/mediatek/sensors-1.0/situation/answercall/ancallhub.h',
        'drivers/misc/mediatek/sensors-1.0/situation/device_orientation/Kconfig',
        'drivers/misc/mediatek/sensors-1.0/situation/device_orientation/Makefile',
        'drivers/misc/mediatek/sensors-1.0/situation/device_orientation/device_orientation.c',
        'drivers/misc/mediatek/sensors-1.0/situation/device_orientation/device_orientation.h',
        'drivers/misc/mediatek/sensors-1.0/situation/flat/Kconfig',
        'drivers/misc/mediatek/sensors-1.0/situation/flat/Makefile',
        'drivers/misc/mediatek/sensors-1.0/situation/flat/flat.c',
        'drivers/misc/mediatek/sensors-1.0/situation/flat/flat.h',
        'drivers/misc/mediatek/sensors-1.0/situation/glance_gesture/Kconfig',
        'drivers/misc/mediatek/sensors-1.0/situation/glance_gesture/Makefile',
        'drivers/misc/mediatek/sensors-1.0/situation/glance_gesture/glance_gesture.c',
        'drivers/misc/mediatek/sensors-1.0/situation/glance_gesture/glance_gesture.h',
        'drivers/misc/mediatek/sensors-1.0/situation/inpocket/Kconfig',
        'drivers/misc/mediatek/sensors-1.0/situation/inpocket/Makefile',
        'drivers/misc/mediatek/sensors-1.0/situation/inpocket/inpocket.c',
        'drivers/misc/mediatek/sensors-1.0/situation/inpocket/inpocket.h',
        'drivers/misc/mediatek/sensors-1.0/situation/motion_detect/Kconfig',
        'drivers/misc/mediatek/sensors-1.0/situation/motion_detect/Makefile',
        'drivers/misc/mediatek/sensors-1.0/situation/motion_detect/motion_detect.c',
        'drivers/misc/mediatek/sensors-1.0/situation/motion_detect/motion_detect.h',
        'drivers/misc/mediatek/sensors-1.0/situation/pickup_gesture/Kconfig',
        'drivers/misc/mediatek/sensors-1.0/situation/pickup_gesture/Makefile',
        'drivers/misc/mediatek/sensors-1.0/situation/pickup_gesture/pickup_gesture.c',
        'drivers/misc/mediatek/sensors-1.0/situation/pickup_gesture/pickup_gesture.h',
        'drivers/misc/mediatek/sensors-1.0/situation/sar/Kconfig',
        'drivers/misc/mediatek/sensors-1.0/situation/sar/Makefile',
        'drivers/misc/mediatek/sensors-1.0/situation/sar/sar_factory.c',
        'drivers/misc/mediatek/sensors-1.0/situation/sar/sar_factory.h',
        'drivers/misc/mediatek/sensors-1.0/situation/sar/sarhub.c',
        'drivers/misc/mediatek/sensors-1.0/situation/sar/sarhub.h',
        'drivers/misc/mediatek/sensors-1.0/situation/situation.c',
        'drivers/misc/mediatek/sensors-1.0/situation/situation.h',
        'drivers/misc/mediatek/sensors-1.0/situation/stationary/Kconfig',
        'drivers/misc/mediatek/sensors-1.0/situation/stationary/Makefile',
        'drivers/misc/mediatek/sensors-1.0/situation/stationary/stationary.c',
        'drivers/misc/mediatek/sensors-1.0/situation/stationary/stationary.h',
        'drivers/misc/mediatek/sensors-1.0/situation/tilt_detector/Kconfig',
        'drivers/misc/mediatek/sensors-1.0/situation/tilt_detector/Makefile',
        'drivers/misc/mediatek/sensors-1.0/situation/tilt_detector/tiltdetecthub.c',
        'drivers/misc/mediatek/sensors-1.0/situation/tilt_detector/tiltdetecthub.h',
        'drivers/misc/mediatek/sensors-1.0/situation/wake_gesture/Kconfig',
        'drivers/misc/mediatek/sensors-1.0/situation/wake_gesture/Makefile',
        'drivers/misc/mediatek/sensors-1.0/situation/wake_gesture/wake_gesture.c',
        'drivers/misc/mediatek/sensors-1.0/situation/wake_gesture/wake_gesture.h',
        'drivers/misc/mediatek/sensors-1.0/step_counter/Kconfig',
        'drivers/misc/mediatek/sensors-1.0/step_counter/Makefile',
        'drivers/misc/mediatek/sensors-1.0/step_counter/step_counter.c',
        'drivers/misc/mediatek/sensors-1.0/step_counter/step_counter.h',
        'drivers/misc/mediatek/sensors-1.0/step_counter/stepsignhub/Kconfig',
        'drivers/misc/mediatek/sensors-1.0/step_counter/stepsignhub/Makefile',
        'drivers/misc/mediatek/sensors-1.0/step_counter/stepsignhub/stepsignhub.c',
        'drivers/misc/mediatek/sensors-1.0/step_counter/stepsignhub/stepsignhub.h',
    ],
    # VMODEM, clkbuf flight mode, SPM MD source request and the PBM/vcorefs/AEE stubs for eccci
    '0048-mtk-ccci-platform-deps.patch': [
        'drivers/misc/mediatek/ccci_platform/Kconfig',
        'drivers/misc/mediatek/ccci_platform/Makefile',
        'drivers/misc/mediatek/ccci_platform/ccci_platform.h',
        'drivers/misc/mediatek/ccci_platform/ccci_pmic_regmap.c',
        'drivers/misc/mediatek/ccci_platform/vmd1_pmic.c',
        'drivers/misc/mediatek/ccci_platform/clkbuf_md.c',
        'drivers/misc/mediatek/ccci_platform/spm_mdsrc.c',
        'drivers/misc/mediatek/ccci_platform/ccci_platform_stubs.c',
        'drivers/misc/mediatek/pmic/include/pmic_api_buck.h',
        'drivers/misc/mediatek/pmic/include/mt6358/mtk_pmic_api_buck.h',
    ],
    # ccmni network interfaces, set_rps_map and weak stand-ins for eccci's two net port calls
    '0049-mtk-ccmni.patch': [
        'drivers/misc/mediatek/ccmni/Kconfig',
        'drivers/misc/mediatek/ccmni/Makefile',
        'drivers/misc/mediatek/ccmni/ccmni.h',
        'drivers/misc/mediatek/ccmni/ccmni.c',
        'drivers/misc/mediatek/ccmni/ccmni_ccci_weak.c',
        'drivers/misc/mediatek/rps/Makefile',
        'drivers/misc/mediatek/rps/rps_perf.h',
        'drivers/misc/mediatek/rps/rps_perf.c',
    ],
    # conn_md (LTE coex bridge) with eccci's IPC headers, the modem PA thermistor zone sensor
    # and the modem throughput coolers
    '0050-mtk-conn-md-modem-cooler.patch': [
        'drivers/misc/mediatek/conn_md/Kconfig',
        'drivers/misc/mediatek/conn_md/Makefile',
        'drivers/misc/mediatek/conn_md/conn_md.c',
        'drivers/misc/mediatek/conn_md/conn_md_exp.c',
        'drivers/misc/mediatek/conn_md/conn_md_log.c',
        'drivers/misc/mediatek/conn_md/conn_md_dump.c',
        'drivers/misc/mediatek/conn_md/conn_md_dbg.c',
        'drivers/misc/mediatek/conn_md/conn_md_test.c',
        'drivers/misc/mediatek/conn_md/include/conn_md.h',
        'drivers/misc/mediatek/conn_md/include/conn_md_dbg.h',
        'drivers/misc/mediatek/conn_md/include/conn_md_dump.h',
        'drivers/misc/mediatek/conn_md/include/conn_md_exp.h',
        'drivers/misc/mediatek/conn_md/include/conn_md_log.h',
        'drivers/misc/mediatek/eccci/port_ipc.h',
        'drivers/misc/mediatek/eccci/ccci_ipc_task_ID.h',
        'drivers/misc/mediatek/eccci/mt6771/ccci_config.h',
        'drivers/misc/mediatek/thermal/Kconfig',
        'drivers/misc/mediatek/thermal/mt6771/inc/mtk_cooler_setting.h',
        'drivers/misc/mediatek/thermal/common/thermal_zones/Makefile',
        'drivers/misc/mediatek/thermal/common/thermal_zones/mtk_ts_btsmdpa.c',
        'drivers/misc/mediatek/thermal/common/coolers/Makefile',
        'drivers/misc/mediatek/thermal/common/coolers/mtk_cooler_mutt.c',
    ],
    # eccci core, fsm, CLDMA and CCIF hif and the MT6771 platform code, with weak stand-ins
    # for ccci_util (M1) and the port layer (M3b)
    '0051-mtk-eccci-core.patch': [
        'drivers/misc/mediatek/eccci/Kconfig',
        'drivers/misc/mediatek/eccci/Makefile',
        'drivers/misc/mediatek/eccci/ccci_bm.c',
        'drivers/misc/mediatek/eccci/ccci_core.c',
        'drivers/misc/mediatek/eccci/ccci_ipc_el1_msg_id.h',
        'drivers/misc/mediatek/eccci/ccci_ipc_msg_id.h',
        'drivers/misc/mediatek/eccci/ccci_modem.c',
        'drivers/misc/mediatek/eccci/ccci_pbm_md.c',
        'drivers/misc/mediatek/eccci/ccci_port_weak.c',
        'drivers/misc/mediatek/eccci/ccci_util_weak.c',
        'drivers/misc/mediatek/eccci/fsm/Makefile',
        'drivers/misc/mediatek/eccci/fsm/ccci_fsm.c',
        'drivers/misc/mediatek/eccci/fsm/ccci_fsm_ee.c',
        'drivers/misc/mediatek/eccci/fsm/ccci_fsm_internal.h',
        'drivers/misc/mediatek/eccci/fsm/ccci_fsm_ioctl.c',
        'drivers/misc/mediatek/eccci/fsm/ccci_fsm_monitor.c',
        'drivers/misc/mediatek/eccci/fsm/ccci_fsm_poller.c',
        'drivers/misc/mediatek/eccci/fsm/ccci_fsm_scp.c',
        'drivers/misc/mediatek/eccci/fsm/ccci_fsm_sys.c',
        'drivers/misc/mediatek/eccci/fsm/ccci_fsm_sys.h',
        'drivers/misc/mediatek/eccci/fsm/mdee_dumper_v1.c',
        'drivers/misc/mediatek/eccci/fsm/mdee_dumper_v1.h',
        'drivers/misc/mediatek/eccci/fsm/mdee_dumper_v2.c',
        'drivers/misc/mediatek/eccci/fsm/mdee_dumper_v2.h',
        'drivers/misc/mediatek/eccci/fsm/mdee_dumper_v3.c',
        'drivers/misc/mediatek/eccci/fsm/mdee_dumper_v3.h',
        'drivers/misc/mediatek/eccci/fsm/mdee_dumper_v5.c',
        'drivers/misc/mediatek/eccci/fsm/mdee_dumper_v5.h',
        'drivers/misc/mediatek/eccci/hif/Makefile',
        'drivers/misc/mediatek/eccci/hif/ccci_hif.c',
        'drivers/misc/mediatek/eccci/hif/ccci_hif_ccif.c',
        'drivers/misc/mediatek/eccci/hif/ccci_hif_ccif.h',
        'drivers/misc/mediatek/eccci/hif/ccci_hif_cldma.c',
        'drivers/misc/mediatek/eccci/hif/ccci_hif_cldma.h',
        'drivers/misc/mediatek/eccci/hif/ccci_hif_dpmaif.h',
        'drivers/misc/mediatek/eccci/hif/ccci_hif_dpmaif_none.c',
        'drivers/misc/mediatek/eccci/hif/ccci_hif_internal.h',
        'drivers/misc/mediatek/eccci/hif/ccci_ringbuf.c',
        'drivers/misc/mediatek/eccci/hif/ccci_ringbuf.h',
        'drivers/misc/mediatek/eccci/hif/modem_cldma_events.h',
        'drivers/misc/mediatek/eccci/inc/ccci_bm.h',
        'drivers/misc/mediatek/eccci/inc/ccci_core.h',
        'drivers/misc/mediatek/eccci/inc/ccci_debug.h',
        'drivers/misc/mediatek/eccci/inc/ccci_fsm.h',
        'drivers/misc/mediatek/eccci/inc/ccci_hif.h',
        'drivers/misc/mediatek/eccci/inc/ccci_modem.h',
        'drivers/misc/mediatek/eccci/inc/ccci_port.h',
        'drivers/misc/mediatek/eccci/mdrf_notify_list.h',
        'drivers/misc/mediatek/eccci/modem_sys.h',
        'drivers/misc/mediatek/eccci/modem_sys1.c',
        'drivers/misc/mediatek/eccci/modem_sys3.c',
        'drivers/misc/mediatek/eccci/mt6771/Makefile',
        'drivers/misc/mediatek/eccci/mt6771/ccci_platform.c',
        'drivers/misc/mediatek/eccci/mt6771/ccci_platform.h',
        'drivers/misc/mediatek/eccci/mt6771/ccif_hif_platform.h',
        'drivers/misc/mediatek/eccci/mt6771/cldma_reg.h',
        'drivers/misc/mediatek/eccci/mt6771/md_sys1_platform.c',
        'drivers/misc/mediatek/eccci/mt6771/md_sys1_platform.h',
        'drivers/misc/mediatek/eccci/mt6771/modem_reg_base.h',
        'drivers/misc/mediatek/eccci/port/port_t.h',
    ],
    # eccci port layer (/dev/ccci_* and ttyC*, RPC, IPC, SMEM, net), udc and the mixdev event log
    '0052-mtk-eccci-port.patch': [
        'drivers/misc/mediatek/eccci/mixdev/Makefile',
        'drivers/misc/mediatek/eccci/mixdev/mix_event.c',
        'drivers/misc/mediatek/eccci/mixdev/mix_event.h',
        'drivers/misc/mediatek/eccci/port/Makefile',
        'drivers/misc/mediatek/eccci/port/ccci_port_util_weak.c',
        'drivers/misc/mediatek/eccci/port/ccci_swtp.c',
        'drivers/misc/mediatek/eccci/port/ccci_swtp.h',
        'drivers/misc/mediatek/eccci/port/port_cfg.c',
        'drivers/misc/mediatek/eccci/port/port_cfg.h',
        'drivers/misc/mediatek/eccci/port/port_char.c',
        'drivers/misc/mediatek/eccci/port/port_char.h',
        'drivers/misc/mediatek/eccci/port/port_ctlmsg.c',
        'drivers/misc/mediatek/eccci/port/port_ctlmsg.h',
        'drivers/misc/mediatek/eccci/port/port_ipc.c',
        'drivers/misc/mediatek/eccci/port/port_ipc_internal.h',
        'drivers/misc/mediatek/eccci/port/port_net.c',
        'drivers/misc/mediatek/eccci/port/port_net.h',
        'drivers/misc/mediatek/eccci/port/port_net_events.h',
        'drivers/misc/mediatek/eccci/port/port_poller.c',
        'drivers/misc/mediatek/eccci/port/port_poller.h',
        'drivers/misc/mediatek/eccci/port/port_proxy.c',
        'drivers/misc/mediatek/eccci/port/port_proxy.h',
        'drivers/misc/mediatek/eccci/port/port_rpc.c',
        'drivers/misc/mediatek/eccci/port/port_rpc.h',
        'drivers/misc/mediatek/eccci/port/port_smem.c',
        'drivers/misc/mediatek/eccci/port/port_smem.h',
        'drivers/misc/mediatek/eccci/port/port_sysmsg.c',
        'drivers/misc/mediatek/eccci/port/port_sysmsg.h',
        'drivers/misc/mediatek/eccci/port/port_udc.c',
        'drivers/misc/mediatek/eccci/port/port_udc.h',
        'drivers/misc/mediatek/eccci/udc/Makefile',
        'drivers/misc/mediatek/eccci/udc/udc.c',
        'drivers/misc/mediatek/eccci/udc/udc.h',
        'drivers/misc/mediatek/eccci/udc/udc_dictionary.h',
        'drivers/misc/mediatek/eccci/udc/udc_lib_inc/udc_zlib.h',
    ],
    # stock's ACCDET headset driver; the PMIC calls it makes are in 0044
    '0053-mtk-accdet.patch': [
        'drivers/misc/mediatek/accdet/Kconfig',
        'drivers/misc/mediatek/accdet/Makefile',
        'drivers/misc/mediatek/accdet/accdet_drv.c',
        'drivers/misc/mediatek/accdet/mt6358/Makefile',
        'drivers/misc/mediatek/accdet/mt6358/accdet.c',
        'drivers/misc/mediatek/accdet/mt6358/accdet.h',
        'drivers/misc/mediatek/accdet/mt6358/reg_accdet.h',
        'include/linux/mfd/mt6358/core.h',
    ],
    # hw_params clears the buffer with memset_io as stock 4.14, since deep buffer's can be AFE SRAM
    '0054-pcm-hw-params-memset-io.patch': ['sound/core/pcm_native.c'],
    # Stock's sunwave-fp, /dev/sunwave_fp and fingerprint_key for the stock Sunwave HAL
    '0055-sunwave-fp.patch': [
        'drivers/misc/mediatek/sunwave/Kconfig',
        'drivers/misc/mediatek/sunwave/Makefile',
        'drivers/misc/mediatek/sunwave/sf_ctl.c',
    ],
    # T's ccci_util (LK modem info, reserved memory, image header, /sys/kernel/ccci, the ccci
    # logs and /dev/ccci_md*_sta), vmap_reserved_mem and mt_irq_get_pending; hooks on 0014's ccci_util Makefile
    '0056-mtk-ccci-util.patch': [
        'drivers/misc/mediatek/ccci_util/Kconfig',
        'drivers/misc/mediatek/ccci_util/ccci_private_log.c',
        'drivers/misc/mediatek/ccci_util/ccci_util_broadcast.c',
        'drivers/misc/mediatek/ccci_util/ccci_util_ld_md_errno.c',
        'drivers/misc/mediatek/ccci_util/ccci_util_lib_fo.c',
        'drivers/misc/mediatek/ccci_util/ccci_util_lib_load_img.c',
        'drivers/misc/mediatek/ccci_util/ccci_util_lib_main.c',
        'drivers/misc/mediatek/ccci_util/ccci_util_lib_main.h',
        'drivers/misc/mediatek/ccci_util/ccci_util_lib_sys.c',
        'drivers/misc/mediatek/ccci_util/ccci_util_lib_sys.h',
        'drivers/misc/mediatek/ccci_util/ccci_util_lib_time.c',
        'drivers/misc/mediatek/ccci_util/ccci_util_log.h',
        'drivers/misc/mediatek/ccci_util/ccci_util_platform.c',
        'drivers/misc/mediatek/ccci_util/ccci_util_sib.c',
        'drivers/misc/mediatek/ccci_util/ccci_util_sib.h',
    ],
    # stock's MT6771 systracker (infra bus timeout monitor, mediatek,bus_dbg-v2), reporting
    # through the die and panic notifiers; hooks on 0014's mediatek Kconfig and Makefile
    '0057-mtk-systracker.patch': [
        'drivers/misc/mediatek/systracker/Kconfig',
        'drivers/misc/mediatek/systracker/Makefile',
        'drivers/misc/mediatek/systracker/systracker_v2.h',
        'drivers/misc/mediatek/systracker/systracker_interface_v2.c',
        'drivers/misc/mediatek/systracker/mt6771/Makefile',
        'drivers/misc/mediatek/systracker/mt6771/systracker_platform.c',
    ],
    # stock's MT6771 videocodec driver, /dev/Vcodec for the stock OMX codecs (power, clocks,
    # HW lock, IRQ wait, VDEC/VENC register mmap, the 32-bit compat path); hooks on 0014's mediatek Kconfig and Makefile
    '0058-mtk-videocodec.patch': [
        'drivers/misc/mediatek/videocodec/Kconfig',
        'drivers/misc/mediatek/videocodec/Makefile',
        'drivers/misc/mediatek/videocodec/videocodec_kernel.c',
        'drivers/misc/mediatek/videocodec/videocodec_kernel.h',
        'drivers/misc/mediatek/videocodec/include/hal_types_private.h',
        'drivers/misc/mediatek/videocodec/include/hal_types_public.h',
        'drivers/misc/mediatek/videocodec/include/val_types_private.h',
        'drivers/misc/mediatek/videocodec/include/val_types_public.h',
        'drivers/misc/mediatek/videocodec/include/kernel/hal_api.h',
        'drivers/misc/mediatek/videocodec/include/kernel/val_api_private.h',
        'drivers/misc/mediatek/videocodec/include/kernel/val_api_public.h',
        'drivers/misc/mediatek/videocodec/mt6771/Makefile',
        'drivers/misc/mediatek/videocodec/mt6771/videocodec_kernel_driver.c',
        'drivers/misc/mediatek/videocodec/mt6771/videocodec_kernel_driver.h',
        'drivers/misc/mediatek/videocodec/mt6771/common/drv/inc/drv_api.h',
        'drivers/misc/mediatek/videocodec/mt6771/common/drv/inc/dvfs_v2.h',
        'drivers/misc/mediatek/videocodec/mt6771/common/drv/src/drv_base.c',
        'drivers/misc/mediatek/videocodec/mt6771/common/drv/src/dvfs_v2.c',
        'drivers/misc/mediatek/videocodec/mt6771/common/val/src/val.c',
    ],
    # the MTK I2C calls imgsensor and cam_cal make, over i2c-mt65xx, and the
    # MM QoS calls of the camera drivers as stubs (STAGED on mmdvfs_pmqos.h).
    '0059-mtk-camera-scaffold.patch': [
        'drivers/i2c/busses/i2c-mtk.h',
        'drivers/misc/mediatek/i2c_shim/Kconfig',
        'drivers/misc/mediatek/i2c_shim/Makefile',
        'drivers/misc/mediatek/i2c_shim/mtk_i2c_shim.c',
    ],
    # imgsensor v1_1 with seninf and the mt6771 camera_hw (MT6358 rails, pins,
    # MCLK), /dev/kd_camera_hw and /dev/seninf, with the OV16880 and OV8865 drivers. The CCU header is T's.
    '0060-mtk-imgsensor.patch': [
        'drivers/misc/mediatek/imgsensor/Kconfig',
        'drivers/misc/mediatek/imgsensor/inc/kd_camera_feature.h',
        'drivers/misc/mediatek/imgsensor/inc/kd_camera_feature_enum.h',
        'drivers/misc/mediatek/imgsensor/inc/kd_camera_feature_id.h',
        'drivers/misc/mediatek/imgsensor/inc/kd_camera_hw.h',
        'drivers/misc/mediatek/imgsensor/inc/kd_camera_typedef.h',
        'drivers/misc/mediatek/imgsensor/inc/kd_imgsensor.h',
        'drivers/misc/mediatek/imgsensor/inc/kd_imgsensor_CA_TA_cmd.h',
        'drivers/misc/mediatek/imgsensor/inc/kd_imgsensor_define.h',
        'drivers/misc/mediatek/imgsensor/inc/kd_imgsensor_errcode.h',
        'drivers/misc/mediatek/imgsensor/inc/kd_seninf.h',
        'drivers/misc/mediatek/imgsensor/inc/kd_seninf_define.h',
        'drivers/misc/mediatek/imgsensor/src/Kconfig',
        'drivers/misc/mediatek/imgsensor/src/Makefile',
        'drivers/misc/mediatek/imgsensor/src/common/v1_1/imgsensor.c',
        'drivers/misc/mediatek/imgsensor/src/common/v1_1/imgsensor.h',
        'drivers/misc/mediatek/imgsensor/src/common/v1_1/imgsensor_ca.h',
        'drivers/misc/mediatek/imgsensor/src/common/v1_1/imgsensor_common.h',
        'drivers/misc/mediatek/imgsensor/src/common/v1_1/imgsensor_hw.c',
        'drivers/misc/mediatek/imgsensor/src/common/v1_1/imgsensor_hw.h',
        'drivers/misc/mediatek/imgsensor/src/common/v1_1/imgsensor_i2c.c',
        'drivers/misc/mediatek/imgsensor/src/common/v1_1/imgsensor_i2c.h',
        'drivers/misc/mediatek/imgsensor/src/common/v1_1/imgsensor_legacy.c',
        'drivers/misc/mediatek/imgsensor/src/common/v1_1/imgsensor_proc.c',
        'drivers/misc/mediatek/imgsensor/src/common/v1_1/imgsensor_proc.h',
        'drivers/misc/mediatek/imgsensor/src/common/v1_1/imgsensor_sensor.h',
        'drivers/misc/mediatek/imgsensor/src/common/v1_1/imgsensor_sensor_list.c',
        'drivers/misc/mediatek/imgsensor/src/common/v1_1/imgsensor_sensor_list.h',
        'drivers/misc/mediatek/imgsensor/src/common/v1_1/ov16880_mipi_raw/Makefile',
        'drivers/misc/mediatek/imgsensor/src/common/v1_1/ov16880_mipi_raw/ov16880mipiraw_Sensor.c',
        'drivers/misc/mediatek/imgsensor/src/common/v1_1/ov16880_mipi_raw/ov16880mipiraw_Sensor.h',
        'drivers/misc/mediatek/imgsensor/src/common/v1_1/ov16880_mipi_raw/ov16880mipiraw_otp.c',
        'drivers/misc/mediatek/imgsensor/src/common/v1_1/ov8865_mipi_raw/Makefile',
        'drivers/misc/mediatek/imgsensor/src/common/v1_1/ov8865_mipi_raw/ov8865mipiraw_Sensor.c',
        'drivers/misc/mediatek/imgsensor/src/common/v1_1/ov8865_mipi_raw/ov8865mipiraw_Sensor.h',
        'drivers/misc/mediatek/imgsensor/src/common/v1_1/seninf.c',
        'drivers/misc/mediatek/imgsensor/src/common/v1_1/seninf.h',
        'drivers/misc/mediatek/imgsensor/src/common/v1_1/seninf_common.h',
        'drivers/misc/mediatek/imgsensor/src/mt6771/Makefile',
        'drivers/misc/mediatek/imgsensor/src/mt6771/camera_hw/Makefile',
        'drivers/misc/mediatek/imgsensor/src/mt6771/camera_hw/gpio/Makefile',
        'drivers/misc/mediatek/imgsensor/src/mt6771/camera_hw/gpio/gpio.c',
        'drivers/misc/mediatek/imgsensor/src/mt6771/camera_hw/gpio/gpio.h',
        'drivers/misc/mediatek/imgsensor/src/mt6771/camera_hw/imgsensor_cfg_table.c',
        'drivers/misc/mediatek/imgsensor/src/mt6771/camera_hw/imgsensor_cfg_table.h',
        'drivers/misc/mediatek/imgsensor/src/mt6771/camera_hw/mclk/Makefile',
        'drivers/misc/mediatek/imgsensor/src/mt6771/camera_hw/mclk/mclk.c',
        'drivers/misc/mediatek/imgsensor/src/mt6771/camera_hw/mclk/mclk.h',
        'drivers/misc/mediatek/imgsensor/src/mt6771/camera_hw/regulator/Makefile',
        'drivers/misc/mediatek/imgsensor/src/mt6771/camera_hw/regulator/regulator.c',
        'drivers/misc/mediatek/imgsensor/src/mt6771/camera_hw/regulator/regulator.h',
        'drivers/misc/mediatek/imgsensor/src/mt6771/seninf/Makefile',
        'drivers/misc/mediatek/imgsensor/src/mt6771/seninf/seninf_cfg.h',
        'drivers/misc/mediatek/imgsensor/src/mt6771/seninf/seninf_clk.c',
        'drivers/misc/mediatek/imgsensor/src/mt6771/seninf/seninf_clk.h',
        'drivers/misc/mediatek/ccu/inc/ccu_imgsensor_if.h',
    ],
    # cam_cal v1, /dev/CAM_CAL_DRV for the sensor EEPROMs.
    '0061-mtk-cam-cal.patch': [
        'drivers/misc/mediatek/cam_cal/Kconfig',
        'drivers/misc/mediatek/cam_cal/inc/cam_cal.h',
        'drivers/misc/mediatek/cam_cal/inc/cam_cal_define.h',
        'drivers/misc/mediatek/cam_cal/src/Makefile',
        'drivers/misc/mediatek/cam_cal/src/common/v1/cam_cal_list.h',
        'drivers/misc/mediatek/cam_cal/src/common/v1/eeprom_driver.c',
        'drivers/misc/mediatek/cam_cal/src/common/v1/eeprom_i2c_common_driver.c',
        'drivers/misc/mediatek/cam_cal/src/common/v1/eeprom_i2c_common_driver.h',
        'drivers/misc/mediatek/cam_cal/src/common/v1/eeprom_i2c_dev.h',
        'drivers/misc/mediatek/cam_cal/src/mt6771/Makefile',
        'drivers/misc/mediatek/cam_cal/src/mt6771/cam_cal_list.c',
        'drivers/misc/mediatek/cam_cal/src/mt6771/eeprom_i2c_custom_driver.c',
        'drivers/misc/mediatek/cam_cal/src/mt6771/eeprom_i2c_custom_driver.h',
        'drivers/misc/mediatek/cam_cal/src/mt6771/eeprom_i2c_dev.c',
    ],
    # the main and sub lens drivers, /dev/MAINAF with AK7371AF.
    '0062-mtk-lens.patch': [
        'drivers/misc/mediatek/lens/Kconfig',
        'drivers/misc/mediatek/lens/Makefile',
        'drivers/misc/mediatek/lens/main/Makefile',
        'drivers/misc/mediatek/lens/main/common/ak7371af/AK7371AF.c',
        'drivers/misc/mediatek/lens/main/common/ak7371af/Makefile',
        'drivers/misc/mediatek/lens/main/inc/lens_info.h',
        'drivers/misc/mediatek/lens/main/inc/lens_list.h',
        'drivers/misc/mediatek/lens/main/main_lens.c',
        'drivers/misc/mediatek/lens/sub/Makefile',
        'drivers/misc/mediatek/lens/sub/inc/lens_info.h',
        'drivers/misc/mediatek/lens/sub/inc/lens_list.h',
        'drivers/misc/mediatek/lens/sub/sub_lens.c',
    ],
    # /dev/flashlight, the flashlight core and flashlights-mt6370 on the Richtek class.
    '0063-mtk-flashlight.patch': [
        'drivers/misc/mediatek/flashlight/Kconfig',
        'drivers/misc/mediatek/flashlight/Makefile',
        'drivers/misc/mediatek/flashlight/flashlight-core.c',
        'drivers/misc/mediatek/flashlight/flashlight-core.h',
        'drivers/misc/mediatek/flashlight/flashlight-device.c',
        'drivers/misc/mediatek/flashlight/flashlight-dt.h',
        'drivers/misc/mediatek/flashlight/flashlight.h',
        'drivers/misc/mediatek/flashlight/flashlights-mt6370.c',
    ],
    # the arch counter to monotonic time sync ISP_GET_GLOBAL_TIME uses.
    '0064-mtk-archcounter-timesync.patch': [
        'drivers/misc/mediatek/timer/timesync/Kconfig',
        'drivers/misc/mediatek/timer/timesync/Makefile',
        'drivers/misc/mediatek/timer/timesync/archcounter_timesync.c',
        'drivers/misc/mediatek/timer/timesync/archcounter_timesync.h',
    ],
    # /dev/camera-isp, /dev/camera-dip and /dev/camera-wpe from stock isp_50.
    '0065-mtk-camera-isp.patch': [
        'drivers/misc/mediatek/cameraisp/Kconfig',
        'drivers/misc/mediatek/cameraisp/Makefile',
        'drivers/misc/mediatek/cameraisp/dip/Makefile',
        'drivers/misc/mediatek/cameraisp/dip/isp_50/Makefile',
        'drivers/misc/mediatek/cameraisp/dip/isp_50/camera_dip.c',
        'drivers/misc/mediatek/cameraisp/dip/isp_50/camera_dip.h',
        'drivers/misc/mediatek/cameraisp/src/Makefile',
        'drivers/misc/mediatek/cameraisp/src/isp_50/Makefile',
        'drivers/misc/mediatek/cameraisp/src/isp_50/camera_isp.c',
        'drivers/misc/mediatek/cameraisp/src/isp_50/inc/cam_regs.h',
        'drivers/misc/mediatek/cameraisp/src/isp_50/inc/camera_isp.h',
        'drivers/misc/mediatek/cameraisp/src/isp_50/inc/met_events_camsys.h',
        'drivers/misc/mediatek/cameraisp/wpe/Makefile',
        'drivers/misc/mediatek/cameraisp/wpe/isp_50/Makefile',
        'drivers/misc/mediatek/cameraisp/wpe/isp_50/camera_wpe.c',
        'drivers/misc/mediatek/cameraisp/wpe/isp_50/inc/camera_wpe.h',
    ],
    # /dev/camera-fdvt (FDVT 4.0) and /dev/camera-rsc (isp_50 RSC with engine_request).
    '0066-mtk-camera-fdvt-rsc.patch': [
        'drivers/misc/mediatek/cameraisp/fdvt/Makefile',
        'drivers/misc/mediatek/cameraisp/fdvt/4.0/Makefile',
        'drivers/misc/mediatek/cameraisp/fdvt/4.0/camera_fdvt.c',
        'drivers/misc/mediatek/cameraisp/fdvt/4.0/inc/camera_fdvt.h',
        'drivers/misc/mediatek/cameraisp/rsc/Makefile',
        'drivers/misc/mediatek/cameraisp/rsc/engine_request.c',
        'drivers/misc/mediatek/cameraisp/rsc/engine_request.h',
        'drivers/misc/mediatek/cameraisp/rsc/isp_50/camera_rsc.c',
        'drivers/misc/mediatek/cameraisp/rsc/isp_50/camera_rsc.h',
    ],
    # CCU 2.0 with the mt6771 code, /dev/ccu.
    '0067-mtk-ccu.patch': [
        'drivers/misc/mediatek/ccu/src/2.0/Makefile',
        'drivers/misc/mediatek/ccu/src/2.0/ccu_cmn.h',
        'drivers/misc/mediatek/ccu/src/2.0/ccu_drv.c',
        'drivers/misc/mediatek/ccu/src/2.0/ccu_drv.h',
        'drivers/misc/mediatek/ccu/src/2.0/ccu_i2c.c',
        'drivers/misc/mediatek/ccu/src/2.0/ccu_i2c.h',
        'drivers/misc/mediatek/ccu/src/2.0/ccu_n3d_a.c',
        'drivers/misc/mediatek/ccu/src/2.0/ccu_n3d_a.h',
        'drivers/misc/mediatek/ccu/src/Kconfig',
        'drivers/misc/mediatek/ccu/src/Makefile',
        'drivers/misc/mediatek/ccu/src/mt6771/CCU_A_c_header.h',
        'drivers/misc/mediatek/ccu/src/mt6771/Makefile',
        'drivers/misc/mediatek/ccu/src/mt6771/ccu_ext_interface/ccu_ext_interface.h',
        'drivers/misc/mediatek/ccu/src/mt6771/ccu_ext_interface/ccu_mailbox_extif.h',
        'drivers/misc/mediatek/ccu/src/mt6771/ccu_ext_interface/ccu_types.h',
        'drivers/misc/mediatek/ccu/src/mt6771/ccu_hw.c',
        'drivers/misc/mediatek/ccu/src/mt6771/ccu_hw.h',
        'drivers/misc/mediatek/ccu/src/mt6771/ccu_i2c_hw.c',
        'drivers/misc/mediatek/ccu/src/mt6771/ccu_i2c_hw.h',
        'drivers/misc/mediatek/ccu/src/mt6771/ccu_imgsensor.c',
        'drivers/misc/mediatek/ccu/src/mt6771/ccu_imgsensor.h',
        'drivers/misc/mediatek/ccu/src/mt6771/ccu_kd_mailbox.c',
        'drivers/misc/mediatek/ccu/src/mt6771/ccu_kd_mailbox.h',
        'drivers/misc/mediatek/ccu/src/mt6771/ccu_mva.c',
        'drivers/misc/mediatek/ccu/src/mt6771/ccu_mva.h',
        'drivers/misc/mediatek/ccu/src/mt6771/ccu_platform_def.h',
        'drivers/misc/mediatek/ccu/src/mt6771/ccu_qos.c',
        'drivers/misc/mediatek/ccu/src/mt6771/ccu_qos.h',
        'drivers/misc/mediatek/ccu/src/mt6771/ccu_reg.c',
        'drivers/misc/mediatek/ccu/src/mt6771/ccu_reg.h',
        'drivers/misc/mediatek/ccu/src/mt6771/ccu_sw_ver.c',
        'drivers/misc/mediatek/ccu/src/mt6771/ccu_sw_ver.h',
        'drivers/misc/mediatek/ccu/src/mt6771/common.h',
    ],
    # JPEG v2 encoder (T builds the encoder only for mt6771), /proc/mtk_jpeg.
    '0068-mtk-jpeg.patch': [
        'drivers/misc/mediatek/jpeg/Kconfig',
        'drivers/misc/mediatek/jpeg/Makefile',
        'drivers/misc/mediatek/jpeg/v2/Makefile',
        'drivers/misc/mediatek/jpeg/v2/jpeg_drv.c',
        'drivers/misc/mediatek/jpeg/v2/jpeg_drv.h',
        'drivers/misc/mediatek/jpeg/v2/jpeg_drv_common.h',
        'drivers/misc/mediatek/jpeg/v2/jpeg_drv_dec.c',
        'drivers/misc/mediatek/jpeg/v2/jpeg_drv_enc.c',
        'drivers/misc/mediatek/jpeg/v2/jpeg_drv_reg.h',
    ],
    # SSPM mailbox and IPI core cut down from T's sspm v1 and mt6771, PLT_INIT and debugfs.
    '0069-mtk-sspm-ipi.patch': [
        'drivers/misc/mediatek/sspm_ipi/Kconfig',
        'drivers/misc/mediatek/sspm_ipi/Makefile',
        'drivers/misc/mediatek/sspm_ipi/sspm_ipi.c',
        'include/linux/soc/mediatek/mtk-sspm.h',
    ],
    # EMI MPU regions over ATF as stock's mpu_v1.c, the locked AP region, debugfs readback.
    '0070-mtk-emi-mpu.patch': [
        'drivers/misc/mediatek/emi/Kconfig',
        'drivers/misc/mediatek/emi/Makefile',
        'drivers/misc/mediatek/emi/mt6771/Makefile',
        'drivers/misc/mediatek/emi/mt6771/emi_mpu.c',
        'drivers/misc/mediatek/emi/mt6771/plat_debug_api.h',
    ],
    # APXGPT as the broadcast clockevent for MCDI core-off.
    '0071-mt6771-gpt-broadcast.patch': [
        'drivers/clocksource/timer-mediatek.c',
    ],
    # MCDI core-off client over SSPM mailbox 3, the idle state off by default.
    '0072-mtk-mcdi-core-off.patch': [
        'drivers/cpuidle/dt_idle_states.c',
        'drivers/misc/mediatek/mcdi_sspm/Kconfig',
        'drivers/misc/mediatek/mcdi_sspm/Makefile',
        'drivers/misc/mediatek/mcdi_sspm/mtk_mcdi.c',
        'include/linux/soc/mediatek/mtk-mcdi.h',
    ],
    # SIP core and cluster power-down after CPU hotplug, as stock's cpuhotplug driver.
    '0073-mt6771-cpuhp-power-down.patch': [
        'drivers/misc/mediatek/cpuhp/Kconfig',
        'drivers/misc/mediatek/cpuhp/Makefile',
        'drivers/misc/mediatek/cpuhp/mt6771_cpuhp.c',
    ],
    # SPM base driver from T's spm_module_init: SPM map, IRQ0, SPMFW_IDX, firmware status, debugfs.
    '0074-mtk-spm-base.patch': [
        'drivers/misc/mediatek/spm/Kconfig',
        'drivers/misc/mediatek/spm/Makefile',
        'drivers/misc/mediatek/spm/mtk_spm_base.c',
        'include/linux/soc/mediatek/mtk-spm.h',
    ],
    # T's spm_vcorefs_init on its DVS and DFS off branch (flag 0x418) with the SSPM QOS
    # IPIs, behind spm_vcorefs.init.
    '0075-mtk-spm-vcorefs-init.patch': [
        'drivers/misc/mediatek/spm/mtk_spm_vcorefs.c',
    ],
    # T's slp_suspend_ops and spm_go_to_sleep for mem, behind spm_suspend.deep, with the SSPM,
    # MCDI and TOPRGU steps (P12b), SYS_CIRQ and the 8250_mtk sleep handshake (P12c).
    '0076-mtk-spm-deep-suspend.patch': [
        'drivers/misc/mediatek/spm/mtk_spm_suspend.c',
        'drivers/misc/mediatek/spm/mtk_sys_cirq.c',
        'drivers/misc/mediatek/spm/mtk_sys_cirq.h',
        'drivers/tty/serial/8250/8250_mtk.c',
        'include/linux/soc/mediatek/mtk-8250.h',
    ],
    # Fixes to files earlier patches own, as STAGED entries.
    # A wakeup source held while a USB host is in, as stock mtu3 does in device mode.
    '0077-mtk-charger-usb-wakelock.patch': [],
    # MT6370 RGB LED as the stock binary: blue read-back, delay_on_off, register mode on 0, CHG_IND auto off.
    '0078-mt6370-rgbled-stock.patch': [],
    # Touchscreen ESD check on its own lock, so its 50 ms sleeps don't hold up touch reports.
    '0079-pocket-touchscreen-esd-lock.patch': [],
    # MT6771 UFS system sleep behind ufs_mediatek.mt6771_sleep, default 2, level 0 keeps the host active.
    '0080-mt6771-ufs-system-sleep.patch': [],
    # charging_enabled on the MTK charger device, for the health HAL's charging control.
    '0081-mtk-charger-charging-enabled.patch': [],
    # input_current, chg1_current and chg2_current print the -1 "no thermal limit" signed.
    '0084-mtk-charger-signed-current-limits.patch': [],
    # sensor_list asks the hub for chip names again until the SCP has finished auto-detect.
    '0086-mtk-sensorlist-retry.patch': [],
    # MT6771 mtu3: with VBUS forced valid, stop the device and power the PHY down for system sleep, and cycle both on bind and resume.
    '0082-mt6771-mtu3-device-sleep.patch': ['drivers/usb/mtu3/mtu3_gadget.c', 'drivers/usb/mtu3/mtu3_dr.h'],
    # Display kthreads wait in TASK_IDLE so they stop counting in the load average.
    '0088-mtk-disp-kthread-idle-waits.patch': [],
    # ccci_fsm, SCP nanoHub and charger kthreads wait in TASK_IDLE so they stop counting in the load average.
    '0089-mtk-kthread-idle-waits.patch': [],
    # MT6771 mtu3: the charger's cable plug-in and plug-out start and stop the device, as VBUS is forced valid.
    '0090-mt6771-mtu3-vbus-from-charger.patch': [],
    # MT6771 PWM memory mode on mediatek,pwm, pwm_set_spec_config() and mt_pwm_disable() for the IR transmitter.
    '0091-mtk-pwm-memory-mode.patch': [
        'drivers/misc/mediatek/pwm/Kconfig',
        'drivers/misc/mediatek/pwm/Makefile',
        'drivers/misc/mediatek/pwm/mtk_pwm.c',
    ],
    # /dev/irtx as stock for the consumerir HAL, LED power from irtx-supply; the MT6370 LDO gets its DT node for that.
    '0092-mtk-irtx.patch': [
        'drivers/misc/mediatek/irtx/Kconfig',
        'drivers/misc/mediatek/irtx/Makefile',
        'drivers/misc/mediatek/irtx/mtk_irtx.h',
        'drivers/misc/mediatek/irtx/mtk_irtx_pwm.c',
    ],
    # The backlight PWM is active low as stock: disp_pwm_set_backlight_cmdq inverts the level (0 and 1 give 1023).
    '0093-mtk-disp-pwm-active-low.patch': [],
}

# The OCV table stays out of the patches: the measured one from tools/make-pocket-oz8806-ocv.py
# goes out with the kernel repo, and the public source scan refuses a patch that adds it.
# The marker is split so this file doesn't hold it.
OCV_HEADER = 'drivers/power/supply/oz8806_ocv.h'
STOCK_OCV = (WORK / OCV_HEADER).is_file() and ('OZ8806_OCV_' + 'STOCK') in (WORK / OCV_HEADER).read_text()
GROUPS['0026-oz8806-gauge.patch'].remove(OCV_HEADER)


# Hook lines in a shared Makefile or Kconfig that name a folder or file a later patch adds. Each patch
# brings its own hooks, so every prefix of the stack builds. GROUPS still owns the whole file; an entry
# (patch number, text) says that patch adds text, and (number, text, before) that it turns before into text.
# The file after a patch is its final content with the later patches' entries undone, last patch first,
# so each text only has to be unique and in one piece once the later ones are gone. Fix patches (0077 on)
# use the same entries for C files.
def _src(*dirs):
    return ''.join(f'source "drivers/misc/mediatek/{d}/Kconfig"\n' for d in dirs)


def _mm(comment, *lines):
    return (f'# {comment}\n' if comment else '') + ''.join(line + '\n' for line in lines)


# The camera drivers' MM QoS calls, added to the display port's mmdvfs_pmqos.h stub by 0059.
_CAM_MM_QOS = (
    '/*\n'
    ' * Camera port: the MM QoS calls the camera drivers make\n'
    ' * (ISP, seninf, JPEG, CCU). Requests are dropped, so the engines run at their\n'
    " * default clocks and bandwidth. T's names and BW_COMP_* values.\n"
    ' */\n'
    'enum {\n'
    '\tBW_COMP_NONE = 0,\n'
    '\tBW_COMP_DEFAULT,\n'
    '\tBW_COMP_VENC,\n'
    '\tBW_COMP_END\n'
    '};\n'
    '\n'
    'static inline s32 mm_qos_add_request(struct plist_head *owner_list,\n'
    '\t\t\t\t     struct mm_qos_request *req, u32 master_id)\n'
    '{\n'
    '\treturn 0;\n'
    '}\n'
    '\n'
    'static inline s32 mm_qos_set_request(struct mm_qos_request *req, u32 bw_value,\n'
    '\t\t\t\t     u32 hrt_value, u32 comp_type)\n'
    '{\n'
    '\treturn 0;\n'
    '}\n'
    '\n'
    'static inline s32 mm_qos_set_bw_request(struct mm_qos_request *req,\n'
    '\t\t\t\t\tu32 bw_value, s32 comp_type)\n'
    '{\n'
    '\treturn 0;\n'
    '}\n'
    '\n'
    'static inline s32 mm_qos_set_hrt_request(struct mm_qos_request *req,\n'
    '\t\t\t\t\t u32 hrt_value)\n'
    '{\n'
    '\treturn 0;\n'
    '}\n'
    '\n'
    'static inline void mm_qos_update_all_request(struct plist_head *owner_list)\n'
    '{\n'
    '}\n'
    '\n'
    'static inline void mm_qos_remove_all_request(struct plist_head *owner_list)\n'
    '{\n'
    '}\n'
    '\n'
    'static inline void mm_qos_update_all_request_zero(struct plist_head *owner_list)\n'
    '{\n'
    '}\n'
    '\n'
    'enum mmdvfs_limit_source {\n'
    '\tMMDVFS_LIMIT_THERMAL = 0,\n'
    '\tMMDVFS_LIMIT_CAM,\n'
    '};\n'
    '\n'
    '/* No MM DVFS steps without mmdvfs_pmqos.c, so no current freq either. */\n'
    'static inline u64 mmdvfs_qos_get_freq(u32 pm_qos_class)\n'
    '{\n'
    '\treturn 0;\n'
    '}\n'
    '\n'
    'static inline void mmdvfs_qos_limit_config(u32 pm_qos_class, u32 limit_value,\n'
    '\t\t\t\t\t   enum mmdvfs_limit_source source)\n'
    '{\n'
    '}\n'
    '\n'
)
_PMIC_INC = 'subdir-ccflags-y += -I$(srctree)/drivers/misc/mediatek/pmic/include\n'
STAGED = {
    'drivers/misc/mediatek/cameraisp/Makefile': [('0066', 'obj-y += rsc/\nobj-y += fdvt/\n')],
    'drivers/misc/mediatek/cameraisp/Kconfig': [('0066', '''
config MTK_CAMERA_ISP_RSC_SUPPORT
	bool "[RSC] Rolling Shutter Cancellation"
	depends on MTK_CAMERA_ISP
	help
	  Motion vectors for EIS and noise reduction, /dev/camera-rsc.

config MTK_CAMERA_ISP_FD_SUPPORT
	bool "[FD] Face Detection"
	depends on MTK_CAMERA_ISP
	help
	  Face detection, /dev/camera-fdvt.
''')],
    'drivers/misc/mediatek/video/common/pwm10/ddp_pwm.c': [
        ('0093', '''	/* The board's backlight PWM is active low. As stock: 0 and 1 give 1023 (off), others an inverted 312..1016. */
	if (level_1024 >= 0 && level_1024 <= 1)
		level_1024 = 0x3ff;
	else
		level_1024 = ((1033 - (7 * level_1024) / 10) * 1010) >> 10;

'''),
        ('0093', '''extern void agold_gpio_set(unsigned int gpio, int value);
/* Matches stock: GPIO165 goes high when going off from a dim level; what it is wired to is unknown. */
static bool g_pwm_gpio165_high;

'''),
        ('0093', '''		if (level_1024 == 0x3ff) {
			if (old_pwm >= 0x3d0) {
				agold_gpio_set(165, 1);
				g_pwm_gpio165_high = true;
			}
		} else if (g_pwm_gpio165_high) {
			agold_gpio_set(165, 0);
			g_pwm_gpio165_high = false;
		}

''')],
    'drivers/misc/Kconfig': [('0015', 'source "drivers/misc/mediatek/Kconfig"\n')],
    'drivers/misc/mediatek/Kconfig': [
        # SMI calls CMDQ v3, so it comes with CMDQ in 0023; M4U's SMI calls are under CONFIG_MTK_SMI_EXT.
        ('0021', _src('m4u', 'cmo') + '\n'),
        ('0023', _src('smi', 'm4u', 'cmo', 'cmdq', 'sync'), _src('m4u', 'cmo')),
        ('0024', _src('lcm', 'video', 'ext_disp', 'leds', 'boot')),
        ('0025', _src('gpu', 'freqhopping')),
        ('0019', '# Charger milestone 2: the MT6370 MFD and the Richtek parts it needs\n'
                 + _src('rt-regmap', 'flashlight/richtek', 'pmic') + '\n'),
        ('0032', '# Vibrator\n' + _src('vibrator') + '\n'),
        ('0036', '# SCP core for the sensor hub\n' + _src('scp') + '\n'),
        ('0040', '# Connectivity built-in adapter and the stock connsys options\n'
                 + _src('connectivity') + '\n'),
        ('0041', '# BTIF for the connsys STP link\n' + _src('btif') + '\n'),
        ('0045', '# ST21NFC\n' + _src('nfc') + '\n'),
        ('0046', '# FS16xx smart amp raw I2C node\n' + _src('smartpa') + '\n'),
        ('0053', '# ACCDET headset jack detect on the MT6358\n'
                 + _src('accdet') + '\n'),
        ('0048', '# PMIC, clock buffer, SPM and stub calls for the eccci modem driver\n'
                 + _src('ccci_platform') + '\n'),
        ('0051', '# eccci core, fsm, CLDMA and CCIF hif and the MT6771 platform code\n'
                 + _src('eccci') + '\n'),
        ('0049', '# ccmni network interfaces for eccci\n' + _src('ccmni') + '\n'),
        ('0050', '# conn_md LTE coex bridge, the modem PA thermistor and the modem coolers\n'
                 + _src('conn_md', 'thermal') + '\n'),
        ('0037', '# Sensor hub stack, stock\'s Sensors menu\nmenu "Sensors"\n\n'
                 'config MTK_SENSOR_SUPPORT\n\tbool "MTK SENSOR SUPPORT"\n\thelp\n'
                 '\t  Sensor config for sensor feature in project.\n'
                 '\t  Please say Y here if you want to support and sensors\n'
                 '\t  with mediatek sensor architecture.\n\t  If unsure, say N.\n\n'
                 'config MTK_SENSOR_ARCHITECTURE\n\tstring "MTK SENSOR ARCHITECTURE"\n\tdefault "dummy"\n\thelp\n'
                 '\t  Sensor config for sensor architecture in project.\n'
                 '\t  Please set 1.0/2.0/3.0 etc if you want to support sensor\n'
                 '\t  with mediatek sensor architecture.\n\t  If unsure, set dummy.\n\n'
                 'source "drivers/misc/mediatek/sensors-1.0/Kconfig"\nendmenu  # Sensors\n\n'),
        ('0055', '# Sunwave fingerprint sensor and the front strip keys\n' + _src('sunwave') + '\n'),
        ('0056', '\n# ccci_util modem capability options\n' + _src('ccci_util')),
        ('0057', '# Systracker, the infra bus timeout monitor\n' + _src('systracker') + '\n'),
        ('0058', '# Video codec, /dev/Vcodec\n' + _src('videocodec') + '\n'),
        ('0059', '# Camera: the MTK I2C calls over i2c-mt65xx\n' + _src('i2c_shim') + '\n'),
        ('0060', '# Camera sensor path: imgsensor with seninf, the sensor list\nconfig CUSTOM_KERNEL_IMGSENSOR\n\tstring "Custom image sensor driver"\n\thelp\n\t  Kernel space image sensor driver. Define  project used all image\n\t  sensors .The value is combination of CUSTOM_KERNEL_MAIN_IMGSENSOR,\n\t  CUSTOM_KERNEL_MAIN_BACKUP_IMGSENSOR, CUSTOM_KERNEL_SUB_IMGSENSOR,\n\t  and CUSTOM_KERNEL_SUB_BACKUP_IMGSENSOR\n\nsource "drivers/misc/mediatek/imgsensor/Kconfig"\n\n'),
        ('0061', '# Camera calibration EEPROM, /dev/CAM_CAL_DRV\nsource "drivers/misc/mediatek/cam_cal/Kconfig"\n\n'),
        ('0062', '# Lens actuators, /dev/MAINAF and /dev/SUBAF\nsource "drivers/misc/mediatek/lens/Kconfig"\n\n'),
        ('0063', '# Camera flashlight: /dev/flashlight and the MT6370 channels\nsource "drivers/misc/mediatek/flashlight/Kconfig"\n\n'),
        ('0064', '# Archcounter to monotonic time sync for the camera ISP\nsource "drivers/misc/mediatek/timer/timesync/Kconfig"\n\n'),
        ('0065', '# Camera ISP, DIP and WPE: /dev/camera-isp, /dev/camera-dip, /dev/camera-wpe\nsource "drivers/misc/mediatek/cameraisp/Kconfig"\n\n'),
        ('0067', '# Camera CCU, /dev/ccu\nsource "drivers/misc/mediatek/ccu/src/Kconfig"\n\n'),
        ('0068', '# Camera JPEG encoder, /proc/mtk_jpeg\nsource "drivers/misc/mediatek/jpeg/Kconfig"\n\n'),
        ('0069', '# SSPM mailbox and IPI core\n' + _src('sspm_ipi') + '\n'),
        ('0070', '# EMI MPU regions over ATF\n' + _src('emi') + '\n'),
        ('0072', '# MCDI core-off through SSPM mailbox 3\n' + _src('mcdi_sspm') + '\n'),
        ('0073', '# Core power-down after CPU hotplug\n' + _src('cpuhp') + '\n'),
        ('0074', '# SPM base driver\n' + _src('spm') + '\n'),
        ('0091', '# PWM memory mode for the IR transmitter\n' + _src('pwm') + '\n'),
        ('0092', '# IR transmitter, /dev/irtx\n' + _src('irtx') + '\n'),
    ],
    'drivers/misc/mediatek/Makefile': [
        ('0056', 'obj-$(CONFIG_MTK_ECCCI_DRIVER) += eccci/\n'
                 '# ccci_util with eccci too, so its strong calls never depend on MTK_FB\n'
                 'obj-$(CONFIG_MTK_ECCCI_DRIVER) += ccci_util/\n', 'obj-$(CONFIG_MTK_ECCCI_DRIVER) += eccci/\n'),
        ('0015', _mm(None, 'obj-$(CONFIG_TRUSTKERNEL_TEE_SUPPORT) += tkcore/', '',
                     '# Milestone 1', 'obj-$(CONFIG_MTK_BASE_POWER) += base/'),
                 'obj-$(CONFIG_TRUSTKERNEL_TEE_SUPPORT) += tkcore/\n'),
        ('0021', 'subdir-ccflags-y += -I$(srctree)/drivers/misc/mediatek/emi/$(MTK_PLATFORM)\n'),
        ('0021', _mm('Milestone 2', 'obj-$(CONFIG_MTK_M4U) += m4u/',
                     'obj-$(CONFIG_MEDIATEK_SOLUTION) += atf/', 'obj-$(CONFIG_MTK_CACHE_FLUSH_BY_SF) += cmo/')),
        # SMI calls CMDQ v3, so it's built from 0023.
        ('0023', _mm('Milestone 2', 'obj-$(CONFIG_MTK_SMI_EXT) += smi/'), '# Milestone 2\n'),
        ('0027', _mm('Milestone 3', 'obj-$(CONFIG_MTK_SSMR) += memory-ssmr/',
                     'obj-$(CONFIG_ZONE_MOVABLE_CMA) += zone_movable_cma/')),
        ('0023', _mm('Milestone 4', 'obj-$(CONFIG_MTK_SYNC) += sync/', 'obj-$(CONFIG_MTK_CMDQ) += cmdq/',
                     'obj-$(CONFIG_MTK_CMDQ) += mdp/')),
        ('0024', _mm('Milestone 5', 'obj-$(CONFIG_MTK_LEDS) += leds/', 'obj-$(CONFIG_MTK_LCM) += lcm/',
                     'obj-$(CONFIG_MTK_LCM) += ext_disp/', 'obj-$(CONFIG_MTK_FB) += video/',
                     'obj-$(CONFIG_MTK_BOOT) += boot/', 'obj-$(CONFIG_MTK_FB) += ccci_util/')),
        ('0025', _mm('Milestone 6', 'obj-$(CONFIG_MTK_GPU_SUPPORT) += gpu/',
                     'obj-$(CONFIG_MTK_FREQ_HOPPING) += freqhopping/')),
        ('0019', _mm('Charger milestone 2', 'obj-$(CONFIG_RT_REGMAP) += rt-regmap/',
                     'obj-$(CONFIG_RT_FLASHLIGHT) += flashlight/richtek/', 'obj-y += pmic/')),
        ('0028', _mm('mtk_charger', 'obj-$(CONFIG_MTK_CHARGER) += power/')),
        ('0032', _mm('Vibrator: the MT6358 VIBR LDO behind /sys/class/leds/vibrator',
                     'obj-$(CONFIG_MTK_VIBRATOR) += vibrator/')),
        ('0036', _mm('SCP core: mailbox IPI and ready notify for the sensor hub',
                     'obj-$(CONFIG_MTK_TINYSYS_SCP_SUPPORT) += scp/')),
        ('0040', _mm('Connectivity built-in adapter for the out-of-tree connsys modules',
                     'obj-$(CONFIG_MTK_COMBO) += connectivity/')),
        ('0041', _mm('BTIF, the AP side of the connsys STP link',
                     'obj-$(CONFIG_MTK_BTIF) += btif/')),
        ('0045', _mm('ST21NFC, /dev/st21nfc for the stock NFC HAL',
                     'obj-$(CONFIG_NFC_CHIP_SUPPORT) += nfc/')),
        ('0046', _mm('FS16xx smart amp raw I2C node /dev/smartpa_i2c',
                     'obj-$(CONFIG_MTK_SMARTPA_FS16XX_I2C) += smartpa/')),
        ('0053', _mm('ACCDET headset jack detect, /dev/accdet and the ACCDET input device',
                     'obj-$(CONFIG_MTK_ACCDET) += accdet/')),
        ('0048', _mm('eccci platform calls: VMODEM, clock buffer flight mode, SPM MD source, PBM/vcorefs/AEE stubs', 'obj-$(CONFIG_MTK_CCCI_PLATFORM_DEPS) += ccci_platform/')),
        ('0051', _mm('eccci core, fsm, CLDMA and CCIF hif and the MT6771 platform code',
                     'obj-$(CONFIG_MTK_ECCCI_DRIVER) += eccci/')),
        ('0049', _mm('ccmni network interfaces for eccci and the set_rps_map they use',
                     'obj-$(CONFIG_MTK_NET_CCMNI) += ccmni/ rps/')),
        ('0050', _mm('conn_md LTE coex bridge, the modem PA thermistor and the modem coolers',
                     'obj-$(CONFIG_MTK_CONN_MD) += conn_md/',
                     'obj-$(CONFIG_MTK_THERMAL_BTSMDPA) += thermal/common/thermal_zones/',
                     'obj-$(CONFIG_MTK_COOLER_MUTT) += thermal/common/coolers/')),
        ('0037', _mm('Sensor hub stack: hwmon misc devices and the hub sensors over the SCP',
                     'ifeq ($(subst ",,$(CONFIG_MTK_SENSOR_ARCHITECTURE)),1.0)', 'obj-y += sensors-1.0/', 'endif')),
        ('0055', _mm('Sunwave fingerprint: /dev/sunwave_fp and the fingerprint_key input device',
                     'obj-$(CONFIG_SUNWAVE_FP) += sunwave/')),
        ('0057', _mm('Systracker: a bus access that hangs ends in an abort naming the address',
                     'obj-$(CONFIG_MTK_SYSTRACKER_V2) += systracker/')),
        ('0058', _mm('Video codec: /dev/Vcodec for the stock OMX codecs',
                     'obj-$(CONFIG_MTK_VIDEOCODEC_DRIVER) += videocodec/')),
        ('0059', _mm('Camera: the MTK I2C calls imgsensor and cam_cal make, over i2c-mt65xx',
                     'obj-$(CONFIG_MTK_I2C_SHIM) += i2c_shim/')),
        ('0060', _mm('Camera sensor path: imgsensor and seninf, /dev/kd_camera_hw and /dev/seninf',
                     'obj-$(CONFIG_MTK_IMGSENSOR) += imgsensor/src/')),
        ('0061', _mm('Camera calibration EEPROM, /dev/CAM_CAL_DRV',
                     'obj-$(CONFIG_MTK_CAM_CAL) += cam_cal/src/')),
        ('0062', _mm('Lens actuators, /dev/MAINAF and /dev/SUBAF',
                     'obj-$(CONFIG_MTK_LENS)   += lens/')),
        ('0063', _mm('Camera flashlight: /dev/flashlight and the MT6370 channels',
                     'obj-$(CONFIG_MTK_FLASHLIGHT) += flashlight/')),
        ('0064', _mm('Archcounter to monotonic time sync for the camera ISP',
                     'obj-$(CONFIG_MTK_ARCHCOUNTER_TIMESYNC) += timer/timesync/')),
        ('0065', _mm('Camera ISP, DIP and WPE: /dev/camera-isp, /dev/camera-dip, /dev/camera-wpe',
                     'obj-$(CONFIG_MTK_CAMERA_ISP) += cameraisp/')),
        ('0067', _mm('Camera CCU: /dev/ccu', 'obj-$(CONFIG_MTK_CCU) += ccu/src/')),
        ('0068', _mm('Camera JPEG encoder: /proc/mtk_jpeg', 'obj-$(CONFIG_MTK_JPEG) += jpeg/')),
        ('0069', _mm('SSPM mailbox and IPI core', 'obj-$(CONFIG_MTK_SSPM_IPI) += sspm_ipi/')),
        ('0070', _mm('EMI MPU regions over ATF', 'obj-$(CONFIG_MTK_EMI) += emi/')),
        ('0072', _mm('MCDI core-off through SSPM mailbox 3', 'obj-$(CONFIG_MTK_MCDI_SSPM) += mcdi_sspm/')),
        ('0073', _mm('Core power-down after CPU hotplug', 'obj-$(CONFIG_MTK_CPUHP_POWER_DOWN) += cpuhp/')),
        ('0074', _mm('SPM base driver: SPM map, IRQ0, firmware index and status',
                     'obj-$(CONFIG_MTK_SPM_BASE) += spm/')),
        ('0091', _mm('PWM memory mode for the IR transmitter', 'obj-$(CONFIG_MTK_PWM) += pwm/')),
        ('0092', _mm('IR transmitter, /dev/irtx', 'obj-$(CONFIG_MTK_IRTX_PWM_SUPPORT) += irtx/')),
    ],
    'drivers/misc/mediatek/pmic/mt6370/mt6370_pmu_ldo.c': [
        ('0092', '\t/* the mt6370_ldo node, so consumers find it through a -supply phandle */\n'
                 '\tstruct regulator_config config = {\n\t\t.dev = dev,\n\t\t.init_data = init_data,\n'
                 '\t\t.driver_data = driver_data,\n'
                 '\t\t.of_node = of_get_child_by_name(dev->of_node, "mt6370_ldo"),\n\t};\n',
         '\tstruct regulator_config config = {\n\t\t.dev = dev,\n\t\t.init_data = init_data,\n'
         '\t\t.driver_data = driver_data,\n\t};\n'),
    ],
    'drivers/misc/mediatek/spm/Kconfig': [('0075', '\nconfig MTK_SPM_VCOREFS\n\tbool "MT6771 vcorefs init and Vcore DVFS"\n\tdepends on MTK_SPM_BASE\n\thelp\n\t  Runs stock\'s vcorefs init with Vcore DVS and DRAM DFS off: the\n\t  SSPM QoS enable and OPP rows, the Vcore OPP table, the PCM\n\t  firmware\'s PMIC wrap entries, PCM flag 0x418 and the DVFSRC set-up,\n\t  then puts the pm_qos DRAM, Vcore and bandwidth requests and the\n\t  screen state into the DVFSRC. Vcore and DRAM stay where they are.\n\t  Runs unless spm_vcorefs.init=0. Debugfs spm/vcorefs and spm/qos.\n\t  With spm_vcorefs.dvfs=1, the default, stock\'s DVS and DFS on branch\n\t  (PCM flag 0x8400) and debugfs spm/force_opp; after a boot with\n\t  dvfs=0, writing 1 to it turns that branch on then, with no way back.\n'),
                                          ('0076', '\nconfig MTK_SPM_SUSPEND\n\tbool "MT6771 SPM deep suspend"\n\tdepends on MTK_SPM_VCOREFS && SUSPEND && ARM_PSCI_FW\n\thelp\n\t  Stock\'s suspend for mem through the SPM: the PCM watchdog, the SSPM\n\t  suspend commands, the MCDI pause and the TOPRGU handover, the GIC\n\t  masked but for SPM IRQ0 and stock\'s edge IRQs, which SYS_CIRQ\n\t  latches while the GIC is off, the 8250_mtk sleep handshake, the SIP\n\t  suspend flags and PSCI CPU_SUSPEND 0x1010005 on CPU0. Then the wake\n\t  reason in dmesg, pm_wakeup_irq and debugfs spm/suspend. Offered as\n\t  mem_sleep "deep", and the default, with spm_suspend.deep=1 and\n\t  spm_vcorefs.init=1 (both default); mem_sleep_default=s2idle or\n\t  spm_suspend.deep=0 keeps s2idle.\n')],
    'drivers/misc/mediatek/spm/Makefile': [('0075', 'obj-$(CONFIG_MTK_SPM_VCOREFS) += mtk_spm_vcorefs.o\n'),
                                           ('0076', 'obj-$(CONFIG_MTK_SPM_SUSPEND) += mtk_spm_suspend.o mtk_sys_cirq.o\n')],
    'include/linux/soc/mediatek/mtk-spm.h': [('0075', '\n#ifdef CONFIG_MTK_SPM_VCOREFS\n'
        '/* True once vcorefs init sent CMD_1; *flag gets that PCM flag */\n'
        'bool spm_vcorefs_init_done(u32 *flag);\n#else\n'
        'static inline bool spm_vcorefs_init_done(u32 *flag)\n{\n\treturn false;\n}\n#endif\n')],
    'drivers/misc/mediatek/mmdvfs/mmdvfs_pmqos.h': [('0059', _CAM_MM_QOS)],
    'drivers/misc/mediatek/base/power/Makefile': [('0025', 'obj-$(CONFIG_MACH_MT6771) += mt6771/\n')],
    'drivers/misc/mediatek/base/power/spm_v4/Makefile': [
        ('0025', 'ccflags-y += -I$(srctree)/drivers/misc/mediatek/base/power/$(MTK_PLATFORM)/\n')],
    'drivers/input/keyboard/Kconfig': [('0029', 'source "drivers/input/keyboard/mediatek/Kconfig"\n\n')],
    'drivers/input/keyboard/Makefile': [('0029', 'obj-$(CONFIG_KEYBOARD_MTK)\t\t+= mediatek/\n')],
    'drivers/misc/mediatek/pmic/Makefile': [
        ('0044', _mm('The legacy MT6358 PMIC calls (AUXADC, efuse, IRQ callbacks) over the 5.10 mt6397 MFD, for the',
                     '# codec and accdet.',
                     'obj-$(CONFIG_MTK_PMIC_CHIP_MT6358) += mt6358/'))],
    'drivers/misc/mediatek/pmic/mt6370/Makefile': [
        ('0028', 'subdir-ccflags-y += -I$(srctree)/drivers/power/supply/mediatek/charger\n'
                 'subdir-ccflags-y += -I$(srctree)/drivers/power/supply/mediatek/misc\n'),
        ('0028', '\nifeq ($(CONFIG_MTK_GAUGE_VERSION),30)\n'
                 'obj-$(CONFIG_MT6370_PMU_CHARGER)\t+= mt6370_pmu_charger.o\n'
                 'else\nobj-$(CONFIG_MT6370_PMU_CHARGER)\t+= mt6370_pmu_charger_gm20.o\nendif\n')],
    'drivers/misc/mediatek/smi/Makefile': [
        ('0023', 'ccflags-y += -I$(srctree)/drivers/misc/mediatek/cmdq/v3/\n'
                 'ccflags-y += -I$(srctree)/drivers/misc/mediatek/cmdq/v3/$(MTK_PLATFORM)/\n')],
    'drivers/misc/mediatek/ext_disp/mt6771/Makefile': [
        ('0025', '             -I$(srctree)/drivers/misc/mediatek/gpu/ged/include \\\n')],
    'drivers/misc/mediatek/video/mt6771/dispsys/Makefile': [
        ('0025', '             -I$(srctree)/drivers/misc/mediatek/gpu/ged/include/ \\\n')],
    'drivers/misc/mediatek/video/mt6771/videox/Makefile': [
        ('0025', '             -I$(srctree)/drivers/misc/mediatek/base/power/$(MTK_PLATFORM) \\\n'),
        ('0025', '             -I$(srctree)/drivers/misc/mediatek/dramc/$(MTK_PLATFORM) \\\n'
                 '             -I$(srctree)/drivers/misc/mediatek/gpu/ged/include/ \n',
                 '             -I$(srctree)/drivers/misc/mediatek/dramc/$(MTK_PLATFORM)\n')],
    'drivers/misc/mediatek/base/power/mt6771/Makefile': [
        ('0028', 'ccflags-y += -I$(srctree)/drivers/misc/mediatek/power/$(MTK_PLATFORM)/\n')],
    'drivers/power/supply/Kconfig': [
        ('0028', 'source "drivers/power/supply/mediatek/battery/Kconfig"\n'
                 'source "drivers/power/supply/mediatek/charger/Kconfig"\n')],
    'drivers/power/supply/Makefile': [('0028', 'obj-$(CONFIG_MTK_CHARGER)\t+= mediatek/\n')],
    'drivers/power/supply/mediatek/Makefile': [('0048', _PMIC_INC)],
    'drivers/power/supply/mediatek/charger/Makefile': [('0048', _PMIC_INC)],
    'drivers/power/supply/mediatek/misc/Makefile': [
        ('0048', 'subdir-ccflags-y += -Werror -I$(srctree)/drivers/misc/mediatek/pmic/include\n')],
    'drivers/misc/mediatek/sensors-1.0/Kconfig': [
        ('0047', _src('sensors-1.0/gyroscope', 'sensors-1.0/magnetometer')),
        ('0047', _src('sensors-1.0/sensorfusion', 'sensors-1.0/step_counter', 'sensors-1.0/situation'))],
    'drivers/misc/mediatek/sensors-1.0/Makefile': [
        ('0047', 'obj-$(CONFIG_CUSTOM_KERNEL_GYROSCOPE) += gyroscope/\n'
                 'obj-$(CONFIG_CUSTOM_KERNEL_MAGNETOMETER) += magnetometer/\n'
                 'obj-$(CONFIG_CUSTOM_KERNEL_STEP_COUNTER)\t+= step_counter/\n'
                 'obj-$(CONFIG_CUSTOM_KERNEL_SIGNIFICANT_MOTION_SENSOR)\t+= step_counter/\n'
                 'obj-$(CONFIG_CUSTOM_KERNEL_SITUATION) += situation/\n'
                 'obj-$(CONFIG_CUSTOM_KERNEL_SENSOR_FUSION)\t+= sensorfusion/\n')],
    'sound/soc/mediatek/Makefile': [
        ('0053', 'subdir-ccflags-y += -Werror -I$(srctree)/drivers/misc/mediatek/accdet/mt6358\n')],
    'sound/soc/mediatek/codec/mt6358/Makefile': [('0044', 'obj-y += mtk-soc-codec-6358.o mtk-auddrv-ana.o\n')],
    # The AFE (0042) calls into the PCM, codec and machine code, so the stack only builds from 0044.
    'sound/soc/mediatek/mt6771/Makefile': [
        ('0044', 'obj-y += mtk-auddrv-clk.o\nobj-y += mtk-soc-afe-connection.o\nobj-y += mt6771-sound.o\n')],
    'sound/soc/mediatek/common_int/Makefile': [
        ('0044', _mm(None, 'ccflags-y += -I$(srctree)/drivers/misc/mediatek/base/power/mcdi/include/', '',
                     'obj-y += mtk-auddrv-devtree-parser.o', 'obj-y += mtk-soc-speaker-amp.o',
                     'obj-y += mtk-auddrv-afe.o mtk-auddrv-gpio.o',
                     'obj-y += mtk-soc-afe-control.o mtk-soc-pcm-common.o mtk-soc-pcm-component.o',
                     'obj-y += mtk-soc-pcm-capture.o mtk-soc-pcm-dl1.o mtk-soc-pcm-dummy.o mtk-soc-pcm-routing.o '
                     'mtk-soc-pcm-capture2.o mtk-soc-pcm-i2s2-adc2.o',
                     'obj-y += mtk-soc-pcm-voice-md1.o mtk-soc-pcm-voice-md2.o mtk-soc-pcm-voice-md1-bt.o '
                     'mtk-soc-pcm-voice-md2-bt.o',
                     'obj-y += mtk-soc-pcm-voice-usb.o mtk-soc-pcm-voice-usb-echoref.o',
                     'obj-y += mtk-soc-pcm-dl1-i2s0.o mtk-soc-pcm-dl1-i2s0Dl1.o mtk-soc-pcm-i2s0-awb.o',
                     'obj-y += mtk-soc-pcm-uldlloopback.o mtk-soc-pcm-dl2.o mtk-soc-pcm-deep-buffer-dl.o',
                     'obj-y += mtk-soc-pcm-mrgrx.o mtk-soc-pcm-mrgrx-awb.o mtk-soc-pcm-fm-i2s.o mtk-soc-pcm-fm-i2s-awb.o',
                     'obj-y += mtk-soc-pcm-dl1-awb.o mtk-soc-pcm-dl1-bt.o mtk-soc-pcm-bt-dai.o',
                     'obj-y += mtk-soc-dai-stub.o mtk-soc-dai-routing.o mtk-soc-codec-dummy.o mtk-soc-pcm-fmtx.o '
                     'mtk-soc-tdm-capture.o',
                     'obj-y += mtk-soc-pcm-hp-impedance.o', 'obj-y += mtk-soc-machine.o'))],
    'drivers/misc/mediatek/eccci/Makefile': [
        ('0052', 'obj-y += port/\nobj-y += udc/\nobj-$(CONFIG_MTK_MIX_DEVICES) +=  mixdev/\n')],
    'drivers/misc/mediatek/ccci_util/Makefile': [
        ('0056', '\n# ccci_util (LK modem info, reserved memory, image header, /sys/kernel/ccci, the ccci\n'
                 '# logs and /dev/ccci_md*_sta), built with eccci as T does. Its strong calls override the weak ones.\n'
                 'ifeq ($(CONFIG_MTK_ECCCI_DRIVER),y)\n'
                 'ccflags-y += -I$(srctree)/drivers/misc/mediatek/ccci_util\n'
                 'obj-y += ccci_util_lib.o\n'
                 'ccci_util_lib-y := ccci_util_lib_fo.o ccci_util_lib_load_img.o ccci_util_lib_sys.o ccci_private_log.o \\\n'
                 '\tccci_util_lib_time.o ccci_util_lib_main.o ccci_util_ld_md_errno.o ccci_util_broadcast.o ccci_util_sib.o \\\n'
                 '\tccci_util_platform.o\n'
                 'endif\n')],
    'drivers/power/supply/mediatek/charger/mtk_chg_type_det.c': [
        ('0077',
         '\t#endif\n'
         '\tbool chg_online; /* Has charger in or not */\n'
         '\tenum charger_type chg_type;\n'
         '\t/* held while a USB host (SDP/CDP) or non-standard charger is in */\n'
         '\tstruct wakeup_source *usb_ws;\n'
         '};\n'
         '\n'
         'static int mt_charger_online(struct mt_charger *mtk_chg)\n',
         '\t#endif\n'
         '\tbool chg_online; /* Has charger in or not */\n'
         '\tenum charger_type chg_type;\n'
         '};\n'
         '\n'
         'static int mt_charger_online(struct mt_charger *mtk_chg)\n'),
        ('0077',
         '\t\t\t(mtk_chg->chg_type == CHARGING_HOST) ||\n'
         '\t\t\t(mtk_chg->chg_type == NONSTANDARD_CHARGER)) {\n'
         '\t\t\tmt_usb_connect();\n'
         '\t\t\t/* stock mtu3 holds a wakelock in device mode; the\n'
         "\t\t\t * gadget-only 5.10 mtu3 doesn't, so hold it here\n"
         '\t\t\t */\n'
         '\t\t\t__pm_stay_awake(mtk_chg->usb_ws);\n'
         '\t\t\t#ifdef CONFIG_EXTCON_USB_CHG\n'
         '\t\t\tinfo->vbus_state = 1;\n'
         '\t\t\t#endif\n'
         '\t\t} else {\n'
         '\t\t\tmt_usb_disconnect();\n'
         '\t\t\t#ifdef CONFIG_EXTCON_USB_CHG\n'
         '\t\t\tinfo->vbus_state = 0;\n'
         '\t\t\t#endif\n'
         '\t\t}\n'
         '\t}\n'
         '\t/* also when ignore_usb is set, after a Type-C role swap */\n'
         '\tif (mtk_chg->chg_type != STANDARD_HOST &&\n'
         '\t    mtk_chg->chg_type != CHARGING_HOST &&\n'
         '\t    mtk_chg->chg_type != NONSTANDARD_CHARGER)\n'
         '\t\t__pm_relax(mtk_chg->usb_ws);\n',
         '\t\t\t(mtk_chg->chg_type == CHARGING_HOST) ||\n'
         '\t\t\t(mtk_chg->chg_type == NONSTANDARD_CHARGER)) {\n'
         '\t\t\tmt_usb_connect();\n'
         '\t\t\t#ifdef CONFIG_EXTCON_USB_CHG\n'
         '\t\t\tinfo->vbus_state = 1;\n'
         '\t\t\t#endif\n'
         '\t\t} else {\n'
         '\t\t\tmt_usb_disconnect();\n'
         '\t\t\t#ifdef CONFIG_EXTCON_USB_CHG\n'
         '\t\t\tinfo->vbus_state = 0;\n'
         '\t\t\t#endif\n'
         '\t\t}\n'
         '\t}\n'),
        ('0077',
         '\tmt_chg->dev = &pdev->dev;\n'
         '\tmt_chg->chg_online = false;\n'
         '\tmt_chg->chg_type = CHARGER_UNKNOWN;\n'
         '\t/* before the power supplies, which mt6370 can set at once */\n'
         '\tmt_chg->usb_ws = wakeup_source_register(&pdev->dev, "usb_host");\n'
         '\n'
         '\tmt_chg->chg_desc.name = "charger";\n'
         '\tmt_chg->chg_desc.type = POWER_SUPPLY_TYPE_UNKNOWN;\n',
         '\tmt_chg->dev = &pdev->dev;\n'
         '\tmt_chg->chg_online = false;\n'
         '\tmt_chg->chg_type = CHARGER_UNKNOWN;\n'
         '\n'
         '\tmt_chg->chg_desc.name = "charger";\n'
         '\tmt_chg->chg_desc.type = POWER_SUPPLY_TYPE_UNKNOWN;\n'),
        ('0077',
         '\t\tdev_notice(&pdev->dev, "Failed to register power supply: %ld\\n",\n'
         '\t\t\tPTR_ERR(mt_chg->chg_psy));\n'
         '\t\tret = PTR_ERR(mt_chg->chg_psy);\n'
         '\t\tgoto err_chg_psy;\n'
         '\t}\n'
         '\n'
         '\tmt_chg->ac_psy = power_supply_register(&pdev->dev, &mt_chg->ac_desc,\n',
         '\t\tdev_notice(&pdev->dev, "Failed to register power supply: %ld\\n",\n'
         '\t\t\tPTR_ERR(mt_chg->chg_psy));\n'
         '\t\tret = PTR_ERR(mt_chg->chg_psy);\n'
         '\t\treturn ret;\n'
         '\t}\n'
         '\n'
         '\tmt_chg->ac_psy = power_supply_register(&pdev->dev, &mt_chg->ac_desc,\n'),
        ('0077',
         '\tpower_supply_unregister(mt_chg->ac_psy);\n'
         'err_ac_psy:\n'
         '\tpower_supply_unregister(mt_chg->chg_psy);\n'
         'err_chg_psy:\n'
         '\twakeup_source_unregister(mt_chg->usb_ws);\n'
         '\treturn ret;\n'
         '}\n'
         '\n',
         '\tpower_supply_unregister(mt_chg->ac_psy);\n'
         'err_ac_psy:\n'
         '\tpower_supply_unregister(mt_chg->chg_psy);\n'
         '\treturn ret;\n'
         '}\n'
         '\n'),
        ('0077',
         '\tpower_supply_unregister(mt_charger->chg_psy);\n'
         '\tpower_supply_unregister(mt_charger->ac_psy);\n'
         '\tpower_supply_unregister(mt_charger->usb_psy);\n'
         '\twakeup_source_unregister(mt_charger->usb_ws);\n'
         '\n'
         '\tpr_info("%s\\n", __func__);\n'
         '\tif (cti->chgdet_task) {\n',
         '\tpower_supply_unregister(mt_charger->chg_psy);\n'
         '\tpower_supply_unregister(mt_charger->ac_psy);\n'
         '\tpower_supply_unregister(mt_charger->usb_psy);\n'
         '\n'
         '\tpr_info("%s\\n", __func__);\n'
         '\tif (cti->chgdet_task) {\n'),
    ],
    'drivers/misc/mediatek/pmic/mt6370/mt6370_pmu_rgbled.c': [
        ('0078',
         '\t0x52, /* MT6370_PMU_REG_RGB3TR: 0x8F */\n'
         '\t0x25, /* MT6370_PMU_REG_RGB3TF: 0x90 */\n'
         '\t0x11, /* MT6370_PMU_REG_RGB3TONTOFF: 0x91 */\n'
         '\t0xE0, /* MT6370_PMU_REG_RGBCHRINDDIM: 0x92, CHG_IND auto off as stock */\n'
         '\t0x07, /* MT6370_PMU_REG_RGBCHRINDCTRL: 0x93 */\n'
         '\t0x52, /* MT6370_PMU_REG_RGBCHRINDTR: 0x94 */\n'
         '\t0x25, /* MT6370_PMU_REG_RGBCHRINDTF: 0x95 */\n',
         '\t0x52, /* MT6370_PMU_REG_RGB3TR: 0x8F */\n'
         '\t0x25, /* MT6370_PMU_REG_RGB3TF: 0x90 */\n'
         '\t0x11, /* MT6370_PMU_REG_RGB3TONTOFF: 0x91 */\n'
         '\t0x60, /* MT6370_PMU_REG_RGBCHRINDDIM: 0x92 */\n'
         '\t0x07, /* MT6370_PMU_REG_RGBCHRINDCTRL: 0x93 */\n'
         '\t0x52, /* MT6370_PMU_REG_RGBCHRINDTR: 0x94 */\n'
         '\t0x25, /* MT6370_PMU_REG_RGBCHRINDTF: 0x95 */\n'),
        ('0078',
         '\t},\n'
         '};\n'
         '/* 6372 end */\n'
         'static int mt6370_pmu_led_change_mode(struct led_classdev *led_cdev, int mode);\n'
         'static void mt6370_pmu_led_bright_set(struct led_classdev *led_cdev,\n'
         '\tenum led_brightness bright)\n'
         '{\n'
         '\tint led_index = mt6370_pmu_led_get_index(led_cdev);\n'
         '\tuint8_t reg_addr = 0, reg_mask = 0x7, reg_shift = 0, en_mask = 0;\n'
         '\tint ret = 0;\n'
         '\n'
         '\tswitch (led_index) {\n'
         '\tcase MT6370_PMU_LED1:\n'
         '\t\treg_addr = MT6370_PMU_REG_RGB1ISINK;\n'
         '\t\ten_mask = 0x80;\n'
         '\t\tbreak;\n'
         '\tcase MT6370_PMU_LED2:\n'
         '\t\treg_addr = MT6370_PMU_REG_RGB2ISINK;\n'
         '\t\ten_mask = 0x40;\n'
         '\t\tbreak;\n'
         '\tcase MT6370_PMU_LED3:\n'
         '\t\treg_addr = MT6370_PMU_REG_RGB3ISINK;\n'
         '\t\ten_mask = 0x20;\n'
         '\t\tbreak;\n'
         '\tcase MT6370_PMU_LED4:\n'
         '\t\treg_addr = MT6370_PMU_REG_RGBCHRINDCTRL;\n'
         '\t\treg_mask = 0x3;\n'
         '\t\ten_mask = 0x10;\n'
         '\t\tbreak;\n'
         '\tdefault:\n'
         '\t\tdev_err(led_cdev->dev, "invalid mt led index\\n");\n',
         '\t},\n'
         '};\n'
         '/* 6372 end */\n'
         'static void mt6370_pmu_led_bright_set(struct led_classdev *led_cdev,\n'
         '\tenum led_brightness bright)\n'
         '{\n'
         '\tint led_index = mt6370_pmu_led_get_index(led_cdev);\n'
         '\tuint8_t reg_addr = 0, reg_mask = 0x7, reg_shift = 0, en_mask = 0;\n'
         '\tbool need_enable_timer = true;\n'
         '\tint ret = 0;\n'
         '\n'
         '\tswitch (led_index) {\n'
         '\tcase MT6370_PMU_LED1:\n'
         '\t\treg_addr = MT6370_PMU_REG_RGB1ISINK;\n'
         '\t\ten_mask = 0x80;\n'
         '\t\tbreak;\n'
         '\tcase MT6370_PMU_LED2:\n'
         '\t\treg_addr = MT6370_PMU_REG_RGB2ISINK;\n'
         '\t\ten_mask = 0x40;\n'
         '\t\tbreak;\n'
         '\tcase MT6370_PMU_LED3:\n'
         '\t\treg_addr = MT6370_PMU_REG_RGB3ISINK;\n'
         '\t\ten_mask = 0x20;\n'
         '\t\tbreak;\n'
         '\tcase MT6370_PMU_LED4:\n'
         '\t\treg_addr = MT6370_PMU_REG_RGBCHRINDCTRL;\n'
         '\t\treg_mask = 0x3;\n'
         '\t\ten_mask = 0x10;\n'
         '\t\tneed_enable_timer = false;\n'
         '\t\tbreak;\n'
         '\tdefault:\n'
         '\t\tdev_err(led_cdev->dev, "invalid mt led index\\n");\n'),
        ('0078',
         '\t\tdev_err(led_cdev->dev, "update brightness fail\\n");\n'
         '\t\treturn;\n'
         '\t}\n'
         '\t/* As the stock 4.14 binary: software takes ISINK4 from the charger */\n'
         '\tif (led_index == MT6370_PMU_LED4) {\n'
         '\t\tret = mt6370_pmu_led_update_bits(led_cdev,\n'
         '\t\t\t\t\t\t MT6370_PMU_REG_RGBCHRINDDIM,\n'
         '\t\t\t\t\t\t 0x80, 0x80);\n'
         '\t\tif (ret < 0) {\n'
         '\t\t\tdev_err(led_cdev->dev, "disable auto mode fail\\n");\n'
         '\t\t\treturn;\n'
         '\t\t}\n'
         '\t}\n'
         '\tif (bright) {\n'
         '\t\t/* the dwork turns on every lit channel together */\n'
         '\t\tmt6370_pmu_led_enable_dwork(led_cdev);\n'
         '\t\treturn;\n'
         '\t}\n'
         '\tret = mt6370_pmu_led_update_bits(led_cdev, MT6370_PMU_REG_RGBEN,\n'
         '\t\t\t\t\t en_mask, ~en_mask);\n'
         '\tif (ret < 0) {\n'
         '\t\tdev_err(led_cdev->dev, "update enable bit fail\\n");\n'
         '\t\treturn;\n'
         '\t}\n'
         "\t/* Off leaves PWM blink mode, so the next steady value doesn't blink */\n"
         '\tret = mt6370_pmu_led_change_mode(led_cdev, MT6370_PMU_LED_REGMODE);\n'
         '\tif (ret < 0)\n'
         '\t\tdev_err(led_cdev->dev, "change mode fail\\n");\n'
         '}\n'
         '\n'
         'static enum led_brightness mt6370_pmu_led_bright_get(\n'
         '\tstruct led_classdev *led_cdev)\n'
         '{\n'
         '\tstruct mt6370_pmu_rgbled_data *rgbled_data =\n'
         '\t\t\t\tdev_get_drvdata(led_cdev->dev->parent);\n'
         '\tint led_index = mt6370_pmu_led_get_index(led_cdev);\n'
         '\tuint8_t reg_addr = 0, reg_mask = 0x7, reg_shift = 0, en_mask = 0;\n'
         '\tint ret = 0;\n'
         '\n'
         '\tswitch (led_index) {\n',
         '\t\tdev_err(led_cdev->dev, "update brightness fail\\n");\n'
         '\t\treturn;\n'
         '\t}\n'
         '\tif (!bright)\n'
         '\t\tneed_enable_timer = false;\n'
         '\tif (need_enable_timer) {\n'
         '\t\tmt6370_pmu_led_enable_dwork(led_cdev);\n'
         '\t\treturn;\n'
         '\t}\n'
         '\tret = mt6370_pmu_led_update_bits(led_cdev, MT6370_PMU_REG_RGBEN,\n'
         '\t\t\t\t\t en_mask,\n'
         '\t\t\t\t\t (bright > 0) ? en_mask : ~en_mask);\n'
         '\tif (ret < 0)\n'
         '\t\tdev_err(led_cdev->dev, "update enable bit fail\\n");\n'
         '}\n'
         '\n'
         'static enum led_brightness mt6370_pmu_led_bright_get(\n'
         '\tstruct led_classdev *led_cdev)\n'
         '{\n'
         '\tint led_index = mt6370_pmu_led_get_index(led_cdev);\n'
         '\tuint8_t reg_addr = 0, reg_mask = 0x7, reg_shift = 0, en_mask = 0;\n'
         '\tbool need_enable_timer = true;\n'
         '\tint ret = 0;\n'
         '\n'
         '\tswitch (led_index) {\n'),
        ('0078',
         '\t\treg_addr = MT6370_PMU_REG_RGBCHRINDCTRL;\n'
         '\t\treg_mask = 0x3;\n'
         '\t\ten_mask = 0x10;\n'
         '\t\tbreak;\n'
         '\tdefault:\n'
         '\t\tdev_err(led_cdev->dev, "invalid mt led index\\n");\n'
         '\t\treturn -EINVAL;\n'
         '\t}\n'
         '\t/*\n'
         '\t * The enable bit is written up to 100 ms after a brightness write.\n'
         '\t * Reading RGBEN before then gives 0, the core stores it in\n'
         '\t * brightness and the dwork then leaves the channel off.\n'
         '\t */\n'
         '\tif (delayed_work_pending(&rgbled_data->dwork))\n'
         '\t\treturn led_cdev->brightness;\n'
         '\tret = mt6370_pmu_led_reg_read(led_cdev, MT6370_PMU_REG_RGBEN);\n'
         '\tif (ret < 0)\n'
         '\t\treturn ret;\n',
         '\t\treg_addr = MT6370_PMU_REG_RGBCHRINDCTRL;\n'
         '\t\treg_mask = 0x3;\n'
         '\t\ten_mask = 0x10;\n'
         '\t\tneed_enable_timer = false;\n'
         '\t\tbreak;\n'
         '\tdefault:\n'
         '\t\tdev_err(led_cdev->dev, "invalid mt led index\\n");\n'
         '\t\treturn -EINVAL;\n'
         '\t}\n'
         '\tret = mt6370_pmu_led_reg_read(led_cdev, MT6370_PMU_REG_RGBEN);\n'
         '\tif (ret < 0)\n'
         '\t\treturn ret;\n'),
        ('0078',
         '\treturn 0;\n'
         '}\n'
         '\n'
         'static int mt6370_pmu_led_blink_set(struct led_classdev *led_cdev,\n'
         '\tunsigned long *delay_on, unsigned long *delay_off)\n'
         '{\n',
         '\treturn 0;\n'
         '}\n'
         '\n'
         'static int mt6370_pmu_led_change_mode(struct led_classdev *led_cdev, int mode);\n'
         'static int mt6370_pmu_led_blink_set(struct led_classdev *led_cdev,\n'
         '\tunsigned long *delay_on, unsigned long *delay_off)\n'
         '{\n'),
        ('0078',
         '\treturn 0;\n'
         '}\n'
         '\n'
         '/*\n'
         ' * delay_on_off: "on off" in ms, as the stock 4.14 LED core had it for the\n'
         ' * stock lights HAL. Sets the blink delays and calls led_blink_set(), which\n'
         ' * lands in mt6370_pmu_led_blink_set(): both non-zero blinks in PWM mode in\n'
         ' * the PMIC, "1 0" goes back to steady.\n'
         ' */\n'
         'static ssize_t delay_on_off_show(struct device *dev,\n'
         '\tstruct device_attribute *attr, char *buf)\n'
         '{\n'
         '\tstruct led_classdev *led_cdev = dev_get_drvdata(dev);\n'
         '\n'
         '\treturn sprintf(buf, "%lu %lu\\n", led_cdev->blink_delay_on,\n'
         '\t\t       led_cdev->blink_delay_off);\n'
         '}\n'
         '\n'
         'static ssize_t delay_on_off_store(struct device *dev,\n'
         '\tstruct device_attribute *attr, const char *buf, size_t size)\n'
         '{\n'
         '\tstruct led_classdev *led_cdev = dev_get_drvdata(dev);\n'
         '\tunsigned long on = 0, off = 0;\n'
         '\tssize_t ret = size;\n'
         '\n'
         '\tif (sscanf(buf, "%lu %lu", &on, &off) != 2)\n'
         '\t\treturn -EINVAL;\n'
         '\tmutex_lock(&led_cdev->led_access);\n'
         '\tif (led_sysfs_is_disabled(led_cdev)) {\n'
         '\t\tret = -EBUSY;\n'
         '\t\tgoto out;\n'
         '\t}\n'
         '\tled_cdev->blink_delay_on = on;\n'
         '\tled_cdev->blink_delay_off = off;\n'
         '\tled_blink_set(led_cdev, &led_cdev->blink_delay_on,\n'
         '\t\t      &led_cdev->blink_delay_off);\n'
         'out:\n'
         '\tmutex_unlock(&led_cdev->led_access);\n'
         '\treturn ret;\n'
         '}\n'
         'static DEVICE_ATTR_RW(delay_on_off);\n'
         '\n'
         'static struct attribute *mt6370_led_attrs[] = {\n'
         '\t&dev_attr_delay_on_off.attr,\n'
         '\tNULL,\n'
         '};\n'
         'ATTRIBUTE_GROUPS(mt6370_led);\n'
         '\n'
         'static struct mt6370_led_classdev mt6370_led_classdev[MT6370_PMU_MAXLED] = {\n'
         '\t{\n'
         '\t\t.led_dev =  {\n',
         '\treturn 0;\n'
         '}\n'
         '\n'
         'static struct mt6370_led_classdev mt6370_led_classdev[MT6370_PMU_MAXLED] = {\n'
         '\t{\n'
         '\t\t.led_dev =  {\n'),
        ('0078',
         '\t\t\t.brightness_set = mt6370_pmu_led_bright_set,\n'
         '\t\t\t.brightness_get = mt6370_pmu_led_bright_get,\n'
         '\t\t\t.blink_set = mt6370_pmu_led_blink_set,\n'
         '\t\t\t.groups = mt6370_led_groups,\n'
         '\t\t},\n'
         '\t\t.led_index = MT6370_PMU_LED1,\n'
         '\t},\n',
         '\t\t\t.brightness_set = mt6370_pmu_led_bright_set,\n'
         '\t\t\t.brightness_get = mt6370_pmu_led_bright_get,\n'
         '\t\t\t.blink_set = mt6370_pmu_led_blink_set,\n'
         '\t\t},\n'
         '\t\t.led_index = MT6370_PMU_LED1,\n'
         '\t},\n'),
        ('0078',
         '\t\t\t.brightness_set = mt6370_pmu_led_bright_set,\n'
         '\t\t\t.brightness_get = mt6370_pmu_led_bright_get,\n'
         '\t\t\t.blink_set = mt6370_pmu_led_blink_set,\n'
         '\t\t\t.groups = mt6370_led_groups,\n'
         '\t\t},\n'
         '\t\t.led_index = MT6370_PMU_LED2,\n'
         '\t},\n',
         '\t\t\t.brightness_set = mt6370_pmu_led_bright_set,\n'
         '\t\t\t.brightness_get = mt6370_pmu_led_bright_get,\n'
         '\t\t\t.blink_set = mt6370_pmu_led_blink_set,\n'
         '\t\t},\n'
         '\t\t.led_index = MT6370_PMU_LED2,\n'
         '\t},\n'),
        ('0078',
         '\t\t\t.brightness_set = mt6370_pmu_led_bright_set,\n'
         '\t\t\t.brightness_get = mt6370_pmu_led_bright_get,\n'
         '\t\t\t.blink_set = mt6370_pmu_led_blink_set,\n'
         '\t\t\t.groups = mt6370_led_groups,\n'
         '\t\t},\n'
         '\t\t.led_index = MT6370_PMU_LED3,\n'
         '\t},\n',
         '\t\t\t.brightness_set = mt6370_pmu_led_bright_set,\n'
         '\t\t\t.brightness_get = mt6370_pmu_led_bright_get,\n'
         '\t\t\t.blink_set = mt6370_pmu_led_blink_set,\n'
         '\t\t},\n'
         '\t\t.led_index = MT6370_PMU_LED3,\n'
         '\t},\n'),
        ('0078',
         '\t\t\t.brightness_set = mt6370_pmu_led_bright_set,\n'
         '\t\t\t.brightness_get = mt6370_pmu_led_bright_get,\n'
         '\t\t\t.blink_set = mt6370_pmu_led_blink_set,\n'
         '\t\t\t.groups = mt6370_led_groups,\n'
         '\t\t},\n'
         '\t\t.led_index = MT6370_PMU_LED4,\n'
         '\t},\n',
         '\t\t\t.brightness_set = mt6370_pmu_led_bright_set,\n'
         '\t\t\t.brightness_get = mt6370_pmu_led_bright_get,\n'
         '\t\t\t.blink_set = mt6370_pmu_led_blink_set,\n'
         '\t\t},\n'
         '\t\t.led_index = MT6370_PMU_LED4,\n'
         '\t},\n'),
        ('0078',
         '\tstruct mt6370_pmu_rgbled_data *rgbled_data =\n'
         '\t\tcontainer_of(work, struct mt6370_pmu_rgbled_data, dwork.work);\n'
         '\tu8 chip_vid = rgbled_data->chip->chip_vid;\n'
         '\tu8 reg_data = 0, reg_mask = 0xF0, reg_addr = MT6370_PMU_REG_RGBEN;\n'
         '\tint ret = 0;\n'
         '\n'
         '\tdev_dbg(rgbled_data->dev, "%s\\n", __func__);\n',
         '\tstruct mt6370_pmu_rgbled_data *rgbled_data =\n'
         '\t\tcontainer_of(work, struct mt6370_pmu_rgbled_data, dwork.work);\n'
         '\tu8 chip_vid = rgbled_data->chip->chip_vid;\n'
         '\tu8 reg_data = 0, reg_mask = 0xE0, reg_addr = MT6370_PMU_REG_RGBEN;\n'
         '\tint ret = 0;\n'
         '\n'
         '\tdev_dbg(rgbled_data->dev, "%s\\n", __func__);\n'),
        ('0078',
         '\t/* green */\n'
         '\tif (mt6370_led_classdev[2].led_dev.brightness != 0)\n'
         '\t\treg_data |= 0x20;\n'
         '\t/* ISINK4 too, as the stock binary */\n'
         '\tif (mt6370_led_classdev[3].led_dev.brightness != 0)\n'
         '\t\treg_data |= 0x10;\n'
         '\t/* if 6372 */\n'
         '\tif (chip_vid == MT6372_VENDOR_ID || chip_vid == MT6372C_VENDOR_ID)\n'
         '\t\treg_addr = 0x82;\n',
         '\t/* green */\n'
         '\tif (mt6370_led_classdev[2].led_dev.brightness != 0)\n'
         '\t\treg_data |= 0x20;\n'
         '\t/* if 6372 */\n'
         '\tif (chip_vid == MT6372_VENDOR_ID || chip_vid == MT6372C_VENDOR_ID)\n'
         '\t\treg_addr = 0x82;\n'),
    ],
    'drivers/input/touchscreen/pocket-gt1151.c': [
        ('0079',
         '\n'
         '\t/* Chip access from the IRQ thread, ESD work, sleep and wake. */\n'
         '\tstruct mutex lock;\n'
         '\t/*\n'
         "\t * The ESD check, sleep and wake, as stock's ESD mutex: the ESD work\n"
         '\t * holds it through its 50 ms sleeps, without lock, so touch reports\n'
         '\t * go on. Taken before lock.\n'
         '\t */\n'
         '\tstruct mutex cmd_lock;\n'
         '\t/* Stock irq_flag: true while this driver holds the IRQ disabled. */\n'
         '\tspinlock_t irq_lock;\n'
         '\tbool irq_off;\n',
         '\n'
         '\t/* Chip access from the IRQ thread, ESD work, sleep and wake. */\n'
         '\tstruct mutex lock;\n'
         '\t/* Stock irq_flag: true while this driver holds the IRQ disabled. */\n'
         '\tspinlock_t irq_lock;\n'
         '\tbool irq_off;\n'),
        ('0079',
         '\treturn 0;\n'
         '}\n'
         '\n'
         '/* Data and checksum to 0x8041, then the command to 0x8040. */\n'
         'static int gt_write_cmd(struct gt1151 *ts, u8 cmd, u8 data)\n'
         '{\n'
         '\tu8 buf[3] = { cmd, data, (u8)(0 - cmd - data) };\n'
         '\tint ret;\n'
         '\n'
         '\tret = gt_write(ts, GT_REG_CMD + 1, buf + 1, 2);\n'
         '\tret |= gt_write(ts, GT_REG_CMD, buf, 1);\n'
         '\treturn ret;\n'
         '}\n'
         '\n'
         '/* The command, then 50 ms. */\n'
         'static int gt_send_cmd(struct gt1151 *ts, u8 cmd, u8 data)\n'
         '{\n'
         '\tint ret = gt_write_cmd(ts, cmd, data);\n'
         '\n'
         '\tmsleep(50);\n'
         '\treturn ret;\n'
         '}\n',
         '\treturn 0;\n'
         '}\n'
         '\n'
         '/* Data and checksum to 0x8041, then the command to 0x8040, then 50 ms. */\n'
         'static int gt_send_cmd(struct gt1151 *ts, u8 cmd, u8 data)\n'
         '{\n'
         '\tu8 buf[3] = { cmd, data, (u8)(0 - cmd - data) };\n'
         '\tint ret;\n'
         '\n'
         '\tret = gt_write(ts, GT_REG_CMD + 1, buf + 1, 2);\n'
         '\tret |= gt_write(ts, GT_REG_CMD, buf, 1);\n'
         '\tmsleep(50);\n'
         '\treturn ret;\n'
         '}\n'),
        ('0079',
         ' * Stock gt1151qm_esd_check_func: up to 3 reads of 0x8040, 50 ms apart; a\n'
         ' * live chip shows 0x8040 != 0xaa and 0x8043 == 0xaa and gets fed 0xaa.\n'
         ' * Otherwise 0x4226 gets 01 01 01 01 and the supply is cycled.\n'
         ' * Only the reset holds lock across its sleeps, to keep the IRQ thread out.\n'
         ' */\n'
         'static void gt_esd_work(struct work_struct *work)\n'
         '{\n'
         '\tstruct gt1151 *ts = container_of(to_delayed_work(work), struct gt1151, esd_work);\n'
         '\tu8 buf[4] = { 0 };\n'
         '\tstatic const u8 reset[4] = { 1, 1, 1, 1 };\n'
         '\tint i, ret;\n'
         '\n'
         '\tmutex_lock(&ts->cmd_lock);\n'
         '\tif (!READ_ONCE(ts->esd_running))\n'
         '\t\tgoto out;\n'
         '\tfor (i = 0; i < 3; i++) {\n'
         '\t\tmutex_lock(&ts->lock);\n'
         '\t\tret = gt_read(ts, GT_REG_CMD, buf, sizeof(buf));\n'
         '\t\tmutex_unlock(&ts->lock);\n'
         '\t\tif (!ret && buf[0] != 0xaa && buf[3] == 0xaa)\n'
         '\t\t\tbreak;\n'
         '\t\tmsleep(50);\n'
         '\t}\n'
         '\tif (i < 3) {\n'
         '\t\tmutex_lock(&ts->lock);\n'
         '\t\tgt_write_cmd(ts, GT_CMD_ESD, 0);\n'
         '\t\tmutex_unlock(&ts->lock);\n'
         '\t\tmsleep(50);\n'
         '\t} else if (READ_ONCE(ts->esd_running)) {\n'
         '\t\tdev_err(&ts->client->dev, "chip not answering ESD check, resetting\\n");\n'
         '\t\tmutex_lock(&ts->lock);\n'
         '\t\tgt_write(ts, GT_REG_ESD_RESET, reset, sizeof(reset));\n'
         '\t\tmsleep(50);\n'
         '\t\tgt_power_reset(ts);\n'
         '\t\tmutex_unlock(&ts->lock);\n'
         '\t}\n'
         'out:\n'
         '\tmutex_unlock(&ts->cmd_lock);\n'
         '\tmutex_lock(&ts->esd_lock);\n'
         '\tif (ts->esd_running)\n'
         '\t\tqueue_delayed_work(ts->wq, &ts->esd_work, GT_ESD_PERIOD);\n',
         ' * Stock gt1151qm_esd_check_func: up to 3 reads of 0x8040, 50 ms apart; a\n'
         ' * live chip shows 0x8040 != 0xaa and 0x8043 == 0xaa and gets fed 0xaa.\n'
         ' * Otherwise 0x4226 gets 01 01 01 01 and the supply is cycled.\n'
         ' */\n'
         'static void gt_esd_work(struct work_struct *work)\n'
         '{\n'
         '\tstruct gt1151 *ts = container_of(to_delayed_work(work), struct gt1151, esd_work);\n'
         '\tu8 buf[4] = { 0 };\n'
         '\tstatic const u8 reset[4] = { 1, 1, 1, 1 };\n'
         '\tint i;\n'
         '\n'
         '\tmutex_lock(&ts->lock);\n'
         '\tif (!READ_ONCE(ts->esd_running))\n'
         '\t\tgoto out;\n'
         '\tfor (i = 0; i < 3; i++) {\n'
         '\t\tif (!gt_read(ts, GT_REG_CMD, buf, sizeof(buf)) && buf[0] != 0xaa && buf[3] == 0xaa)\n'
         '\t\t\tbreak;\n'
         '\t\tmsleep(50);\n'
         '\t}\n'
         '\tif (i < 3) {\n'
         '\t\tgt_send_cmd(ts, GT_CMD_ESD, 0);\n'
         '\t} else if (READ_ONCE(ts->esd_running)) {\n'
         '\t\tdev_err(&ts->client->dev, "chip not answering ESD check, resetting\\n");\n'
         '\t\tgt_write(ts, GT_REG_ESD_RESET, reset, sizeof(reset));\n'
         '\t\tmsleep(50);\n'
         '\t\tgt_power_reset(ts);\n'
         '\t}\n'
         'out:\n'
         '\tmutex_unlock(&ts->lock);\n'
         '\tmutex_lock(&ts->esd_lock);\n'
         '\tif (ts->esd_running)\n'
         '\t\tqueue_delayed_work(ts->wq, &ts->esd_work, GT_ESD_PERIOD);\n'),
        ('0079',
         '\n'
         '\tdev_info(&ts->client->dev, "suspend\\n");\n'
         '\tgt_esd_switch(ts, false);\n'
         '\tmutex_lock(&ts->cmd_lock);\n'
         '\tmutex_lock(&ts->lock);\n'
         '\tts->halted = true;\n'
         '\tif (ts->wakeup_level == 1)\n',
         '\n'
         '\tdev_info(&ts->client->dev, "suspend\\n");\n'
         '\tgt_esd_switch(ts, false);\n'
         '\tmutex_lock(&ts->lock);\n'
         '\tts->halted = true;\n'
         '\tif (ts->wakeup_level == 1)\n'),
        ('0079',
         '\t\tmsleep(10);\n'
         '\t}\n'
         '\tmutex_unlock(&ts->lock);\n'
         '\tmutex_unlock(&ts->cmd_lock);\n'
         '\tif (ret)\n'
         '\t\tdev_err(&ts->client->dev, "enter sleep failed\\n");\n'
         '\tmsleep(58);\n',
         '\t\tmsleep(10);\n'
         '\t}\n'
         '\tmutex_unlock(&ts->lock);\n'
         '\tif (ret)\n'
         '\t\tdev_err(&ts->client->dev, "enter sleep failed\\n");\n'
         '\tmsleep(58);\n'),
        ('0079',
         '\tint ret;\n'
         '\n'
         '\tdev_info(&ts->client->dev, "resume\\n");\n'
         '\tmutex_lock(&ts->cmd_lock);\n'
         '\tmutex_lock(&ts->lock);\n'
         '\tgt_irq_disable(ts);\n'
         '\tret = gt_reset_guitar(ts);\n',
         '\tint ret;\n'
         '\n'
         '\tdev_info(&ts->client->dev, "resume\\n");\n'
         '\tmutex_lock(&ts->lock);\n'
         '\tgt_irq_disable(ts);\n'
         '\tret = gt_reset_guitar(ts);\n'),
        ('0079',
         '\tts->halted = false;\n'
         '\tgt_irq_enable(ts);\n'
         '\tmutex_unlock(&ts->lock);\n'
         '\tmutex_unlock(&ts->cmd_lock);\n'
         '\tgt_esd_switch(ts, true);\n'
         '}\n'
         '\n',
         '\tts->halted = false;\n'
         '\tgt_irq_enable(ts);\n'
         '\tmutex_unlock(&ts->lock);\n'
         '\tgt_esd_switch(ts, true);\n'
         '}\n'
         '\n'),
        ('0079',
         '\t\treturn -ENOMEM;\n'
         '\tts->client = client;\n'
         '\tmutex_init(&ts->lock);\n'
         '\tmutex_init(&ts->cmd_lock);\n'
         '\tmutex_init(&ts->esd_lock);\n'
         '\tspin_lock_init(&ts->irq_lock);\n'
         '\tINIT_DELAYED_WORK(&ts->esd_work, gt_esd_work);\n',
         '\t\treturn -ENOMEM;\n'
         '\tts->client = client;\n'
         '\tmutex_init(&ts->lock);\n'
         '\tmutex_init(&ts->esd_lock);\n'
         '\tspin_lock_init(&ts->irq_lock);\n'
         '\tINIT_DELAYED_WORK(&ts->esd_work, gt_esd_work);\n'),
    ],
    'drivers/scsi/ufs/ufs-mediatek.h': [
        ('0080',
         '\tbool unipro_lpm;\n'
         '\tbool ref_clk_enabled;\n'
         '\tbool ram_probe;\n'
         '\t/* MT6771 system sleep level in force, 0 outside system suspend. */\n'
         '\tunsigned int sleep_level;\n'
         '\tbool vcc_always_on_saved;\n'
         '\tu16 ref_clk_ungating_wait_us;\n'
         '\tu16 ref_clk_gating_wait_us;\n'
         '};\n',
         '\tbool unipro_lpm;\n'
         '\tbool ref_clk_enabled;\n'
         '\tbool ram_probe;\n'
         '\tu16 ref_clk_ungating_wait_us;\n'
         '\tu16 ref_clk_gating_wait_us;\n'
         '};\n'),
    ],
    'drivers/scsi/ufs/ufs-mediatek.c': [
        ('0080',
         '\n'
         '#define CREATE_TRACE_POINTS\n'
         '#include "ufs-mediatek-trace.h"\n'
         '\n'
         '/*\n'
         ' * MT6771 system sleep depth, read at each system suspend:\n'
         ' * 0 leaves host, link and device active,\n'
         ' * 1 sends SSU (sleep), puts the link in Hibern8 with UniPro power-down and\n'
         ' *   gates the host clocks,\n'
         " * 2 also powers the M-PHY down and gates XO_UFS, in stock's order.\n"
         ' * VA09 and VCC stay on at every level. Runtime PM stays pinned.\n'
         ' */\n'
         'static unsigned int mt6771_sleep = 2;\n'
         'module_param(mt6771_sleep, uint, 0644);\n'
         'MODULE_PARM_DESC(mt6771_sleep, "MT6771 UFS system sleep level (0-2)");\n'
         '\n'
         'static bool ufs_mtk_uses_mt6771_fw(struct ufs_hba *hba)\n'
         '{\n',
         '\n'
         '#define CREATE_TRACE_POINTS\n'
         '#include "ufs-mediatek-trace.h"\n'
         '\n'
         'static bool ufs_mtk_uses_mt6771_fw(struct ufs_hba *hba)\n'
         '{\n'),
        ('0080',
         '\t\treturn 0;\n'
         '\tif (!host->legacy_ref_clk)\n'
         '\t\treturn -ENODEV;\n'
         '\t/*\n'
         '\t * Off only in a level 2 system sleep. Level 1 keeps it on and lets the\n'
         '\t * host clocks gate. Stock off also drops the UFS spm_resource_req vote,\n'
         "\t * which only deep idle and SODI read, so system suspend doesn't need it.\n"
         '\t */\n'
         '\tif (!on) {\n'
         '\t\tif (host->sleep_level < 2)\n'
         '\t\t\treturn host->sleep_level ? 0 : -EOPNOTSUPP;\n'
         '\t\t/* Stock wait between Hibern8 and gating, in us. */\n'
         '\t\tswitch (hba->dev_info.wmanufacturerid) {\n'
         '\t\tcase UFS_VENDOR_TOSHIBA:\n'
         '\t\t\tudelay(100);\n'
         '\t\t\tbreak;\n'
         '\t\tcase UFS_VENDOR_SAMSUNG:\n'
         '\t\t\tudelay(1);\n'
         '\t\t\tbreak;\n'
         '\t\tdefault:\n'
         '\t\t\tudelay(30);\n'
         '\t\t\tbreak;\n'
         '\t\t}\n'
         '\t\tclk_disable_unprepare(host->legacy_ref_clk);\n'
         '\t\thost->ref_clk_enabled = false;\n'
         '\t\treturn 0;\n'
         '\t}\n'
         '\tret = clk_prepare_enable(host->legacy_ref_clk);\n'
         '\tif (ret)\n'
         '\t\treturn ret;\n',
         '\t\treturn 0;\n'
         '\tif (!host->legacy_ref_clk)\n'
         '\t\treturn -ENODEV;\n'
         '\t/* Stock off also releases the UFS SPM resource vote. No SPM supplier\n'
         '\t * exists in this port yet: fail visibly without clock/PHY/power writes.\n'
         '\t * Production PM stays disabled; the RAM probe pins runtime PM and\n'
         '\t * rejects suspend until that complete dependency is integrated.\n'
         '\t */\n'
         '\tif (!on)\n'
         '\t\treturn -EOPNOTSUPP;\n'
         '\tret = clk_prepare_enable(host->legacy_ref_clk);\n'
         '\tif (ret)\n'
         '\t\treturn ret;\n'),
        ('0080',
         '\t\t}\n'
         '\t} else if (on && status == POST_CHANGE) {\n'
         '\t\t/* Generic resume restores clocks before the variant resume hook. */\n'
         '\t\tif (ufs_mtk_uses_mt6771_fw(hba)) {\n'
         '\t\t\t/* Stock turns XO_UFS on before it releases the M-PHY. */\n'
         '\t\t\tret = ufs_mtk_setup_ref_clk(hba, true);\n'
         '\t\t\tif (ret)\n'
         '\t\t\t\treturn ret;\n'
         '\t\t}\n'
         '\t\tif (ufs_mtk_uses_mt6771_fw(hba) && !host->mphy_powered_on) {\n'
         '\t\t\tret = ufs_mtk_mphy_power_on(hba, true);\n'
         '\t\t\tif (ret)\n',
         '\t\t}\n'
         '\t} else if (on && status == POST_CHANGE) {\n'
         '\t\t/* Generic resume restores clocks before the variant resume hook. */\n'
         '\t\tif (ufs_mtk_uses_mt6771_fw(hba) && !host->mphy_powered_on) {\n'
         '\t\t\tret = ufs_mtk_mphy_power_on(hba, true);\n'
         '\t\t\tif (ret)\n'),
        ('0080',
         '\t\t\t\t   REGULATOR_MODE_NORMAL);\n'
         '}\n'
         '\n'
         '/* Level 2: drop both PHY votes so phy-mtk-ufs runs its power-down, then gate\n'
         ' * XO_UFS. VA09 stays on.\n'
         ' */\n'
         'static int ufs_mt6771_phy_ref_off(struct ufs_hba *hba)\n'
         '{\n'
         '\tstruct ufs_mtk_host *host = ufshcd_get_variant(hba);\n'
         '\tint err;\n'
         '\n'
         '\terr = ufs_mtk_wait_link_state(hba, VS_LINK_HIBERN8, 15);\n'
         '\tif (err)\n'
         '\t\treturn err;\n'
         '\tif (host->clk_phy_voted) {\n'
         '\t\terr = phy_power_off(host->mphy);\n'
         '\t\tif (err)\n'
         '\t\t\treturn err;\n'
         '\t\thost->clk_phy_voted = false;\n'
         '\t}\n'
         '\tif (host->mphy_enabled) {\n'
         '\t\terr = phy_power_off(host->mphy);\n'
         '\t\tif (err)\n'
         '\t\t\tgoto phy_on;\n'
         '\t\thost->mphy_enabled = false;\n'
         '\t\thost->mphy_powered_on = false;\n'
         '\t}\n'
         '\terr = ufs_mt6771_setup_ref_clk(hba, false);\n'
         '\tif (!err)\n'
         '\t\treturn 0;\n'
         'phy_on:\n'
         '\tif (!ufs_mtk_mphy_power_on(hba, true) && !phy_power_on(host->mphy))\n'
         '\t\thost->clk_phy_voted = true;\n'
         '\treturn err;\n'
         '}\n'
         '\n'
         '/* ufshcd_suspend() has sent SSU (sleep) and put the link in Hibern8. */\n'
         'static int ufs_mt6771_suspend(struct ufs_hba *hba)\n'
         '{\n'
         '\tstruct ufs_mtk_host *host = ufshcd_get_variant(hba);\n'
         '\tint err;\n'
         '\n'
         '\tif (!ufshcd_is_link_hibern8(hba))\n'
         '\t\treturn -EINVAL;\n'
         '\t/* Vendor UniPro power-down, as stock; it undoes itself on failure. */\n'
         '\terr = ufs_mtk_link_set_lpm(hba);\n'
         '\tif (err)\n'
         '\t\treturn err;\n'
         '\tif (host->sleep_level < 2)\n'
         '\t\treturn 0;\n'
         '\terr = ufs_mt6771_phy_ref_off(hba);\n'
         '\tif (err)\n'
         '\t\tufs_mtk_unipro_set_pm(hba, false);\n'
         '\treturn err;\n'
         '}\n'
         '\n'
         'static int ufs_mtk_suspend(struct ufs_hba *hba, enum ufs_pm_op pm_op)\n'
         '{\n'
         '\tint err;\n'
         '\tstruct arm_smccc_res res;\n'
         '\tstruct ufs_mtk_host *host = ufshcd_get_variant(hba);\n'
         '\n'
         '\tif (host->ram_probe) {\n'
         '\t\tif (pm_op != UFS_SYSTEM_PM || !host->sleep_level)\n'
         '\t\t\treturn -EOPNOTSUPP;\n'
         '\t\treturn ufs_mt6771_suspend(hba);\n'
         '\t}\n'
         '\tif (ufshcd_is_link_hibern8(hba)) {\n'
         '\t\terr = ufs_mtk_link_set_lpm(hba);\n'
         '\t\tif (err)\n',
         '\t\t\t\t   REGULATOR_MODE_NORMAL);\n'
         '}\n'
         '\n'
         'static int ufs_mtk_suspend(struct ufs_hba *hba, enum ufs_pm_op pm_op)\n'
         '{\n'
         '\tint err;\n'
         '\tstruct arm_smccc_res res;\n'
         '\tstruct ufs_mtk_host *host = ufshcd_get_variant(hba);\n'
         '\n'
         '\tif (host->ram_probe)\n'
         '\t\treturn -EOPNOTSUPP;\n'
         '\tif (ufshcd_is_link_hibern8(hba)) {\n'
         '\t\terr = ufs_mtk_link_set_lpm(hba);\n'
         '\t\tif (err)\n'),
        ('0080',
         '\tint err;\n'
         '\tstruct ufs_mtk_host *host = ufshcd_get_variant(hba);\n'
         '\n'
         '\t/* setup_clocks() has already restored XO_UFS and the M-PHY. */\n'
         '\tif (host->ram_probe && (pm_op != UFS_SYSTEM_PM || !host->sleep_level))\n'
         '\t\treturn -EOPNOTSUPP;\n'
         '\terr = ufs_mtk_mphy_power_on(hba, true);\n'
         '\tif (err)\n',
         '\tint err;\n'
         '\tstruct ufs_mtk_host *host = ufshcd_get_variant(hba);\n'
         '\n'
         '\tif (host->ram_probe)\n'
         '\t\treturn -EOPNOTSUPP;\n'
         '\terr = ufs_mtk_mphy_power_on(hba, true);\n'
         '\tif (err)\n'),
        ('0080',
         'static int ufs_mtk_apply_dev_quirks(struct ufs_hba *hba)\n'
         '{\n'
         '\tstruct ufs_dev_info *dev_info = &hba->dev_info;\n'
         '\tstruct ufs_mtk_host *host = ufshcd_get_variant(hba);\n'
         '\tu16 mid = dev_info->wmanufacturerid;\n'
         '\n'
         '\t/*\n'
         '\t * The card is known now: take a clock reference on the inherited-on\n'
         '\t * XO_UFS so a level 2 sleep can gate it. If that fails the buffer is\n'
         "\t * left as it is and sleep just won't gate it.\n"
         '\t */\n'
         '\tif (ufs_mtk_uses_mt6771_fw(hba) && !host->ref_clk_enabled) {\n'
         '\t\tint ret = ufs_mt6771_setup_ref_clk(hba, true);\n'
         '\n'
         '\t\tif (ret)\n'
         '\t\t\tdev_warn(hba->dev, "XO_UFS not owned: %d\\n", ret);\n'
         '\t}\n'
         '\n'
         '\tif (mid == UFS_VENDOR_SAMSUNG)\n'
         '\t\tufshcd_dme_set(hba, UIC_ARG_MIB(PA_TACTIVATE), 6);\n',
         'static int ufs_mtk_apply_dev_quirks(struct ufs_hba *hba)\n'
         '{\n'
         '\tstruct ufs_dev_info *dev_info = &hba->dev_info;\n'
         '\tu16 mid = dev_info->wmanufacturerid;\n'
         '\n'
         '\tif (mid == UFS_VENDOR_SAMSUNG)\n'
         '\t\tufshcd_dme_set(hba, UIC_ARG_MIB(PA_TACTIVATE), 6);\n'),
        ('0080',
         '\n'
         '#ifdef CONFIG_PM_SLEEP\n'
         '/*\n'
         ' * MT6771 binding: with mt6771_sleep at 0, system sleep leaves the host, link\n'
         ' * and device active, since ufshcd_suspend() would send SSU and enter Hibern8\n'
         ' * before ufs_mtk_suspend() could refuse. Levels 1 and 2 go through\n'
         ' * ufshcd_suspend() with VCC held on.\n'
         ' */\n'
         'static int ufs_mtk_system_suspend(struct device *dev)\n'
         '{\n'
         '\tstruct ufs_hba *hba = dev_get_drvdata(dev);\n'
         '\tstruct ufs_mtk_host *host = ufshcd_get_variant(hba);\n'
         '\tstruct ufs_vreg *vcc = hba->vreg_info.vcc;\n'
         '\tint ret;\n'
         '\n'
         '\tif (host->ram_probe) {\n'
         '\t\thost->sleep_level = min(READ_ONCE(mt6771_sleep), 2U);\n'
         '\t\tif (!host->sleep_level)\n'
         '\t\t\treturn 0;\n'
         '\t\tif (vcc) {\n'
         '\t\t\thost->vcc_always_on_saved = vcc->always_on;\n'
         '\t\t\tvcc->always_on = true;\n'
         '\t\t}\n'
         '\t}\n'
         '\tret = ufshcd_pltfrm_suspend(dev);\n'
         '\tif (ret && host->ram_probe) {\n'
         '\t\tdev_err(dev, "sleep level %u failed: %d\\n", host->sleep_level, ret);\n'
         '\t\tif (vcc)\n'
         '\t\t\tvcc->always_on = host->vcc_always_on_saved;\n'
         '\t\thost->sleep_level = 0;\n'
         '\t}\n'
         '\treturn ret;\n'
         '}\n'
         '\n'
         'static int ufs_mtk_system_resume(struct device *dev)\n'
         '{\n'
         '\tstruct ufs_hba *hba = dev_get_drvdata(dev);\n'
         '\tstruct ufs_mtk_host *host = ufshcd_get_variant(hba);\n'
         '\tint ret;\n'
         '\n'
         '\tif (host->ram_probe && !host->sleep_level)\n'
         '\t\treturn 0;\n'
         '\tret = ufshcd_pltfrm_resume(dev);\n'
         '\tif (host->ram_probe) {\n'
         '\t\tif (ret)\n'
         '\t\t\tdev_err(dev, "resume from sleep level %u failed: %d\\n",\n'
         '\t\t\t\thost->sleep_level, ret);\n'
         '\t\tif (hba->vreg_info.vcc)\n'
         '\t\t\thba->vreg_info.vcc->always_on = host->vcc_always_on_saved;\n'
         '\t\thost->sleep_level = 0;\n'
         '\t}\n'
         '\treturn ret;\n'
         '}\n'
         '#else\n'
         '#define ufs_mtk_system_suspend\tNULL\n',
         '\n'
         '#ifdef CONFIG_PM_SLEEP\n'
         '/*\n'
         ' * The RAM storage binding has no tested low-power path, and ufshcd_suspend()\n'
         ' * would send START STOP UNIT and enter Hibern8 before ufs_mtk_suspend() can\n'
         ' * refuse. So system sleep (s2idle) leaves the host, link and device active.\n'
         ' */\n'
         'static int ufs_mtk_system_suspend(struct device *dev)\n'
         '{\n'
         '\tstruct ufs_hba *hba = dev_get_drvdata(dev);\n'
         '\tstruct ufs_mtk_host *host = ufshcd_get_variant(hba);\n'
         '\n'
         '\tif (host->ram_probe)\n'
         '\t\treturn 0;\n'
         '\treturn ufshcd_pltfrm_suspend(dev);\n'
         '}\n'
         '\n'
         'static int ufs_mtk_system_resume(struct device *dev)\n'
         '{\n'
         '\tstruct ufs_hba *hba = dev_get_drvdata(dev);\n'
         '\tstruct ufs_mtk_host *host = ufshcd_get_variant(hba);\n'
         '\n'
         '\tif (host->ram_probe)\n'
         '\t\treturn 0;\n'
         '\treturn ufshcd_pltfrm_resume(dev);\n'
         '}\n'
         '#else\n'
         '#define ufs_mtk_system_suspend\tNULL\n'),
    ],
    'drivers/power/supply/mediatek/charger/mtk_charger.c': [
        ('0089', '\tint bat_current = 0, chg_current = 0;\n\n\twhile (1) {\n\t\twait_event_idle(info->wait_que,\n\t\t\t(info->charger_thread_timeout == true));\n\n\t\tmutex_lock(&info->charger_lock);\n',
         '\tint bat_current = 0, chg_current = 0;\n\n\twhile (1) {\n\t\twait_event(info->wait_que,\n\t\t\t(info->charger_thread_timeout == true));\n\n\t\tmutex_lock(&info->charger_lock);\n'),
        ('0081', '\n/*\n * charging_enabled: 0 pauses charging, 1 lets it run again (the health HAL\'s\n * charging control). It sets cmd_discharging, which charger_check_status reads\n * each loop, so the charger thread turns charging off the same way as for a\n * temperature stop: CHG_EN off, the algorithm in CHR_ERROR, status not\n * charging. The input stays on, so the phone runs from USB power.\n */\nstatic ssize_t show_charging_enabled(struct device *dev,\n\t\tstruct device_attribute *attr, char *buf)\n{\n\tstruct charger_manager *pinfo = dev->driver_data;\n\n\treturn sprintf(buf, "%d\\n", !pinfo->cmd_discharging);\n}\n\nstatic ssize_t store_charging_enabled(struct device *dev,\n\t\tstruct device_attribute *attr, const char *buf, size_t size)\n{\n\tstruct charger_manager *pinfo = dev->driver_data;\n\tbool en;\n\n\tif (kstrtobool(buf, &en))\n\t\treturn -EINVAL;\n\n\tmutex_lock(&pinfo->charger_lock);\n\tpinfo->cmd_discharging = !en;\n\tmutex_unlock(&pinfo->charger_lock);\n\tchr_err("%s: %d\\n", __func__, en);\n\t_wake_up_charger(pinfo);\n\treturn size;\n}\nstatic DEVICE_ATTR(charging_enabled, 0644, show_charging_enabled,\n\t\t   store_charging_enabled);\n'),
        ('0081', '\n\tret = device_create_file(&(pdev->dev), &dev_attr_charging_enabled);\n\tif (ret)\n\t\tgoto _out;\n'),
    ] + [('0084', '\t/* -1 means no thermal limit, so print it signed. */\n\treturn sprintf(buf, "%d\\n",\n'
                  '\t\t\tpinfo->' + field + ');\n',
          '\treturn sprintf(buf, "%u\\n",\n\t\t\tpinfo->' + field + ');\n')
         for field in ('chg1_data.thermal_input_current_limit', 'chg1_data.thermal_charging_current_limit',
                       'chg2_data.thermal_charging_current_limit')],
    'drivers/misc/mediatek/sensors-1.0/hwmon/sensor_list/sensor_list.c': [
        ('0086', '\n#ifdef CONFIG_CUSTOM_KERNEL_SENSORHUB\n/*\n * The SCP auto-detects its chips for a second or more after READY, so a name\n * asked for at SENSOR_POWER_UP may not be there yet. Ask again once a second,\n * up to SENSORLIST_TRIES times, for the entries still "NULL".\n */\n#define SENSORLIST_TRIES 10\nstatic struct delayed_work sensorlist_work;\nstatic int sensorlist_tries;\n#endif\nstatic atomic_t first_ready_after_boot;\n',
         '\n#ifdef CONFIG_CUSTOM_KERNEL_SENSORHUB\nstatic struct work_struct sensorlist_work;\n#endif\nstatic atomic_t first_ready_after_boot;\n'),
        ('0086', 'static void sensorlist_get_deviceinfo(struct work_struct *work)\n{\n\tint err = 0, handle = -1, sensor = -1, missing = 0;\n\tbool last = ++sensorlist_tries >= SENSORLIST_TRIES;\n\tstruct sensorInfo_t devinfo;\n\n',
         'static void sensorlist_get_deviceinfo(struct work_struct *work)\n{\n\tint err = 0, handle = -1, sensor = -1;\n\tstruct sensorInfo_t devinfo;\n\n'),
        ('0086', '\t\tif (sensor < 0)\n\t\t\tcontinue;\n\t\tif (strcmp(sensorlist_info[handle].name, "NULL"))\n\t\t\tcontinue;\n\t\tmemset(&devinfo, 0, sizeof(struct sensorInfo_t));\n\t\terr = sensor_set_cmd_to_hub(sensor,\n\t\t\tCUST_ACTION_GET_SENSOR_INFO, &devinfo);\n\t\tif (err < 0) {\n\t\t\tmissing++;\n\t\t\tif (last)\n\t\t\t\tpr_err("sensor(%d) not register\\n", sensor);\n\t\t\tcontinue;\n\t\t}\n',
         '\t\tif (sensor < 0)\n\t\t\tcontinue;\n\t\tmemset(&devinfo, 0, sizeof(struct sensorInfo_t));\n\t\terr = sensor_set_cmd_to_hub(sensor,\n\t\t\tCUST_ACTION_GET_SENSOR_INFO, &devinfo);\n\t\tif (err < 0) {\n\t\t\tpr_err("sensor(%d) not register\\n", sensor);\n\t\t\tcontinue;\n\t\t}\n'),
        ('0086', '\t\t\tsizeof(sensorlist_info[handle].name));\n\t\tspin_unlock(&sensorlist_info_lock);\n\t\tpr_info("sensor(%d) %s, try %d\\n", sensor,\n\t\t\tsensorlist_info[handle].name, sensorlist_tries);\n\t}\n\tif (missing && !last)\n\t\tschedule_delayed_work(&sensorlist_work, HZ);\n}\n\n',
         '\t\t\tsizeof(sensorlist_info[handle].name));\n\t\tspin_unlock(&sensorlist_info_lock);\n\t}\n}\n\n'),
        ('0086', '\t\tif (likely(atomic_xchg(&first_ready_after_boot, 1)))\n\t\t\treturn 0;\n\t\tschedule_delayed_work(&sensorlist_work, 0);\n\t\tbreak;\n\tcase SENSOR_POWER_DOWN:\n',
         '\t\tif (likely(atomic_xchg(&first_ready_after_boot, 1)))\n\t\t\treturn 0;\n\t\tschedule_work(&sensorlist_work);\n\t\tbreak;\n\tcase SENSOR_POWER_DOWN:\n'),
        ('0086', '\tatomic_set(&first_ready_after_boot, 0);\n#ifdef CONFIG_CUSTOM_KERNEL_SENSORHUB\n\tINIT_DELAYED_WORK(&sensorlist_work, sensorlist_get_deviceinfo);\n\tscp_power_monitor_register(&scp_ready_notifier);\n#endif\n',
         '\tatomic_set(&first_ready_after_boot, 0);\n#ifdef CONFIG_CUSTOM_KERNEL_SENSORHUB\n\tINIT_WORK(&sensorlist_work, sensorlist_get_deviceinfo);\n\tscp_power_monitor_register(&scp_ready_notifier);\n#endif\n'),
    ],
    'drivers/usb/mtu3/mtu3_plat.c': [
        ('0082', '\treturn 0;\n}\n\nint ssusb_phy_power_on(struct ssusb_mtk *ssusb)\n{\n\tint i;\n\tint ret;\n',
         '\treturn 0;\n}\n\nstatic int ssusb_phy_power_on(struct ssusb_mtk *ssusb)\n{\n\tint i;\n\tint ret;\n'),
        ('0082', '\treturn ret;\n}\n\nvoid ssusb_phy_power_off(struct ssusb_mtk *ssusb)\n{\n\tunsigned int i;\n\n',
         '\treturn ret;\n}\n\nstatic void ssusb_phy_power_off(struct ssusb_mtk *ssusb)\n{\n\tunsigned int i;\n\n'),
        ('0082', '\n\tdev_dbg(dev, "%s\\n", __func__);\n\n\t/*\n\t * MT6771 forces VBUS valid, so the gadget stays up on any cable and\n\t * through deep suspend. If a host link was up, stop the device and\n\t * power the PHY down as stock does on unplug.\n\t */\n\tif (!ssusb->is_host) {\n\t\tif (ssusb->force_vbus && ssusb->u3d &&\n\t\t    mtu3_gadget_sleep(ssusb->u3d))\n\t\t\tssusb_phy_power_off(ssusb);\n\t\treturn 0;\n\t}\n\n\tssusb_host_disable(ssusb, true);\n\tssusb_phy_power_off(ssusb);\n',
         '\n\tdev_dbg(dev, "%s\\n", __func__);\n\n\t/* REVISIT: disconnect it for only device mode? */\n\tif (!ssusb->is_host)\n\t\treturn 0;\n\n\tssusb_host_disable(ssusb, true);\n\tssusb_phy_power_off(ssusb);\n'),
        ('0082', '\n\tdev_dbg(dev, "%s\\n", __func__);\n\n\t/* PHY on with its calibration, then a fresh device MAC, as stock on plug-in */\n\tif (!ssusb->is_host) {\n\t\tif (ssusb->u3d && ssusb->u3d->sleep_stopped) {\n\t\t\tret = ssusb_phy_power_on(ssusb);\n\t\t\tif (ret) {\n\t\t\t\tdev_err(dev, "phy power on failed %d\\n", ret);\n\t\t\t\treturn ret;\n\t\t\t}\n\t\t\tmtu3_gadget_wake(ssusb->u3d);\n\t\t}\n\t\treturn 0;\n\t}\n\n\tssusb_wakeup_set(ssusb, false);\n\tret = ssusb_clks_enable(ssusb);\n',
         '\n\tdev_dbg(dev, "%s\\n", __func__);\n\n\tif (!ssusb->is_host)\n\t\treturn 0;\n\n\tssusb_wakeup_set(ssusb, false);\n\tret = ssusb_clks_enable(ssusb);\n'),
        ('0090', '\t\t\tret = ssusb_phy_power_on(ssusb);\n\t\t\tif (ret) {\n\t\t\t\tdev_err(dev, "phy power on failed %d\\n", ret);\n\t\t\t\tmtu3_gadget_wake_failed(ssusb->u3d);\n\t\t\t\treturn ret;\n\t\t\t}\n\t\t\tmtu3_gadget_wake(ssusb->u3d);\n',
         '\t\t\tret = ssusb_phy_power_on(ssusb);\n\t\t\tif (ret) {\n\t\t\t\tdev_err(dev, "phy power on failed %d\\n", ret);\n\t\t\t\treturn ret;\n\t\t\t}\n\t\t\tmtu3_gadget_wake(ssusb->u3d);\n'),
    ],
    'drivers/usb/mtu3/mtu3_core.c': [
        ('0082', '\n\tdev_info(mtu->dev, "gadget (%s) pullup D%s\\n",\n\t\tusb_speed_string(mtu->speed), is_on ? "+" : "-");\n}\n\nstatic void mtu3_regs_init(struct mtu3 *mtu);\n\n/*\n * Reset the device MAC and set it up again as at probe. Stock does this on\n * every cable plug-in; with VBUS forced valid MT6771 never sees one, so it\n * runs on each UDC bind and on resume from system sleep instead.\n * Caller holds mtu->lock.\n */\nvoid mtu3_device_reinit(struct mtu3 *mtu)\n{\n\tmtu3_clrbits(mtu->ippc_base, U3D_SSUSB_IP_PW_CTRL2, SSUSB_IP_DEV_PDN);\n\tmtu3_device_reset(mtu);\n\tmtu3_regs_init(mtu);\n}\n\nvoid mtu3_start(struct mtu3 *mtu)\n',
         '\n\tdev_info(mtu->dev, "gadget (%s) pullup D%s\\n",\n\t\tusb_speed_string(mtu->speed), is_on ? "+" : "-");\n}\n\nvoid mtu3_start(struct mtu3 *mtu)\n'),
    ],
    'drivers/usb/mtu3/mtu3.h': [
        ('0082', '\tunsigned is_u3_ip:1;\n\tunsigned delayed_status:1;\n\tunsigned gen2cp:1;\n\t/* stopped for system sleep by mtu3_gadget_sleep() */\n\tunsigned sleep_stopped:1;\n\n\tu8 address;\n\tu8 test_mode_nr;\n',
         '\tunsigned is_u3_ip:1;\n\tunsigned delayed_status:1;\n\tunsigned gen2cp:1;\n\n\tu8 address;\n\tu8 test_mode_nr;\n'),
        ('0082', 'void mtu3_ep0_setup(struct mtu3 *mtu);\nvoid mtu3_start(struct mtu3 *mtu);\nvoid mtu3_stop(struct mtu3 *mtu);\nvoid mtu3_device_reinit(struct mtu3 *mtu);\nint ssusb_phy_power_on(struct ssusb_mtk *ssusb);\nvoid ssusb_phy_power_off(struct ssusb_mtk *ssusb);\nvoid mtu3_dev_on_off(struct mtu3 *mtu, int is_on);\nvoid mtu3_set_speed(struct mtu3 *mtu, enum usb_device_speed speed);\n\n',
         'void mtu3_ep0_setup(struct mtu3 *mtu);\nvoid mtu3_start(struct mtu3 *mtu);\nvoid mtu3_stop(struct mtu3 *mtu);\nvoid mtu3_dev_on_off(struct mtu3 *mtu, int is_on);\nvoid mtu3_set_speed(struct mtu3 *mtu, enum usb_device_speed speed);\n\n'),
    ],
    'drivers/misc/mediatek/video/mt6771/dispsys/ddp_irq.c': [
        ('0088', '#include "ddp_manager.h"\n#include "primary_display.h"\n\n/* IRQ log wait queue; nothing waits on it as the log thread is not built */\nstatic wait_queue_head_t disp_irq_log_wq;\nstatic int disp_irq_log_module;\n\n',
         '#include "ddp_manager.h"\n#include "primary_display.h"\n\n/* IRQ log print kthread */\nstatic struct task_struct *disp_irq_log_task;\nstatic wait_queue_head_t disp_irq_log_wq;\nstatic int disp_irq_log_module;\n\n'),
        ('0088', '\treturn IRQ_HANDLED;\n}\n\nint disp_init_irq(void)\n{\n\tif (irq_init)\n',
         '\treturn IRQ_HANDLED;\n}\n\nstatic int disp_irq_log_kthread_func(void *data)\n{\n\tunsigned int i = 0;\n\n\twhile (1) {\n\t\twait_event_interruptible(disp_irq_log_wq, disp_irq_log_module);\n\t\tDDPMSG("%s: dump intr register: disp_irq_log_module=%d\\n",\n\t\t       __func__, disp_irq_log_module);\n\n\t\tfor (i = 0; i < DISP_MODULE_NUM; i++) {\n\t\t\tif (disp_irq_log_module & (1 << i))\n\t\t\t\tddp_dump_reg(i);\n\t\t}\n\t\tdisp_irq_log_module = 0;\n\t}\n\treturn 0;\n}\n\nint disp_init_irq(void)\n{\n\tif (irq_init)\n'),
        ('0088', '\tirq_init = 1;\n\tDDPMSG("%s\\n", __func__);\n\n\t/*\n\t * MTK creates an IRQ log thread here but never wakes it, so it sat in\n\t * kthread()\'s uninterruptible first sleep and added 1 to the load\n\t * average. It is left out; nothing ever ran it.\n\t */\n\tinit_waitqueue_head(&disp_irq_log_wq);\n\treturn 0;\n}\nunsigned int get_display_ut_status(void)\n',
         '\tirq_init = 1;\n\tDDPMSG("%s\\n", __func__);\n\n\t/* create irq log thread */\n\tinit_waitqueue_head(&disp_irq_log_wq);\n\tdisp_irq_log_task = kthread_create(disp_irq_log_kthread_func,\n\t\t\t\t\t   NULL, "ddp_irq_log_kthread");\n\tif (IS_ERR(disp_irq_log_task))\n\t\tDDPPR_ERR(" can not create disp_irq_log_task kthread\\n");\n\n\t/* wake_up_process(disp_irq_log_task); */\n\treturn 0;\n}\nunsigned int get_display_ut_status(void)\n'),
    ],
    'drivers/misc/mediatek/video/mt6771/videox/disp_lowpower.c': [
        ('0088', '\n\t\tif (primary_get_state() != DISP_ALIVE) {\n\t\t\tprimary_display_manual_unlock();\n\t\t\tprimary_display_idle_wait_state(DISP_ALIVE,\n\t\t\t\t\t\t\tMAX_SCHEDULE_TIMEOUT);\n\t\t\tcontinue;\n\t\t}\n\n',
         '\n\t\tif (primary_get_state() != DISP_ALIVE) {\n\t\t\tprimary_display_manual_unlock();\n\t\t\tprimary_display_wait_state(DISP_ALIVE,\n\t\t\t\t\t\t   MAX_SCHEDULE_TIMEOUT);\n\t\t\tcontinue;\n\t\t}\n\n'),
    ],
    'drivers/misc/mediatek/video/mt6771/videox/disp_recovery.c': [
        ('0088', '\tsched_setscheduler(current, SCHED_RR, &param);\n\n\twhile (1) {\n\t\t/* interruptible so the 2 s nap does not count as load */\n\t\tmsleep_interruptible(2000);\n\t\tret = wait_event_interruptible(_check_task_wq,\n\t\t\t\t\tatomic_read(&_check_task_wakeup));\n\t\tif (ret < 0) {\n',
         '\tsched_setscheduler(current, SCHED_RR, &param);\n\n\twhile (1) {\n\t\tmsleep(2000); /* 2s */\n\t\tret = wait_event_interruptible(_check_task_wq,\n\t\t\t\t\tatomic_read(&_check_task_wakeup));\n\t\tif (ret < 0) {\n'),
    ],
    'drivers/misc/mediatek/video/mt6771/videox/primary_display.c': [
        ('0088', '\tret = __primary_display_wait_state(primary_get_state() == state,\n\t\t\t\t\t   timeout);\n\treturn ret;\n}\n\n/* As primary_display_wait_state, but sleeps in TASK_IDLE for kernel threads */\nlong primary_display_idle_wait_state(enum DISP_POWER_STATE state, long timeout)\n{\n\treturn wait_event_idle_timeout(display_state_wait_queue,\n\t\t\t\t       primary_get_state() == state, timeout);\n}\n\nlong primary_display_wait_not_state(enum DISP_POWER_STATE state, long timeout)\n',
         '\tret = __primary_display_wait_state(primary_get_state() == state,\n\t\t\t\t\t   timeout);\n\treturn ret;\n}\n\nlong primary_display_wait_not_state(enum DISP_POWER_STATE state, long timeout)\n'),
        ('0088', '\tsched_setscheduler(current, SCHED_RR, &param);\n\n\twhile (1) {\n\t\twait_event_idle(decouple_trigger_wq,\n\t\t\t\tatomic_read(&decouple_trigger_event));\n\t\tdpmgr_wait_event(pgc->dpmgr_handle, DISP_PATH_EVENT_IF_VSYNC);\n\n\t\t_primary_path_lock(__func__);\n',
         '\tsched_setscheduler(current, SCHED_RR, &param);\n\n\twhile (1) {\n\t\twait_event(decouple_trigger_wq,\n\t\t\t   atomic_read(&decouple_trigger_event));\n\t\tdpmgr_wait_event(pgc->dpmgr_handle, DISP_PATH_EVENT_IF_VSYNC);\n\n\t\t_primary_path_lock(__func__);\n'),
    ],
    'drivers/misc/mediatek/video/mt6771/videox/primary_display.h': [
        ('0088', 'void _cmdq_insert_wait_frame_done_token_mira(void *handle);\nint primary_display_get_max_layer(void);\nlong primary_display_wait_state(enum DISP_POWER_STATE state, long timeout);\nlong primary_display_idle_wait_state(enum DISP_POWER_STATE state,\n\t\t\t\t     long timeout);\nint do_primary_display_switch_mode(int sess_mode, unsigned int session,\n\t\t\t\t   int need_lock, struct cmdqRecStruct *handle,\n\t\t\t\t   int block);\n',
         'void _cmdq_insert_wait_frame_done_token_mira(void *handle);\nint primary_display_get_max_layer(void);\nlong primary_display_wait_state(enum DISP_POWER_STATE state, long timeout);\nint do_primary_display_switch_mode(int sess_mode, unsigned int session,\n\t\t\t\t   int need_lock, struct cmdqRecStruct *handle,\n\t\t\t\t   int block);\n'),
    ],
    'drivers/misc/mediatek/eccci/fsm/ccci_fsm.c': [
        ('0089', '\tunsigned long flags;\n\n\twhile (1) {\n\t\twait_event_idle(ctl->command_wq,\n\t\t\t!list_empty(&ctl->command_queue));\n\t\tspin_lock_irqsave(&ctl->command_lock, flags);\n\t\tcmd = list_first_entry(&ctl->command_queue,\n',
         '\tunsigned long flags;\n\n\twhile (1) {\n\t\twait_event(ctl->command_wq,\n\t\t\t!list_empty(&ctl->command_queue));\n\t\tspin_lock_irqsave(&ctl->command_lock, flags);\n\t\tcmd = list_first_entry(&ctl->command_queue,\n'),
    ],
    'drivers/misc/mediatek/eccci/fsm/ccci_fsm_poller.c': [
        ('0089', '\t\t\t}\n\t\t}\nnext:\n\t\t/* interruptible so the 15 s nap does not count as load */\n\t\tmsleep_interruptible(POLLING_INTERVAL_TIME);\n\t}\n\treturn 0;\n}\n',
         '\t\t\t}\n\t\t}\nnext:\n\t\tmsleep(POLLING_INTERVAL_TIME);\n\t}\n\treturn 0;\n}\n'),
    ],
    'drivers/misc/mediatek/sensors-1.0/sensorHub/SCP_nanoHub/SCP_nanoHub.c': [
        ('0089', 'static int SCP_sensorHub_direct_push_work(void *data)\n{\n\tfor (;;) {\n\t\twait_event_idle(chre_kthread_wait,\n\t\t\tREAD_ONCE(chre_kthread_wait_condition));\n\t\tWRITE_ONCE(chre_kthread_wait_condition, false);\n\t\tmark_timestamp(0, WORK_START, ktime_get_boottime_ns(), 0);\n',
         'static int SCP_sensorHub_direct_push_work(void *data)\n{\n\tfor (;;) {\n\t\twait_event(chre_kthread_wait,\n\t\t\tREAD_ONCE(chre_kthread_wait_condition));\n\t\tWRITE_ONCE(chre_kthread_wait_condition, false);\n\t\tmark_timestamp(0, WORK_START, ktime_get_boottime_ns(), 0);\n'),
        ('0089', '\tstruct SCP_sensorHub_data *obj = obj_data;\n\tunsigned long flags = 0;\n\n\twait_event_idle(power_reset_wait,\n\t\tREAD_ONCE(scp_system_ready) && READ_ONCE(scp_chre_ready));\n\tspin_lock_irqsave(&scp_state_lock, flags);\n\tWRITE_ONCE(scp_chre_ready, false);\n',
         '\tstruct SCP_sensorHub_data *obj = obj_data;\n\tunsigned long flags = 0;\n\n\twait_event(power_reset_wait,\n\t\tREAD_ONCE(scp_system_ready) && READ_ONCE(scp_chre_ready));\n\tspin_lock_irqsave(&scp_state_lock, flags);\n\tWRITE_ONCE(scp_chre_ready, false);\n'),
    ],
    'drivers/usb/mtu3/mtu3_gadget.c': [
        ('0090', '\treturn 0;\n}\n\n/*\n * MT6771 forces VBUS valid, so cable plug-in and plug-out come from the\n * charger type detection instead (mt_usb_connect and mt_usb_disconnect).\n * vbus_lock orders them with UDC bind and unbind; vbus_stopped is set while\n * the cable is out and the device is stopped.\n */\nstatic DEFINE_MUTEX(vbus_lock);\nstatic bool vbus_stopped;\nstatic bool vbus_on = true;\nstatic struct mtu3 *vbus_mtu;\nstatic void mtu3_vbus_work(struct work_struct *work);\nstatic DECLARE_WORK(vbus_work, mtu3_vbus_work);\n\nstatic int mtu3_gadget_start(struct usb_gadget *gadget,\n\t\tstruct usb_gadget_driver *driver)\n{\n',
         '\treturn 0;\n}\n\nstatic int mtu3_gadget_start(struct usb_gadget *gadget,\n\t\tstruct usb_gadget_driver *driver)\n{\n'),
        ('0090', '\n\tdev_dbg(mtu->dev, "bind driver %s\\n", driver->function);\n\n\t/* with the cable out the device starts on the next plug-in */\n\tmutex_lock(&vbus_lock);\n\n\t/*\n\t * MT6771: the PHY and device MAC are otherwise only set up at probe,\n\t * so cycle the PHY (calibration again) and reset the MAC on each bind\n\t */\n\tif (mtu->ssusb->force_vbus && !vbus_stopped &&\n\t    mtu->ssusb->dr_mode == USB_DR_MODE_PERIPHERAL) {\n\t\tssusb_phy_power_off(mtu->ssusb);\n\t\tif (ssusb_phy_power_on(mtu->ssusb))\n',
         '\n\tdev_dbg(mtu->dev, "bind driver %s\\n", driver->function);\n\n\t/*\n\t * MT6771: the PHY and device MAC are otherwise only set up at probe,\n\t * so cycle the PHY (calibration again) and reset the MAC on each bind\n\t */\n\tif (mtu->ssusb->force_vbus &&\n\t    mtu->ssusb->dr_mode == USB_DR_MODE_PERIPHERAL) {\n\t\tssusb_phy_power_off(mtu->ssusb);\n\t\tif (ssusb_phy_power_on(mtu->ssusb))\n'),
        ('0090', '\tmtu->softconnect = 0;\n\tmtu->gadget_driver = driver;\n\n\tif (mtu->ssusb->dr_mode == USB_DR_MODE_PERIPHERAL && !vbus_stopped) {\n\t\tif (mtu->ssusb->force_vbus)\n\t\t\tmtu3_device_reinit(mtu);\n\t\tmtu3_start(mtu);\n\t}\n\n\tspin_unlock_irqrestore(&mtu->lock, flags);\n\tmutex_unlock(&vbus_lock);\n\n\treturn 0;\n}\n',
         '\tmtu->softconnect = 0;\n\tmtu->gadget_driver = driver;\n\n\tif (mtu->ssusb->dr_mode == USB_DR_MODE_PERIPHERAL) {\n\t\tif (mtu->ssusb->force_vbus)\n\t\t\tmtu3_device_reinit(mtu);\n\t\tmtu3_start(mtu);\n\t}\n\n\tspin_unlock_irqrestore(&mtu->lock, flags);\n\n\treturn 0;\n}\n'),
        ('0090', '\n\tdev_dbg(mtu->dev, "%s\\n", __func__);\n\n\tmutex_lock(&vbus_lock);\n\tspin_lock_irqsave(&mtu->lock, flags);\n\n\tstop_activity(mtu);\n\tmtu->gadget_driver = NULL;\n\n\t/* a plug-out already stopped it */\n\tif (mtu->ssusb->dr_mode == USB_DR_MODE_PERIPHERAL && !vbus_stopped)\n\t\tmtu3_stop(mtu);\n\n\tspin_unlock_irqrestore(&mtu->lock, flags);\n\tmutex_unlock(&vbus_lock);\n\n\tsynchronize_irq(mtu->irq);\n\treturn 0;\n',
         '\n\tdev_dbg(mtu->dev, "%s\\n", __func__);\n\n\tspin_lock_irqsave(&mtu->lock, flags);\n\n\tstop_activity(mtu);\n\tmtu->gadget_driver = NULL;\n\n\tif (mtu->ssusb->dr_mode == USB_DR_MODE_PERIPHERAL)\n\t\tmtu3_stop(mtu);\n\n\tspin_unlock_irqrestore(&mtu->lock, flags);\n\n\tsynchronize_irq(mtu->irq);\n\treturn 0;\n'),
        ('0090', '\nint mtu3_gadget_setup(struct mtu3 *mtu)\n{\n\tint ret;\n\n\tmtu->g.ops = &mtu3_gadget_ops;\n\tmtu->g.max_speed = mtu->max_speed;\n\tmtu->g.speed = USB_SPEED_UNKNOWN;\n',
         '\nint mtu3_gadget_setup(struct mtu3 *mtu)\n{\n\tmtu->g.ops = &mtu3_gadget_ops;\n\tmtu->g.max_speed = mtu->max_speed;\n\tmtu->g.speed = USB_SPEED_UNKNOWN;\n'),
        ('0090', '\n\tmtu3_gadget_init_eps(mtu);\n\n\tret = usb_add_gadget_udc(mtu->dev, &mtu->g);\n\t/* the device stays on until the first plug-out, so adb works at boot */\n\tif (!ret && mtu->ssusb->force_vbus)\n\t\tsmp_store_release(&vbus_mtu, mtu);\n\n\treturn ret;\n}\n\nvoid mtu3_gadget_cleanup(struct mtu3 *mtu)\n{\n\tif (vbus_mtu == mtu) {\n\t\tWRITE_ONCE(vbus_mtu, NULL);\n\t\tcancel_work_sync(&vbus_work);\n\t}\n\tusb_del_gadget_udc(&mtu->g);\n}\n\n',
         '\n\tmtu3_gadget_init_eps(mtu);\n\n\treturn usb_add_gadget_udc(mtu->dev, &mtu->g);\n}\n\nvoid mtu3_gadget_cleanup(struct mtu3 *mtu)\n{\n\tusb_del_gadget_udc(&mtu->g);\n}\n\n'),
        ('0090', '\telse\n\t\tmtu3_state_reset(mtu);\n}\n\n/*\n * Plug-out: pull-up off and a disconnect to the functions through the UDC\n * core, which then keeps the pull-up off across binds, then end all requests\n * and stop the device MAC, as stock does on unplug. The PHY stays powered.\n * Plug-in: as on bind, PHY off and on and a fresh MAC, then the pull-up.\n */\nstatic void mtu3_vbus_work(struct work_struct *work)\n{\n\tstruct mtu3 *mtu = smp_load_acquire(&vbus_mtu);\n\tunsigned long flags;\n\tbool on;\n\tint i;\n\n\tif (!mtu)\n\t\treturn;\n\n\tmutex_lock(&vbus_lock);\n\ton = READ_ONCE(vbus_on);\n\tif (on != vbus_stopped)\n\t\tgoto out;\n\n\tif (!on) {\n\t\tusb_udc_vbus_handler(&mtu->g, false);\n\n\t\tspin_lock_irqsave(&mtu->lock, flags);\n\t\tnuke(mtu->ep0, -ESHUTDOWN);\n\t\tfor (i = 1; i < mtu->num_eps; i++) {\n\t\t\tnuke(mtu->in_eps + i, -ESHUTDOWN);\n\t\t\tnuke(mtu->out_eps + i, -ESHUTDOWN);\n\t\t}\n\t\tmtu->g.speed = USB_SPEED_UNKNOWN;\n\t\tmtu3_state_reset(mtu);\n\t\tusb_gadget_set_state(&mtu->g, USB_STATE_NOTATTACHED);\n\t\tif (mtu->is_active)\n\t\t\tmtu3_stop(mtu);\n\t\tvbus_stopped = true;\n\t\tspin_unlock_irqrestore(&mtu->lock, flags);\n\n\t\tsynchronize_irq(mtu->irq);\n\t\tdev_info(mtu->dev, "cable out, device stopped\\n");\n\t\tgoto out;\n\t}\n\n\tif (mtu->gadget_driver) {\n\t\tssusb_phy_power_off(mtu->ssusb);\n\t\tif (ssusb_phy_power_on(mtu->ssusb)) {\n\t\t\t/* stays stopped; the next plug-in tries again */\n\t\t\tdev_err(mtu->dev, "cable in, phy power on failed\\n");\n\t\t\tgoto out;\n\t\t}\n\t\tspin_lock_irqsave(&mtu->lock, flags);\n\t\tmtu3_device_reinit(mtu);\n\t\tmtu3_start(mtu);\n\t\tspin_unlock_irqrestore(&mtu->lock, flags);\n\t}\n\tvbus_stopped = false;\n\tusb_udc_vbus_handler(&mtu->g, true);\n\tdev_info(mtu->dev, "cable in, device started\\n");\nout:\n\tmutex_unlock(&vbus_lock);\n}\n\n/*\n * The PHY didn\'t power on after sleep: IRQ back on and the device left\n * stopped as after a plug-out, so the plug-in work cycles the PHY and starts\n * it. It tries once now; if that fails too, the next plug-in tries again.\n */\nvoid mtu3_gadget_wake_failed(struct mtu3 *mtu)\n{\n\tunsigned long flags;\n\n\tmutex_lock(&vbus_lock);\n\tspin_lock_irqsave(&mtu->lock, flags);\n\tmtu->sleep_stopped = 0;\n\tvbus_stopped = true;\n\tspin_unlock_irqrestore(&mtu->lock, flags);\n\tenable_irq(mtu->irq);\n\tmutex_unlock(&vbus_lock);\n\n\tif (smp_load_acquire(&vbus_mtu))\n\t\tqueue_work(system_freezable_wq, &vbus_work);\n}\n\nstatic void mtu3_vbus_set(bool on)\n{\n\tWRITE_ONCE(vbus_on, on);\n\t/* events before the gadget is registered are dropped */\n\tif (smp_load_acquire(&vbus_mtu))\n\t\tqueue_work(system_freezable_wq, &vbus_work);\n}\n\n/* the charger saw a USB host: SDP, CDP or a non-standard charger */\nvoid mt_usb_connect(void)\n{\n\tmtu3_vbus_set(true);\n}\n\n/* the charger saw a plug-out or a charger that isn\'t a host */\nvoid mt_usb_disconnect(void)\n{\n\tmtu3_vbus_set(false);\n}\n',
         '\telse\n\t\tmtu3_state_reset(mtu);\n}\n'),
    ],
    'drivers/usb/mtu3/mtu3_dr.h': [
        ('0090', 'void ssusb_gadget_exit(struct ssusb_mtk *ssusb);\nbool mtu3_gadget_sleep(struct mtu3 *mtu);\nvoid mtu3_gadget_wake(struct mtu3 *mtu);\nvoid mtu3_gadget_wake_failed(struct mtu3 *mtu);\n/* cable plug-in and plug-out from the charger type detection, as on stock */\nvoid mt_usb_connect(void);\nvoid mt_usb_disconnect(void);\n#else\nstatic inline int ssusb_gadget_init(struct ssusb_mtk *ssusb)\n{\n',
         'void ssusb_gadget_exit(struct ssusb_mtk *ssusb);\nbool mtu3_gadget_sleep(struct mtu3 *mtu);\nvoid mtu3_gadget_wake(struct mtu3 *mtu);\n#else\nstatic inline int ssusb_gadget_init(struct ssusb_mtk *ssusb)\n{\n'),
        ('0090', '}\n\nstatic inline void mtu3_gadget_wake(struct mtu3 *mtu)\n{}\n\nstatic inline void mtu3_gadget_wake_failed(struct mtu3 *mtu)\n{}\n#endif\n\n',
         '}\n\nstatic inline void mtu3_gadget_wake(struct mtu3 *mtu)\n{}\n#endif\n\n'),
    ],
    'drivers/misc/mediatek/include/mt-plat/charger_type.h': [
        ('0090', '\tWIRELESS_CHARGER,\n};\n\n/* built-in mtu3 gadget: the charger tells it about cable plug-in and out */\n#if defined(CONFIG_USB_MTK_HDRC) || defined(CONFIG_USB_MU3D_DRV) \\\n\t|| defined(CONFIG_EXTCON_MTK_USB) \\\n\t|| (IS_BUILTIN(CONFIG_USB_MTU3) && !IS_ENABLED(CONFIG_USB_MTU3_HOST))\nextern void mt_usb_connect(void);\nextern void mt_usb_disconnect(void);\n#else\n',
         '\tWIRELESS_CHARGER,\n};\n\n#if defined(CONFIG_USB_MTK_HDRC) || defined(CONFIG_USB_MU3D_DRV) \\\n\t|| defined(CONFIG_EXTCON_MTK_USB)\nextern void mt_usb_connect(void);\nextern void mt_usb_disconnect(void);\n#else\n'),
    ],
}


def owner(path):
    """The GROUPS patch that holds this file."""
    return next(name for name, files in GROUPS.items() if path in files)


def patch_name(number):
    return next(name for name in GROUPS if name.startswith(number + '-'))


def stages(path, final):
    """[(patch, content after it)] for a STAGED file, first its owner, then each patch with an entry, in order."""
    numbers = sorted({e[0] for e in STAGED[path]})
    first = owner(path)
    assert all(patch_name(n) > first for n in numbers), path
    text, out = final, []
    for number in reversed(numbers):
        out.append((patch_name(number), text))
        for entry in reversed([e for e in STAGED[path] if e[0] == number]):
            new, before = entry[1], entry[2] if len(entry) > 2 else ''
            assert text.count(new) == 1, (path, number, new)
            text = text.replace(new, before)
    out.append((first, text))
    return list(reversed(out))


def main():
    destination = ROOT / 'patches/kernel-upgrade-5.10'
    destination.mkdir(parents=True, exist_ok=True)
    artifact = ROOT / 'artifacts/kernel-upgrade'
    artifact.mkdir(parents=True, exist_ok=True)
    # path -> {patch: (content before it, content after it)} for the STAGED files
    steps = {}
    for relative in STAGED:
        previous = (BASE / relative).read_text() if (BASE / relative).exists() else ''
        steps[relative] = {}
        for name, text in stages(relative, (WORK / relative).read_text()):
            steps[relative][name] = (previous, text)
            previous = text
    records = []
    for name, files in GROUPS.items():
        touched = [(relative, *(steps[relative][name] if relative in steps else
                    ((BASE / relative).read_text() if (BASE / relative).exists() else '',
                     (WORK / relative).read_text())))
                   for relative in files]
        touched += [(relative, *steps[relative][name]) for relative in sorted(steps)
                    if name in steps[relative] and relative not in files]
        diff = []
        for relative, before, after in touched:
            diff.extend(difflib.unified_diff(before.splitlines(True), after.splitlines(True),
                        fromfile='a/' + relative if before else '/dev/null', tofile='b/' + relative))
        patch = destination / name
        patch.write_text(''.join(diff))
        with tempfile.TemporaryDirectory(prefix='patch-replay-', dir=artifact) as temporary:
            replay = Path(temporary)
            for relative, before, after in touched:
                target = replay / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                if relative in steps and relative not in files or relative in steps and before:
                    target.write_text(before)
                elif (BASE / relative).exists():
                    shutil.copyfile(BASE / relative, target)
            subprocess.run(['patch', '--batch', '--forward', '-p1', '-d', str(replay),
                            '--input', str(patch)], capture_output=True, text=True, check=True)
            for relative, before, after in touched:
                if relative in steps:
                    assert (replay / relative).read_text() == after, relative
                else:
                    assert (replay / relative).read_bytes() == (WORK / relative).read_bytes(), relative
        record = {'path': str(patch), 'sha256': hashlib.sha256(patch.read_bytes()).hexdigest(),
                  'replay': 'Applied to independent pristine file fixture; all resulting bytes match workspace',
                  'files': [{'path': p, 'sha256': hashlib.sha256((WORK / p).read_bytes()).hexdigest()} for p in files]}
        staged = [{'path': relative, 'sha256': hashlib.sha256(after.encode()).hexdigest()}
                  for relative, before, after in touched if relative not in files]
        if staged:
            record['hooks'] = staged
        records.append(record)
    (ROOT / 'evidence/kernel-upgrade/patch-validation.json').write_text(json.dumps(records, indent=2) + '\n')
    print(f'{len(records)} exported patches replay exactly against the pristine reference files')
    print(f'{OCV_HEADER} is left out of 0026' + ('; it is still the stock stand-in, measure the real one' if STOCK_OCV else ''))


if __name__ == '__main__':
    main()
