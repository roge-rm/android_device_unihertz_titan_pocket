#!/usr/bin/env python3
"""Audit the resolved first-boot 5.10 .config against Boston's android-base config, the adb path and the v9 board drivers.

Prints every option that is missing or differs, with a reason class, and writes
evidence/kernel-upgrade/firstboot-config-audit.json. Exit 1 if anything is
missing without a recorded reason.
"""
import pocket_paths
import argparse,hashlib,json,re,xml.etree.ElementTree as ET
from datetime import datetime,timezone
from pathlib import Path
ROOT=Path(__file__).resolve().parent.parent
PLATFORM=pocket_paths.platform_source()
BASE_DIR=PLATFORM/'kernel/configs/t/android-5.10'
SOURCE=ROOT/'tools/kernel-source/upgrade-5.10'
V9=ROOT/'configs/kernel-diagnostic-5.10-v9.fragment'
FRAGMENT=ROOT/'configs/kernel-firstboot-5.10.fragment'
ENFORCING_FRAGMENT=ROOT/'configs/kernel-firstboot-5.10-enforcing.fragment'
REPORT=ROOT/'evidence/kernel-upgrade/firstboot-config-audit.json'
REPORT_ENFORCING=ROOT/'evidence/kernel-upgrade/firstboot-config-audit-enforcing.json'
# The enforcing boot image has no wrapper, so devtmpfs goes back off as stock.
ENFORCING_EXPECT={'DEVTMPFS':('n','no wrapper in the enforcing image: init mounts tmpfs on /dev as stock; the wrapper kernel keeps devtmpfs')}

# Needed on the path from kernel start to adbd answering on USB (first-stage
# mount of super, /metadata and /data, APEX, init, netbpfload, adbd).
ADB_PATH={
 'USB_MTU3_GADGET':('y','MTU3 device mode, the only UDC'),
 'CONFIGFS_FS':('y','init.mt6771.usb.rc builds the gadget in configfs'),
 'USB_CONFIGFS':('y','configfs gadget'),
 'USB_CONFIGFS_F_FS':('y','adbd FunctionFS at /dev/usb-ffs/adb'),
 'DEVTMPFS':('y','first-stage init /dev'),
 'TMPFS_XATTR':('y','SELinux labels on tmpfs /dev'),
 'ANDROID_BINDERFS':('y','servicemanager, hwservicemanager'),
 'SECURITY_SELINUX':('y','init loads policy before second stage'),
 'SECURITY_SELINUX_DEVELOP':('y','androidboot.selinux=permissive for fault isolation'),
 'SCSI_UFS_MEDIATEK':('y','UFS host for every partition; the engineering binding has no write gate (check-pocket-ufs-write-path.py)'),
 'SCSI_UFSHCD_PLATFORM':('y','platform glue for the MediaTek UFS host'),
 'BLK_DEV_SD':('y','UFS LUNs as sda/sdb/sdc'),
 'BLK_DEV_DM':('y','dm-linear for logical partitions in super'),
 'DM_VERITY':('y','APEX and AVB hashtree (vbmeta flags 3 skip it for super)'),
 'DM_DEFAULT_KEY':('y','metadata encryption of /data (keydirectory in fstab)'),
 'DM_BOW':('y','checkpoint=block on /data'),
 'BLK_DEV_LOOP':('y','apexd mounts APEX payloads on loop'),
 'EXT4_FS':('y','every fstab filesystem is ext4'),
 'EXT4_FS_SECURITY':('y','SELinux xattrs on ext4'),
 'QUOTA':('y','quota on /data'),
 'BLK_INLINE_ENCRYPTION':('y','inlinecrypt on /data'),
 'BLK_INLINE_ENCRYPTION_FALLBACK':('y','no UFS HIE yet, so software inline crypto'),
 'FS_ENCRYPTION':('y','fileencryption=...:v2 on /data'),
 'FS_ENCRYPTION_INLINE_CRYPT':('y','inlinecrypt on /data'),
 'CRYPTO_XTS':('y','aes-256-xts contents and dm-default-key'),
 'CRYPTO_CTS':('y','aes-256-cts filenames'),
 'FUSE_FS':('y','/sdcard; built in rather than =m'),
 'COMPAT':('y','32-bit vendor services'),
 'COMPAT_32BIT_TIME':('y','32-bit bionic futex/clock_gettime; all 32-bit vendor HALs abort without it'),
 'BPF_SYSCALL':('y','netbpfload is reboot_on_failure'),
 'BPF_JIT':('y','netbpfload writes bpf_jit_enable'),
 'BPF_JIT_ALWAYS_ON':('y','netbpfload JIT check'),
 'CGROUP_BPF':('y','netd cgroup programs'),
 'NET_CLS_BPF':('y','netbpfload sched_cls programs'),
 'NET_ACT_BPF':('y','netd rate limiting'),
 'NET_CLS_MATCHALL':('y','flagged in M2, netd rate limiting'),
 'NET_ACT_POLICE':('y','flagged in M2, netd rate limiting'),
 'NETFILTER_XT_MATCH_BPF':('y','netd xt_bpf programs'),
 'BPF_EVENTS':('y','tracepoint programs (timeInState) in the platform loader'),
 'CPUSETS':('y','cgroups.json cpuset'),
 'CGROUP_SCHED':('y','cgroups.json cpu'),
 'BLK_CGROUP':('y','cgroups.json blkio'),
 'MEMCG':('y','cgroups.json memory (optional)'),
 'TRUSTKERNEL_TEE_SUPPORT':('y','keymaster for metadata/FBE keys'),
 'TRUSTKERNEL_TEE_RAM_DIAGNOSTIC':('y','SHM ownership guard stays on'),
 'PSTORE_RAM':('y','ramoops for a failed run'),
 'PSTORE_CONSOLE':('y','console in ramoops'),
 'MEDIATEK_WATCHDOG':('y','adopt and ping mtk_wdt'),
 'MEDIATEK_SOLUTION':('y','drivers/misc/mediatek glue for the display and GPU port'),
 'MTK_PLATFORM':('"mt6771"','platform name the 4.14 MTK Makefiles expand into include paths'),
 'MACH_MT6771':('y','MT6771 branches of the 4.14 MTK Makefiles and sources'),
 'MTK_BASE_POWER':('y','base/power: the SPM idle notifier and SODI calls DISP and Mali make'),
 'COMMON_CLK_MT6771':('y','clk-mt6771 and the scpsys power-gate clocks DISP, SMI and Mali use'),
 'MEMORY':('y','drivers/memory menu for the SMI driver'),
 'MTK_SMI_EXT':('y','4.14 SMI: mtk-smi larb and common, smi_drv bus control and mmdvfs, as stock'),
 'MTK_SMI':('y','drivers/memory/mtk-smi.c, selected by MTK_SMI_EXT'),
 'MTK_M4U':('y','legacy M4U (m4u/2.4, m4u/mt6771) with the MVA API DISP, ION and CMDQ call'),
 'MTK_CACHE_FLUSH_BY_SF':('y','M4U full cache flush through the ATF snoop-filter call, as stock'),
 'ION':('y','4.14 legacy ION in place of 5.10 staging ION: /dev/ion handle ABI, ION_IOC_CUSTOM'),
 'MTK_ION':('y','MTK ION heaps as stock: system 0, carveout 2, multimedia 10, camera 12'),
 'MAILBOX':('y','mailbox framework the 4.14 GCE driver registers with'),
 'MTK_CMDQ':('y','CMDQ: drivers/misc/mediatek/cmdq and the GCE mailbox helper'),
 'MTK_CMDQ_MBOX':('y','4.14 GCE mailbox driver on /gce_mbox@10238000 (mediatek,mt6771-gce)'),
 'MTK_CMDQ_V3':('y','CMDQ v3: /dev/mtk_cmdq on /gce@10238000 for DISP and MDP, as stock'),
 'MTK_SYNC':('y','mtk_sync timelines DISP fences use'),
 'SYNC_FILE':('y','sync_file fds for mtk_sync and /dev/mdp_sync'),
 'CMA':('y','CMA areas for the ZMC driver, selected by ZONE_MOVABLE_CMA'),
 'ZONE_MOVABLE_CMA':('y','4.14 ZMC driver for /reserved-memory/zone-movable-cma-memory, as stock'),
 'ZONE_DMA':('y','DMA zone below 4 GiB for M4U page tables and 32-bit DMA masks, as stock'),
 'ZONE_DMA32':('y','arm64 default; empty here since ZONE_DMA already ends at 4 GiB'),
 'FB':('y','fbdev core for mtkfb (fb0), as stock'),
 'MTK_FB':('y','DISP: dispsys, videox, mtkfb fb0 and /dev/mtk_disp_mgr, as stock'),
 'MTK_LCM':('y','LCM list and helpers with the R63308 panel driver, as stock'),
 'CUSTOM_KERNEL_LCM':('"R63308_CASCADEMDZ40"','the panel stock builds into the LCM list'),
 'LCM_WIDTH':('"720"','panel width, as stock'),
 'LCM_HEIGHT':('"720"','panel height, as stock'),
 'MTK_FB_SUPPORT_ASSERTION_LAYER':('y','DISP assertion layer, as stock'),
 'MTK_LEDS':('y','leds-mt65xx: lcd-backlight through disp_pwm (mode 5), as stock'),
 'MTK_BOOT':('y','boot mode from LK atag,boot: get_boot_mode for DISP, /sys/class/BOOT/BOOT/boot, as stock'),
 'MTK_PMIC_CHIP_MT6358':('y','MT6358 branches of the 4.14 sources (leds-mt65xx skips the ISINK blink path), as stock'),
 'MTK_DRAMC':('y','DISP layering rule picks the LP4_HD HRT table and LEVEL2 from the mtk_dramc.h answers, as stock'),
 'MTK_QOS_SUPPORT':('y','DISP and SMI mmdvfs PM QoS requests reach the no-op pm_qos calls, as stock builds them'),
 'MTK_GPU_SUPPORT':('y','GED (/proc/ged), gpu/hal and Mali, as stock'),
 'MTK_GPU_VERSION':('"mali bifrost r25p0"','the kbase that answers UK 11.27 to libGLES_mali, as stock'),
 'MTK_GPU_COMMON_DVFS_SUPPORT':('y','GED DVFS through MT6771 gpufreq, as stock'),
 'MTK_GPU_OPP_STATS_SUPPORT':('y','GPU OPP stats, as stock'),
 'MTK_FREQ_HOPPING':('y','mt_dfs_general_pll for the GPUPLL frequency changes gpufreq makes, as stock'),
 'INPUT_KEYBOARD':('y','keyboard drivers menu for the aw9523'),
 'KEYBOARD_AW9523':('y','physical keyboard, aw9523-key on i2c4 0x58'),
 'LEDS_MT65XX_BUTTON':('y','keyboard backlight at /sys/class/leds/button-backlight'),
 'INPUT_POCKET_TOUCHPAD':('y','keyboard touchpad, mtk-pad on i2c6 (talks at 0x20)'),
 'INPUT_TOUCHSCREEN':('y','touchscreen drivers menu for the GT1151QM'),
 'TOUCHSCREEN_POCKET_GT1151':('y','touchscreen, mtk-tpd on i2c0 (talks at 0x14)'),
 'POWER_RESET':('y','board power-off drivers menu'),
 'POWER_RESET_MT6358':('y','power off through the MT6358 RTC and PWRHOLD, as stock'),
 'RTC_DRV_MT6397':('y','MT6358 RTC as rtc0 for alarm wake and HCTOSYS; stock used its own MTK_RTC driver'),
 'MT6358_BATTERY_OC':('y','MT6358 FG_CUR_H/L battery OC IRQs and register_battery_oc_notify for gpufreq, as stock pmic_throttling_dlpt'),
 'MEDIATEK_MT6577_AUXADC':('y','SoC AUXADC channel 0 for the board thermistor mtkts_bts_get_hw_temp reads; stock used MTK_AUXADC'),
 'KEYBOARD_MTK':('y','mtk-kpd: volume keys on the keypad matrix, as stock'),
 'KPD_PWRKEY_USE_PMIC':('y','power and home keys from the MT6358 IRQs on mtk-kpd, as stock'),
 'ONEKEY_REBOOT_NORMAL_MODE':('y','8 s power key long-press reset, as stock'),
 'ONEKEY_REBOOT_OTHER_MODE':('y','8 s power key long-press reset in other boot modes, as stock'),
 'KPD_PMIC_LPRST_TD':('0','RG_PWRKEY_RST_TD 0 (8 s), as stock'),
 'MTK_MRDUMP_KEY':('y','KEY_RESTART on mtk-kpd, as stock'),
 'ARM64_ERRATUM_858921':('y','A73 r0p2 timer erratum, as stock; needed once CPU4-7 boot'),
 'HOTPLUG_CPU':('y','sysfs CPU online/offline, as stock; for taking CPUs on and off line'),
 'THERMAL':('y','thermal core for the SoC zone; a critical trip calls orderly_poweroff'),
 'THERMAL_OF':('y','thermal zones and trips from the board DT'),
 'MTK_THERMAL':('y','MT6771 sensors, the 117 C critical trip and stock\'s TOPRGU hardware reset'),
 'ARM_MEDIATEK_CPUFREQ':('y','mediatek-cpufreq on the mcucfg CPU muxes, fixed OPPs from the board DT'),
 'CPU_FREQ_GOV_SCHEDUTIL':('y','built in; init.pocket.power.rc selects it after boot'),
 'UCLAMP_TASK':('y','stock has it; Android task profiles write uclamp for top-app'),
 'UCLAMP_TASK_GROUP':('y','stock has it; cpu.uclamp.min and max in the cpu cgroup'),
 'ENERGY_MODEL':('y','energy model from the board DT dynamic-power-coefficient; EAS needs it'),
 'SCHED_MC':('y','cluster level in the sched domains, as stock; EAS pairs it with the asymmetric capacities'),
 'CPU_FREQ_DEFAULT_GOV_PERFORMANCE':('y','first boot runs the performance governor'),
 'CPU_FREQ_THERMAL':('y','cpufreq cooling devices for cpu_thermal\'s 65 C control trip and cpu_backstop\'s 95 C trip'),
 'THERMAL_GOV_POWER_ALLOCATOR':('y','power_allocator (IPA) on cpu_thermal, stock-like ATM power budget'),
 'THERMAL_DEFAULT_GOV_STEP_WISE':('y','step_wise stays the default, so cpu_backstop and zones without sustainable-power keep it'),
 'THERMAL_EMULATION':('y','emul_temp in each zone for the trial\'s IPA test'),
 'WATCHDOG_OPEN_TIMEOUT':('0','no rc file starts watchdogd; the kernel must keep pinging'),
 'LEDS_TRIGGERS':('y','MT6370 RGB LED cc, pwm and breath mode triggers, as stock'),
 'LEDS_TRIGGER_TIMER':('y','timer trigger the stock lights HAL writes to blink the MT6370 RGB LED, as stock'),
 'RT_REGMAP':('y','Richtek register map the MT6370 MFD reads and writes through'),
 'RT_FLASHLIGHT':('y','Richtek flashlight class the MT6370 FLED and BLED register with'),
 'MFD_MT6370_PMU':('y','MT6370 MFD on i2c5 0x34, as stock'),
 'MT6370_PMU_FLED':('y','MT6370 flash LEDs, as stock'),
 'POCKET_TORCH':('y','torch LED at /sys/class/leds/torch on both MT6370 flash LEDs, stock torch currents'),
 'MT6370_PMU_BLED':('y','MT6370 backlight LED, as stock'),
 'MT6370_PMU_RGBLED':('y','MT6370 RGB LED, as stock'),
 'MT6370_PMU_LDO':('y','MT6370 LDO and the agold LDO calls, as stock'),
 'MT6370_PMU_DSV':('y','MT6370 DSV, the dsv_pos and dsv_neg panel bias the LCM looks up'),
 'BATTERY_OZ8806':('y','OZ8806 gauge on i2c6 0x2f, coulomb counter with OCV at boot and rest'),
 'OZ8806_WRITE':('y','gauge writes the counter, as the level needs it'),
 'OZ8806_BATTERY':('y','battery supply at /devices/platform/battery, the parent stock sepolicy labels'),
 'MTK_GAUGE_VERSION':('30','the GM3.0 charger interface, as stock (GM3.0 itself is not built)'),
 'MTK_CHARGER':('y','mtk_charger with SwitchCharging and the stock limits'),
 'MTK_EXTERNAL_CHARGER_TYPE_DETECT':('y','charger type from the MT6370 BC1.2, not the MT6358'),
 'MT6370_PMU_CHARGER':('y','MT6370 charger as primary_chg, as stock'),
 'MT6370_PMU_CHARGER_TYPE_DETECT':('y','MT6370 BC1.2 charger type detection, as stock'),
 'MTK_TINYSYS_SCP_SUPPORT':('y','SCP core: mailbox IPI, ready notify and scp_share for the sensor hub; LK loads the firmware, as stock'),
 'IIO':('y','IIO core, as stock; nanohub keeps its data in an iio_dev'),
 'NANOHUB':('y','nanohub comms to the SCP CHRE over IPI_CHRE, as stock'),
 'NANOHUB_MTK_IPI':('y','nanohub IPI transport, as stock'),
 'MTK_SENSOR_SUPPORT':('y','MTK sensor stack, as stock'),
 'MTK_SENSOR_ARCHITECTURE':('"1.0"','hwmon 1.0 interface sensors.mt6771.so opens, as stock'),
 'MTK_HWMON':('y','m_*_misc devices, /sys/class/sensor and /dev/sensorlist, as stock'),
 'CUSTOM_KERNEL_SENSORHUB':('y','SCP_nanoHub sensor commands and events, as stock'),
 'CUSTOM_KERNEL_ACCELEROMETER':('y','accel core and /dev/m_acc_misc, as stock'),
 'MTK_ACCELHUB':('y','accelerometer on the SCP hub, as stock'),
 'CUSTOM_KERNEL_ALSPS':('y','alsps core, /dev/m_als_misc and /dev/m_ps_misc, as stock'),
 'MTK_ALSPSHUB':('y','light and proximity on the SCP hub, as stock'),
 'SND_SOC':('y','ASoC core for the 4.14 MTK sound stack, as stock'),
 'MTK_SND_SOC_NEW_ARCH':('y','MTK 4.14 sound stack (card mt-snd-card) the vendor audio HAL expects, as stock'),
 'MTK_SND_SOC_CODEC':('"mt6358"','codec directory for the MTK sound stack, as stock'),
 'SND_DYNAMIC_MINORS':('y','mt-snd-card has 32 PCM devices; static minors fit 8 per card and snd_card_register fails -EBUSY, as stock'),
 'SND_MAX_CARDS':('32','as stock'),
 'MTK_ACCDET':('y','headset jack detect, /dev/accdet and the ACCDET input device, as stock'),
 'ACCDET_EINT_IRQ':('y','ACCDET on the PMIC EINT, as stock'),
 'ACCDET_SUPPORT_EINT0':('y','PMIC EINT0 for the jack, as stock'),
 'MTK_VIDEOCODEC_DRIVER':('y','/dev/Vcodec for the stock OMX video codecs, as stock'),
 'MTK_I2C_SHIM':('y','mtk_i2c_transfer for imgsensor and cam_cal over i2c-mt65xx'),
 'MTK_IMGSENSOR':('y','imgsensor v1_1 and seninf, /dev/kd_camera_hw and /dev/seninf, as stock'),
 'CUSTOM_KERNEL_IMGSENSOR':('"ov16880_mipi_raw ov8865_mipi_raw"','the rear and front sensor drivers, as stock'),
 'MTK_CAM_CAL':('y','cam_cal v1, /dev/CAM_CAL_DRV, as stock'),
 'MTK_LENS':('y','main and sub lens cores, /dev/MAINAF with AK7371AF, as stock'),
 'MTK_FLASHLIGHT':('y','flashlight core, /dev/flashlight, as stock'),
 'MTK_FLASHLIGHT_MT6370':('y','flashlights-mt6370 on the Richtek FLED class, as stock'),
 'MTK_FLASHLIGHT_PT':('y','flashlight power throttling, as stock'),
 'MTK_FLASHLIGHT_PT_STRICT':('y','strict power throttling, as stock'),
 'MTK_FLASHLIGHT_DLPT':('y','flashlight DLPT calls into PBM (weak stub), as stock'),
 'MTK_ARCHCOUNTER_TIMESYNC':('y','archcounter to monotonic time for ISP_GET_GLOBAL_TIME, as stock'),
 'MTK_CAMERA_ISP':('y','isp_50 ISP and DIP, /dev/camera-isp and /dev/camera-dip, as stock'),
 'MTK_CAMERA_ISP_WPE_SUPPORT':('y','isp_50 WPE, /dev/camera-wpe, as stock'),
 'MTK_CAMERA_ISP_RSC_SUPPORT':('y','isp_50 RSC, /dev/camera-rsc, as stock'),
 'MTK_CAMERA_ISP_FD_SUPPORT':('y','FDVT 4.0, /dev/camera-fdvt, as stock'),
 'MTK_CCU':('y','CCU 2.0, /dev/ccu, as stock'),
 'MTK_JPEG':('y','JPEG v2 encoder, /proc/mtk_jpeg, as stock'),
 'MTK_SSPM_IPI':('y','SSPM mailbox and IPI core, PLT_INIT and debugfs, cut down from stock sspm v1'),
 'MTK_EMI':('y','EMI MPU regions over ATF as stock: AP region 31 locked at boot, SCP 6, connsys 26 and 25'),
 'CPU_IDLE':('y','cpuidle for the MCDI core-off state, off by default'),
 'CPU_IDLE_GOV_MENU':('y','menu governor for cpuidle-psci'),
 'ARM_PSCI_CPUIDLE':('y','cpuidle-psci: WFI and mcdi-cpu (PSCI 0x10001) from the board idle-states'),
 'ARM_PSCI_CPUIDLE_DOMAIN':('n','stock ATF has no PSCI OSI mode, so no PSCI power domains'),
 'MTK_MCDI_SSPM':('y','MCDI core-off client over SSPM mailbox 3, off until mtk_mcdi.enable=1'),
 'MTK_CPUHP_POWER_DOWN':('y','SIP core and cluster power-down after CPU hotplug, as stock, so an offline CPU can come back'),
 'MTK_SPM_BASE':('y','SPM base driver: SPM map, IRQ0, SPMFW_IDX and firmware status as stock spm_module_init, no vcorefs or suspend'),
 'MTK_SPM_VCOREFS':('y','vcorefs init with DVS and DFS off (flag 0x418), the SSPM QOS IPIs and the pm_qos DVFSRC requests as stock recovery, on by default with DVS and DFS (flag 0x8400), spm_vcorefs.init=0 or dvfs=0 turns them off'),
 'MTK_SPM_SUSPEND':('y','SPM deep suspend for mem as stock slp_suspend_ops: PCM WDT, SSPM suspend commands, MCDI pause, TOPRGU handover, GIC masked but SPM IRQ0 and the edge IRQs, SYS_CIRQ clone and flush, 8250_mtk sleep handshake, SIP suspend flags 0x8009a 0x300, PSCI CPU_SUSPEND 0x1010005, wake reason and pm_wakeup_irq; offered with spm_suspend.deep=1 and spm_vcorefs.init=1, both default, and mem_sleep deep by default'),
 'LOCALVERSION':('"-titanpocket-firstboot"','first-boot identity'),
}
FORBIDDEN={
 'SCSI_UFS_CRYPTO':'UFS HIE not ported; blk-crypto fallback instead',
 'SCSI_UFS_HPB':'HPB changes the read path; stock has it off and the engineering profile is untested with it',
 'TRUSTKERNEL_TEE_RPMB_SUPPORT':'outside the stock support boundary',
 'TEE':'upstream TEE collides with TrustKernel tee_* names',
 'F2FS_FS':'product and vendor fstab use ext4 only',
 'SHADOW_CALL_STACK':'see intentional differences',
 'DMA_CMA':'stock has it off; no default CMA area besides ZMC',
 'DRM_MEDIATEK':'mainline mediatek-drm would bind the display against the 4.14 DISP driver',
 'FB_SIMPLE':'simplefb would take LK\'s framebuffer before mtkfb',
 'DRM_PANFROST':'mainline panfrost would bind /mali@13040000 against kbase',
 'DRM_LIMA':'mainline lima matches arm,mali-* compatibles',
 'MTK_TINYSYS_SSPM_SUPPORT':'SSPM IPI is not ported; freqhopping and gpufreq take their non-SSPM paths',
 'PWM_MTK_DISP':'mainline disp_pwm would compete with ddp_pwm for the backlight PWM',
 'SND_SOC_MT8183':'mainline MT8183 AFE; the 4.14 MTK AFE drives the MT6771 audio block',
 'SND_SOC_MT6358':'mainline MT6358 codec; the 4.14 MTK codec drives it over pwrap',
 'VIDEO_MEDIATEK_VCODEC':'mainline V4L2 mtk-vcodec needs VPU/SCP firmware MT6771 lacks; the 4.14 videocodec driver serves the stock OMX libs',
 'VIDEO_MEDIATEK_VPU':'mainline MT8173 VPU, no MT6771 firmware',
 'MTK_LENS_USE_MODULE':'the lens cores are built in, as stock; this kernel loads no camera modules',
}
# Deliberate differences from android-base or v9, with why.
INTENTIONAL={
 'SHADOW_CALL_STACK':'x18 preservation by the stock secure monitor and TrustKernel is unverified; off for the first boot',
 'PM_SLEEP':'v9 had no system sleep; the first boot has s2idle only',
 'CPU_IDLE':'v9 had no cpuidle; cpuidle-psci carries the MCDI core-off state, off on every CPU at boot',
 'LOCALVERSION':'first-boot identity instead of the RAM diagnostic one',
 'I2C_CHARDEV':'only the v9 userspace I2C ID probes used it',
 'NET':'v9 had no networking; Android needs it',
 'INPUT':'v9 had no input; android-base wants the core',
 'SOUND':'v9 had no sound; android-base wants the core',
 'RTC_CLASS':'v9 had no RTC; android-base wants the core',
 'MODULES':'v9 had no modules; android-base wants them on (no 5.10 modules exist)',
 'EXT4_FS':'v9 had no filesystems; every fstab entry is ext4',
 'TRACE_GPU_MEM':'hidden symbol selected only by GPU drivers; no GPU driver yet',
 'CPU_FREQ':'v9 had no cpufreq; mediatek-cpufreq with fixed OPPs',
 'WATCHDOG_OPEN_TIMEOUT':'v9 used a 90 s deadline as a return timer; nothing in the ROM opens /dev/watchdog',
 'FB':'v9 had no display; mtkfb (display port milestone 5) needs the fbdev core',
 'MMC':'v9 had no MMC; the MMC core (no host driver) gives the SDIO exports stock wmt_drv links, as stock MMC=y',
}

def parse_config(text):
 values={}
 for line in text.splitlines():
  m=re.match(r'^CONFIG_([A-Za-z0-9_]+)=(.*)$',line)
  if m:values[m.group(1)]=m.group(2);continue
  m=re.match(r'^# CONFIG_([A-Za-z0-9_]+) is not set$',line)
  if m:values[m.group(1)]='n'
 return values
def kconfig_symbols():
 symbols=set()
 for p in SOURCE.rglob('Kconfig*'):
  for m in re.finditer(r'^\s*(?:menu)?config\s+([A-Za-z0-9_]+)\s*$',p.read_text(errors='replace'),re.M):symbols.add(m.group(1))
 return symbols
def conditional(xml_path,config):
 text=xml_path.read_text();text=re.sub(r'<kernel[^>]*/>','',text)
 root=ET.fromstring('<root>'+text+'</root>');out=[]
 for group in root.findall('group'):
  conds=[(c.findtext('key')[7:],c.findtext('value')) for c in group.find('conditions').findall('config')]
  if all((config.get(k,'n')=='y')==(v=='y') for k,v in conds):
   for c in group.findall('config'):out.append((c.findtext('key')[7:],c.findtext('value'),'conditional: '+' && '.join(k+'='+v for k,v in conds)))
 return out
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()

def main():
 ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--config');ap.add_argument('--variant',choices=['wrapper','enforcing'],default='wrapper');a=ap.parse_args()
 enf=a.variant=='enforcing'
 if not a.config:a.config=str(pocket_paths.build_root() / 'kernel-firstboot-5.10')+('-enforcing' if enf else '')+'/.config'
 cfg_path=Path(a.config);config=parse_config(cfg_path.read_text());symbols=kconfig_symbols();items=[]
 def check(option,expected,source,reason):
  actual=config.get(option,'n')
  if actual==expected:return
  if option not in symbols and expected!='n':cls,ok,why='not in this tree',True,'no Kconfig symbol in the 5.10 source'
  elif enf and option in ENFORCING_EXPECT:cls,ok,why='intentionally different',True,ENFORCING_EXPECT[option][1]
  elif option in INTENTIONAL:cls,ok,why='intentionally different',True,INTENTIONAL[option]
  else:cls,ok,why=source,False,reason
  items.append({'option':'CONFIG_'+option,'expected':expected,'actual':actual,'class':cls,'reason':why,'ok':ok})
 base_files=[BASE_DIR/'android-base.config'];arm64=BASE_DIR/'android-base-arm64.config'
 if arm64.exists():base_files.append(arm64)
 counts={}
 for bf in base_files:
  wanted=parse_config(bf.read_text());counts[bf.name]=len(wanted)
  for k,v in sorted(wanted.items()):check(k,v,'required by android-base',bf.name)
 cond=conditional(BASE_DIR/'android-base-conditional.xml',config);counts['android-base-conditional.xml (applicable)']=len(cond)
 for k,v,why in cond:check(k,v,'required by android-base',why)
 adb_path=dict(ADB_PATH)
 if enf:adb_path.update({k:(v,why) for k,(v,why) in ENFORCING_EXPECT.items()})
 for k,(v,why) in adb_path.items():check(k,v,'needed for adb path',why)
 for k,why in FORBIDDEN.items():
  if config.get(k,'n') not in ('n',''):items.append({'option':'CONFIG_'+k,'expected':'n','actual':config[k],'class':'needed for adb path','reason':why,'ok':False})
 # Board drivers carried over from v9.
 v9=parse_config(V9.read_text());counts['v9 board/diagnostic lines']=len(v9)
 for k,v in sorted(v9.items()):check(k,v,'v9 board driver dropped','v9 diagnostic had it; board drivers must carry over')
 # Every fragment request must have resolved as written.
 frag=parse_config(FRAGMENT.read_text())
 if enf:frag.update(parse_config(ENFORCING_FRAGMENT.read_text()))
 counts['firstboot fragment lines']=len(frag)
 for k,v in sorted(frag.items()):check(k,v,'fragment request dropped by Kconfig','olddefconfig did not keep it; a dependency is missing')
 seen=set();unique=[]
 for it in items:
  key=(it['option'],it['expected'])
  if key in seen:continue
  seen.add(key);unique.append(it)
 summary={}
 for it in unique:summary[it['class']]=summary.get(it['class'],0)+1
 failures=[it for it in unique if not it['ok']]
 for it in unique:print(('OK  ' if it['ok'] else 'FAIL')+' %-45s want %-6s got %-6s [%s] %s'%(it['option'],it['expected'],it['actual'],it['class'],it['reason']))
 report={'utc':datetime.now(timezone.utc).isoformat(),'config':str(cfg_path),'config_sha256':sha(cfg_path),'variant':a.variant,'fragment_sha256':sha(FRAGMENT),'enforcing_fragment_sha256':sha(ENFORCING_FRAGMENT) if enf else None,
  'references':{str(p):sha(p) for p in base_files+[BASE_DIR/'android-base-conditional.xml',V9]},'android_base_arm64_file_present':arm64.exists(),
  'checked_counts':counts,'differences_by_class':summary,'unexplained_failures':len(failures),'items':unique,'auditor_sha256':sha(Path(__file__)),
  'limits':['Config only: says nothing about whether the drivers work on the phone','Requirements beyond android-base are from the product fstab, cgroups.json and NetBpfLoad source, not from a boot']}
 out=REPORT_ENFORCING if enf else REPORT
 out.parent.mkdir(parents=True,exist_ok=True);out.write_text(json.dumps(report,indent=2)+'\n')
 print('Differences:',summary,'unexplained:',len(failures));print('Report:',out)
 raise SystemExit(1 if failures else 0)
if __name__=='__main__':main()
