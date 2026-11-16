#!/usr/bin/env python3
"""Turn on the keyboard, its backlight and the touchpad in the v9 board dtb; no image packaging or phone access.

Reads the v9 board (evidence/kernel-upgrade/diagnostic-board-v9.json, made by
prepare-pocket-storage-tree.py) and enables, with the stock properties as captured:
- /i2c@11008000/aw9523@58 (awinic,aw9523-key) and its three pinctrl states
- /odm/led@5 (mediatek,button-backlight), with gpios = GPIO 159 added, and /odm
- /odm/vibrator@0 (mediatek,vibrator), with vib-supply = ldo_vibr and the MT6358 VIBR_OC IRQ added
- /i2c@11005000/cap_tkpd@21 (mediatek,cap_tkpd), the touchpad, with the stock /touch_pad
  IRQ (EINT 2, level low) and reset-gpios = GPIO 9 added
- /i2c@11007000/cap_touch@5d (mediatek,cap_touch), the touchscreen, with the stock /touch
  IRQ (EINT 1, falling), its pinctrl states and power-gpios = GPIO 153 (stock gpio-en-std),
  plus a tpd_eint_as_int pin state rebuilt from the stock eint@0 one, which our tree loses
- /i2c@11005000/coulomb@2f (mediatek,coulomb), the OZ8806 gauge, and /battery
  (mediatek,bat_gm30), the parent of the battery supply, both as stock (no other properties)
- i2c5 (/i2c@11017000, as mediatek,mt6771-i2c) with the MT6370 at subpmic_pmu@34, /mt6370_pmu_dts
  and all its children (charger included), /mt_charger and /charger, with the stock properties
- the status of the nodes in kernel-upgrade/dts/pocket-mm-providers.dtso, pocket-display.dtso and
  pocket-gpu.dtso (scpsys, mmsys_config, M4U, SMI, GCE, DISP, mtkfb, dsi_te, led@6, mfgcfg, gpufreq,
  mali, fhctl), set to okay as stock, and pocket-gpu.dtso's vgpu-supply and vsram_gpu-supply on /gpufreq
- /kp@10010000 (mediatek,kp, the mtk-kpd keypad) and the MT6358's mt-pmic child (mediatek,mt-pmic, the
  pwrkey/homekey IRQs mtk-kpd takes, and fg_cur_h/fg_cur_l for mt6358-battery-oc), both with the stock live properties
- the thermal controller, /therm_ctrl@1100b000 with stock reg, IRQ and THERM clock, as mediatek,mt6771-thermal
  with the AUXADC clock, the infracfg_ao reset 0 (bank 0x120 bit 0, stock's thermal reset), and /auxadc@11001000,
  /apmixed@1000c000 and /toprgu@10007000 (given a phandle) by phandle; /thermal-zones/cpu_thermal on sensor 0
  (the hottest of the six) for power_allocator: passive 50 C (switch-on) and 65 C (control), sustainable-power
  2000 mW, then stock's 117 C critical; /thermal-zones/cpu_backstop on sensor id 1 (the same reading), a 95 C
  step_wise trip
- cpufreq for mediatek-cpufreq: /mcucfg@0c530000 as mediatek,mt6771-mcucfg (the CPU muxes), each cpu with its
  cluster mux and clk26m as cpu and intermediate clocks, proc-supply (VPROC12 for CPU0-3, VPROC11 for CPU4-7),
  a shared OPP table per cluster and #cooling-cells; regulator-ramp-delay and a 1050 mV max on buck_vproc11/12;
  cooling maps from the 65 C control trip and the 95 C backstop trip to both clusters; /gpufreq gets a phandle and
  #cooling-cells and joins the 65 C map only
  The fuses come from LK's atag,devinfo; /efusec@11f10000 stays as stock, gpufreq maps it by its compatible
- /scp_dvfs (mediatek,scp_dvfs), the SCP clock mux and parents on topckgen, with the stock properties; scp@10500000
  okay as in stock's boot dtb, since LK only loads the SCP when this tree has it okay (it then writes okay or disabled
  back), and reserve-memory-scp_share stays as stock
- Audio (AUDIO_PORT.md milestone 0), as stock: /audio@11220000 (audsys clocks), /mt_soc_dl1_pcm@11220000 (the AFE)
  with its 25 clocks, IRQ and 12 pin states, /audio_sram@11221000, the /mt_soc_* stubs and /mt_soc_codec_name, and
  speaker_amp@34 on i2c3. /accdet, the PMIC accdet channel and /mtk-btcvsd-snd@18000000 stay disabled
- Connectivity (WIFI_PORT.md milestone 1), as stock: /consys@18070000 with consys_default and gpslna@0 to 2, plus
  vcn18-supply, vcn28-supply, vcn33_bt-supply, vcn33_wifi-supply and memory-region = consys-reserve-memory (given a
  phandle); /nfc, /irq_nfc and /i2c@1100f000/nfc@08; /wifi@180f0000 (trial A fix)
- Systracker (BT_WATCHDOG.md fix 2), as stock: /bus_dbg@10208000
- Video codec (CAMERA_PORT.md milestone V), as stock: /vdec@16020000 and /venc@17020000, whose reg and IRQ the
  videocodec driver reads (it binds to vdec_gcon@16000000, already okay with its scpsys and gcon clocks)
- Camera sensor path (CAMERA_PORT.md milestone C1), as stock: /kd_camera_hw1@1a040000 and the 36 camera pin states it
  names, /seninf_top@1a040000, i2c-2 (/i2c@11009000, as mediatek,mt6771-i2c with mediatek,ch-offset 0x100 like i2c-4) and
  the camera_* children of i2c-2 and i2c-4
- Camera flashlight (CAMERA_PORT.md milestone C2), as stock: /flashlight_core and /flashlights_mt6370
- Camera ISP (CAMERA_PORT.md milestone C3), as stock: cam1..4 and camsv1..6 (camera_isp), dip1 (camera_dip) and wpe_a,
  wpe_b (camera_wpe) with their IRQs. camsys and imgsys were okay already. dip2..6 stay disabled
- Camera FDVT and RSC (milestone C4), as stock: /imgsyscq, /rsc (camera_rsc) and /fdvt (camera_fdvt) with their IRQs
- Camera CCU (milestone C5), as stock: /ccu@1a0a0000 (/dev/ccu) with IRQ 264 and the ccu_sensor_i2c_2_hw@33 and
  ccu_sensor_i2c_4_hw@36 children of i2c-2 and i2c-4
- Camera JPEG (milestone C6), as stock: /venc_jpg@17030000 (jpeg_driver, /proc/mtk_jpeg) with IRQ 249 and the venc_gcon JPGENC clock
- BTIF (WIFI_PORT.md milestone 2), as stock: /btif@1100c000 with its three IRQs, the AP DMA TX and RX channel
  registers and the infracfg_ao btif and apdma clocks
- Power (POWER_PORT.md P1 and P3): the MT6358's mt6358_rtc as stock, and /auxadc@11001000 as mediatek,mt6771-auxadc with
  the mediatek,mt6765-auxadc fallback, clock-names main and #io-channel-cells; /charger gets io-channels = <&auxadc 0>, "bts"
- SSPM (POWER_PORT.md P7): /sspm@10440000 as stock; reserve-memory-sspm_share was okay already and stays as stock
- SPM base (POWER_PORT.md P11a): /sleep@10006000 (mediatek,sleep, SPI 0xbb level low, wakeup-source) and
  /sleep_reg_md@1000f000 as stock
- SYS_CIRQ (POWER_PORT.md P12c): /sys_cirq@10204000 (mediatek,sys_cirq, 231 lines from SPI 72, its IRQ SPI 0x12f level
  low) as stock; only the deep suspend path uses it
- vcorefs (POWER_PORT.md P11b): /dvfsrc_top@10012000 (DVFSRC and the SSPM QOS SRAM) as stock. LK adds the DRAMC
  dummy-read reserved-memory nodes on our boots, so the board doesn't
- MCDI core-off (POWER_PORT.md P8): /cpus/idle-states/mcdi-cpu okay with local-timer-stop and mediatek,default-off
  (cpuidle-psci registers it disabled on every CPU), cpu-idle-states = <&mcdi-cpu> on every cpu; the other idle states
  stay disabled. /apxgpt@10008000 okay as mediatek,mt6771-timer on a new /clocks/clk13m (13 MHz fixed-clock), the
  tick broadcast timer
- Sunwave fingerprint (TOUCHPAD_PORT.md, FINGERPRINT_PORT.md): /fingerprint (mediatek,fingerprint) and the 18 pin states
  it names, as stock, plus spi0@1100a000's three clocks (parent-clk, sel-clk, spi-clk) so sunwave-fp can set the SPI0
  source and turn its clock on for the TA. spi0@1100a000 stays disabled: its registers are secure only (stock logs a
  DEVAPC violation when Linux reads them) and the TrustKernel TA drives SPI0
- Modem thermal (MODEM_PORT.md M5): /thermal-sensor2 (mediatek,mtboard-thermistor2, AUXADC channel 1 as thermistor-ch1),
  /thermal-zones/mtktsbtsmdpa on it with stock thermal.conf's tzbtspa trips (68 C mtk-cl-adp-mutt, 100 C mtk-cl-noIMS,
  110 C mtk-cl-mdoff, active, no hysteresis, 1000 ms polling) and /modem-coolers with a node per cooler for the maps
- Modem (MODEM_PORT.md M1), in keyboard-modem-on.dtb only: /mdcldma@10014000 (eccci's CLDMA and CCIF0 node),
  /ap_ccif0@10209000, /md_ccif0@1020a000 and /md_auxadc (port_rpc's MD ADC, AUXADC channel 4), with the stock live
  properties. keyboard.dtb, the default board, keeps them disabled so a boot never starts MD1. The two md1_sim hot plug nodes
  stay disabled: port_rpc finds them by name and reads their properties whatever the status, and their two-cell
  interrupts don't fit the GIC's three, so as platform devices they'd only carry a bad IRQ entry
- IR blaster (IR_PORT.md): /irtx_pwm (mediatek,irtx-pwm) and its two GPIO90 pin states and /pwm@11006000 (mediatek,pwm, PWM1
  memory mode) as stock, plus irtx-supply = the MT6370 mt6370_ldo regulator, given a phandle. irtx@1100d000 stays disabled
Everything else on i2c2, i2c4, i2c5, i2c6 and under /odm stays disabled, and /touch and the auxadc's adc_channel@ child too. Writes keyboard.dtb and keyboard-modem-on.dtb next to
their .dts and the record evidence/kernel-upgrade/firstboot-board-keyboard.json.
"""
import pocket_paths
import hashlib,json,os,re,runpy,struct,subprocess
from pathlib import Path
ROOT=Path(__file__).resolve().parent.parent
BULK=pocket_paths.build_root()
SOURCE_RECORD=ROOT/'evidence/kernel-upgrade/diagnostic-board-v9.json'
OUTPUT=BULK/'artifacts/firstboot-5.10/board'
RECORD=ROOT/'evidence/kernel-upgrade/firstboot-board-keyboard.json'
PIO=0x1b                      # /1000b000.pinctrl phandle in the stock tree
BUS='/i2c@11008000';KEY=BUS+'/aw9523@58'
STATES={'/1000b000.pinctrl/aw9523@0':(0x103,0xb200,'output-low'),     # aw9523_reset_low, GPIO 178
        '/1000b000.pinctrl/aw9523@1':(0x104,0xb200,'output-high'),    # aw9523_reset_high, GPIO 178
        '/1000b000.pinctrl/aw9523@2':(0x105,0x0000,'bias-disable')}   # aw9523_eint, GPIO 0
ODM='/odm';LED=ODM+'/led@5';LED_GPIO=159
# Vibrator (VIBRATOR_PORT.md): stock node, plus the VIBR LDO as vib-supply and VIBR_OC (MT6358 hwirq 44,
# LDO_TOP_INT_CON1 bit 12) on the PMIC, both of which stock's driver took from the PMIC code.
VIB=ODM+'/vibrator@0';VIBR_LDO=0x74;PMIC_H=0x65;VIBR_OC=44
PAD_BUS='/i2c@11005000';PAD=PAD_BUS+'/cap_tkpd@21';PAD_IRQ=(2,8);PAD_RESET=9   # EINT 2 IRQ_TYPE_LEVEL_LOW
TOUCH_PAD='/touch_pad';COULOMB=PAD_BUS+'/coulomb@2f';BATTERY='/battery'
TS_BUS='/i2c@11007000';TS=TS_BUS+'/cap_touch@5d';TOUCH='/touch';TS_IRQ=(1,2);TS_POWER=153   # EINT 1 IRQ_TYPE_EDGE_FALLING
# The stock /touch pin states in its order. eint@0 (0xec, GPIO 1 input, bias off) is lost when fdtoverlay
# merges it with the remote's eint node (STOCK_DEVICE_TREE.md), so it is rebuilt as TS_AS_INT.
TS_STATE_NAMES=['default','state_eint_as_int','state_eint_output0','state_eint_output1','state_rst_output0','state_rst_output1']
TS_STATES={'/1000b000.pinctrl/eint0default':(0xeb,None,None),                 # default, no pins
           '/1000b000.pinctrl/eintoutput0':(0xed,0x0100,'output-low'),     # GPIO 1
           '/1000b000.pinctrl/eintoutput1':(0xee,0x0100,'output-high'),
           '/1000b000.pinctrl/rstoutput0':(0xef,0x1200,'output-low'),      # GPIO 18
           '/1000b000.pinctrl/rstoutput1':(0xf0,0x1200,'output-high')}
TS_AS_INT='/1000b000.pinctrl/tpd_eint_as_int'
# POWER_PORT.md P4: capacity per MHz and dynamic power per core (stock upower fit C*f*V^2: A53 81.5, A73 211.1), A53 then A73.
CAP_DMIPS=(655,1024);DYN_POWER=(82,211)
I2C5='/i2c@11017000';SUBPMIC=I2C5+'/subpmic_pmu@34';PMU='/mt6370_pmu_dts';PMU_IRQ_GPIO=10
MT_CHARGER='/mt_charger';CHARGER='/charger'
KP='/kp@10010000';MT_PMIC='/pwrap@1000d000/mt6358-pmic/mt-pmic'
KEY_IRQS=['pwrkey','pwrkey_r','homekey','homekey_r']
THERM='/therm_ctrl@1100b000';AUXADC='/auxadc@11001000';EFUSE='/efusec@11f10000'
TOPRGU='/toprgu@10007000';APMIXED='/apmixed@1000c000';INFRA='/infracfg_ao@10001000'
ZONES='/thermal-zones';ZONE=ZONES+'/cpu_thermal';TRIPS=ZONE+'/trips'
BACKSTOP=ZONES+'/cpu_backstop';BACK_TRIPS=BACKSTOP+'/trips'
THERM_CG=10;AUXADC_CG=36;THERM_RESET=0   # INFRACFG_AO_THERM_CG, INFRACFG_AO_AUXADC_CG; infracfg reset bank 0x120 bit 0
# Power (POWER_PORT.md P1 and P3). rtc-mt6397 takes the RTC registers and IRQ 64 from the mfd cell, not the node.
# mt6577_auxadc as mt6765 (same CON1, DAT0 and MISC layout as stock's mt6771 header, no global idle wait as stock),
# its clock named main; /charger reads the board NTC on channel 0 as io-channels "bts".
RTC='/pwrap@1000d000/mt6358-pmic/mt6358_rtc';RTC_IRQ=64
# SSPM IPI core (POWER_PORT.md P7): the stock node, cfgreg and mailboxes 0 to 4 (data 0x100, IN/OUT IRQ at +0x1000),
# SPI 0xd0 ipc and 0xd3 to 0xd7 mbox0 to 4, level high. reserve-memory-sspm_share stays as stock: no-map, 0x510000,
# 64 KB aligned, placed by the kernel below 0xa0000000; LK only rewrites its status (okay) and has no debug-only part.
SSPM='/sspm@10440000';SSPM_SHARE='/reserved-memory/reserve-memory-sspm_share';SSPM_SHARE_SIZE=0x510000
# SPM base driver (POWER_PORT.md P11a): the stock sleep node (SPM at 0x10006000, IRQ0 on SPI 0xbb level low through
# sysirq, stock's wakeup-source list) and sleep_reg_md, both with the stock live properties.
SLEEP='/sleep@10006000';SLEEP_REG_MD='/sleep_reg_md@1000f000'
# SYS_CIRQ (POWER_PORT.md P12c): the stock node, 0xe7 lines from SPI offset 0x48, SPI 0x12f level low through sysirq.
CIRQ='/sys_cirq@10204000'
# vcorefs init (POWER_PORT.md P11b): the stock dvfsrc_top, DVFSRC at 0x10012000 and the SSPM QOS SRAM at 0x11bb80.
DVFSRC='/dvfsrc_top@10012000'
SLEEP_WAKEUP=[0x28,0,4,0x29,1,0x20,0x2a,3,0x2000000]
SSPM_REG=[0,0x10440000,0,0x10000]+[x for i in range(5) for x in (0,0x10450000+i*0x10000,0,0x100,0,0x10451000+i*0x10000,0,8)]
SSPM_IRQS=[0,0xd0,4]+[x for i in range(5) for x in (0,0xd3+i,4)]
# MCDI core-off (POWER_PORT.md P8): every cpu gets cpu-idle-states = <&mcdi-cpu> (PSCI 0x10001, T's mode 2), with
# local-timer-stop (stock's driver sets TIMER_STOP) and mediatek,default-off (disabled on every CPU at boot). standby,
# mcdi-cluster and the SPM states stay disabled and unreferenced. The stock DT latencies stay (600/600/1200 us).
# Broadcast timer: apxgpt@10008000 (stock reg and SPI 176 level low through sysirq) as mediatek,mt6771-timer on a
# new 13 MHz fixed clock, since U's GPT driver hard-codes the 13 MHz source (stock ran it on clk32k).
IDLE='/cpus/idle-states';MCDI_CPU=IDLE+'/mcdi-cpu';MCDI_PARAM=0x10001;MCDI_LAT=(600,600,1200)
APXGPT='/apxgpt@10008000';CLK13M='/clocks/clk13m';CLK32K_H=0x2b
AUXADC_COMPAT=['mediatek,mt6771-auxadc','mediatek,mt6765-auxadc'];BTS_CHANNEL=0
# Modem M5: the modem PA NTC (stock tmp_bts.h AUX_IN1_NTC, thermal.conf tzbtspa_param channel 1) as T's
# mtboard-thermistor2 node, and the zone stock's thermal.conf writes to tzbtspa (mtktsbtsmdpa): its three bound
# trips, type 0 (active) with no hysteresis, polling 1000 ms. Its 120 C row has no cooler, so it is left out.
MDPA_SENSOR='/thermal-sensor2';MDPA_CHANNEL=1;MDPA_ZONE=ZONES+'/mtktsbtsmdpa';MDPA_TRIPS=MDPA_ZONE+'/trips'
MODEM_COOLERS='/modem-coolers';MDPA_POLL_MS=1000
MDPA_TRIP_LIST=[('adp_mutt',68000,'mtk-cl-adp-mutt'),('no_ims',100000,'mtk-cl-noIMS'),('md_off',110000,'mtk-cl-mdoff')]
# cpu_thermal runs power_allocator (POWER_PORT.md P5): mtk_thermal sets it on a zone with sustainable-power.
# IPA takes the first passive trip as switch-on and the last passive one before the critical as control, and stops
# reading trips at the first critical one, so the critical trip goes last. 117 C is stock's mtktscpu-sysrst and
# the hardware reset threshold. Polling 200 ms as stock's thermal_manager sets it.
THERM_TRIPS=[('ipa_switch_on',50000,'passive'),('ipa_control',65000,'passive'),('critical',117000,'critical')]
IPA_CONTROL='ipa_control';SUSTAINABLE_MW=2000;POLL_MS=200;POLL_PASSIVE_MS=40
# cpu_backstop: the same reading (sensor id 1) under step_wise, stock's 95 C cpu00 step, in case IPA does nothing.
BACKSTOP_TRIPS=[('backstop',95000,'passive')]
# cpufreq (CPUFREQ_PORT.md): mediatek-cpufreq on the mcucfg cluster muxes with 26 MHz as the intermediate clock.
# Worst-bin OPPs over every non-V6 stock pv table (POWER_PORT.md P6), 825 mV floor on VPROC12 for the CCI,
# A73 at fy5t + 62.5 mV for EEM's headroom, at most 1050 mV. VSRAM follows VPROC by MT6358 hardware tracking.
# Steps above 1417 MHz are turbo-mode, so they stay out until cpufreq/boost is 1. Every OPP has
# opp-supported-hw: OPP_HW_ALL is every stock level but V6 (bit 5), 2106 MHz is V5_T (bit 6) only.
MCUCFG='/mcucfg@0c530000';CPUS='/cpus';CLK26M='/clocks/clk26m';VPROC11='buck_vproc11';VPROC12='buck_vproc12'
MCU_MP0,MCU_MP1=0,1           # MCUCFG_MP0_SEL, MCUCFG_MP1_SEL in mt6771-clk.h
CPU_OPPS={'/opp-table-0':[(793,825000),(910,825000),(1014,825000),(1131,825000),(1248,825000),(1326,825000),
                          (1417,850000),(1508,868750),(1586,893750),(1625,906250),(1677,931250),(1716,943750),
                          (1781,975000),(1846,1000000),(1924,1025000),(1989,1050000)],            # A53, VPROC12
          '/opp-table-1':[(793,737500),(910,762500),(1014,787500),(1131,812500),(1248,837500),(1326,862500),
                          (1417,887500),(1508,912500),(1586,937500),(1625,950000),(1677,968750),(1716,987500),
                          (1781,1012500),(1846,1037500),(1924,1050000),(2106,1050000)]}           # A73, VPROC11
# P10d: the A53 rows held at the 825 mV floor carry their worst-bin voltage as the opp-microvolt min,
# <825000 min 825000>. mediatek-cpufreq uses the min only with its a53_floor knob at 0 and the CCI managed.
A53_MIN_UV={793:650000,910:687500,1014:718750,1131:756250,1248:800000,1326:818750}
# CCI (POWER_PORT.md P10): the 16 worst-bin rows of evidence/power/cci-rea.md, MHz and uV, on VPROC12 with the A53s.
CCI='/cci';CCI_TABLE='/opp-table-cci';APMIXED_CCIPLL=3;MCUCFG_BUS_SEL=2;MCUCFG_BUS_DIV=3   # ids in mt6771-clk.h
CCI_OPPS=[(273,650000),(338,687500),(403,718750),(481,756250),(546,800000),(624,818750),(689,850000),(767,868750),
          (845,893750),(871,906250),(923,931250),(962,943750),(1027,975000),(1092,1000000),(1144,1025000),(1196,1050000)]
OPP_TOP_NON_TURBO=1417        # MHz; the policy max with boost off
OPP_HW_ALL=0xdf;OPP_HW_V5_T=0x40;OPP_V5_T_ONLY=2106
VPROC_RAMP=7500               # uV/us, stock's slower (down) slew; mt6358-regulator has no ramp_delay of its own
VPROC_MAX=1050000             # the highest worst-bin OPP; stock's MAX_VPROC_VOLT is 1120 mV
GPUFREQ='/gpufreq'
COOLING_TRIPS=[TRIPS+'/'+IPA_CONTROL,BACK_TRIPS+'/backstop']   # each throttles both clusters; the backstop starts at the first state below 1417 MHz
# SCP core (SENSORS_PORT.md). Stock /scp_dvfs clocks: scp_sel, then its seven parents in mux order, clk26m first.
# The topckgen IDs are stock mt6771-clk.h numbering, which 5.10's mt6771-clk.h keeps.
SCP='/scp@10500000';SCP_DVFS='/scp_dvfs';SCP_SHARE='/reserved-memory/reserve-memory-scp_share'
TOPCK='/topckgen@10000000';TOPCK_H=0x44;SCPSYS='/scpsys@10001000'
SCP_CLOCKS=[('clk_mux','TOP_MUX_SCP'),('clk_pll_0',None),('clk_pll_1','TOP_UNIVPLL_D2_D8'),('clk_pll_2','TOP_SYSPLL_D5'),
            ('clk_pll_3','TOP_SYSPLL_D2_D2'),('clk_pll_4','TOP_UNIVPLL_D2_D2'),('clk_pll_5','TOP_SYSPLL_D3'),('clk_pll_6','TOP_UNIVPLL_D3')]
CLK_HEADER=Path(os.environ.get('POCKET_KERNEL_SOURCE',str(ROOT/'tools/kernel-source/upgrade-5.10')))/'include/dt-bindings/clock/mt6771-clk.h'
# Audio (AUDIO_PORT.md milestone 0). The AFE's stock clocks in DT order: name, provider, mt6771-clk.h name (None for clk26m).
AUDSYS='/audio@11220000';AUDSYS_H=0x3e;AFE='/mt_soc_dl1_pcm@11220000';AUD_SRAM='/audio_sram@11221000'
AMP_BUS='/i2c@1100f000';AMP=AMP_BUS+'/speaker_amp@34';ACCDET='/accdet';BTCVSD='/mtk-btcvsd-snd@18000000'
# Headset (milestone 5): /accdet and the MT6358 AUXADC node with the two channels pmic_legacy.c reads (accdet, hpofs_cal).
PMIC_ADC='/pwrap@1000d000/mt6358-pmic/mt635x-auxadc';PMIC_ADC_CHANNELS={PMIC_ADC+'/accdet':9,PMIC_ADC+'/hpofs_cal':12}
INFRA_H=0x15;SCPSYS_H=0x2e
AFE_CLOCKS=[('aud_afe_clk',AUDSYS_H,'AUDIO_AFE'),('aud_dac_clk',AUDSYS_H,'AUDIO_DAC'),('aud_dac_predis_clk',AUDSYS_H,'AUDIO_DAC_PREDIS'),
            ('aud_adc_clk',AUDSYS_H,'AUDIO_ADC'),('aud_adc_adda6_clk',AUDSYS_H,'AUDIO_PDN_ADDA6_ADC'),('aud_apll22m_clk',AUDSYS_H,'AUDIO_22M'),
            ('aud_apll24m_clk',AUDSYS_H,'AUDIO_24M'),('aud_apll1_tuner_clk',AUDSYS_H,'AUDIO_APLL_TUNER'),('aud_apll2_tuner_clk',AUDSYS_H,'AUDIO_APLL2_TUNER'),
            ('aud_tml_clk',AUDSYS_H,'AUDIO_TML'),('scp_sys_audio',SCPSYS_H,'SCP_SYS_AUDIO'),('aud_infra_clk',INFRA_H,'INFRACFG_AO_AUDIO_CG'),
            ('mtkaif_26m_clk',INFRA_H,'INFRACFG_AO_AUDIO_26M_BCLK_CK'),('top_mux_audio',TOPCK_H,'TOP_MUX_AUDIO'),('top_mux_audio_int',TOPCK_H,'TOP_MUX_AUD_INTBUS'),
            ('top_syspll_d2_d4',TOPCK_H,'TOP_SYSPLL_D2_D4'),('top_mux_aud_1',TOPCK_H,'TOP_MUX_AUD_1'),('top_apll1_ck',TOPCK_H,'TOP_APLL1_CK'),
            ('top_mux_aud_2',TOPCK_H,'TOP_MUX_AUD_2'),('top_apll2_ck',TOPCK_H,'TOP_APLL2_CK'),('top_mux_aud_eng1',TOPCK_H,'TOP_MUX_AUD_ENG1'),
            ('top_apll1_d8',TOPCK_H,'TOP_APLL1_D8'),('top_mux_aud_eng2',TOPCK_H,'TOP_MUX_AUD_ENG2'),('top_apll2_d8',TOPCK_H,'TOP_APLL2_D8'),
            ('top_clk26m_clk',None,None)]
# pinctrl-0 to 11 in pinctrl-names order, phandles 0xf1 to 0xfc. The vow states go unused (VOW is off), as on stock.
AFE_PINS=[('aud_clk_mosi_off','aud_clk_mosi_off'),('aud_clk_mosi_on','aud_clk_mosi_on'),('aud_dat_mosi_off','aud_dat_mosi_off'),
          ('aud_dat_mosi_on','aud_dat_mosi_on'),('aud_dat_miso_off','aud_dat_miso_off'),('aud_dat_miso_on','aud_dat_miso_on'),
          ('aud_smartpa_off','aud_pins_smartpa_off'),('aud_smartpa_on','aud_pins_smartpa_on'),('vow_dat_miso_off','vow_dat_miso_off'),
          ('vow_dat_miso_on','vow_dat_miso_on'),('vow_clk_miso_off','vow_clk_miso_off'),('vow_clk_miso_on','vow_clk_miso_on')]
# Connectivity (WIFI_PORT.md milestone 1). consys as stock plus the four LDO supplies the mt6771 platform file
# asks for by name (regulator_get "vcn18", ...) and memory-region, which the 4.15+ WMT reads for its EMI.
CONSYS='/consys@18070000';CONSYS_MEM='/reserved-memory/consys-reserve-memory'
CONSYS_SUPPLIES={'vcn18-supply':0x7a,'vcn28-supply':0x7d,'vcn33_bt-supply':0x89,'vcn33_wifi-supply':0x8a}
CONSYS_PINS=['/1000b000.pinctrl/consys_default','/1000b000.pinctrl/gpslna@0','/1000b000.pinctrl/gpslna@1','/1000b000.pinctrl/gpslna@2']
NFC_NODES=['/nfc','/irq_nfc','/i2c@1100f000/nfc@08']
# Sunwave fingerprint. EINT 8 as stock's interrupts cells; SPI0's clocks are topckgen syspll_d5_d2 (55) as parent,
# topckgen spi_sel (7) and infracfg_ao infra_spi0 (28), the same IDs on 5.10.
FP='/fingerprint';SPI0='/spi0@1100a000';FP_IRQ=[8,8,8,0];SPI0_CLOCKS=[TOPCK_H,55,TOPCK_H,7,INFRA_H,28]
BTIF='/btif@1100c000';BTIF_CG=27;APDMA_CG=43   # INFRACFG_AO_BTIF_CG, INFRACFG_AO_AP_DMA_CG
WIFI='/wifi@180f0000';CQDMA_CG=78   # INFRACFG_AO_CQ_DMA_CG
BUS_DBG='/bus_dbg@10208000'   # systracker (BT_WATCHDOG.md fix 2)
# Video codec (CAMERA_PORT.md milestone V): reg and SPI as stock's live tree, level low
VCODEC_NODES={'/vdec@16020000':('mediatek,vdec',[0,0x16020000,0,0x10000],[0,0xfa,8]),
              '/venc@17020000':('mediatek,venc',[0,0x17020000,0,0x1000],[0,0xf7,8])}
VDEC_GCON='/vdec_gcon@16000000'
# Camera sensor path (CAMERA_PORT.md milestone C1). Rear on i2c-2 (i2c@11009000), front on i2c-4 with the keyboard.
CAM_HW='/kd_camera_hw1@1a040000';SENINF_TOP='/seninf_top@1a040000';CAM_BUS='/i2c@11009000'
CAM_I2C=[CAM_BUS+'/camera_main@1a',CAM_BUS+'/camera_main_af@72',CAM_BUS+'/camera_main_eeprom@50',CAM_BUS+'/camera_sub_two@28',
         BUS+'/camera_main_two@10',BUS+'/camera_main_two_af@72',BUS+'/camera_main_two_eeprom@51',BUS+'/camera_sub@35',
         BUS+'/camera_sub_eeprom@54']
CAM_SUPPLIES={'cam0_vcama':139,'cam0_vcamd':121,'cam0_vcamio':120,'cam0_vldo28':140,'cam1_vcama':133,'cam1_vcamd':121,'cam1_vcamio':120}
# Camera flashlight (CAMERA_PORT.md milestone C2): the core and the MT6370 channels node, as stock's live tree.
FL_CORE='/flashlight_core';FL_MT6370='/flashlights_mt6370'
# IR blaster (IR_PORT.md): the stock nodes, LED power from the MT6370 LDO, which stock switched by register.
IRTX='/irtx_pwm';IRTX_BLOCK='/irtx@1100d000';PWM_NODE='/pwm@11006000'
IRTX_STATES={'/1000b000.pinctrl/irtx_gpio_led_def@gpio90':(0x101,0x5a00),'/1000b000.pinctrl/irtx_gpio_led_set@gpio90':(0x102,0x5a01)}
# Camera ISP (CAMERA_PORT.md milestone C3): the nodes camera_isp (after camsys), camera_dip (after imgsys) and camera_wpe
# bind, in DT order, as stock's live tree. camera_isp indexes its devices by probe order, so all ten have to be okay.
ISP_NODES=['/cam1@1a003000','/cam2@1a004000','/cam3@1a006000','/cam4@1a008000','/camsv1@1a050000','/camsv2@1a051000',
           '/camsv3@1a052000','/camsv4@1a053000','/camsv5@1a054000','/camsv6@1a055000']
DIP_NODES=['/dip1@15022000'];WPE_NODES=['/wpe_a@1502a000','/wpe_b@1502d000']
# Camera FDVT and RSC (milestone C4): camera_rsc counts its devices by probe order and registers /dev/camera-rsc on the
# second, so /imgsyscq (no IRQ, reg only) has to probe before /rsc, as the DT order gives. fdvt_dma is not bound.
RSC_NODES=['/imgsyscq@15020000','/rsc@15029000'];FDVT_NODES=['/fdvt@1502b000'];CCU='/ccu@1a0a0000'
JPEG='/venc_jpg@17030000'
CAMSYS='/camsys@1a000000';IMGSYS='/imgsys@15020000'
# SPI and level as stock: cam1..4 253..256, camsv1..4 258..261, dip1 268, wpe_a 273, wpe_b 274 (camsv5, camsv6 have none)
ISP_IRQS={'/cam1@1a003000':0xfd,'/cam2@1a004000':0xfe,'/cam3@1a006000':0xff,'/cam4@1a008000':0x100,'/camsv1@1a050000':0x102,
          '/camsv2@1a051000':0x103,'/camsv3@1a052000':0x104,'/camsv4@1a053000':0x105,'/dip1@15022000':0x10c,
          '/wpe_a@1502a000':0x111,'/wpe_b@1502d000':0x112,'/rsc@15029000':0x10f,'/fdvt@1502b000':0x10d}
# Modem M1: nodes stock's live tree has okay (no status) for the modem, as they are there. The md1_sim hot plug
# nodes stay disabled; port_rpc reads them by name whatever the status.
MDCLDMA='/mdcldma@10014000';MD_AUXADC='/md_auxadc'
MODEM_NODES=[MDCLDMA,'/ap_ccif0@10209000','/md_ccif0@1020a000',MD_AUXADC]
MD_SIM_NODES=['/md1_sim1_hot_plug_eint','/md1_sim2_hot_plug_eint']
LIVE=ROOT/'evidence/device/20261029T000648.917229Z/live-root-20230105/fdt.dtb'
LIVE_SHA='d6d1b6a89e13ad130022ad31b9394e5b7def449c88a181d40cfcc47ec452763f'
OVERLAYS=[ROOT/'kernel-upgrade/dts/pocket-mm-providers.dtso',ROOT/'kernel-upgrade/dts/pocket-display.dtso',
          ROOT/'kernel-upgrade/dts/pocket-gpu.dtso']

def sha(p):return hashlib.sha256(Path(p).read_bytes()).hexdigest()
def main():
 os.environ.setdefault('POCKET_DIAGNOSTIC_VARIANT','v4')
 tree=runpy.run_path(str(ROOT/'tools/prepare-pocket-diagnostic-tree.py'),run_name='keyboard_board_helpers')
 providers=runpy.run_path(str(ROOT/'tools/prepare-pocket-storage-tree.py'),run_name='keyboard_board_helpers')['validate_providers']
 decode=tree['DECODE'];cells=tree['cells'];strings=tree['strings'];values=tree['values'];text=tree['text'];enabled=tree['enabled']
 source=json.loads(SOURCE_RECORD.read_text())['board_dtb'];original=Path(source['path'])
 assert sha(original)==source['sha256'],'v9 board dtb does not match its record'
 blob=original.read_bytes();nodes=decode(blob)['nodes'];before={p:dict(v) for p,v in nodes.items()}
 okay=strings('okay')

 pio='/1000b000.pinctrl'
 assert values(nodes[pio]['phandle'])==[PIO] and 'gpio-controller' in nodes[pio] and 'interrupt-controller' in nodes[pio]
 assert enabled(nodes,pio)
 # i2c4 is already on (v9) with stock reg, IRQ, clocks and the +0x100 AP channel; it carries the camera CCU too.
 assert enabled(nodes,BUS) and values(nodes[BUS]['mediatek,ch-offset'])==[0x100]
 others=[c for c in nodes if c.startswith(BUS+'/') and c!=KEY]
 assert others and not any(enabled(nodes,c) for c in others),'Other i2c4 children must stay disabled'
 others=[c for c in others if c not in CAM_I2C]   # the camera ones are enabled below (C1)

 k=nodes[KEY]
 assert text(k['compatible'])==['awinic,aw9523-key'] and values(k['reg'])==[0x58]
 assert values(k['awinic,irq-gpio'])==[PIO,0,0] and values(k['irq-gpio'])==[PIO,0,0]
 assert values(k['awinic,reset-gpio'])==[PIO,0xb2,0] and values(k['reset-gpio'])==[PIO,0xb2,0]
 assert text(k['pinctrl-names'])==['aw9523_reset_low','aw9523_reset_high','aw9523_eint']
 assert [values(k['pinctrl-'+str(i)]) for i in range(3)]==[[0x103],[0x104],[0x105]]
 assert 'interrupts' not in k,'Stock takes the IRQ from awinic,irq-gpio'
 k['status']=okay
 for path,(handle,pinmux,flag) in STATES.items():
  sub=path+'/pins_cmd_dat'
  assert values(nodes[path]['phandle'])==[handle] and values(nodes[sub]['pinmux'])==[pinmux] and flag in nodes[sub]
  assert [c for c in nodes if c.startswith(path+'/')]==[sub]
  nodes[path]['status']=okay;nodes[sub]['status']=okay

 # The stock driver hard-codes GPIO 159; 5.10 has no fixed GPIO numbers, so the node names it.
 led=nodes[LED]
 assert text(nodes[ODM]['compatible'])==['simple-bus']
 assert text(led['compatible'])==['mediatek,button-backlight'] and values(led['led_mode'])==[2] and values(led['data'])==[1]
 assert 'gpios' not in led
 led['gpios']=cells(PIO,LED_GPIO,0);led['status']=okay;nodes[ODM]['status']=okay
 v=nodes[VIB]
 assert text(v['compatible'])==['mediatek,vibrator'] and [values(v[k]) for k in ('vib_timer','vib_limit','vib_vol')]==[[25],[9],[0xb]]
 assert not {'vib-supply','interrupts','interrupts-extended','interrupt-parent'}&set(v)
 [ldo]=[p for p in nodes if p.endswith('/ldo_vibr')];[pm]=[p for p in nodes if p.endswith('/mt6358-pmic')]
 assert values(nodes[ldo]['phandle'])==[VIBR_LDO] and text(nodes[ldo]['regulator-name'])==['vibr'] and enabled(nodes,ldo)
 assert values(nodes[ldo]['regulator-min-microvolt'])==[1200000] and values(nodes[ldo]['regulator-max-microvolt'])==[3300000]
 assert values(nodes[pm]['phandle'])==[PMIC_H] and 'interrupt-controller' in nodes[pm] and values(nodes[pm]['#interrupt-cells'])==[2]
 v['vib-supply']=cells(VIBR_LDO);v['interrupts-extended']=cells(PMIC_H,VIBR_OC,4);v['status']=okay   # IRQ_TYPE_LEVEL_HIGH as mt-pmic
 odm_others=[c for c in nodes if c.startswith(ODM+'/') and c not in (LED,VIB)]
 assert odm_others and not any(enabled(nodes,c) for c in odm_others),'Other /odm children must stay disabled'

 # Touchpad. Stock takes its IRQ from /touch_pad and pulses GPIO 9 by number; 5.10 needs both on the client node.
 assert enabled(nodes,PAD_BUS) and values(nodes[PAD_BUS]['id'])==[6]
 pad_others=[c for c in nodes if c.startswith(PAD_BUS+'/') and c not in (PAD,COULOMB)]
 assert pad_others and not any(enabled(nodes,c) for c in pad_others),'Other i2c6 children must stay disabled'
 pad=nodes[PAD]
 assert text(pad['compatible'])==['mediatek,cap_tkpd'] and values(pad['reg'])==[0x21]
 assert not {'interrupts','interrupt-parent','interrupts-extended','reset-gpios'}&set(pad)
 tp=nodes[TOUCH_PAD]
 assert text(tp['compatible'])==['mediatek,touch_pad'] and values(tp['interrupt-parent'])==[PIO]
 assert values(tp['interrupts'])[:2]==list(PAD_IRQ) and not enabled(nodes,TOUCH_PAD)
 assert values(nodes[pio]['#interrupt-cells'])==[2] and values(nodes[pio]['#gpio-cells'])==[2]
 pad['interrupt-parent']=cells(PIO);pad['interrupts']=cells(*PAD_IRQ);pad['reset-gpios']=cells(PIO,PAD_RESET,0);pad['status']=okay

 # OZ8806 gauge and the /battery parent of its supply. Stock has both okay with no IRQ, GPIO or
 # supply properties; the driver reads the hw_ver pin (GPIO 5) through the pinctrl chip itself.
 g=nodes[COULOMB]
 assert text(g['compatible'])==['mediatek,coulomb'] and values(g['reg'])==[0x2f] and set(g)=={'compatible','reg','phandle','status'}
 assert [p for p,v in nodes.items() if 'compatible' in v and 'mediatek,coulomb' in text(v['compatible'])]==[COULOMB]
 bat=nodes[BATTERY]
 assert text(bat['compatible'])==['mediatek,bat_gm30'] and not enabled(nodes,BATTERY)
 assert [p for p,v in nodes.items() if 'compatible' in v and 'mediatek,bat_gm30' in text(v['compatible'])]==[BATTERY]
 assert not [c for c in nodes if c.startswith(BATTERY+'/')]
 g['status']=okay;bat['status']=okay

 # MT6370 on i2c5, for mtk_charger. Properties as the stock live DT; only i2c5's compatible changes, to the
 # 5.10 driver's (same reg layout: bus plus AP DMA, main/dma/arb clocks, channel 0 with no ch_offset).
 assert sha(LIVE)==LIVE_SHA;live=decode(LIVE.read_bytes())['nodes']
 bus5=nodes[I2C5]
 assert text(bus5['compatible'])==['mediatek,i2c'] and values(bus5['id'])==[5] and not enabled(nodes,I2C5)
 assert values(bus5['reg'])==[0,0x11017000,0,0x1000,0,0x11000580,0,0x80] and text(bus5['clock-names'])==['main','dma','arb']
 assert values(bus5['clock-frequency'])==[3400000] and 'mediatek,hs_only' in bus5 and 'mediatek,ch-offset' not in bus5 and 'ch_offset_default' not in bus5
 i2c5_others=[c for c in nodes if c.startswith(I2C5+'/') and c!=SUBPMIC]
 assert i2c5_others==[I2C5+'/usb_type_c@4e'] and not enabled(nodes,i2c5_others[0])
 assert text(nodes[SUBPMIC]['compatible'])==['mediatek,subpmic_pmu'] and values(nodes[SUBPMIC]['reg'])==[0x34]
 pmu=nodes[PMU]
 assert values(pmu['mt6370,intr_gpio'])==[PIO,PMU_IRQ_GPIO,0] and values(pmu['mt6370,intr_gpio_num'])==[PMU_IRQ_GPIO]
 pmu_nodes=[PMU]+sorted(c for c in nodes if c.startswith(PMU+'/'))
 assert text(nodes[PMU+'/charger']['compatible'])==['mediatek,mt6370_pmu_charger']
 assert text(nodes[MT_CHARGER]['compatible'])==['mediatek,mt-charger'] and text(nodes[CHARGER]['compatible'])==['mediatek,charger']
 mt6370_nodes=[I2C5,SUBPMIC]+pmu_nodes+[MT_CHARGER,CHARGER]
 for p in mt6370_nodes:
  assert enabled(live,p),p
  assert {k:v for k,v in nodes[p].items() if k not in ('status','compatible')}=={k:v for k,v in live[p].items() if k not in ('status','compatible')},p
  if p!=I2C5:assert nodes[p].get('compatible')==live[p].get('compatible'),p
 bus5['compatible']=strings('mediatek,mt6771-i2c')
 for p in mt6370_nodes:
  if 'status' in nodes[p]:nodes[p]['status']=okay
 mt6370_changed=[p for p in mt6370_nodes if nodes[p]!=before[p]]

 # RTC alarm wake (P1): mt6358_rtc okay as stock's node; rtc-mt6397 writes no PDN or spare registers.
 r=nodes[RTC]
 assert text(r['compatible'])==['mediatek,mt6358-rtc'] and values(r['interrupts'])==[RTC_IRQ,0] and not enabled(nodes,RTC)
 r['status']=okay
 # Board NTC (P3): the SoC AUXADC for mt6577_auxadc, channel 0 on /charger.
 a=nodes[AUXADC]
 assert text(a['compatible'])==['mediatek,auxadc'] and text(a['clock-names'])==['auxadc-main'] and '#io-channel-cells' not in a
 assert values(a['interrupts'])==[0,0x4a,2] and not enabled(nodes,AUXADC) and enabled(nodes,INFRA)
 auxadc_children=[c for c in nodes if c.startswith(AUXADC+'/')]
 assert auxadc_children==[AUXADC+'/adc_channel@'] and not enabled(nodes,auxadc_children[0])
 a['compatible']=strings(*AUXADC_COMPAT);a['clock-names']=strings('main');a['#io-channel-cells']=cells(1);a['status']=okay
 c=nodes[CHARGER];assert 'io-channels' not in c and 'io-channel-names' not in c
 c['io-channels']=cells(values(a['phandle'])[0],BTS_CHANNEL);c['io-channel-names']=strings('bts')
 power_changed=[RTC,AUXADC]+([] if CHARGER in mt6370_changed else [CHARGER])

 # SSPM (P7): sspm@10440000 okay with the stock live properties; its reserved region is unchanged and okay already.
 sp=nodes[SSPM];sh=nodes[SSPM_SHARE]
 assert text(sp['compatible'])==['mediatek,sspm'] and not enabled(nodes,SSPM) and enabled(live,SSPM)
 assert {k:v for k,v in sp.items() if k!='status'}=={k:v for k,v in live[SSPM].items() if k!='status'}
 assert values(sp['reg'])==SSPM_REG and values(sp['interrupts'])==SSPM_IRQS
 assert text(sp['reg-names'])==['cfgreg']+[f'mbox{i}_{n}' for i in range(5) for n in ('base','ctrl')]
 assert text(sp['interrupt-names'])==['ipc']+[f'mbox{i}' for i in range(5)]
 assert text(sh['compatible'])==['mediatek,reserve-memory-sspm_share'] and 'no-map' in sh and 'reg' not in sh and 'debug-only' not in sh
 assert values(sh['size'])==[0,SSPM_SHARE_SIZE] and values(sh['alignment'])==[0,0x10000] and values(sh['alloc-ranges'])==[0,0x40000000,0,0x60000000]
 assert enabled(nodes,SSPM_SHARE) and {k:v for k,v in sh.items() if k!='status'}=={k:v for k,v in live[SSPM_SHARE].items() if k!='status'}
 assert [p for p,v in nodes.items() if 'compatible' in v and 'mediatek,sspm' in text(v['compatible'])]==[SSPM]
 sp['status']=okay
 power_changed+=[SSPM]

 # SPM base (P11a): sleep and sleep_reg_md okay with the stock live properties.
 for p in (SLEEP,SLEEP_REG_MD):
  assert not enabled(nodes,p) and enabled(live,p),p
  assert {k:v for k,v in nodes[p].items() if k!='status'}=={k:v for k,v in live[p].items() if k!='status'},p
 sl=nodes[SLEEP];md=nodes[SLEEP_REG_MD]
 assert text(sl['compatible'])==['mediatek,sleep'] and values(sl['reg'])==[0,0x10006000,0,0x1000]
 assert values(sl['interrupts'])==[0,0xbb,8] and values(sl['wakeup-source'])==SLEEP_WAKEUP
 assert text(md['compatible'])==['mediatek,sleep_reg_md'] and values(md['reg'])==[0,0x1000f000,0,0x1000]
 assert [p for p,v in nodes.items() if 'compatible' in v and set(text(v['compatible']))&{'mediatek,sleep','mediatek,sleep_reg_md'}]==[SLEEP,SLEEP_REG_MD]
 sl['status']=okay;md['status']=okay
 power_changed+=[SLEEP,SLEEP_REG_MD]

 # SYS_CIRQ (P12c): sys_cirq okay with the stock live properties.
 c=nodes[CIRQ]
 assert not enabled(nodes,CIRQ) and enabled(live,CIRQ)
 assert {k:v for k,v in c.items() if k!='status'}=={k:v for k,v in live[CIRQ].items() if k!='status'}
 assert text(c['compatible'])==['mediatek,sys_cirq'] and values(c['reg'])==[0,0x10204000,0,0x1000]
 assert values(c['mediatek,cirq_num'])==[0xe7] and values(c['mediatek,spi_start_offset'])==[0x48] and values(c['interrupts'])==[0,0x12f,8]
 assert 'sw_reset' not in c
 assert [p for p,v in nodes.items() if 'compatible' in v and 'mediatek,sys_cirq' in text(v['compatible'])]==[CIRQ]
 c['status']=okay
 power_changed+=[CIRQ]

 # vcorefs (P11b): dvfsrc_top okay with the stock live properties.
 assert not enabled(nodes,DVFSRC) and enabled(live,DVFSRC)
 assert {k:v for k,v in nodes[DVFSRC].items() if k!='status'}=={k:v for k,v in live[DVFSRC].items() if k!='status'}
 assert text(nodes[DVFSRC]['compatible'])==['mediatek,dvfsrc_top'] and values(nodes[DVFSRC]['reg'])==[0,0x10012000,0,0x1000,0,0x11bb80,0,0x80]
 assert [p for p,v in nodes.items() if 'compatible' in v and 'mediatek,dvfsrc_top' in text(v['compatible'])]==[DVFSRC]
 assert not any('dummy_read' in p for p in nodes)
 nodes[DVFSRC]['status']=okay
 power_changed+=[DVFSRC]

 # Multimedia providers, the display and the GPU, as the three overlays: status okay, plus the
 # GPU overlay's regulator supplies on /gpufreq (single phandles, each to a node with a regulator-name).
 overlay_targets=[];supplies={}
 for o in OVERLAYS:
  src=o.read_text();found=re.findall(r'target-path = "([^"]+)"',src)
  props=re.findall(r'^\s*([\w,.-]+) = ([^;]+);',src,re.M)
  sup=[(k,v) for k,v in props if k.endswith('-supply')]
  assert len(found)==src.count('status = "okay";')==src.count('__overlay__') and len(props)==2*len(found)+len(sup),o
  for k,v in sup:
   assert o.name=='pocket-gpu.dtso' and re.fullmatch(r'<0x[0-9a-f]+>',v),(o,k,v)
   supplies[k]=int(v[1:-1],16)
  overlay_targets+=found
 assert len(overlay_targets)==len(set(overlay_targets))
 assert set(supplies)=={'vgpu-supply','vsram_gpu-supply'},supplies
 for p in overlay_targets:
  assert p in nodes and enabled(live,p),p
  nodes[p]['status']=okay
 by_phandle={values(v['phandle'])[0]:p for p,v in nodes.items() if 'phandle' in v}
 for k,h in supplies.items():
  reg=nodes[by_phandle[h]]
  assert text(reg['regulator-name'])==[k[:-len('-supply')]] and enabled(nodes,by_phandle[h]),(k,by_phandle[h])
  nodes['/gpufreq'][k]=cells(h)
 overlay_changed=[p for p in overlay_targets if nodes[p]!=before[p]]

 # Touchscreen. Stock takes the IRQ, pin states and GPIO 153 from /touch; 5.10 needs them on the client
 # node. reg stays 0x5d (the driver talks at 0x14, as stock); /touch stays disabled.
 assert enabled(nodes,TS_BUS) and values(nodes[TS_BUS]['id'])==[0]
 ts_others=[c for c in nodes if c.startswith(TS_BUS+'/') and c!=TS]
 assert not any(enabled(nodes,c) for c in ts_others),'Other i2c0 children must stay disabled'
 ts=nodes[TS]
 assert text(ts['compatible'])==['mediatek,cap_touch'] and values(ts['reg'])==[0x5d]
 assert not ({'interrupts','interrupt-parent','interrupts-extended','power-gpios'}|{p for p in ts if p.startswith('pinctrl-')})&set(ts)
 touch=nodes[TOUCH]
 assert text(touch['compatible'])==['mediatek,touch'] and not enabled(nodes,TOUCH)
 assert values(touch['interrupt-parent'])==[PIO] and values(touch['interrupts'])[:2]==list(TS_IRQ)
 assert values(touch['gpio-en-std'])==[PIO,TS_POWER,0] and text(touch['pinctrl-names'])==TS_STATE_NAMES
 stock_states=[values(touch['pinctrl-'+str(i)])[0] for i in range(len(TS_STATE_NAMES))]
 handles={values(v['phandle'])[0]:p for p,v in nodes.items() if 'phandle' in v}
 assert 0xec not in handles and stock_states[1]==0xec,'eint@0 (0xec) is expected to be missing'
 for path,(handle,pinmux,flag) in TS_STATES.items():
  assert values(nodes[path]['phandle'])==[handle] and handle in stock_states
  subs=[c for c in nodes if c.startswith(path+'/')]
  if pinmux is None:assert not subs
  else:
   sub=path+'/pins_cmd_dat';assert subs==[sub] and values(nodes[sub]['pinmux'])==[pinmux] and flag in nodes[sub]
   assert values(nodes[sub]['slew-rate'])==[1];nodes[sub]['status']=okay
  nodes[path]['status']=okay
 assert TS_AS_INT not in nodes and TS_AS_INT+'/pins_cmd_dat' not in nodes
 as_int=max(handles)+1
 nodes[TS_AS_INT]={'phandle':cells(as_int),'status':okay}
 nodes[TS_AS_INT+'/pins_cmd_dat']={'bias-disable':{'hex':''},'pinmux':cells(0x0100),'slew-rate':cells(0),'status':okay}
 ts_handles=[stock_states[0],as_int]+stock_states[2:]
 ts['interrupt-parent']=cells(PIO);ts['interrupts']=cells(*TS_IRQ);ts['power-gpios']=cells(PIO,TS_POWER,0)
 ts['pinctrl-names']=strings(*TS_STATE_NAMES)
 for i,h in enumerate(ts_handles):ts['pinctrl-'+str(i)]=cells(h)
 ts['status']=okay
 handles[as_int]=TS_AS_INT
 for h in ts_handles:assert enabled(nodes,handles[h]),h

 # Keypad and the MT6358 key IRQs for mtk-kpd. Both as the stock live DT. mtk-kpd reads its pwrkey, pwrkey_r,
 # homekey and homekey_r IRQs from mt-pmic (MT6358 hwirqs 48, 50, 49, 51); mt6358-battery-oc binds it as an
 # mfd cell for fg_cur_h and fg_cur_l (82, 83).
 for p in (KP,MT_PMIC):
  assert enabled(live,p) and not enabled(nodes,p),p
  assert {k:v for k,v in nodes[p].items() if k!='status'}=={k:v for k,v in live[p].items() if k!='status'},p
  assert not [c for c in nodes if c.startswith(p+'/')],p
 assert text(nodes[KP]['compatible'])==['mediatek,kp'] and values(nodes[KP]['interrupts'])==[0,186,2]
 assert values(nodes[KP]['mediatek,kpd-sw-pwrkey'])==[116] and values(nodes[KP]['mediatek,kpd-sw-rstkey'])==[102]
 mp=nodes[MT_PMIC];names=text(mp['interrupt-names']);irqs=values(mp['interrupts'])
 assert text(mp['compatible'])==['mediatek,mt-pmic'] and 'interrupt-parent' not in mp
 assert [irqs[2*names.index(n)] for n in KEY_IRQS]==[48,50,49,51]
 pmic=MT_PMIC.rsplit('/',1)[0]
 assert 'interrupt-controller' in nodes[pmic] and values(nodes[pmic]['#interrupt-cells'])==[2] and enabled(nodes,pmic)
 assert sorted(p for p,v in nodes.items() if 'compatible' in v and set(text(v['compatible']))&{'mediatek,kp','mediatek,mt-pmic'})==sorted([KP,MT_PMIC])
 nodes[KP]['status']=okay;nodes[MT_PMIC]['status']=okay

 # SoC thermal protection for mtk_thermal's MT6771 entry. Stock node values; the driver gets the fuse words
 # from LK's atag,devinfo. efusec stays untouched: 5.10 gpufreq maps it by its stock compatible.
 t=nodes[THERM]
 assert text(t['compatible'])==['mediatek,therm_ctrl'] and values(t['reg'])==[0,0x1100b000,0,0x1000] and not enabled(nodes,THERM)
 assert values(t['interrupts'])==[0,0x4c,8] and values(t['clocks'])==[0x15,THERM_CG] and text(t['clock-names'])==['therm-main']
 assert values(nodes[INFRA]['phandle'])==[0x15] and '#reset-cells' in nodes[INFRA] and enabled(nodes,INFRA)
 assert values(nodes[AUXADC]['phandle'])==[0x2f] and values(nodes[AUXADC]['reg'])==[0,0x11001000,0,0x1000] and values(nodes[AUXADC]['clocks'])==[0x15,AUXADC_CG]
 assert values(nodes[APMIXED]['phandle'])==[0x64] and values(nodes[APMIXED]['reg'])==[0,0x1000c000,0,0x1000] and enabled(nodes,APMIXED)
 assert text(nodes[TOPRGU]['compatible'])==['mediatek,mt6771-wdt'] and values(nodes[TOPRGU]['reg'])==[0,0x10007000,0,0x1000] and 'phandle' not in nodes[TOPRGU]
 e=nodes[EFUSE]
 assert text(e['compatible'])==['mediatek,efusec'] and values(e['reg'])==[0,0x11f10000,0,0x1000] and set(e)=={'compatible','reg','status'}
 assert not [c for c in nodes if c.startswith(EFUSE+'/')] and ZONES not in nodes
 assert [p for p,v in nodes.items() if 'compatible' in v and set(text(v['compatible']))&{'mediatek,therm_ctrl','mediatek,efusec'}]==[THERM,EFUSE]
 handles={values(v['phandle'])[0] for v in nodes.values() if 'phandle' in v};rgu_h,therm_h=[max(handles)+i for i in (1,2)]
 nodes[TOPRGU]['phandle']=cells(rgu_h)
 t['compatible']=strings('mediatek,mt6771-thermal');t['clocks']=cells(0x15,THERM_CG,0x15,AUXADC_CG);t['clock-names']=strings('therm','auxadc')
 t['resets']=cells(0x15,THERM_RESET);t['#thermal-sensor-cells']=cells(1)
 t['mediatek,auxadc']=cells(0x2f);t['mediatek,apmixedsys']=cells(0x64);t['mediatek,toprgu']=cells(rgu_h)
 t['phandle']=cells(therm_h);t['status']=okay
 nodes[ZONES]={}
 nodes[ZONE]={'polling-delay-passive':cells(POLL_PASSIVE_MS),'polling-delay':cells(POLL_MS),'sustainable-power':cells(SUSTAINABLE_MW),
              'thermal-sensors':cells(therm_h,0)}
 nodes[TRIPS]={}
 for name,temp,kind in THERM_TRIPS:nodes[TRIPS+'/'+name]={'temperature':cells(temp),'hysteresis':cells(2000),'type':strings(kind)}
 nodes[BACKSTOP]={'polling-delay-passive':cells(POLL_PASSIVE_MS),'polling-delay':cells(POLL_MS),'thermal-sensors':cells(therm_h,1)}
 nodes[BACK_TRIPS]={}
 for name,temp,kind in BACKSTOP_TRIPS:nodes[BACK_TRIPS+'/'+name]={'temperature':cells(temp),'hysteresis':cells(2000),'type':strings(kind)}
 assert [k for _,_,k in THERM_TRIPS]==['passive','passive','critical'] and [t for _,t,_ in THERM_TRIPS]==sorted(t for _,t,_ in THERM_TRIPS)
 assert dict((n,t) for n,t,_ in THERM_TRIPS)['critical']==117000 and BACKSTOP_TRIPS[0][1]<117000
 thermal_added=[ZONES,ZONE,TRIPS]+[TRIPS+'/'+n for n,_,_ in THERM_TRIPS]+[BACKSTOP,BACK_TRIPS]+[BACK_TRIPS+'/'+n for n,_,_ in BACKSTOP_TRIPS]

 # cpufreq. mcucfg keeps its stock compatible after ours; nothing on 5.10 binds mediatek,mcucfg.
 m=nodes[MCUCFG]
 assert text(m['compatible'])==['mediatek,mcucfg'] and values(m['reg'])==[0,0x0c530000,0,0x1000] and not enabled(nodes,MCUCFG)
 assert 'phandle' not in m and '#clock-cells' not in m
 assert [p for p,v in nodes.items() if 'compatible' in v and 'mediatek,mcucfg' in text(v['compatible'])]==[MCUCFG]
 assert values(nodes[CLK26M]['phandle'])==[0x2c] and values(nodes[CLK26M]['clock-frequency'])==[26000000] and enabled(nodes,CLK26M)
 regs={}
 for name in (VPROC11,VPROC12):
  [rp]=[p for p in nodes if p.endswith('/'+name)];r=nodes[rp]
  assert text(r['regulator-name'])==[name[len('buck_'):]] and values(r['regulator-min-microvolt'])==[500000] and values(r['regulator-max-microvolt'])==[1293750]
  assert 'regulator-ramp-delay' not in r and enabled(nodes,rp)
  r['regulator-max-microvolt']=cells(VPROC_MAX);r['regulator-ramp-delay']=cells(VPROC_RAMP);regs[name]=rp
 assert values(nodes[regs[VPROC11]]['phandle'])==[0x6c] and values(nodes[regs[VPROC12]]['phandle'])==[0x6d]
 handles={values(v['phandle'])[0] for v in nodes.values() if 'phandle' in v}
 mcu_h,opp0_h,opp1_h,ctl_h,back_h,gpu_h,cci_h,cci_opp_h=[max(handles)+i for i in range(1,9)]
 m['compatible']=strings('mediatek,mt6771-mcucfg','mediatek,mcucfg');m['#clock-cells']=cells(1);m['phandle']=cells(mcu_h);m['status']=okay
 cpu_nodes=[CPUS+'/cpu@00'+str(i) for i in range(4)]+[CPUS+'/cpu@10'+str(i) for i in range(4)]
 for i,cp in enumerate(cpu_nodes):
  c=nodes[cp];big=i>=4
  assert text(c['compatible'])==['arm,cortex-a73' if big else 'arm,cortex-a53'] and values(c['reg'])==[(0x100 if big else 0)+i%4] and enabled(nodes,cp)
  assert not {'clocks','clock-names','proc-supply','operating-points-v2','#cooling-cells','capacity-dmips-mhz','dynamic-power-coefficient','mediatek,cci'}&set(c)
  c['clocks']=cells(mcu_h,MCU_MP1 if big else MCU_MP0,0x2c);c['clock-names']=strings('cpu','intermediate')
  c['proc-supply']=cells(0x6c if big else 0x6d);c['operating-points-v2']=cells(opp1_h if big else opp0_h);c['#cooling-cells']=cells(2)
  c['mediatek,cci']=cells(cci_h)
  c['capacity-dmips-mhz']=cells(CAP_DMIPS[big]);c['dynamic-power-coefficient']=cells(DYN_POWER[big])
 opp_added=[]
 for (table,opps),h in zip(CPU_OPPS.items(),(opp0_h,opp1_h)):
  assert table not in nodes and max(uv for _,uv in opps)<=VPROC_MAX
  nodes[table]={'compatible':strings('operating-points-v2'),'opp-shared':{'hex':''},'phandle':cells(h)};opp_added.append(table)
  for mhz,uv in opps:
   mv=cells(uv,A53_MIN_UV[mhz],uv) if table=='/opp-table-0' and mhz in A53_MIN_UV else cells(uv)
   o=table+'/opp-'+str(mhz*1000000);nodes[o]={'opp-hz':cells(0,mhz*1000000),'opp-microvolt':mv,
     'opp-supported-hw':cells(OPP_HW_V5_T if mhz==OPP_V5_T_ONLY else OPP_HW_ALL)}
   if mhz>OPP_TOP_NON_TURBO:nodes[o]['turbo-mode']={'hex':''}
   opp_added.append(o)
 # The CCI node: clock names and supply as mediatek-cpufreq's mtk_cci_setup reads them. The bus mux, divider and
 # CCIPLL come from mcucfg and apmixed. Same worst bin as the A53 rows (CCI row i has the LL row i voltage).
 assert CCI not in nodes and CCI_TABLE not in nodes and len(CCI_OPPS)==16 and max(uv for _,uv in CCI_OPPS)<=VPROC_MAX
 assert values(nodes[regs[VPROC12]]['phandle'])==[0x6d]
 nodes[CCI]={'compatible':strings('mediatek,mt6771-cci'),
             'clocks':cells(mcu_h,MCUCFG_BUS_SEL,mcu_h,MCUCFG_BUS_DIV,0x64,APMIXED_CCIPLL,0x2c),
             'clock-names':strings('cci','div','pll','intermediate'),'proc-supply':cells(0x6d),
             'operating-points-v2':cells(cci_opp_h),'phandle':cells(cci_h)}
 nodes[CCI_TABLE]={'compatible':strings('operating-points-v2'),'phandle':cells(cci_opp_h)};opp_added+=[CCI,CCI_TABLE]
 for mhz,uv in CCI_OPPS:
  o=CCI_TABLE+'/opp-'+str(mhz*1000000);nodes[o]={'opp-hz':cells(0,mhz*1000000),'opp-microvolt':cells(uv),'opp-supported-hw':cells(OPP_HW_ALL)};opp_added.append(o)
 assert all(max(f for f,_ in o if f<=OPP_TOP_NON_TURBO)==OPP_TOP_NON_TURBO for o in CPU_OPPS.values())
 assert min(uv for _,uv in CPU_OPPS['/opp-table-0'])>=825000,'VPROC12 floor for the CCI'
 # The A53 min is the worst-bin voltage: CCI row i has the LL row i voltage, both ascending (cci-rea.md).
 a53=CPU_OPPS['/opp-table-0']
 assert all(A53_MIN_UV.get(mhz,uv)==CCI_OPPS[i][1] and A53_MIN_UV.get(mhz,uv)<=uv for i,(mhz,uv) in enumerate(a53)),'A53 min against the worst bin'
 assert all(uv==825000 for mhz,uv in a53 if mhz in A53_MIN_UV) and all(uv>825000 for mhz,uv in a53 if mhz not in A53_MIN_UV)
 # GPU cooling (POWER_PORT.md P5b): gpufreq registers a cooling device on its node, states are its OPP
 # indexes. It joins the IPA map only; the step_wise backstop stays CPU only.
 g=nodes[GPUFREQ];assert text(g['compatible'])==['mediatek,mt6771-gpufreq'] and enabled(nodes,GPUFREQ)
 assert 'phandle' not in g and '#cooling-cells' not in g
 g['phandle']=cells(gpu_h);g['#cooling-cells']=cells(2)
 # Only cpu0 and cpu4 bind (the policy CPUs); the other entries are ignored. No contribution: IPA then weighs
 # both clusters the same and splits the budget by what each asks for.
 cooling_added=[];no_limit=0xffffffff
 for trip,h in zip(COOLING_TRIPS,(ctl_h,back_h)):
  nodes[trip]['phandle']=cells(h)
  maps=trip.rsplit('/trips/',1)[0]+'/cooling-maps';nodes[maps]={};cooling_added.append(maps)
  dev=[]
  for cp in cpu_nodes:
   lo=no_limit
   if trip.startswith(BACK_TRIPS):
    # states 0..n-1 are 1417 MHz and up, which cap nothing with boost off: start at the first real cap
    fr=sorted((f for f,_ in CPU_OPPS['/opp-table-1' if cp in cpu_nodes[4:] else '/opp-table-0']),reverse=True)
    lo=sum(1 for f in fr if f>=OPP_TOP_NON_TURBO);assert fr[lo]<OPP_TOP_NON_TURBO<=fr[lo-1],cp
   dev+=[values(nodes[cp]['phandle'])[0],lo,no_limit]
  if trip==TRIPS+'/'+IPA_CONTROL:dev+=[gpu_h,no_limit,no_limit]
  nodes[maps+'/map0']={'trip':cells(h),'cooling-device':cells(*dev)};cooling_added.append(maps+'/map0')
 cpufreq_added=opp_added+cooling_added

 # SCP. LK's load_scp reads the status of the first mediatek,scp node in this tree and only loads the SCP when
 # it's okay; it then writes okay, or disabled if the load failed. Stock's boot dtb has okay, so it's set here.
 # scp_dvfs only needs its status; its clocks already point at our topckgen.
 c=nodes[SCP]
 assert text(c['compatible'])==['mediatek,scp'] and not enabled(nodes,SCP) and values(c['phandle'])==[0x94]
 assert values(c['reg'])==[0,0x10500000,0,0x80000,0,0x105c0000,0,0x3000,0,0x105c4000,0,0x1000,0,0x105d4000,0,0x6000]
 assert values(c['interrupts'])==[0,0xae,4] and values(c['scp_sramSize'])==[0x80000] and text(c['core_1'])==['enable']
 ids={m.group(1):int(m.group(2)) for m in re.finditer(r'#define (TOP_\w+) (\d+)',CLK_HEADER.read_text())}
 assert values(nodes[TOPCK]['phandle'])==[TOPCK_H] and 'mediatek,topckgen' in text(nodes[TOPCK]['compatible']) and enabled(nodes,TOPCK)
 d=nodes[SCP_DVFS]
 assert text(d['compatible'])==['mediatek,scp_dvfs'] and not enabled(nodes,SCP_DVFS)
 assert text(d['clock-names'])==[n for n,_ in SCP_CLOCKS]
 assert values(d['clocks'])==[x for _,i in SCP_CLOCKS for x in ((TOPCK_H,ids[i]) if i else (values(nodes[CLK26M]['phandle'])[0],))]
 assert [ids[i] for _,i in SCP_CLOCKS if i]==[0x0f,0x42,0x2e,0x30,0x40,0x2d,0x3d]
 assert next(p for p in nodes if 'compatible' in nodes[p] and 'mediatek,scp' in text(nodes[p]['compatible']))==SCP,'LK sets the first mediatek,scp node'
 c['status']=okay;d['status']=okay
 r=nodes[SCP_SHARE]
 assert text(r['compatible'])==['mediatek,reserve-memory-scp_share'] and 'no-map' in r and enabled(nodes,SCP_SHARE)
 assert values(r['size'])==[0,0x380000] and values(r['alignment'])==[0,0x1000000] and values(r['alloc-ranges'])==[0,0x40000000,0,0x50000000]
 assert SCPSYS in overlay_targets and enabled(nodes,SCPSYS),'scp_helper takes INFRA_IRQ and the SCP reset from scpsys'
 scp_others=[p for p in nodes if p.startswith('/scp_') and p!=SCP_DVFS]
 assert scp_others and not any(enabled(nodes,p) for p in scp_others),'The scp_* register nodes stay disabled'

 # Audio. Every node keeps the stock live properties and gets stock's okay. No 5.10 driver matches the AFE, the
 # mt_soc_* stubs or speaker_amp yet, so only the audsys clock provider (CLK_OF_DECLARE) runs at boot.
 ids={m.group(1):int(m.group(2)) for m in re.finditer(r'#define\s+(\w+)\s+(\d+)',CLK_HEADER.read_text())}
 a=nodes[AUDSYS]
 assert text(a['compatible'])==['mediatek,audio','syscon'] and values(a['phandle'])==[AUDSYS_H] and values(a['#clock-cells'])==[1]
 assert values(a['reg'])==[0,0x11220000,0,0x1000] and not enabled(nodes,AUDSYS)
 f=nodes[AFE]
 assert text(f['compatible'])==['mediatek,mt_soc_pcm_dl1'] and values(f['reg'])==[0,0x11220000,0,0x1000] and values(f['interrupts'])==[0,161,8]
 assert text(f['clock-names'])==[n for n,_,_ in AFE_CLOCKS]
 assert values(f['clocks'])==[x for _,h,i in AFE_CLOCKS for x in ((h,ids[i]) if h else (values(nodes[CLK26M]['phandle'])[0],))]
 assert [values(nodes[p]['phandle'])[0] for p in (SCPSYS,INFRA,TOPCK)]==[SCPSYS_H,INFRA_H,TOPCK_H]
 assert all(enabled(nodes,p) for p in (SCPSYS,INFRA,TOPCK,CLK26M)),'The AFE clock providers besides audsys are already on'
 assert text(f['pinctrl-names'])==[n for n,_ in AFE_PINS]
 pin_nodes=[]
 for i,(n,node) in enumerate(AFE_PINS):
  path=pio+'/'+node;assert values(f['pinctrl-'+str(i)])==[0xf1+i] and values(nodes[path]['phandle'])==[0xf1+i],path
  subs=[c for c in nodes if c.startswith(path+'/')];assert subs and all('pinmux' in nodes[c] for c in subs),path
  pin_nodes+=[path]+subs
 assert text(nodes[AUD_SRAM]['compatible'])==['mediatek,audio_sram'] and values(nodes[AUD_SRAM]['reg'])==[0,0x11221000,0,0xc000]
 assert text(nodes[AMP]['compatible'])==['mediatek,speaker_amp'] and values(nodes[AMP]['reg'])==[0x34] and enabled(nodes,AMP_BUS)
 assert values(nodes[AMP_BUS]['id'])==[3]
 stubs=sorted(p for p in nodes if p.startswith('/mt_soc_') and '/' not in p[1:] and p!=AFE)
 assert len(stubs)==35 and '/mt_soc_codec_name' in stubs,len(stubs)
 audio_nodes=[AUDSYS,AFE,AUD_SRAM,AMP]+stubs+pin_nodes
 for p in audio_nodes:
  assert not enabled(nodes,p) and enabled(live,p),p
  assert {k:v for k,v in nodes[p].items() if k!='status'}=={k:v for k,v in live[p].items() if k!='status'},p
  nodes[p]['status']=okay
 accdets=[p for p in nodes if p==ACCDET or p.endswith('/accdet')]
 assert sorted(accdets)==sorted([ACCDET,PMIC_ADC+'/accdet']) and not enabled(nodes,BTCVSD),'btcvsd (milestone 7) stays off'
 assert text(nodes[ACCDET]['compatible'])==['mediatek,pmic-accdet'] and text(nodes[PMIC_ADC]['compatible'])==['mediatek,mt6358-auxadc']
 assert all(values(nodes[p]['channel'])==[ch] for p,ch in PMIC_ADC_CHANNELS.items()) and values(nodes[PMIC_ADC+'/hpofs_cal']['avg-num'])==[0x100]
 assert text(nodes['/pwrap@1000d000/mt6358-pmic']['compatible'])==['mediatek,mt6358'] and enabled(nodes,'/pwrap@1000d000/mt6358-pmic')
 headset_nodes=[ACCDET,PMIC_ADC]+list(PMIC_ADC_CHANNELS)
 for p in headset_nodes:
  assert not enabled(nodes,p) and enabled(live,p),p
  assert {k:v for k,v in nodes[p].items() if k!='status'}=={k:v for k,v in live[p].items() if k!='status'},p
  nodes[p]['status']=okay
 adc_others=[c for c in nodes if c.startswith(PMIC_ADC+'/') and c not in PMIC_ADC_CHANNELS]
 assert len(adc_others)==11 and not any(enabled(nodes,c) for c in adc_others),adc_others

 # Connectivity. consys, its pin states and the NFC nodes keep the stock live properties and get stock's okay;
 # consys also gets the vcn* supplies and memory-region.
 c=nodes[CONSYS]
 assert text(c['compatible'])==['mediatek,mt6771-consys'] and not enabled(nodes,CONSYS) and enabled(live,CONSYS)
 assert {k:v for k,v in c.items() if k!='status'}=={k:v for k,v in live[CONSYS].items() if k!='status'}
 assert [values(c['pinctrl-'+str(i)])[0] for i in range(4)]==[values(nodes[p]['phandle'])[0] for p in CONSYS_PINS]
 assert len(text(c['pinctrl-names']))==4 and 'pinctrl-4' not in c and not set(CONSYS_SUPPLIES)&set(c) and 'memory-region' not in c
 assert values(c['clocks'])==[SCPSYS_H,2] and enabled(nodes,SCPSYS),'consys takes its power domain clock from scpsys'
 for k,h in CONSYS_SUPPLIES.items():
  [rp]=[p for p,v in nodes.items() if values(v.get('phandle',cells()))==[h]]
  assert rp.endswith('/ldo_'+k[:-len('-supply')]) and text(nodes[rp]['regulator-name'])==[k[:-len('-supply')]] and enabled(nodes,rp),(k,rp)
  c[k]=cells(h)
 r=nodes[CONSYS_MEM]
 assert text(r['compatible'])==['mediatek,consys-reserve-memory'] and 'no-map' in r and 'phandle' not in r and enabled(nodes,CONSYS_MEM)
 assert values(r['size'])==[0,0x200000] and r==live[CONSYS_MEM]
 handles={values(v['phandle'])[0] for v in nodes.values() if 'phandle' in v};mem_h=max(handles)+1
 r['phandle']=cells(mem_h);c['memory-region']=cells(mem_h);c['status']=okay
 consys_pins=[]
 for p in CONSYS_PINS:consys_pins+=[p]+[q for q in nodes if q.startswith(p+'/')]
 assert consys_pins==CONSYS_PINS[:2]+[CONSYS_PINS[1]+'/pins_cmd_dat',CONSYS_PINS[2],CONSYS_PINS[2]+'/pins_cmd_dat',CONSYS_PINS[3],CONSYS_PINS[3]+'/pins_cmd_dat']
 assert all(values(nodes[p+'/pins_cmd_dat']['pinmux'])==[0x9b00] for p in CONSYS_PINS[1:]),'gpslna is GPIO 155'
 nfc=NFC_NODES
 assert text(nodes[nfc[0]]['compatible'])==['mediatek,nfc-gpio-v2'] and text(nodes[nfc[1]]['compatible'])==['mediatek,irq_nfc-eint']
 assert text(nodes[nfc[2]]['compatible'])==['mediatek,nfc'] and values(nodes[nfc[2]]['reg'])==[0x08] and values(nodes[AMP]['reg'])!=[0x08]
 for p in consys_pins+nfc:
  assert not enabled(nodes,p) and enabled(live,p),p
  assert {k:v for k,v in nodes[p].items() if k!='status'}=={k:v for k,v in live[p].items() if k!='status'},p
  nodes[p]['status']=okay
 # BTIF as stock: the UART registers, the AP DMA TX and RX channels (0x11000a80, 0x11000b00), SPI 0x72, 0x8b and 0x8c,
 # and the btif and apdma gates on infracfg_ao.
 b=nodes[BTIF]
 assert text(b['compatible'])==['mediatek,btif'] and not enabled(nodes,BTIF) and enabled(live,BTIF)
 assert {k:v for k,v in b.items() if k!='status'}=={k:v for k,v in live[BTIF].items() if k!='status'}
 assert values(b['reg'])==[0,0x1100c000,0,0x1000,0,0x11000a80,0,0x80,0,0x11000b00,0,0x80]
 assert values(b['interrupts'])==[0,0x72,8,0,0x8b,8,0,0x8c,8]
 assert values(b['clocks'])==[INFRA_H,BTIF_CG,INFRA_H,APDMA_CG] and text(b['clock-names'])==['btifc','apdmac'] and enabled(nodes,INFRA)
 b['status']=okay
 # wifi@180f0000 as stock. gen3's platform driver (mediatek,wifi) registers its probe with WMT only from this
 # node's probe; without it Wi-Fi on fails with a null mtk_wcn_wlan_probe. Registers: WFDMA, the CQ DMA channel at
 # 0x10212180, infracfg_ao and conn cfg; SPI 0x122 and 0x76; the infracfg_ao CQ DMA gate as wifi-dma.
 w=nodes[WIFI]
 assert text(w['compatible'])==['mediatek,wifi'] and not enabled(nodes,WIFI) and enabled(live,WIFI)
 assert {k:v for k,v in w.items() if k!='status'}=={k:v for k,v in live[WIFI].items() if k!='status'}
 assert values(w['clocks'])==[INFRA_H,CQDMA_CG] and text(w['clock-names'])==['wifi-dma']
 assert values(w['reg'])==[0,0x180f0000,0,0x1100,0,0x10212180,0,0x6c,0,0x10001000,0,0x1000,0,0x180e0000,0,0x70]
 assert values(w['interrupts'])==[0,0x122,8,0,0x76,8] and values(w['hardware-values'])==[0x788,0xa5800,0xa5800]
 w['status']=okay
 # Systracker as stock: bus_dbg-v2 at 0x10208000, SPI 0x90 level low (the driver maps it but stock requests no IRQ).
 t=nodes[BUS_DBG]
 assert text(t['compatible'])==['mediatek,bus_dbg-v2'] and not enabled(nodes,BUS_DBG) and enabled(live,BUS_DBG)
 assert {k:v for k,v in t.items() if k!='status'}=={k:v for k,v in live[BUS_DBG].items() if k!='status'}
 assert values(t['reg'])==[0,0x10208000,0,0x1000] and values(t['interrupts'])==[0,0x90,8]
 t['status']=okay
 # Video codec as stock: vdec and venc okay with the stock live properties. The driver matches vdec_gcon, which the
 # v9 board already has okay with stock's five clocks (scpsys DIS, VDE, VEN, vdec_gcon VDEC, venc_gcon VENC).
 for p,(comp,reg,irq) in VCODEC_NODES.items():
  v=nodes[p]
  assert text(v['compatible'])==[comp] and not enabled(nodes,p) and enabled(live,p),p
  assert {k:x for k,x in v.items() if k!='status'}=={k:x for k,x in live[p].items() if k!='status'},p
  assert values(v['reg'])==reg and values(v['interrupts'])==irq,p
  v['status']=okay
 g=nodes[VDEC_GCON]
 assert enabled(nodes,VDEC_GCON) and {k:x for k,x in g.items() if k!='status'}=={k:x for k,x in live[VDEC_GCON].items() if k!='status'}
 assert text(g['clock-names'])==['MT_SCP_SYS_DIS','MT_SCP_SYS_VDE','MT_SCP_SYS_VEN','MT_CG_VDEC','MT_CG_VENC']

 # Camera sensor path (C1), as stock: kd_camera_hw1 (imgsensor, with the MT6358 camera supplies), its 36 pin states,
 # seninf_top (seninf, clocks and MTCMOS taken at /dev/seninf open only), i2c-2 and the camera children of i2c-2 and
 # i2c-4. i2c-2 gets the same 5.10 compatible and AP channel offset as i2c-4. The CCU sensor children follow (C5).
 c=nodes[CAM_HW]
 assert text(c['compatible'])==['mediatek,imgsensor'] and not enabled(nodes,CAM_HW) and enabled(live,CAM_HW)
 assert {k:v for k,v in c.items() if k!='status'}=={k:v for k,v in live[CAM_HW].items() if k!='status'}
 assert {k:values(c[k+'-supply']) for k in CAM_SUPPLIES}=={k:[h] for k,h in CAM_SUPPLIES.items()}
 # The default state, camdefault, is empty: it sets no pins.
 cam_names=text(c['pinctrl-names']);assert len(cam_names)==36 and cam_names[0]=='default' and cam_names[21]=='cam0_mclk_off'
 handles={values(v['phandle'])[0]:p for p,v in nodes.items() if 'phandle' in v}
 cam_pins=[]
 for i in range(len(cam_names)):
  q=handles[values(c['pinctrl-'+str(i)])[0]];assert q.startswith(pio+'/'),q
  cam_pins+=[r for r in [q]+[r for r in nodes if r.startswith(q+'/')] if r not in cam_pins]
 assert set(nodes[pio+'/camdefault'])=={'phandle','status'}
 for q in cam_pins:
  assert not enabled(nodes,q) and enabled(live,q),q
  assert {k:v for k,v in nodes[q].items() if k!='status'}=={k:v for k,v in live[q].items() if k!='status'},q
  nodes[q]['status']=okay
 c['status']=okay
 st=nodes[SENINF_TOP]
 assert text(st['compatible'])==['mediatek,seninf_top'] and not enabled(nodes,SENINF_TOP) and enabled(live,SENINF_TOP)
 assert {k:v for k,v in st.items() if k!='status'}=={k:v for k,v in live[SENINF_TOP].items() if k!='status'}
 assert values(st['reg'])==[0,0x1a040000,0,0x1000] and len(text(st['clock-names']))==15
 st['status']=okay
 cb=nodes[CAM_BUS]
 assert text(cb['compatible'])==['mediatek,i2c'] and values(cb['id'])==[2] and not enabled(nodes,CAM_BUS) and enabled(live,CAM_BUS)
 assert {k:v for k,v in cb.items() if k!='status'}=={k:v for k,v in live[CAM_BUS].items() if k!='status'}
 assert values(cb['reg'])==[0,0x11009000,0,0x1000,0,0x11000280,0,0x80] and values(cb['interrupts'])==[0,0x53,8]
 assert values(cb['clocks'])==[INFRA_H,13,INFRA_H,43,INFRA_H,74] and text(cb['clock-names'])==['main','dma','arb']
 assert values(cb['ch_offset_default'])==[0x100] and 'mediatek,ch-offset' not in cb and 'i2c2' not in nodes['/aliases']
 cb['compatible']=strings('mediatek,mt6771-i2c');cb['mediatek,ch-offset']=cells(0x100);cb['status']=okay
 for q in CAM_I2C:
  assert not enabled(nodes,q) and enabled(live,q),q
  assert {k:v for k,v in nodes[q].items() if k!='status'}=={k:v for k,v in live[q].items() if k!='status'},q
  nodes[q]['status']=okay
 cam_off=[q for q in nodes if q.startswith((CAM_BUS+'/',BUS+'/')) and q not in CAM_I2C and q!=KEY]
 assert sorted(q.rsplit('/',1)[1] for q in cam_off if 'ccu' in q)==['ccu_sensor_i2c_2_hw@33','ccu_sensor_i2c_4_hw@36']
 assert not any(enabled(nodes,q) for q in cam_off)
 camera_nodes=[CAM_HW,SENINF_TOP,CAM_BUS]+cam_pins+CAM_I2C

 # Camera CCU (C5), as stock: /ccu@1a0a0000 (ccu_drv, /dev/ccu) and the ccu_sensor children, whose i2c clients give
 # the CCU each bus's adapter and its CCU channel. ccu_sensor_i2c_7_hw stays off with its bus, which no sensor uses.
 ccu_i2c=sorted((q for q in cam_off if 'ccu' in q),key=lambda q:q.rsplit('/',1)[1]);cam_off=[q for q in cam_off if q not in ccu_i2c]
 ccu_all=[q for q,v in nodes.items() if 'compatible' in v and any(c.startswith('mediatek,ccu') or c=='mediatek,n3d_ctl_a' for c in text(v['compatible']))]
 assert sorted(q.rsplit('/',1)[1] for q in ccu_all)==['ccu@1a0a0000','ccu_sensor_i2c_2_hw@33','ccu_sensor_i2c_4_hw@36','ccu_sensor_i2c_7_hw@43'],ccu_all
 for p in [CCU]+ccu_i2c:
  assert not enabled(nodes,p) and enabled(live,p),p
  assert {k:v for k,v in nodes[p].items() if k!='status'}=={k:v for k,v in live[p].items() if k!='status'},p
 assert text(nodes[CCU]['compatible'])==['mediatek,ccu'] and values(nodes[CCU]['interrupts'])==[0,0x108,8]
 assert values(nodes[CCU]['reg'])==[0,0x1a0a1000,0,0x1000] and text(nodes[CCU]['clock-names'])==['CCU_CLK_CAM_CCU','CCU_CLK_MMSYS_CCU','CAM_PWR']
 assert [(q.rsplit('/',1)[1],text(nodes[q]['compatible'])) for q in ccu_i2c]==[('ccu_sensor_i2c_2_hw@33',['mediatek,ccu_sensor_i2c_2_hw']),('ccu_sensor_i2c_4_hw@36',['mediatek,ccu_sensor_i2c_4_hw'])]
 for p in [CCU]+ccu_i2c:nodes[p]['status']=okay
 camera_nodes+=[CCU]+ccu_i2c

 # Camera JPEG (C6), as stock: /venc_jpg (jpeg_driver, /proc/mtk_jpeg), the only node it binds. Its IRQ is SPI 249, its one clock
 # the venc_gcon JPGENC gate; larb 4 and the VEN power gate are taken through smi_bus_prepare_enable at encode time, as stock.
 jv=nodes[JPEG]
 assert text(jv['compatible'])==['mediatek,venc_jpg'] and not enabled(nodes,JPEG) and enabled(live,JPEG)
 assert {k:x for k,x in jv.items() if k!='status'}=={k:x for k,x in live[JPEG].items() if k!='status'}
 assert values(jv['reg'])==[0,0x17030000,0,0x1000] and values(jv['interrupts'])==[0,0xf9,8]
 assert text(jv['clock-names'])==['MT_CG_VENC_JPGENC'] and values(jv['clocks'])[1:]==[3]
 assert values(jv['clocks'])[0]==values(nodes['/venc_gcon@17000000']['phandle'])[0] and enabled(nodes,'/venc_gcon@17000000')
 assert sorted(q for q,v in nodes.items() if 'compatible' in v and any(c in ('mediatek,venc_jpg','mediatek,jpgdec') for c in text(v['compatible'])))==[JPEG]
 jv['status']=okay
 camera_nodes+=[JPEG]

 # Camera flashlight (C2), as stock: /flashlight_core (the /dev/flashlight driver) and /flashlights_mt6370 (couple
 # mode, channel 1 ct 0 part 0, channel 2 ct 1 part 0), with the stock live properties. The old lm3643 i2c node stays off.
 for p in (FL_CORE,FL_MT6370):
  assert not enabled(nodes,p) and enabled(live,p),p
  assert {k:v for k,v in nodes[p].items() if k!='status'}=={k:v for k,v in live[p].items() if k!='status'},p
 assert text(nodes[FL_CORE]['compatible'])==['mediatek,flashlight_core'] and text(nodes[FL_MT6370]['compatible'])==['mediatek,flashlights_mt6370']
 assert values(nodes[FL_MT6370]['decouple'])==[0]
 fl_ch=[(values(nodes[FL_MT6370+'/channel@'+n]['type'])[0],values(nodes[FL_MT6370+'/channel@'+n]['ct'])[0],values(nodes[FL_MT6370+'/channel@'+n]['part'])[0]) for n in '12']
 assert fl_ch==[(0,0,0),(0,1,0)]
 for p in (FL_CORE,FL_MT6370):nodes[p]['status']=okay
 camera_nodes+=[FL_CORE,FL_MT6370]

 # Camera ISP (C3), as stock: cam1..4 and camsv1..6 (camera_isp, after camsys), dip1 (camera_dip, after imgsys) and
 # wpe_a/wpe_b (camera_wpe), with the stock live properties and IRQs. camsys and imgsys are okay already (clock
 # providers) and hold the clocks the drivers take. dip2..6 and the C5 and later engines stay disabled.
 # C4 adds imgsyscq and rsc (camera_rsc) and fdvt (camera_fdvt), same checks.
 isp_engines=ISP_NODES+DIP_NODES+WPE_NODES+RSC_NODES+FDVT_NODES
 assert [list(nodes).index(p) for p in RSC_NODES]==sorted(list(nodes).index(p) for p in RSC_NODES)
 order=list(nodes);assert [order.index(p) for p in [CAMSYS]+ISP_NODES]==sorted(order.index(p) for p in [CAMSYS]+ISP_NODES)
 assert order.index(IMGSYS)<order.index(DIP_NODES[0]) and enabled(nodes,CAMSYS) and enabled(nodes,IMGSYS)
 for p in isp_engines:
  assert not enabled(nodes,p) and enabled(live,p),p
  assert {k:v for k,v in nodes[p].items() if k!='status'}=={k:v for k,v in live[p].items() if k!='status'},p
  assert text(nodes[p]['compatible'])==['mediatek,'+p[1:].split('@')[0]],p
  assert (values(nodes[p]['interrupts'])==[0,ISP_IRQS[p],8]) if p in ISP_IRQS else 'interrupts' not in nodes[p],p
 for p in isp_engines:nodes[p]['status']=okay
 camera_nodes+=isp_engines

 # Sunwave fingerprint. /fingerprint and its pin states keep the stock live properties and get stock's okay;
 # /fingerprint also gets spi0's clocks. spi0 stays disabled (secure only, no 5.10 driver).
 f=nodes[FP];sp=nodes[SPI0]
 assert text(f['compatible'])==['mediatek,fingerprint'] and not enabled(nodes,FP) and enabled(live,FP)
 assert {k:v for k,v in f.items() if k!='status'}=={k:v for k,v in live[FP].items() if k!='status'}
 assert values(f['interrupt-parent'])==[PIO] and values(f['interrupts'])==FP_IRQ and not {'clocks','clock-names'}&set(f)
 fp_names=text(f['pinctrl-names'])
 assert len(fp_names)==18 and fp_names[10:14]==['finger_rst_low','finger_rst_high','finger_power_low','finger_power_high']
 handles={values(v['phandle'])[0]:p for p,v in nodes.items() if 'phandle' in v}
 fp_pins=[]
 for i in range(len(fp_names)):
  q=handles[values(f['pinctrl-'+str(i)])[0]];assert q.startswith(pio+'/'),q
  fp_pins+=[q]+[r for r in nodes if r.startswith(q+'/')]
 for q in fp_pins:
  assert not enabled(nodes,q) and enabled(live,q),q
  assert {k:v for k,v in nodes[q].items() if k!='status'}=={k:v for k,v in live[q].items() if k!='status'},q
  nodes[q]['status']=okay
 assert text(sp['compatible'])==['mediatek,mt6765-spi'] and not enabled(nodes,SPI0) and enabled(live,SPI0)
 assert values(sp['clocks'])==SPI0_CLOCKS and text(sp['clock-names'])==['parent-clk','sel-clk','spi-clk']
 assert enabled(nodes,TOPCK) and enabled(nodes,INFRA)
 f['clocks']=cells(*SPI0_CLOCKS);f['clock-names']=strings('parent-clk','sel-clk','spi-clk');f['status']=okay

 # Modem thermal (M5): the sensor, a node per cooler (mtk_cooler_mutt registers on /modem-coolers/<name>) and the zone.
 assert not {MDPA_SENSOR,MODEM_COOLERS,MDPA_ZONE}&set(nodes) and enabled(nodes,AUXADC)
 aux_h=values(nodes[AUXADC]['phandle'])[0]
 assert not [q for q,v in nodes.items() if 'io-channels' in v and values(v['io-channels'])==[aux_h,MDPA_CHANNEL]],'channel 1 already has a consumer'
 handles={values(v['phandle'])[0] for v in nodes.values() if 'phandle' in v}
 mdpa_h=max(handles)+1;cooler_h={cn:mdpa_h+1+i for i,(_,_,cn) in enumerate(MDPA_TRIP_LIST)};trip_h={tn:mdpa_h+4+i for i,(tn,_,_) in enumerate(MDPA_TRIP_LIST)}
 nodes[MDPA_SENSOR]={'compatible':strings('mediatek,mtboard-thermistor2'),'io-channels':cells(values(nodes[AUXADC]['phandle'])[0],MDPA_CHANNEL),
                     'io-channel-names':strings('thermistor-ch1'),'#thermal-sensor-cells':cells(0),'phandle':cells(mdpa_h),'status':okay}
 nodes[MODEM_COOLERS]={}
 for cn,ch in cooler_h.items():nodes[MODEM_COOLERS+'/'+cn]={'#cooling-cells':cells(2),'phandle':cells(ch)}
 nodes[MDPA_ZONE]={'polling-delay-passive':cells(0),'polling-delay':cells(MDPA_POLL_MS),'thermal-sensors':cells(mdpa_h)}
 nodes[MDPA_TRIPS]={};nodes[MDPA_ZONE+'/cooling-maps']={}
 for i,(tn,mc,cn) in enumerate(MDPA_TRIP_LIST):
  nodes[MDPA_TRIPS+'/'+tn]={'temperature':cells(mc),'hysteresis':cells(0),'type':strings('active'),'phandle':cells(trip_h[tn])}
  nodes[MDPA_ZONE+'/cooling-maps/map'+str(i)]={'trip':cells(trip_h[tn]),'cooling-device':cells(cooler_h[cn],0xffffffff,0xffffffff)}
 assert [mc for _,mc,_ in MDPA_TRIP_LIST]==sorted(mc for _,mc,_ in MDPA_TRIP_LIST)
 modem_thermal_added=[MDPA_SENSOR,MODEM_COOLERS]+[MODEM_COOLERS+'/'+c for c in cooler_h]+[MDPA_ZONE,MDPA_TRIPS,MDPA_ZONE+'/cooling-maps']+\
  [MDPA_TRIPS+'/'+tn for tn,_,_ in MDPA_TRIP_LIST]+[MDPA_ZONE+'/cooling-maps/map'+str(i) for i in range(len(MDPA_TRIP_LIST))]

 # Modem (M1): the stock live properties, status okay. md_auxadc reads AUXADC channel 4 through the board's auxadc.
 for q in MODEM_NODES:
  assert not enabled(nodes,q) and enabled(live,q),q
  assert {k:v for k,v in nodes[q].items() if k!='status'}=={k:v for k,v in live[q].items() if k!='status'},q
  nodes[q]['status']=okay
 assert values(nodes[MD_AUXADC]['io-channels'])==[values(nodes[AUXADC]['phandle'])[0],4]
 assert text(nodes[MDCLDMA]['compatible'])==['mediatek,mdcldma'] and values(nodes[MDCLDMA]['mediatek,md_id'])==[0]

 # MCDI core-off (P8): mcdi-cpu on every cpu, off by default; APXGPT as the 13 MHz broadcast timer.
 idle=nodes[IDLE];mc=nodes[MCDI_CPU]
 assert text(idle['entry-method'])==['arm,psci'] and not enabled(nodes,IDLE)
 idle_children=sorted(c for c in nodes if c.startswith(IDLE+'/'))
 assert [c.rsplit('/',1)[1] for c in idle_children]==sorted(['standby','mcdi-cpu','mcdi-cluster','sodi','sodi3','dpidle','suspend'])
 assert not any(enabled(nodes,c) for c in idle_children)
 assert text(mc['compatible'])==['arm,idle-state'] and values(mc['arm,psci-suspend-param'])==[MCDI_PARAM]
 assert [values(mc[k])[0] for k in ('entry-latency-us','exit-latency-us','min-residency-us')]==list(MCDI_LAT)
 assert 'local-timer-stop' not in mc and 'mediatek,default-off' not in mc
 assert not any('cpu-idle-states' in nodes[cpu] for cpu in cpu_nodes)
 mcdi_h=values(mc['phandle'])[0]
 idle['status']=okay;mc['status']=okay;mc['local-timer-stop']={'hex':''};mc['mediatek,default-off']={'hex':''}
 for cpu in cpu_nodes:nodes[cpu]['cpu-idle-states']=cells(mcdi_h)
 g=nodes[APXGPT]
 assert text(g['compatible'])==['mediatek,apxgpt'] and not enabled(nodes,APXGPT)
 assert values(g['reg'])==[0,0x10008000,0,0x100] and values(g['interrupts'])==[0,0xb0,8] and values(g['clocks'])==[CLK32K_H]
 assert values(nodes['/']['interrupt-parent'])==[values(nodes['/intpol-controller@0c530620']['phandle'])[0]]
 timers=[p for p,v in nodes.items() if 'compatible' in v and set(text(v['compatible']))&{'mediatek,mt6577-timer','mediatek,mt6765-timer','mediatek,mt6771-timer','mediatek,sys_timer'}]
 assert timers==['/sys_timer@10017000'] and not enabled(nodes,timers[0])
 assert CLK13M not in nodes and all(values(v['clock-frequency'])!=[13000000] for p,v in nodes.items() if p.startswith('/clocks/'))
 handles={values(v['phandle'])[0] for v in nodes.values() if 'phandle' in v};clk13m_h=max(handles)+1
 nodes[CLK13M]={'compatible':strings('fixed-clock'),'#clock-cells':cells(0),'clock-frequency':cells(13000000),'phandle':cells(clk13m_h),'status':okay}
 g['compatible']=strings('mediatek,mt6771-timer');g['clocks']=cells(clk13m_h);g['status']=okay
 mcdi_added=[CLK13M];mcdi_changed=[IDLE,MCDI_CPU,APXGPT]

 # IR blaster: /irtx_pwm, its pin states and /pwm@11006000 as stock's live tree, and irtx-supply on mt6370_ldo.
 ldo=PMU+'/ldo/mt6370_ldo'
 assert ldo in pmu_nodes and text(nodes[ldo]['regulator-name'])==['mt6370_ldo'] and enabled(nodes,ldo) and 'phandle' not in nodes[ldo]
 assert not any('irtx-supply' in v for v in nodes.values())
 for p in [IRTX,PWM_NODE]+list(IRTX_STATES)+[s+'/pins_cmd_dat' for s in IRTX_STATES]:
  assert not enabled(nodes,p) and enabled(live,p),p
  assert {k:v for k,v in nodes[p].items() if k!='status'}=={k:v for k,v in live[p].items() if k!='status'},p
 ir=nodes[IRTX]
 assert text(ir['compatible'])==['mediatek,irtx-pwm'] and values(ir['pwm_ch'])==[0] and values(ir['pwm_data_invert'])==[0]
 assert text(ir['pinctrl-names'])==['irtx_gpio_led_default','irtx_gpio_led_set']
 assert [values(ir['pinctrl-'+str(i)]) for i in range(2)]==[[h] for h,_ in IRTX_STATES.values()]
 for s,(h,mux) in IRTX_STATES.items():
  assert values(nodes[s]['phandle'])==[h] and values(nodes[s+'/pins_cmd_dat']['pinmux'])==[mux]
  assert [c for c in nodes if c.startswith(s+'/')]==[s+'/pins_cmd_dat']
 assert text(nodes[PWM_NODE]['compatible'])==['mediatek,pwm'] and not enabled(nodes,IRTX_BLOCK)
 assert sorted(p for p,v in nodes.items() if 'compatible' in v and set(text(v['compatible']))&{'mediatek,pwm','mediatek,irtx-pwm'})==sorted([PWM_NODE,IRTX])
 handles={values(v['phandle'])[0]:p for p,v in nodes.items() if 'phandle' in v};ldo_h=max(handles)+1
 pwm_clocks=values(nodes[PWM_NODE]['clocks'])
 assert pwm_clocks==[0x15,0x10,0x15,0x11,0x15,0x12,0x15,0x13,0x15,0x0f,0x15,0x14] and enabled(nodes,handles[0x15])
 nodes[ldo]['phandle']=cells(ldo_h)
 ir['irtx-supply']=cells(ldo_h)
 for p in [IRTX,PWM_NODE]+list(IRTX_STATES)+[s+'/pins_cmd_dat' for s in IRTX_STATES]:nodes[p]['status']=okay
 irtx_changed=[IRTX,PWM_NODE]+list(IRTX_STATES)+[s+'/pins_cmd_dat' for s in IRTX_STATES]+([] if ldo in mt6370_changed else [ldo])

 added=sorted(p for p in nodes if p not in before)
 assert added==sorted([TS_AS_INT,TS_AS_INT+'/pins_cmd_dat']+thermal_added+cpufreq_added+modem_thermal_added+mcdi_added),added
 changed=sorted(p for p in nodes if p not in before or nodes[p]!=before[p])
 assert changed==sorted([KEY,ODM,LED,VIB,PAD,COULOMB,BATTERY]+list(STATES)+[p+'/pins_cmd_dat' for p in STATES]
                        +[TS]+list(TS_STATES)+[p+'/pins_cmd_dat' for p,s in TS_STATES.items() if s[1] is not None]+added
                        +mt6370_changed+[p for p in overlay_changed if p not in mt6370_changed]+[KP,MT_PMIC]
                        +[THERM,TOPRGU]+[MCUCFG]+cpu_nodes+list(regs.values())+[SCP,SCP_DVFS]+audio_nodes+headset_nodes
                        +[CONSYS,CONSYS_MEM]+consys_pins+nfc+[BTIF,WIFI,BUS_DBG]+list(VCODEC_NODES)+camera_nodes+power_changed+[FP]+fp_pins+MODEM_NODES+mcdi_changed+irtx_changed),changed
 # validate_providers (storage tree) requires scpsys disabled, which the overlays turn on, so it runs on the
 # board without the overlay changes; check-pocket-disp-dt.py and check-pocket-gpu-dt.py check the overlay nodes' providers.
 # The AFE, consys, mdcldma, seninf_top, the ISP engines, the CCU and venc_jpg take clocks from scpsys (and imgsys, an overlay node), so they
 # are checked here against the full board instead.
 edges=providers({p:(dict(v,status=before[p]['status']) if p in overlay_changed or p in (AFE,CONSYS,MDCLDMA,SENINF_TOP,CCU,JPEG) or p in isp_engines else v) for p,v in nodes.items()},values,enabled)
 handles={values(v['phandle'])[0]:p for p,v in nodes.items() if 'phandle' in v}
 cl=values(nodes[AFE]['clocks']);i=0
 while i<len(cl):
  q=handles[cl[i]];assert enabled(nodes,q),(AFE,q);i+=1+values(nodes[q]['#clock-cells'])[0]
 assert enabled(nodes,handles[values(nodes[AFE]['pinctrl-0'])[0]].rpartition('/')[0]),'AFE pin controller'
 cl=values(nodes[SENINF_TOP]['clocks']);i=0;seninf_clk=[]
 while i<len(cl):
  q=handles[cl[i]];assert enabled(nodes,q),(SENINF_TOP,q);seninf_clk.append(q);i+=1+values(nodes[q]['#clock-cells'])[0]
 assert len(seninf_clk)==15 and sorted(set(seninf_clk))==['/camsys@1a000000','/clocks/clk26m','/scpsys@10001000','/topckgen@10000000']
 cl=values(nodes[MDCLDMA]['clocks']);i=0
 while i<len(cl):
  q=handles[cl[i]];assert enabled(nodes,q),(MDCLDMA,q);i+=1+values(nodes[q]['#clock-cells'])[0]
 isp_clk=set()
 for q0 in isp_engines:
  cl=values(nodes[q0]['clocks']) if 'clocks' in nodes[q0] else [];i=0
  while i<len(cl):
   q=handles[cl[i]];assert enabled(nodes,q),(q0,q);isp_clk.add(q);i+=1+values(nodes[q]['#clock-cells'])[0]
 print('isp engine clock providers',sorted(isp_clk))
 cl=values(nodes[CCU]['clocks']);i=0;ccu_clk=[]
 while i<len(cl):
  q=handles[cl[i]];assert enabled(nodes,q),(CCU,q);ccu_clk.append((q,cl[i+1]));i+=1+values(nodes[q]['#clock-cells'])[0]
 assert ccu_clk==[('/camsys@1a000000',9),('/mmsys_config@14000000',6),('/scpsys@10001000',9)],ccu_clk
 assert enabled(nodes,handles[values(nodes[JPEG]['clocks'])[0]]) and handles[values(nodes[JPEG]['clocks'])[0]]=='/venc_gcon@17000000'
 assert enabled(nodes,handles[values(nodes[CONSYS]['clocks'])[0]]) and enabled(nodes,handles[values(nodes[CONSYS]['memory-region'])[0]])
 assert all(enabled(nodes,handles[values(nodes[CONSYS][k])[0]]) for k in CONSYS_SUPPLIES)
 assert all(enabled(nodes,handles[values(nodes[CONSYS]['pinctrl-'+str(i)])[0]]) for i in range(4))

 OUTPUT.mkdir(parents=True,exist_ok=True);offset=struct.unpack_from('>I',blob,16)[0];reservations=[]
 while True:
  address,size=struct.unpack_from('>QQ',blob,offset);offset+=16
  if not address and not size:break
  reservations.append((address,size))
 dtc=ROOT/'tools/kernel-build-config/upgrade-5.10/scripts/dtc/dtc'
 def write(tree_nodes,stem):
  dts=OUTPUT/(stem+'.dts');out=OUTPUT/(stem+'.dtb');dts.write_text(tree['render'](tree_nodes,reservations))
  result=subprocess.run([str(dtc),'-I','dts','-O','dtb','-o',str(out),str(dts)],capture_output=True,text=True)
  (OUTPUT/(stem+'.dtc.stderr.txt')).write_text(result.stderr);result.check_returncode()
  back=decode(out.read_bytes())['nodes'];assert set(back)==set(tree_nodes)
  for p in tree_nodes:assert {a:v['hex'] for a,v in back[p].items()}=={a:v['hex'] for a,v in tree_nodes[p].items()},p
  return out,back
 # Two boards: keyboard-modem-on.dtb has the modem nodes okay (trial M only); keyboard.dtb, the default, has them
 # disabled as before M1, so ccci_mdinit can't start MD1 (eccci never probes without mdcldma).
 dtb_on,after=write(nodes,'keyboard-modem-on')
 for p in [KEY,LED,VIB,PAD,COULOMB,BATTERY]+list(STATES):assert enabled(after,p),p
 assert not enabled(after,TOUCH_PAD) and not any(enabled(after,c) for c in pad_others)
 for p in [TS,TS_AS_INT]+list(TS_STATES):assert enabled(after,p),p
 assert not enabled(after,TOUCH) and not any(enabled(after,c) for c in ts_others)
 for p in mt6370_nodes+overlay_targets+[KP,MT_PMIC,THERM,ZONE,BACKSTOP,MCUCFG]+cpu_nodes+cpufreq_added:assert enabled(after,p),p
 assert enabled(after,SSPM) and enabled(after,SSPM_SHARE) and after[SSPM_SHARE]==before[SSPM_SHARE]
 assert enabled(after,SLEEP) and enabled(after,SLEEP_REG_MD) and enabled(after,DVFSRC) and enabled(after,CIRQ)
 assert enabled(after,MCDI_CPU) and enabled(after,APXGPT) and enabled(after,CLK13M) and 'local-timer-stop' in after[MCDI_CPU] and 'mediatek,default-off' in after[MCDI_CPU]
 assert all(values(after[c]['cpu-idle-states'])==[mcdi_h] for c in cpu_nodes) and not any(enabled(after,c) for c in idle_children if c!=MCDI_CPU)
 assert enabled(after,RTC) and enabled(after,AUXADC) and not enabled(after,AUXADC+'/adc_channel@') and after[EFUSE]==before[EFUSE]
 assert text(after[AUXADC]['compatible'])==AUXADC_COMPAT and values(after[CHARGER]['io-channels'])==[values(after[AUXADC]['phandle'])[0],BTS_CHANNEL]
 assert enabled(after,MDPA_SENSOR) and enabled(after,MDPA_ZONE) and values(after[MDPA_SENSOR]['io-channels'])==[values(after[AUXADC]['phandle'])[0],MDPA_CHANNEL]
 assert [values(after[MDPA_ZONE+'/cooling-maps/map'+str(i)]['cooling-device'])[0] for i in range(len(MDPA_TRIP_LIST))]==[values(after[MODEM_COOLERS+'/'+cn]['phandle'])[0] for _,_,cn in MDPA_TRIP_LIST]
 assert not any(enabled(after,c) for c in i2c5_others)
 assert enabled(after,SCP) and enabled(after,SCP_DVFS) and enabled(after,SCP_SHARE) and not any(enabled(after,p) for p in scp_others)
 assert all(enabled(after,p) for p in audio_nodes+headset_nodes) and not any(enabled(after,p) for p in adc_others+[BTCVSD])
 a=after[CONSYS];assert all(enabled(after,p) for p in [CONSYS,CONSYS_MEM,WIFI,BUS_DBG]+consys_pins+nfc)
 assert all(enabled(after,p) for p in [FP]+fp_pins) and not enabled(after,SPI0) and values(after[FP]['clocks'])==SPI0_CLOCKS
 assert all(enabled(after,p) for p in MODEM_NODES) and not any(enabled(after,p) for p in MD_SIM_NODES)
 assert all(enabled(after,p) for p in camera_nodes) and not any(enabled(after,p) for p in cam_off)
 assert all(enabled(after,p) for p in irtx_changed) and not enabled(after,IRTX_BLOCK)
 assert values(after[IRTX]['irtx-supply'])==values(after[ldo]['phandle'])==[ldo_h]
 assert {k:values(a[k]) for k in CONSYS_SUPPLIES}=={k:[h] for k,h in CONSYS_SUPPLIES.items()} and values(a['memory-region'])==values(after[CONSYS_MEM]['phandle'])
 assert [values(a['pinctrl-'+str(i)])[0] for i in range(4)]==[values(after[p]['phandle'])[0] for p in CONSYS_PINS]
 off_nodes={p:(dict(v,status=before[p]['status']) if p in MODEM_NODES else v) for p,v in nodes.items()}
 dtb,after_off=write(off_nodes,'keyboard')
 assert not any(enabled(after_off,p) for p in MODEM_NODES+MD_SIM_NODES)
 assert all(after_off[p]==after[p] for p in nodes if p not in MODEM_NODES)
 sources=[Path(__file__),ROOT/'tools/prepare-pocket-diagnostic-tree.py',ROOT/'tools/prepare-pocket-storage-tree.py',ROOT/'tools/inspect-fdt.py']
 record={'source_board':source,'generator_inputs':{str(p.relative_to(ROOT)):sha(p) for p in sources},
  'board_dtb':{'path':str(dtb),'sha256':sha(dtb),'bytes':dtb.stat().st_size},
  'board_dtb_modem_on':{'path':str(dtb_on),'sha256':sha(dtb_on),'bytes':dtb_on.stat().st_size,'differs_by':'status okay on '+', '.join(MODEM_NODES),'use':'trial M only; package-pocket-boot.py --board modem-on'},'nodes':len(nodes),'changed_nodes':changed,
  'enabled':{'keyboard':KEY,'pinctrl_states':list(STATES),'backlight':LED,'backlight_gpio':LED_GPIO,
             'vibrator':VIB,'vibrator_supply_phandle':VIBR_LDO,'vibrator_oc_hwirq':VIBR_OC,
             'touchpad':PAD,'touchpad_eint':PAD_IRQ[0],'touchpad_irq_type':'level-low','touchpad_reset_gpio':PAD_RESET,
             'touchscreen':TS,'touchscreen_eint':TS_IRQ[0],'touchscreen_irq_type':'edge-falling','touchscreen_power_gpio':TS_POWER,
             'touchscreen_pinctrl':dict(zip(TS_STATE_NAMES,ts_handles)),'touchscreen_eint_as_int':TS_AS_INT,
             'gauge':COULOMB,'battery_supply_parent':BATTERY,
             'i2c5':I2C5,'mt6370':SUBPMIC,'mt6370_nodes':pmu_nodes,'mt6370_irq_gpio':PMU_IRQ_GPIO,'mt_charger':MT_CHARGER,'charger':CHARGER,
             'keypad':KP,'pmic_key_irqs':MT_PMIC,
             'thermal':THERM,'thermal_zone':ZONE,'thermal_trips':{n:{'mC':v,'type':k} for n,v,k in THERM_TRIPS},
             'thermal_governor':'power_allocator (set by mtk_thermal on a zone with sustainable-power)','sustainable_power_mW':SUSTAINABLE_MW,
             'polling_ms':{'idle':POLL_MS,'passive':POLL_PASSIVE_MS},
             'backstop_zone':BACKSTOP,'backstop_trips':{n:{'mC':v,'type':k} for n,v,k in BACKSTOP_TRIPS},'backstop_governor':'step_wise (default)',
             'toprgu_phandle':rgu_h,
             'cpufreq':{'mcucfg':MCUCFG,'mcucfg_phandle':mcu_h,'intermediate':CLK26M,'opp_tables':{t:[{'MHz':f,'uV':v} for f,v in o] for t,o in CPU_OPPS.items()},
                        'proc_supply':{'cpu0-3':regs[VPROC12],'cpu4-7':regs[VPROC11]},'regulator_ramp_delay_uV_per_us':VPROC_RAMP,'regulator_max_uV':VPROC_MAX,'turbo_above_MHz':OPP_TOP_NON_TURBO,'opp_supported_hw':{'all':OPP_HW_ALL,'v5_t_only':OPP_HW_V5_T},
                        'cci':{'node':CCI,'phandle':cci_h,'table':CCI_TABLE,'opps':[{'MHz':f,'uV':v} for f,v in CCI_OPPS],'clocks':'cci=mcu_bus_sel div=mcu_bus_div pll=ccipll intermediate=clk26m','proc_supply':regs[VPROC12]},
                        'cooling_trips':COOLING_TRIPS,'gpu_cooling':{'node':GPUFREQ,'phandle':gpu_h,'trips':[TRIPS+'/'+IPA_CONTROL]}},
             'scp':{'scp':SCP,'scp_status':'okay as stock, LK loads the SCP only then','scp_dvfs':SCP_DVFS,'scp_dvfs_clocks':{n:i or 'clk26m' for n,i in SCP_CLOCKS},'scp_share':SCP_SHARE},
             'audio':{'audsys':AUDSYS,'afe':AFE,'afe_clocks':{n:i or 'clk26m' for n,_,i in AFE_CLOCKS},'afe_pinctrl':dict(AFE_PINS),
                      'sram':AUD_SRAM,'stubs':stubs,'speaker_amp':AMP,'headset':headset_nodes,'left_disabled':[BTCVSD]+adc_others},
             'connectivity':{'consys':CONSYS,'supplies':CONSYS_SUPPLIES,'memory_region':CONSYS_MEM,'memory_region_phandle':mem_h,
                             'pinctrl':dict(zip(text(c['pinctrl-names']),CONSYS_PINS)),'nfc':nfc,'wifi':WIFI,'wifi_clock':{'wifi-dma':CQDMA_CG}},
             'modem_thermal':{'sensor':MDPA_SENSOR,'auxadc_channel':MDPA_CHANNEL,'zone':MDPA_ZONE,'polling_ms':MDPA_POLL_MS,'governor':'step_wise (default)',
                              'trips':{tn:{'mC':mc,'type':'active','hysteresis':0,'cooler':cn,'cooler_node':MODEM_COOLERS+'/'+cn} for tn,mc,cn in MDPA_TRIP_LIST}},
             'fingerprint':{'node':FP,'interrupts':FP_IRQ,'pinctrl':dict(zip(fp_names,[handles[values(f['pinctrl-'+str(i)])[0]] for i in range(len(fp_names))])),
                            'clocks_from':SPI0,'clocks':dict(zip(['parent-clk','sel-clk','spi-clk'],['topckgen 55 syspll_d5_d2','topckgen 7 spi_sel','infracfg_ao 28 infra_spi0'])),
                            'spi0':'disabled'},
             'systracker':{'node':BUS_DBG,'status':'okay as stock, no property changes'},
             'videocodec':{'nodes':list(VCODEC_NODES),'status':'okay as stock, no property changes','driver_node':VDEC_GCON},
             'camera':{'imgsensor':CAM_HW,'seninf':SENINF_TOP,'pin_nodes':len(cam_pins),'i2c2':CAM_BUS,'i2c_children':CAM_I2C,'left_disabled':cam_off,
                       'status':'okay as stock, no property changes except i2c-2 compatible mediatek,mt6771-i2c and mediatek,ch-offset 0x100'},
             'camera_ccu':{'ccu':CCU,'irq':'SPI 264 level low','i2c_children':ccu_i2c,'status':'okay as stock, no property changes'},
             'camera_jpeg':{'node':JPEG,'irq':'SPI 249 level low','clock':'venc_gcon 3 (JPGENC)','status':'okay as stock, no property changes'},
             'camera_isp':{'isp':[CAMSYS]+ISP_NODES,'dip':[IMGSYS]+DIP_NODES,'wpe':WPE_NODES,'rsc':RSC_NODES,'fdvt':FDVT_NODES,'irqs':{p:'SPI %d level low'%v for p,v in ISP_IRQS.items()},'status':'okay as stock, no property changes'},
             'irtx':{'node':IRTX,'pwm':PWM_NODE,'pinctrl':dict(zip(['irtx_gpio_led_default','irtx_gpio_led_set'],IRTX_STATES)),
                     'supply':ldo,'supply_phandle':ldo_h,'left_disabled':IRTX_BLOCK,
                     'status':'okay as stock, no property changes except irtx-supply on /irtx_pwm and a phandle on mt6370_ldo'},
             'flashlight':{'core':FL_CORE,'mt6370':FL_MT6370,'channels':'1: type 0 ct 0 part 0, 2: type 0 ct 1 part 0, decouple 0','status':'okay as stock, no property changes'},
             'modem':{'nodes':MODEM_NODES,'md_auxadc_channel':4,'status':'okay in board_dtb_modem_on, disabled in board_dtb (default)','left_disabled':MD_SIM_NODES},
             'power':{'rtc':RTC,'rtc_irq':RTC_IRQ,'auxadc':AUXADC,'auxadc_compatible':AUXADC_COMPAT,'bts_consumer':CHARGER,'bts_channel':BTS_CHANNEL,
                       'sspm':SSPM,'sspm_share':SSPM_SHARE,'sspm_status':'okay as stock, no property changes; sspm_share unchanged',
                       'spm':SLEEP,'sleep_reg_md':SLEEP_REG_MD,'spm_irq':'SPI 0xbb level low','spm_status':'okay as stock, no property changes',
                       'sys_cirq':CIRQ,'sys_cirq_status':'okay as stock, no property changes',
                       'dvfsrc':DVFSRC,'dvfsrc_status':'okay as stock, no property changes; the dummy-read regions come from LK',
                       'mcdi_cpu':MCDI_CPU,'mcdi_param':hex(MCDI_PARAM),'mcdi_status':'okay with local-timer-stop and mediatek,default-off; cpu-idle-states on every cpu; the other idle states disabled and unreferenced',
                       'broadcast_timer':APXGPT,'broadcast_clock':CLK13M+' (13 MHz fixed-clock, new)'},
             'overlays':{str(o.relative_to(ROOT)):sha(o) for o in OVERLAYS},'overlay_nodes':overlay_targets,'gpufreq_supplies':supplies},
  'i2c4_other_children_disabled':others,'i2c6_other_children_disabled':pad_others,'odm_other_children_disabled':odm_others,'i2c0_other_children_disabled':ts_others,'i2c5_other_children_disabled':i2c5_others,'provider_edges':len(edges),
  'image_packaged':False,'phone_accessed':False,
  'limits':['package-pocket-boot.py packs this board into the first-boot image','Static check only; IRQ trigger, reset and backlight waveform not run on the phone',
           'The touchpad IRQ and reset come from the stock /touch_pad node and driver, put on cap_tkpd@21 for 5.10',
           'The touchscreen IRQ, pin states and power GPIO come from the stock /touch node, put on cap_touch@5d for 5.10; the eint@0 as_int state is rebuilt as tpd_eint_as_int',
           'coulomb@2f and /battery are enabled as stock, with no property changes',
           '/odm/vibrator@0 is enabled with the stock properties plus vib-supply (ldo_vibr) and interrupts-extended (MT6358 VIBR_OC), which stock took from its PMIC code',
           'i2c5, the MT6370 nodes, /mt_charger and /charger are enabled with the stock live DT properties; only i2c5 compatible changes, to mediatek,mt6771-i2c',
           'The MT6370 IRQ is GPIO 10 through mt6370,intr_gpio, falling edge, as stock; GPIO 10 is an EINT on 5.10 pinctrl (static), not run on the phone',
           'usb_type_c@4e stays disabled: tcpc is not ported',
           'kp@10010000 and the MT6358 mt-pmic node are enabled with the stock live DT properties; mtk-kpd uses both',
           'therm_ctrl@1100b000 keeps the stock reg, IRQ and THERM clock; its fuse words come from atag,devinfo 100 to 102 and efusec@11f10000 is left as stock',
           'cpu_thermal (sensor 0) has passive 50 and 65 C trips, sustainable-power 2000 mW and the 117 C critical last, for power_allocator, which mtk_thermal selects; cpu_backstop (sensor id 1, the same reading) has a 95 C step_wise trip; both map to both clusters with no limits. The IPA tuning is a starting point (POWER_PORT.md device test 5)',
           'cpufreq OPPs are the worst-bin tables from POWER_PORT.md P6, above 1417 MHz turbo-mode (behind cpufreq/boost), opp-supported-hw by stock CPU level (V6 refused by the driver, 2106 MHz on V5_T only); no sram-supply, no EEM, no SSPM DVFS; a cci node (mediatek,mt6771-cci) with the 16 worst-bin CCI rows, off until the cci parameter is 1; the A53 rows at the 825 mV floor carry their worst-bin voltage as opp-microvolt min (P10d, used only with a53_floor 0 and the CCI managed)',
           '/scp_dvfs is enabled with the stock clocks (topckgen scp_sel, clk26m and the topckgen parents, same IDs on 5.10); scp@10500000 okay as in the stock boot dtb, since LK loads the SCP only when it is okay; the scp_* register nodes stay disabled',
           'Audio nodes are enabled as stock with no property changes: audsys, the AFE (mt_soc_dl1_pcm), audio_sram, the mt_soc_* stubs, speaker_amp@34 and the AFE pin states; only the audsys clock provider has 5.10 code so far; btcvsd stays disabled',
           '/accdet, the MT6358 mt635x-auxadc node and its accdet (channel 9) and hpofs_cal (channel 12) children are enabled as stock with no property changes; no 5.10 driver binds mt635x-auxadc, pmic_legacy.c reads the two children; the other AUXADC channels stay disabled',
           'consys@18070000, its four pin states and the NFC nodes (/nfc, /irq_nfc, nfc@08 on i2c3) are enabled with the stock live properties; consys also gets vcn18, vcn28, vcn33_bt and vcn33_wifi supplies and memory-region (consys-reserve-memory, given a phandle), which stock had no need for; wifi@180f0000 is enabled with the stock live properties',
           '/bus_dbg@10208000 (mediatek,bus_dbg-v2, the systracker) is enabled with the stock live properties',
           '/kd_camera_hw1, its 36 camera pin states, /seninf_top, i2c-2 and the camera children of i2c-2 and i2c-4 are enabled with the stock live properties; i2c-2 gets mediatek,mt6771-i2c and mediatek,ch-offset 0x100 like i2c-4. Nothing is powered at probe; whether the sensors answer on 5.10 is for the camera trial (CAMERA_PORT.md C1)',
           'cam1..4, camsv1..6, dip1, wpe_a and wpe_b are enabled with the stock live properties and IRQs for camera_isp, camera_dip and camera_wpe (CAMERA_PORT.md C3); camsys and imgsys were okay already; dip2..6, owe, mfb, dpe and tsf stay disabled; /imgsyscq and /rsc (camera_rsc, /dev/camera-rsc) and /fdvt (camera_fdvt, /dev/camera-fdvt) are enabled the same way (CAMERA_PORT.md C4)',
           '/ccu@1a0a0000 (IRQ 264) and ccu_sensor_i2c_2_hw@33 on i2c-2 and ccu_sensor_i2c_4_hw@36 on i2c-4 are enabled with the stock live properties for ccu_drv (CAMERA_PORT.md C5); ccu_sensor_i2c_7_hw@43 stays off with i2c-7',
           '/venc_jpg@17030000 is enabled with the stock live properties for jpeg_driver (CAMERA_PORT.md C6); mediatek,jpgdec (the hybrid decoder) does not exist on this board',
           '/flashlight_core and /flashlights_mt6370 are enabled with the stock live properties (couple mode, channels ct 0 and ct 1); /flashlights_lm3643_i2c@63 stays disabled (CAMERA_PORT.md C2)',
           '/vdec@16020000 and /venc@17020000 are enabled with the stock live properties; the videocodec driver binds vdec_gcon@16000000 (already okay) and reads their reg and IRQ',
           '/btif@1100c000 is enabled with the stock live properties: three IRQs, the AP DMA TX and RX channel registers and the infracfg_ao btif and apdma clocks',
           '/fingerprint and its 18 pin states are enabled with the stock live properties, plus spi0@1100a000\'s clocks; spi0 stays disabled, unlike stock, since 5.10 has no SPI0 driver and its registers are secure only. The SPI0 source clock stock used is inferred from the 4.14 spi driver setting parent-clk, not read on the phone',
           'mt6358_rtc is enabled as stock; rtc-mt6397 takes its registers and IRQ from the MT6358 mfd cell',
           'sspm@10440000 is enabled with the stock live properties for the SSPM IPI core (POWER_PORT.md P7); reserve-memory-sspm_share is unchanged (no-map, 0x510000, placed by the kernel); whether SSPM answers PLT_INIT is for device test 8',
           'sleep@10006000 and sleep_reg_md@1000f000 are enabled with the stock live properties for the SPM base driver (POWER_PORT.md P11a); whether ATF reports the PCM firmware ready on our boot is for P11 device test 1',
           'dvfsrc_top@10012000 is enabled with the stock live properties for vcorefs init (POWER_PORT.md P11b); the DRAMC dummy-read reserved-memory nodes are left to LK, which added them on our 5.10 boots (trial A, 2026-11-02), and orig_dram_info to LK\'s memory fixup',
           'MCDI (POWER_PORT.md P8): every cpu has cpu-idle-states = <&mcdi-cpu> (PSCI 0x10001) with local-timer-stop and mediatek,default-off, so cpuidle-psci registers it disabled on every CPU; apxgpt@10008000 is the tick broadcast timer as mediatek,mt6771-timer on a new 13 MHz /clocks/clk13m (stock: 32 kHz). Whether SSPM powers a core off and on is for device test 9',
           '/thermal-sensor2 reads AUXADC channel 1 as stock\'s mtktsbtsmdpa; /thermal-zones/mtktsbtsmdpa has stock thermal.conf\'s tzbtspa trips (68, 100 and 110 C, active, no hysteresis) mapped to mtk-cl-adp-mutt, mtk-cl-noIMS and mtk-cl-mdoff under /modem-coolers. AUX_IN1 as the modem PA NTC is stock\'s default, not seen on a schematic',
           'mdcldma@10014000, ap_ccif0, md_ccif0 and md_auxadc are enabled with the stock live properties in keyboard-modem-on.dtb only (MODEM_PORT.md M1); keyboard.dtb, the default, keeps them disabled so MD1 never starts; whether MD1 boots on them is for trial M. The md1_sim hot plug nodes stay disabled (stock okay): port_rpc reads them by name whatever the status, and their two-cell interrupts do not fit the GIC',
           'auxadc@11001000 is enabled as mediatek,mt6771-auxadc with the mt6765 fallback and its clock named main; /charger gets io-channels channel 0 (bts). AUX_IN0 as the board NTC is stock\'s default, not seen on a schematic',
           'The overlay nodes get status okay, as pocket-mm-providers.dtso, pocket-display.dtso and pocket-gpu.dtso, and /gpufreq gets vgpu-supply and vsram_gpu-supply from pocket-gpu.dtso; check-pocket-disp-dt.py and check-pocket-gpu-dt.py check them']}
 RECORD.write_text(json.dumps(record,indent=2)+'\n')
 print(f'{len(nodes)} nodes; aw9523@58, its pin states, button-backlight, cap_tkpd@21, cap_touch@5d, coulomb@2f, /battery, '
       f'i2c5 with {len(mt6370_nodes)-1} MT6370 and charger nodes, kp@10010000, mt-pmic, the thermal controller and cpu_thermal, mcucfg and the cpufreq OPPs and cooling maps, scp_dvfs, {len(audio_nodes)} audio nodes, {len(headset_nodes)} headset nodes, consys with its supplies and pin states, the NFC nodes, btif, the camera sensor path ({len(camera_nodes)} nodes), /fingerprint and its pin states, mt6358_rtc, the auxadc, sspm, the SPM sleep nodes, the modem PA thermistor zone and its coolers, the IR blaster, {len(MODEM_NODES)} modem nodes and {len(overlay_targets)} overlay nodes enabled; dtb round-trips; no image or phone operation')
if __name__=='__main__':main()
