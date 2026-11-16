#!/usr/bin/env python3
"""Package a gated RAM-only 5.10 recovery diagnostic; never stage or flash it."""
import pocket_paths
import gzip,hashlib,json,os,runpy,struct,subprocess,sys,tempfile
from pathlib import Path
ROOT=Path(__file__).resolve().parent.parent
BULK=pocket_paths.build_root()
VARIANT=os.environ.get('POCKET_DIAGNOSTIC_VARIANT','v1')
if VARIANT not in ('v1','v2','v3','v4','v5','v6','v7','v8','v9','v10','v11','v12'):raise ValueError('Diagnostic variant must be v1, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11 or v12')
SUFFIX='' if VARIANT=='v1' else '-'+VARIANT
OUT=BULK/('artifacts/diagnostic-5.10'+SUFFIX+'/package')
EVIDENCE=ROOT/('evidence/kernel-upgrade/diagnostic-package'+SUFFIX)
STOCK_SHA='c18cce5f01d69796ab2991fca0e5a5246185c775a87bc1598655a3e4f9539967'
CMDLINE='bootopt=64S3,32N2,64N2 buildvariant=userdebug rdinit=/init loglevel=8 ignore_loglevel printk.time=1 clk_ignore_unused regulator_ignore_unused maxcpus=1 nokaslr panic=10'
if VARIANT!='v1':CMDLINE=CMDLINE.replace('panic=10','panic=0 watchdog.handle_boot_enabled=1 watchdog.open_timeout=90')
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def main():
 OUT.mkdir(parents=True,exist_ok=True);EVIDENCE.mkdir(parents=True,exist_ok=True)
 image=OUT/'recovery.img'
 if image.exists():raise RuntimeError('Refuse to overwrite an existing candidate; preserve it and select a new build root')
 build=json.loads((ROOT/('evidence/kernel-upgrade/diagnostic-kernel-build'+SUFFIX+'.json')).read_text());assert build['returncode']==0 and build['engineering_config_unchanged']
 source=Path(build['source']);kernel_out=Path(build['output']);config=kernel_out/'.config'
 for name,digest in build['source_hashes'].items():assert sha(source/name)==digest,name
 assert sha(config)==build['config_sha256']
 actual=config.read_text().splitlines();assert '# CONFIG_MODULES is not set' in actual
 assert ('CONFIG_BLOCK=y' if VARIANT in ('v5','v6','v7','v8','v9','v10','v11','v12') else '# CONFIG_BLOCK is not set') in actual
 if VARIANT in ('v5','v6','v7','v8','v9','v10','v11','v12'):
  for option in ['SCSI_UFS_MEDIATEK','BLK_DEV_SD','PHY_MTK_UFS','COMMON_CLK_MT6358_UFS','REGULATOR_FIXED_VOLTAGE','TRUSTKERNEL_TEE_SUPPORT','TRUSTKERNEL_TEE_RAM_DIAGNOSTIC','ARCH_KEEP_MEMBLOCK']:assert 'CONFIG_'+option+'=y' in actual,option
  # v10 adds ext4 and dm-linear for the super mount test; earlier variants mount nothing.
  if VARIANT in ('v10','v11','v12'):
   for option in ['EXT4_FS','MD','BLK_DEV_DM']:assert 'CONFIG_'+option+'=y' in actual,option
   # v12 runs stock teed: devpts, tmpfs and madvise for it, and the TEE log reader as first boot has it.
   if VARIANT=='v12':
    for option in ['UNIX98_PTYS','TMPFS','ADVISE_SYSCALLS','TRUSTKERNEL_TEE_DIAGNOSTIC_LOGGER']:assert 'CONFIG_'+option+'=y' in actual,option
   for option in ['F2FS_FS','SCSI_UFS_CRYPTO','TRUSTKERNEL_TEE_RPMB_SUPPORT','TEE','DM_CRYPT','DM_VERITY','DM_DEFAULT_KEY','FS_ENCRYPTION']:assert 'CONFIG_'+option+'=y' not in actual,option
  else:
   for option in ['EXT4_FS','F2FS_FS','SCSI_UFS_CRYPTO','TRUSTKERNEL_TEE_RPMB_SUPPORT','TEE']:assert 'CONFIG_'+option+'=y' not in actual,option
 for option in ['DEBUG_KERNEL','USB_CONFIGFS','USB_CONFIGFS_ACM','BLK_DEV_INITRD','RD_GZIP','BINFMT_ELF','REGULATOR_MT6358']:assert 'CONFIG_'+option+'=y' in actual,option
 if VARIANT!='v1':
  for option in ['PSTORE','PSTORE_RAM','PSTORE_CONSOLE','WATCHDOG','MEDIATEK_WATCHDOG','WATCHDOG_HANDLE_BOOT_ENABLED']:assert 'CONFIG_'+option+'=y' in actual,option
 symbols={s.split()[-1] for s in (kernel_out/'System.map').read_text().splitlines()}
 required=['mt6771_pinctrl_probe','pwrap_probe','mt6397_probe','mt6358_irq_init','mt6358_regulator_probe','mtk_sysirq_of_init','gic_of_init','arch_timer_of_init','psci_sys_reset','mtu3_probe','mtk_usb_phy_probe']
 if VARIANT!='v1':required+=['ramoops_probe','mtk_wdt_probe']
 if VARIANT in ('v5','v6','v7','v8','v9','v10','v11','v12'):required+=['ufshcd_pltfrm_init','ufs_mtk_phy_probe','tee_core_init']
 if VARIANT in ('v10','v11','v12'):required+=['dm_linear_init','ext4_init_fs']
 assert set(required)<=symbols,set(required)-symbols
 raw=kernel_out/'arch/arm64/boot/Image';payload=raw.read_bytes();assert payload[56:60]==b'ARM\x64'
 text_offset,image_size,flags=struct.unpack_from('<QQQ',payload,8);assert image_size>=len(payload) and not flags&1 and flags&6==2
 load=0x40200000;assert (load-text_offset)%0x200000==0
 kernel=OUT/'Image.gz';kernel.write_bytes(gzip.compress(payload,mtime=0));assert gzip.decompress(kernel.read_bytes())==payload
 if VARIANT in ('v10','v11','v12'):
  # v10's ext4/jbd2/dm image no longer clears the old conservative low-staging assert.
  # LK REA (firstboot-tkcore-lk-staging.md) shows recovery stages the whole image at
  # 0x56900000 and inflates it into a 200 MiB reservation at the header kernel address,
  # so use the real limits tools/package-pocket-boot.py checks instead.
  KERNEL_RESERVE=0xc800000  # LK reserves 200 MiB at the header kernel address and inflates into it
  assert image_size<=KERNEL_RESERVE,'arm64 image_size 0x%x is over the 200 MiB LK reservation'%image_size
  assert load%0x80000==0,'kernel address is not 512 KiB aligned (LK panics)'
  assert 0x40000000<=load and load+KERNEL_RESERVE<=0x54000000,'LK kernel reservation is not between the base and the DT at 0x54000000'
 else:
  # Conservative check for the observed low recovery staging address too.
  assert 0x40008000+2048+kernel.stat().st_size<=load,'Compressed source would overlap the diagnostic destination in low-address staging'
 ram_record=json.loads((ROOT/('evidence/kernel-upgrade/diagnostic-ramdisk'+SUFFIX+'.json')).read_text());ramdisk=BULK/('artifacts/diagnostic-5.10'+SUFFIX+'/ramdisk/ramdisk.cpio.gz')
 for item in ram_record['files']:assert sha(ROOT/item['path'])==item['sha256']
 for item in ram_record['source_inputs']:assert sha(ROOT/item['path'])==item['sha256']
 board_record=json.loads((ROOT/('evidence/kernel-upgrade/diagnostic-board'+SUFFIX+'.json')).read_text());board=Path(board_record['board_dtb']['path']);assert sha(board)==board_record['board_dtb']['sha256']
 table=runpy.run_path(str(ROOT/'tools/prepare-upgrade-boot-layout.py'));stock=ROOT/'firmware/installed-20230105/recovery'
 dtb=OUT/'dtb.table';dtb.write_bytes(table['pack'](board.read_bytes(),table['parse_table']((stock/'dtb').read_bytes())['entries'][0]['identity']))
 empty=OUT/'identity.dts';empty.write_text('/dts-v1/;\n/plugin/;\n/ {};\n');empty_dtb=OUT/'identity.dtbo'
 subprocess.run([str(kernel_out/'scripts/dtc/dtc'),'-@','-I','dts','-O','dtb','-o',str(empty_dtb),str(empty)],check=True)
 dtbo=OUT/'recovery_dtbo.table';dtbo.write_bytes(table['pack'](empty_dtb.read_bytes(),table['parse_table']((stock/'recovery_dtbo').read_bytes())['entries'][0]['identity']))
 applied=OUT/'identity-applied.dtb';subprocess.run([str(ROOT/'artifacts/kernel-upgrade/fdtoverlay'),'-i',str(board),'-o',str(applied),str(empty_dtb)],check=True)
 decode=runpy.run_path(str(ROOT/'tools/inspect-fdt.py'))['decode'];assert decode(applied.read_bytes())['nodes']==decode(board.read_bytes())['nodes']
 regions=[('kernel',load,image_size),('dtb',0x54000000,max(0x80000,dtb.stat().st_size)),('ramdisk',0x55000000,ramdisk.stat().st_size)]
 for i,(_,a,size) in enumerate(regions):
  for _,b,other in regions[i+1:]:assert a+size<=b or b+other<=a
 # These captured ranges corroborate static placement only; LK must regenerate them.
 live=decode((ROOT/'evidence/device/20261029T000648.917229Z/live-root-20230105/fdt.dtb').read_bytes())['nodes']
 reservations=[]
 for name,value in live.items():
  if not name.startswith('/reserved-memory/') or 'reg' not in value:continue
  cells=value['reg']['cells'];assert len(cells)==4;start=(cells[0]<<32)|cells[1];size=(cells[2]<<32)|cells[3];reservations.append([name,start,size])
  for region,address,count in regions:assert address+count<=start or start+size<=address,(region,name)
 restore_source=ROOT/'artifacts/kernel-upgrade/recovery-configfs-link/stock-recovery-restore.img';assert sha(restore_source)==STOCK_SHA and restore_source.stat().st_size==33554432
 restore=OUT/'stock-recovery-restore.img';restore.write_bytes(restore_source.read_bytes())
 platform=pocket_paths.platform_source();mkboot=platform/'system/tools/mkbootimg/mkbootimg.py'
 command=[sys.executable,'-B',str(mkboot),'--header_version','2','--pagesize','2048','--base','0x40000000','--kernel_offset','0x200000','--ramdisk_offset','0x15000000','--tags_offset','0x14000000','--dtb_offset','0x14000000','--os_version','11.0.0','--os_patch_level','2022-09','--kernel',str(kernel),'--ramdisk',str(ramdisk),'--dtb',str(dtb),'--recovery_dtbo',str(dtbo),'--cmdline',CMDLINE,'--output',str(image)]
 subprocess.run(command,check=True);raw_size=image.stat().st_size;raw_sha=sha(image)
 fields=struct.unpack_from('<10I',image.read_bytes(),8);assert fields[:4]==(kernel.stat().st_size,load,ramdisk.stat().st_size,0x55000000);assert fields[6:9]==(0x54000000,2048,2)
 with tempfile.TemporaryDirectory(dir=OUT) as tmp:
  p=subprocess.run([sys.executable,'-B',str(ROOT/'tools/unpack_bootimg.py'),'--boot_img',str(image),'--out',tmp],check=True,capture_output=True,text=True)
  for name,original in [('kernel',kernel),('ramdisk',ramdisk),('dtb',dtb),('recovery_dtbo',dtbo)]:assert (Path(tmp)/name).read_bytes()==original.read_bytes()
  (EVIDENCE/'header.txt').write_text(p.stdout)
 avb=ROOT/'tools/avbtool.py';subprocess.run([sys.executable,'-B',str(avb),'add_hash_footer','--image',str(image),'--partition_name','recovery','--partition_size','33554432','--algorithm','NONE','--hash_algorithm','sha256','--salt',raw_sha,'--rollback_index','0'],check=True)
 assert image.stat().st_size==33554432
 for operation in ['info_image','verify_image']:
  p=subprocess.run([sys.executable,'-B',str(avb),operation,'--image',str(image)],capture_output=True,text=True,check=True);(EVIDENCE/(operation+'.txt')).write_text(p.stdout+p.stderr)
 record={'state':'Packaged offline; not staged, flashed or hardware-qualified','candidate':{'path':str(image),'bytes':image.stat().st_size,'sha256':sha(image)},'restore_image':{'path':str(restore),'bytes':restore.stat().st_size,'sha256':sha(restore)},'boot_partition_unchanged':True,'header_command':command,'payload_bytes':raw_size,'payload_sha256':raw_sha,'arm64_header':{'text_offset':text_offset,'image_size':image_size,'flags':flags,'load':load,'placement_aligned_2MiB':True},'header_os_fields':'Retain stock packaging values for the diagnostic; not an Android release/security-patch claim','regions':[{'name':n,'address':a,'bytes':s} for n,a,s in regions],'captured_reserved_ranges_checked':reservations,'components':{str(p):sha(p) for p in [raw,kernel,ramdisk,board,dtb,dtbo,config]},'builder_sha256':sha(Path(__file__)),'symbols_present':required,'usb_identity':{'vid':'1d6b','pid':'0104','serial':('TP510-RAM-'+VARIANT.upper() if VARIANT!='v1' else 'TP510-RAM')},'return_timer_seconds':(300 if VARIANT in ('v8','v9','v10','v11','v12') else 150 if VARIANT!='v1' else 120),'watchdog_open_deadline_seconds':(90 if VARIANT!='v1' else None),'watchdog_userspace_ping_seconds':(330 if VARIANT in ('v8','v9','v10','v11','v12') else 180 if VARIANT in ('v6','v7') else None),'device_accessed':False,'ready_for_attended_trial':False,'remaining_checks':['Host libavb verification','Passive-capture host tests','Current phone/host preflight and exact restore staging','Owner present for physical-key entry and failure recovery'],'limits':['No target execution; init timer and PSCI reset are unqualified on this kernel',('RAM retention and watchdog/PSCI reset behavior remain unqualified; absent watchdog needs the '+('300' if VARIANT in ('v8','v9','v10','v11','v12') else '150')+'-second init fallback or physical restart' if VARIANT!='v1' else 'First probe has no storage or pstore driver; USB failure can leave no retained diagnostic log'),'LK must regenerate memory/calibration/initrd data and accept the aligned kernel placement on the actual device','No Android, encryption, hardware parity or public-release claim']+(['Writes are confined to the last 1 MiB of userdata and the original bytes are restored on exit; write budget 2 MiB + 4 KiB; the super re-hash proves the read-only mount wrote nothing'] if VARIANT in ('v10','v11','v12') else [])+[('Kernel performs UFS configuration and secure SHM/RoT negotiation; userspace requests bounded read-only block I/O and a local feature ioctl'+(', plus I2C ID reads (register pointer write then read) at known addresses' if VARIANT in ('v8','v9','v10','v11','v12') else '')+(', and GPIO 178 reset pulse for the aw9523 read' if VARIANT in ('v9','v10','v11','v12') else '')+(', one restore-on-exit write test confined to the last 1 MiB of userdata and read-only dm-linear mounts of super system/vendor/product'+(', stock teed from the read-only vendor mount with every writable path on tmpfs and no RPMB option, one keymaster TA session opened and closed, protect1/protect2/persist/nvdata/nvcfg/proinfo hashed before and after' if VARIANT=='v12' else ', no TA sessions') if VARIANT in ('v10','v11','v12') else ', no filesystem mounts or TA sessions') if VARIANT in ('v5','v6','v7','v8','v9','v10','v11','v12') else 'USB/RAM diagnostic; no storage workload')]}
 (EVIDENCE/'candidate-validation.json').write_text(json.dumps(record,indent=2)+'\n');print('RAM-only diagnostic recovery packaged and round-trip/AVB-checked: '+record['candidate']['sha256'])
if __name__=='__main__':main()
