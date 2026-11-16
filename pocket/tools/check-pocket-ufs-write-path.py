#!/usr/bin/env python3
"""Check offline that the first-boot UFS profile has no block-write gate and keeps PM, gating, WriteBooster and crypto off.

Covers the driver source, the generic UFS core against the pinned donor, the
board tree the boot packager uses, the first-boot .config and the write-path
facts already seen in saved 5.10 diagnostic consoles. No device access.
Writes evidence/kernel-upgrade/ufs-write-path-check.json.
"""
import pocket_paths
import hashlib,json,os,re,runpy
from datetime import datetime,timezone
from pathlib import Path
ROOT=Path(__file__).resolve().parent.parent
BULK=pocket_paths.build_root()
SOURCE=Path(os.environ.get('POCKET_KERNEL_SOURCE',str(ROOT/'tools/kernel-source/upgrade-5.10')))
CONFIG=BULK/'kernel-firstboot-5.10/.config'
BOARD_RECORD=ROOT/'evidence/kernel-upgrade/diagnostic-board-v9.json'
CONSOLES=[ROOT/'evidence/kernel-upgrade/diagnostic-v7-trial-20261030T195551Z/after/console.txt',
          ROOT/'evidence/kernel-upgrade/diagnostic-v8-trial-20261030T205846Z/after/console.txt']
REPORT=ROOT/'evidence/kernel-upgrade/ufs-write-path-check.json'
HOST='/ufshci@11270000'
# Generic UFS and SCSI disk code that carries every block write; none of it is patched.
UNPATCHED=['drivers/scsi/ufs/ufshcd.c','drivers/scsi/ufs/ufshcd.h','drivers/scsi/ufs/ufshcd-pltfrm.c','drivers/scsi/sd.c']

def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def main():
 checks=[]
 def check(name,ok,detail=''):
  checks.append({'check':name,'ok':bool(ok),'detail':detail});print(('OK  ' if ok else 'FAIL')+' '+name+(': '+detail if detail else ''))
 export=runpy.run_path(str(ROOT/'tools/export-kernel-upgrade-patches.py'),run_name='catalog')
 base=export['BASE'];patched={p for v in export['GROUPS'].values() for p in v}
 for rel in UNPATCHED:
  check('unpatched '+rel,rel not in patched and sha(SOURCE/rel)==sha(base/rel),'matches the pinned donor')
 src=(SOURCE/'drivers/scsi/ufs/ufs-mediatek.c').read_text()
 # The variant driver never looks at SCSI opcodes or disk state, so it can't refuse a write.
 opcodes=[w for w in ['WRITE_6','WRITE_10','WRITE_16','UNMAP','SYNCHRONIZE_CACHE','WRITE_SAME','set_disk_ro','write_prot','scsi_cmnd'] if w in src]
 check('ufs-mediatek.c has no command or read-only filter',not opcodes,'found '+','.join(opcodes) if opcodes else 'no SCSI opcode, cmnd or disk read-only reference')
 check('MT6771 probe needs the engineering opt-in',re.search(r'"mediatek,mt6771-ufshci"\)\) \{\s*if \(!of_property_read_bool\(dev->of_node,\s*"unihertz,ram-storage-probe"\)\)\s*return -ENODEV;',src))
 check('profile clears autosuspend, clock gating, H8 gating and WriteBooster',re.search(r'if \(host->ram_probe\) \{[^}]*hba->caps &= ~\(UFSHCD_CAP_RPM_AUTOSUSPEND \|\s*UFSHCD_CAP_CLK_GATING \|\s*UFSHCD_CAP_HIBERN8_WITH_CLK_GATING \|\s*UFSHCD_CAP_WB_EN\);',src))
 check('MT6771 clears hardware crypto',re.search(r'if \(ufs_mtk_uses_mt6771_fw\(hba\)\)\s*hba->caps &= ~UFSHCD_CAP_CRYPTO;',src))
 # ufs_mediatek.mt6771_sleep (0080) picks the system sleep level; the default is 2, 0 keeps the host active.
 check('mt6771_sleep defaults to 2',re.search(r'^static unsigned int mt6771_sleep = 2;$',src,re.M))
 check('sleep level comes only from mt6771_sleep at system suspend',src.count('host->sleep_level = min(READ_ONCE(mt6771_sleep), 2U);')==1)
 for fn,pattern in [('ufs_mtk_suspend',r'^\s*if \(host->ram_probe\) \{\s*if \(pm_op != UFS_SYSTEM_PM \|\| !host->sleep_level\)\s*return -EOPNOTSUPP;'),
                    ('ufs_mtk_resume',r'^\s*if \(host->ram_probe && \(pm_op != UFS_SYSTEM_PM \|\| !host->sleep_level\)\)\s*return -EOPNOTSUPP;')]:
  m=re.search(r'static int '+fn+r'\([^)]*\)\s*\{(.*?)\n\}',src,re.S)
  check(fn+' refuses before hardware at level 0 and outside system sleep',m and re.search(pattern,m.group(1),re.M))
 # s2idle: at level 0 system sleep must not reach ufshcd_suspend() (SSU and Hibern8) under this binding.
 for fn,pattern in [('ufs_mtk_system_suspend',r'^\s*if \(host->ram_probe\) \{\s*host->sleep_level = min\(READ_ONCE\(mt6771_sleep\), 2U\);\s*if \(!host->sleep_level\)\s*return 0;'),
                    ('ufs_mtk_system_resume',r'^\s*if \(host->ram_probe && !host->sleep_level\)\s*return 0;')]:
  m=re.search(r'static int '+fn+r'\([^)]*\)\s*\{(.*?)\n\}',src,re.S)
  check(fn+' leaves the RAM binding active at level 0',m and re.search(pattern,m.group(1),re.M))
 check('system sleep ops use the RAM binding wrappers',re.search(r'ufs_mtk_pm_ops = \{\s*\.suspend\s*= ufs_mtk_system_suspend,\s*\.resume\s*= ufs_mtk_system_resume,',src))
 check('refclk off refuses before hardware at level 0',re.search(r'if \(!on\) \{\s*if \(host->sleep_level < 2\)\s*return host->sleep_level \? 0 : -EOPNOTSUPP;',src))
 check('disable-ah8 drops auto-hibern8',re.search(r'capabilities &= ~MASK_AUTO_HIBERN8_SUPPORT;\s*hba->ahit = 0;',src))
 # Board tree the first-boot boot image carries (package-pocket-boot.py uses the v9 record).
 record=json.loads(BOARD_RECORD.read_text());dtb=Path(record['output'])
 os.environ['POCKET_DIAGNOSTIC_VARIANT']='v4'
 tree=runpy.run_path(str(ROOT/'tools/prepare-pocket-diagnostic-tree.py'),run_name='storage_tree_helpers')
 check('board dtb matches its record',sha(dtb)==record['sha256'],str(dtb))
 host=tree['DECODE'](dtb.read_bytes())['nodes'][HOST]
 check('host is the MT6771 engineering binding',host['compatible']['strings']==['mediatek,mt6771-ufshci'] and host['status']['strings']==['okay'] and 'unihertz,ram-storage-probe' in host)
 check('host keeps disable-ah8 and VA09',all(k in host for k in ['mediatek,ufs-disable-ah8','mediatek,ufs-support-va09','va09-supply']))
 check('host has no boost-crypt or broken-vcc',not any(k in host for k in ['mediatek,ufs-boost-crypt','mediatek,ufs-broken-vcc']))
 cfg=dict(re.findall(r'^CONFIG_([A-Z0-9_]+)=(.*)$',CONFIG.read_text(),re.M))
 want={'SCSI_UFSHCD':'y','SCSI_UFSHCD_PLATFORM':'y','SCSI_UFS_MEDIATEK':'y','BLK_DEV_SD':'y','BLK_DEV_DM':'y','EXT4_FS':'y'}
 off=['SCSI_UFS_CRYPTO','SCSI_UFS_HPB']
 check('first-boot config has the write path',all(cfg.get(k)==v for k,v in want.items()),', '.join(k+'='+cfg.get(k,'n') for k in want))
 check('first-boot config keeps crypto and HPB off',not any(k in cfg for k in off),', '.join(k+'='+cfg.get(k,'n') for k in off))
 # Observed under 5.10 on the phone (v7 and v8 RAM diagnostics, read-only workloads).
 observed={}
 for c in CONSOLES:
  text=c.read_text(errors='replace')
  wp=re.findall(r'\[(sd[abc])\] Write Protect is off',text);wc=re.findall(r'\[(sd[abc])\] Write cache: enabled, read cache: enabled, supports DPO and FUA',text)
  sync=re.findall(r'\[(sd[abc])\] Synchronizing SCSI cache',text)
  observed[c.parent.parent.name]={'write_protect_off':sorted(set(wp)),'write_cache_fua':sorted(set(wc)),'sync_cache_at_restart':sorted(set(sync)),
   'sync_cache_failed':'Synchronize Cache(10) failed' in text,
   'shutdown_eopnotsupp':'ufshcd_shutdown failed, err -95' in text}
  o=observed[c.parent.parent.name]
  check('observed '+c.parent.parent.name,o['write_protect_off']==['sda','sdb','sdc'] and o['write_cache_fua']==['sda','sdb','sdc'] and o['sync_cache_at_restart']==['sda','sdb','sdc'] and not o['sync_cache_failed'],json.dumps(o))
 failures=[c for c in checks if not c['ok']]
 report={'utc':datetime.now(timezone.utc).isoformat(),'checker_sha256':sha(Path(__file__)),'source':str(SOURCE),'config':str(CONFIG),'config_sha256':sha(CONFIG),
  'board_dtb':str(dtb),'board_dtb_sha256':sha(dtb),'source_hashes':{p:sha(SOURCE/p) for p in UNPATCHED+['drivers/scsi/ufs/ufs-mediatek.c']},
  'checks':checks,'failures':len(failures),'observed':observed,
  'finding':'No block-write gate exists in the 5.10 kernel for this binding. The read-only rule of the RAM diagnostics is their userspace workload (O_RDONLY opens, no mounts).',
  'limits':['Static and saved-log checks only; no write has been issued under 5.10',
   'Shutdown under this profile: SYNC CACHE per LUN and SSU power-down, then the refused variant suspend triggers a host reset and restore and logs err -95 (observed in v7/v8)',
   'Write error recovery, sustained writes, discard/UNMAP and ext4 rw on UFS are untested']}
 REPORT.write_text(json.dumps(report,indent=2)+'\n');print('checks',len(checks),'failures',len(failures),'report',REPORT)
 raise SystemExit(1 if failures else 0)
if __name__=='__main__':main()
