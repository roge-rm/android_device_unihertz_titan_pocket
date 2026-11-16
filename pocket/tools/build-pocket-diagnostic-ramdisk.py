#!/usr/bin/env python3
"""Build only the RAM diagnostic's static init/archive; no phone access."""
import pocket_paths
import os,runpy
from pathlib import Path
ROOT=Path(__file__).resolve().parent.parent
BULK=pocket_paths.build_root()
VARIANT=os.environ.get('POCKET_DIAGNOSTIC_VARIANT','v1')
if VARIANT not in ('v1','v2','v3','v4','v5','v6','v7','v8','v9','v10','v11','v12'):raise ValueError('Diagnostic variant must be v1, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11 or v12')
SUFFIX='' if VARIANT=='v1' else '-'+VARIANT
# v12's probes.h takes the TEE ioctl layouts from the stock tkcore headers.
TKCORE=ROOT/'tools/kernel-source/upgrade-5.10/drivers/misc/mediatek/tkcore'
if __name__=='__main__':
 evidence=ROOT/'evidence/kernel-upgrade';evidence.mkdir(parents=True,exist_ok=True)
 runpy.run_path(str(ROOT/'tools/build-upgrade-ramdisk.py'),run_name='builder')['build'](ROOT/('kernel-upgrade/diagnostic-probe'+SUFFIX+'/init.c'),BULK/('artifacts/diagnostic-5.10'+SUFFIX+'/ramdisk'),evidence/('diagnostic-ramdisk'+SUFFIX+'.json'), extra_sources=([ROOT/'kernel-upgrade/ram-probe/ufs-readonly.h', ROOT/'kernel-upgrade/tkcore-probe/feature_query.h'] if VARIANT in ('v5','v6','v7','v8','v9','v10','v11','v12') else [])+([ROOT/('kernel-upgrade/diagnostic-probe-'+VARIANT+'/probes.h')] if VARIANT in ('v8','v9','v10','v11','v12') else [])+([TKCORE/'include/linux/tee_ioc.h',TKCORE/'include/linux/tee_client_api.h'] if VARIANT=='v12' else []),include_dirs=[TKCORE/'include'] if VARIANT=='v12' else [])
