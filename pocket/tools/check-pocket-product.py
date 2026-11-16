#!/usr/bin/env python3
"""Check the gated product hardware contract against saved, verified local inputs."""
import pocket_paths
import hashlib,json,re,subprocess
from pathlib import Path
ROOT=Path(__file__).resolve().parent.parent
def main():
 device=pocket_paths.DEVICE_TREE;board=device/'BoardConfig.hardware.mk';text=board.read_text()
 values=dict(re.findall(r'^(\w+)\s*:=\s*(.*?)\s*$',text,re.M))
 for key,expected in {'BOARD_BOOTIMAGE_PARTITION_SIZE':33554432,'BOARD_RECOVERYIMAGE_PARTITION_SIZE':33554432,'BOARD_SUPER_PARTITION_SIZE':4831838208,'BOARD_KERNEL_BASE':0x40000000,'BOARD_KERNEL_PAGESIZE':2048,'BOARD_KERNEL_OFFSET':0x80000,'BOARD_RAMDISK_OFFSET':0x15000000,'BOARD_KERNEL_TAGS_OFFSET':0x14000000,'BOARD_DTB_OFFSET':0x14000000,'BOARD_BOOT_HEADER_VERSION':2}.items():assert int(values[key],0)==expected,key
 for name in ['boot','recovery']:assert (ROOT/'firmware/installed-20230105'/(name+'.img')).stat().st_size==int(values['BOARD_'+name.upper()+'IMAGE_PARTITION_SIZE'])
 assert (ROOT/'firmware/installed-20230105/super.raw.img').stat().st_size==int(values['BOARD_SUPER_PARTITION_SIZE'])
 layout=json.loads((ROOT/'evidence/installed-20230105/super-layout.json').read_text());main=next(g for g in layout['groups'] if g['name']=='main');assert int(values['BOARD_POCKET_DYNAMIC_SIZE'])==main['max_bytes']
 assert set(values['BOARD_POCKET_DYNAMIC_PARTITION_LIST'].split())=={p['name'] for p in layout['partitions']}
 assert values['BOARD_VNDK_VERSION']=='30' and values['BOARD_SEPOLICY_VERS']=='30.0'
 for option in ['kernel_offset','ramdisk_offset','tags_offset','dtb_offset']:assert '--'+option in text
 fstab=(device/'boot/fstab.stock-contract').read_text();assert '/dev/block/by-name/md_udc /metadata' in fstab and 'fileencryption=aes-256-xts:aes-256-cts:v2' in fstab
 # The production target must fail before generation of any image/build rules.
 p=subprocess.run(['make','-f',str(device/'BoardConfig.mk'),'TARGET_PRODUCT=lineage_titan_pocket'],capture_output=True,text=True)
 assert p.returncode and 'image builds are gated' in p.stderr
 record={'hardware_contract_sha256':hashlib.sha256(board.read_bytes()).hexdigest(),'stock_geometry_checked':True,'mixed_32_64_bit_contract':values['TARGET_ARCH']=='arm64' and values['TARGET_2ND_ARCH']=='arm','shipping_image_target_rejected':True,'fstab_reference_only':True,'audit_product_is_generic_not_stock_vendor_qualification':True,'device_accessed':False}
 (ROOT/'evidence/kernel-upgrade/pocket-product-contract-check.json').write_text(json.dumps(record,indent=2)+'\n');print('Pocket product geometry/header contract matches saved inputs; shipping build remains gated')
if __name__=='__main__':main()
