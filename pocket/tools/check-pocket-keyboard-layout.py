#!/usr/bin/env python3
"""Check the keyboard layout overlay matches the base aw9523-key.kcm and is in the product."""
import pocket_paths
from pathlib import Path
ROOT=Path(__file__).resolve().parent.parent
DEV=pocket_paths.DEVICE_TREE

def keys(path,kind):
 lines=path.read_text().split('\n')
 assert lines.count('type '+kind)==1,f'{path}: needs one "type {kind}"'
 return lines[lines.index('type '+kind)+1:]

def main():
 base=keys(DEV/'rootdir/usr/keychars/aw9523-key.kcm','ALPHA')
 overlay=keys(DEV/'keyboard-layout/res/raw/aw9523_key.kcm','OVERLAY')
 assert base==overlay,'keyboard-layout/res/raw/aw9523_key.kcm keys differ from rootdir/usr/keychars/aw9523-key.kcm'
 xml=(DEV/'keyboard-layout/res/xml/keyboard_layouts.xml').read_text()
 assert 'androidprv:vendorId="0"' in xml and 'androidprv:productId="0"' in xml,'layout must match vendor 0 product 0'
 mk=(DEV/'lineage_titan_pocket.mk').read_text()
 assert 'PocketKeyboardLayout' in mk,'PocketKeyboardLayout missing from PRODUCT_PACKAGES'
 print(f'keyboard layout overlay: {sum(l.startswith("key ") for l in overlay)} keys match the base map')

if __name__=='__main__':main()
