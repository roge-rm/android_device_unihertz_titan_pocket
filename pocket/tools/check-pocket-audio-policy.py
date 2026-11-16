#!/usr/bin/env python3
"""Checks that the shipped policy and init files cover the audio nodes (AUDIO_PORT.md milestone 4).

Reads the private vendor overlay image (debugfs) and the built product output; no build, no phone.
Checks: /dev/smartpa_i2c is labelled smartpa1_device and the HAL domain may use it, init chmods it
0666 system at boot and may setattr it, /dev/snd is labelled audio_device and ueventd gives it
0660 system audio, the HAL domain may use audio_device, /proc/asound is readable by hal_audio, and
the HAL service runs as audioserver in group audio. Static only: it does not run the policy.
"""
import pocket_paths
import argparse, re, subprocess, sys
from pathlib import Path

BULK = pocket_paths.build_root()
PRODUCT = BULK / 'product-out/target/product/titan_pocket'
IMG = pocket_paths.private_vendor_overlay() / 'v4/vendor.img'


def cat(img, path):
    r = subprocess.run(['debugfs', '-R', f'cat {path}', str(img)], capture_output=True, text=True)
    return r.stdout


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--vendor-img', type=Path, default=IMG)
    a = ap.parse_args()
    cil = cat(a.vendor_img, '/etc/selinux/vendor_sepolicy.cil')
    fc = cat(a.vendor_img, '/etc/selinux/vendor_file_contexts')
    rc = cat(a.vendor_img, '/etc/init/hw/init.mt6771.rc')
    hal_rc = cat(a.vendor_img, '/etc/init/android.hardware.audio.service.mediatek.rc')
    plat = PRODUCT / 'system/etc/selinux'
    pfc = (plat / 'plat_file_contexts').read_text()
    pcil = (plat / 'plat_sepolicy.cil').read_text()
    ue = (PRODUCT / 'system/etc/ueventd.rc').read_text()
    perms = lambda s: set(s.split())

    def allow(text, src, dst, cls, need):
        for m in re.finditer(rf'^\(allow {src} {dst} \({cls} \(([^)]*)\)\)\)', text, re.M):
            if set(need) <= perms(m.group(1)):
                return True
        return False

    checks = [
        ('vendor_file_contexts labels /dev/smartpa_i2c smartpa1_device',
         bool(re.search(r'^/dev/smartpa_i2c\(/\.\*\)\?\s+u:object_r:smartpa1_device:s0', fc, re.M))),
        ('HAL domain may open, read, write, ioctl smartpa1_device',
         allow(cil, 'mtk_hal_audio', 'smartpa1_device', 'chr_file', ['open', 'read', 'write', 'ioctl'])),
        ('vendor init rc chmods /dev/smartpa_i2c 0666 and chowns system system, in "on boot"',
         bool(re.search(r'^on boot\b(?:(?!^on ).)*?chmod 0666 /dev/smartpa_i2c\s+chown system system /dev/smartpa_i2c',
                        rc, re.M | re.S))),
        ('init may setattr any dev_type chr_file bar a few (platform)',
         bool(re.search(r'^\(allow init base_typeattr_\d+ \(chr_file \(setattr\)\)\)', pcil, re.M)
              and re.search(r'^\(typeattributeset base_typeattr_\d+ \(and \(dev_type \) \(not \(vm_manager_device_type keychord_device hw_random_device port_device \)\)\)\)', pcil, re.M))),
        ('platform file_contexts labels /dev/snd audio_device',
         bool(re.search(r'^/dev/snd\(/\.\*\)\?\s+u:object_r:audio_device:s0', pfc, re.M))),
        ('ueventd gives /dev/snd/* 0660 system audio',
         bool(re.search(r'^/dev/snd/\*\s+0660\s+system\s+audio', ue, re.M))),
        ('HAL domain may use audio_device dir and chr_file',
         allow(cil, 'mtk_hal_audio', 'audio_device_30_0', 'dir', ['search', 'read', 'open'])
         and allow(cil, 'mtk_hal_audio', 'audio_device_30_0', 'chr_file', ['open', 'read', 'write', 'ioctl'])),
        ('HAL domain is in hal_audio, which may read proc_asound',
         bool(re.search(r'^\(typeattributeset hal_audio \([^)]*\bmtk_hal_audio\b', cil, re.M)
              or 'mtk_hal_audio' in re.search(r'\(typeattributeset hal_audio \(([^)]*)\)', (plat / 'mapping/30.0.cil').read_text()).group(1))
         and allow(pcil, 'hal_audio', 'proc_asound', 'file', ['open', 'read'])
         and allow(pcil, 'hal_audio', 'proc_asound', 'dir', ['search', 'read'])),
        ('platform labels /proc/asound proc_asound',
         'genfscon proc "/asound" (u object_r proc_asound' in pcil),
        ('vendor.audio-hal runs as audioserver in group audio',
         bool(re.search(r'user audioserver\b[^\n]*\n(?:\s*#[^\n]*\n)*\s*group audio\b', hal_rc))),
        ('no allowxperm rule restricts the HAL on audio_device or smartpa1_device',
         not re.search(r'^\(allowxperm (mtk_hal_audio|hal_audio|hal_audio_server) (audio_device\S*|smartpa1_device) ', cil + pcil, re.M)),
    ]
    bad = 0
    for name, ok in checks:
        print(('ok   ' if ok else 'FAIL ') + name)
        bad += not ok
    sys.exit(1 if bad else 0)


main()
