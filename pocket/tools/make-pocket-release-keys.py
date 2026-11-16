#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Make the release keys for signing Titan Pocket builds, as LineageOS's "Signing builds" guide does.

Writes into a new folder (mode 700, files 600), unencrypted:
  releasekey, platform, shared, media, networkstack, sdk_sandbox, bluetooth, nfc, cyngn-app,
  testcert, verity    RSA 2048 .pk8 and .x509.pem, from development/tools/make_key
  testkey             links to releasekey, as the guide does
  com.android.*.      RSA 4096 APEX keys (.pk8, .x509.pem and the payload .pem), the guide's list
  avb.pem             RSA 2048 AVB key for vbmeta, vbmeta_system, boot and recovery, with its
                      public key avb.avbpubkey. 2048 as stock's vbmeta and recovery use
                      SHA256_RSA2048, the algorithm LK is known to parse.
Refuses to run if the folder exists, so keys are never overwritten. Keys never go in the repo.
"""
import pocket_paths
import argparse
import os
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parent.parent
DEFAULT = pocket_paths.release_keys()
SOURCE = pocket_paths.platform_source()
AVBTOOL = ROOT / 'tools/avbtool.py'
SUBJECT = '/C=CA/O=Titan Pocket LineageOS/CN=Titan Pocket'
CERTS = ['releasekey', 'platform', 'shared', 'media', 'networkstack', 'sdk_sandbox', 'bluetooth',
         'nfc', 'cyngn-app', 'testcert', 'verity']
# The guide's APEX list for LineageOS 23.
APEXES = '''com.android.adbd com.android.adservices com.android.adservices.api com.android.appsearch
com.android.art com.android.bluetooth com.android.bt com.android.btservices com.android.cellbroadcast
com.android.compos com.android.configinfrastructure com.android.connectivity.resources
com.android.conscrypt com.android.crashrecovery com.android.devicelock com.android.extservices
com.android.graphics.pdf com.android.hardware.authsecret com.android.hardware.biometrics.face.virtual
com.android.hardware.biometrics.fingerprint.virtual com.android.hardware.boot com.android.hardware.cas
com.android.hardware.contexthub com.android.hardware.drm.clearkey com.android.hardware.dumpstate
com.android.hardware.gatekeeper.nonsecure com.android.hardware.neuralnetworks com.android.hardware.power
com.android.hardware.rebootescrow com.android.hardware.thermal com.android.hardware.threadnetwork
com.android.hardware.uwb com.android.hardware.vibrator com.android.hardware.wifi com.android.healthfitness
com.android.hotspot2.osulogin com.android.i18n com.android.ipsec com.android.media com.android.media.swcodec
com.android.mediaprovider com.android.nearby.halfsheet com.android.networkstack.tethering
com.android.neuralnetworks com.android.nfcservices com.android.npumanager com.android.ondevicepersonalization
com.android.os.statsd com.android.permission com.android.profiling com.android.resolv com.android.rkpd
com.android.runtime com.android.safetycenter.resources com.android.scheduling com.android.sdkext
com.android.support.apexer com.android.telephony com.android.telephonycore com.android.telephonymodules
com.android.tethering com.android.tzdata com.android.uprobestats com.android.uwb com.android.uwb.resources
com.android.virt com.android.vndk.current com.android.vndk.current.on_vendor com.android.webapp
com.android.wifi com.android.wifi.dialog com.android.wifi.resources com.google.pixel.camera.hal
com.google.pixel.vibrator.hal com.qorvo.uwb'''.split()


def make_key(script, name):
    # make_key asks for a password; a blank line means none.
    # Its exit trap always returns 1, so check the files instead.
    subprocess.run(['bash', str(script), name, SUBJECT], input=b'\n', stdout=subprocess.DEVNULL)
    if not (Path(name + '.pk8').is_file() and Path(name + '.x509.pem').is_file()):
        raise SystemExit('make_key failed for ' + name)


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument('--keys', type=Path, default=DEFAULT,
                    help='new key folder (default: release_keys in configs/local-paths.json)')
    args = ap.parse_args()
    keys = args.keys.expanduser()
    if keys.exists() or keys.is_symlink():
        raise SystemExit(f'{keys} already exists; not touching existing keys')
    original = SOURCE / 'development/tools/make_key'
    os.umask(0o077)
    keys.mkdir(mode=0o700)
    os.chdir(keys)
    with tempfile.TemporaryDirectory() as tmp:
        rsa2048 = Path(tmp) / 'make_key'
        rsa2048.write_text(original.read_text())
        rsa4096 = Path(tmp) / 'make_key_4096'
        rsa4096.write_text(original.read_text().replace('2048', '4096'))
        for name in CERTS:
            make_key(rsa2048, name)
        for name in APEXES:
            make_key(rsa4096, name)
            subprocess.run(['openssl', 'pkcs8', '-in', name + '.pk8', '-inform', 'DER', '-nocrypt',
                            '-out', name + '.pem'], check=True)
    for suffix in ('.pk8', '.x509.pem'):
        os.symlink('releasekey' + suffix, 'testkey' + suffix)
    subprocess.run(['openssl', 'genrsa', '-out', 'avb.pem', '2048'], check=True,
                   stderr=subprocess.DEVNULL)
    subprocess.run(['python3', str(AVBTOOL), 'extract_public_key', '--key', 'avb.pem',
                    '--output', 'avb.avbpubkey'], check=True)
    for path in keys.iterdir():
        if not path.is_symlink():
            path.chmod(0o600)
    keys.chmod(0o700)
    print(f'{len(list(keys.iterdir()))} files in {keys}')


if __name__ == '__main__':
    main()
