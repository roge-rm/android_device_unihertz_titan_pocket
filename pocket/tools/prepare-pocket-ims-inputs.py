#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Stage stock com.mediatek.ims and mediatek-ims-base.jar for the product build (MODEM_PORT.md, M8).

Copies both from the January stock system dump into the private vendor tree in bulk
storage, next to what prepare-pocket-product-inputs.py stages, and writes their
Android.bp. The APK's dex is patched first (baksmali and smali from Lineage's
prebuilts/extract-tools) so it no longer calls classes and methods Android 16 removed;
see PATCHES. Nothing is installed unless POCKET_IMS=true (device/.../ims/ims.mk).
No signing happens here: the build re-signs the APK with the platform key.
"""
import pocket_paths
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import zipfile

ROOT = Path(__file__).resolve().parent.parent
BULK = pocket_paths.build_root()
STOCK = ROOT / 'firmware/installed-20230105/rootfs/system/system'
INPUTS = {
    'ImsService.apk': (STOCK / 'priv-app/ImsService/ImsService.apk',
                       'd5d61c72799d2ebccb23e09ab271adb2f847102d42a50f0bb9c0520bb7e54544'),
    'mediatek-ims-base.jar': (STOCK / 'framework/mediatek-ims-base.jar',
                              '4f64f719da0426cc24e0ed3840520b81378c36ab3f6aa5bc7e5af5d70318fb51'),
}
SMALI = pocket_paths.platform_source() / 'prebuilts/extract-tools/common/smali'
# Pinned result of patching the stock APK; the build only takes this exact file.
PATCHED_SHA = 'db72000e3863f22fe589dddecfc07c1b95193c2ec8a3e04ba254382ff985cd84'

TM = 'Lcom/android/internal/telephony/metrics/TelephonyMetrics;'
# (smali file, regex, replacement, expected count). Each one replaces an Android 11 API that
# Android 16 removed with its Android 16 home, or with nothing where it only fed metrics.
PATCHES = [
    # TelephonyMetrics is gone: no instance, and every write*() call dropped. The field and
    # the access$300 getters become Object below, so no reference to the class is left.
    ('com/mediatek/ims/ril/ImsRILAdapter.smali',
     r'invoke-static \{\}, ' + re.escape(TM) + r'->getInstance\(\)' + re.escape(TM) + r'\s+move-result-object (v\d+)', r'const/4 \1, 0x0', 1),
    ('com/mediatek/wfo/ril/MwiRIL.smali',
     r'invoke-static \{\}, ' + re.escape(TM) + r'->getInstance\(\)' + re.escape(TM) + r'\s+move-result-object (v\d+)', r'const/4 \1, 0x0', 1),
    ('com/mediatek/ims/ril/ImsRILAdapter.smali', r'invoke-virtual(?:/range)? \{[^}]*\}, ' + re.escape(TM) + r'->write\w+\([^)]*\)V', 'nop', 3),
    ('com/mediatek/ims/ril/ImsRILAdapter$RilHandler.smali', r'invoke-virtual(?:/range)? \{[^}]*\}, ' + re.escape(TM) + r'->write\w+\([^)]*\)V', 'nop', 1),
    ('com/mediatek/wfo/ril/MwiRIL.smali', r'invoke-virtual(?:/range)? \{[^}]*\}, ' + re.escape(TM) + r'->write\w+\([^)]*\)V', 'nop', 1),
    ('com/mediatek/wfo/ril/MwiRIL$RilHandler.smali', r'invoke-virtual(?:/range)? \{[^}]*\}, ' + re.escape(TM) + r'->write\w+\([^)]*\)V', 'nop', 1),
    # SubscriptionManager.getSimStateForSlotIndex moved to TelephonyManager, same signature.
    ('com/mediatek/ims/ImsService.smali', r'Landroid/telephony/SubscriptionManager;->getSimStateForSlotIndex\(I\)I',
     'Landroid/telephony/TelephonyManager;->getSimStateForSlotIndex(I)I', 1),
    ('com/mediatek/ims/ImsService$MyHandler.smali', r'Landroid/telephony/SubscriptionManager;->getSimStateForSlotIndex\(I\)I',
     'Landroid/telephony/TelephonyManager;->getSimStateForSlotIndex(I)I', 1),
    ('com/mediatek/ims/config/internal/ImsConfigEventReceiver.smali', r'Landroid/telephony/SubscriptionManager;->getSimStateForSlotIndex\(I\)I',
     'Landroid/telephony/TelephonyManager;->getSimStateForSlotIndex(I)I', 3),
    # RIL.arrayListToPrimitiveArray moved to RILUtils, same signature.
    ('com/mediatek/ims/ril/ImsRadioIndication.smali', r'Lcom/android/internal/telephony/RIL;->arrayListToPrimitiveArray',
     'Lcom/android/internal/telephony/RILUtils;->arrayListToPrimitiveArray', 2),
    # gsm SmsMessage.newFromCDS was new SmsMessage() plus parsePdu(), as createFromPdu still is.
    ('com/mediatek/ims/feature/MtkImsSmsImpl.smali', r'Lcom/android/internal/telephony/gsm/SmsMessage;->newFromCDS\(',
     'Lcom/android/internal/telephony/gsm/SmsMessage;->createFromPdu(', 1),
    # SmsMessageConverter.newSmsMessageFromCdmaSmsMessage(m) was new SmsMessage(RILUtils.convertHalCdmaSmsMessage(m)).
    # v1 is free here: the next instruction loads it.
    ('com/mediatek/ims/ril/ImsRadioIndication.smali',
     r'invoke-static \{p2\}, Lcom/android/internal/telephony/cdma/SmsMessageConverter;->newSmsMessageFromCdmaSmsMessage'
     r'\(Landroid/hardware/radio/V1_0/CdmaSmsMessage;\)Landroid/telephony/SmsMessage;\s+move-result-object v0',
     'invoke-static {p2}, Lcom/android/internal/telephony/RILUtils;->convertHalCdmaSmsMessage'
     '(Landroid/hardware/radio/V1_0/CdmaSmsMessage;)Lcom/android/internal/telephony/cdma/SmsMessage;\n\n'
     '    move-result-object v1\n\n    new-instance v0, Landroid/telephony/SmsMessage;\n\n'
     '    invoke-direct {v0, v1}, Landroid/telephony/SmsMessage;-><init>(Lcom/android/internal/telephony/SmsMessageBase;)V', 1),
    # The static ImsManager.updateImsServiceConfig(context, phoneId, force) became an instance
    # method without force: getInstance(context, phoneId).updateImsServiceConfig().
    ('com/mediatek/ims/plugin/impl/ImsManagerOemPluginBase.smali',
     r'\.registers 4(\s+\.param p1[^\n]*\s+\.param p2[^\n]*\s+\.param p3[^\n]*\s+\.line \d+\s+)'
     r'invoke-static \{p1, p2, p3\}, Lcom/android/ims/ImsManager;->updateImsServiceConfig\(Landroid/content/Context;IZ\)V',
     '.registers 5\\1invoke-static {p1, p2}, Lcom/android/ims/ImsManager;->getInstance(Landroid/content/Context;I)Lcom/android/ims/ImsManager;\n\n'
     '    move-result-object v0\n\n    invoke-virtual {v0}, Lcom/android/ims/ImsManager;->updateImsServiceConfig()V', 1),
    # StorageManager.inCryptKeeperBounce went with full-disk encryption; it is always false now.
    ('com/mediatek/wfo/impl/WfcHandler.smali', r'invoke-static \{\}, Landroid/os/storage/StorageManager;->inCryptKeeperBounce\(\)Z\s+move-result (v\d+)',
     r'const/4 \1, 0x0', 1),
    ('com/mediatek/wfo/impl/WifiPdnHandler.smali', r'invoke-static \{\}, Landroid/os/storage/StorageManager;->inCryptKeeperBounce\(\)Z\s+move-result (v\d+)',
     r'const/4 \1, 0x0', 1),
]
REMOVED = [TM, 'Lcom/android/internal/telephony/cdma/SmsMessageConverter;', 'SubscriptionManager;->getSimStateForSlotIndex',
           'StorageManager;->inCryptKeeperBounce', 'ImsManager;->updateImsServiceConfig(Landroid/content/Context;IZ)V',
           'RIL;->arrayListToPrimitiveArray', 'SmsMessage;->newFromCDS']


def patch_apk(src, dest):
    """Write src with its classes.dex patched by PATCHES and the old v1 signature dropped."""
    with tempfile.TemporaryDirectory(dir=BULK / 'tmp') as tmp:
        tmp = Path(tmp)
        with zipfile.ZipFile(src) as z:
            infos = z.infolist()
            assert [i.filename for i in infos if i.filename.endswith('.dex')] == ['classes.dex']
            (tmp / 'classes.dex').write_bytes(z.read('classes.dex'))
        java = ['java', '-Djava.io.tmpdir=' + str(tmp)]
        subprocess.run(java + ['-jar', str(SMALI / 'baksmali.jar'), 'd', '-j', '1', '-o', str(tmp / 'smali'), str(tmp / 'classes.dex')], check=True)
        for rel, pattern, repl, count in PATCHES:
            f = tmp / 'smali' / rel
            text, n = re.subn(pattern, repl, f.read_text())
            assert n == count, f'{rel}: {pattern} matched {n} times, expected {count}'
            f.write_text(text)
        changed = 0
        for f in sorted((tmp / 'smali').rglob('*.smali')):
            text = f.read_text()
            if TM in text:
                f.write_text(text.replace(TM, 'Ljava/lang/Object;'))
                changed += 1
        assert changed == 4, f'TelephonyMetrics retyped in {changed} files, expected 4'
        left = [str(f.relative_to(tmp / 'smali')) for f in (tmp / 'smali').rglob('*.smali') if any(r in f.read_text() for r in REMOVED)]
        assert not left, left
        subprocess.run(java + ['-jar', str(SMALI / 'smali.jar'), 'a', '-j', '1', '-a', '30', '-o', str(tmp / 'patched.dex'), str(tmp / 'smali')], check=True)
        dex = (tmp / 'patched.dex').read_bytes()
        with zipfile.ZipFile(src) as zin, zipfile.ZipFile(dest, 'w') as zout:
            for i in infos:
                if re.fullmatch(r'META-INF/(MANIFEST\.MF|[^/]+\.(SF|RSA|DSA|EC))', i.filename):
                    continue
                zout.writestr(i, dex if i.filename == 'classes.dex' else zin.read(i.filename))


BP = '''// PRIVATE generated input; never export the proprietary directory.
// Stock com.mediatek.ims has sharedUserId android.uid.phone, so it must carry the
// platform certificate; stock signed it with MediaTek's demo platform key.
android_app_import {
    name: "ImsService",
    apk: "proprietary/ImsService.apk",
    certificate: "platform",
    privileged: true,
    system_ext_specific: true,
    dex_preopt: {
        enabled: false,
    },
    optional_uses_libs: [
        "com.mediatek.op.ims.common",
        "com.mediatek.ims.oemplugin",
        "com.mediatek.ims.plugin",
        "com.mediatek.ims.legacy",
        "com.mediatek.wfo.legacy",
    ],
}

// Boot jar, as on stock: the IMtkIms* AIDL types and MtkCallForwardInfo the APK uses.
// On /system/framework: system_ext lives in system here, and zygote only allows open
// boot jars under /system/framework/ or /system_ext/framework/.
dex_import {
    name: "mediatek-ims-base",
    jars: ["proprietary/mediatek-ims-base.jar"],
    use_generic_config: true,
}
'''


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    out = pocket_paths.private_vendor() / 'unihertz/titan_pocket/ims'
    (out / 'proprietary').mkdir(parents=True, exist_ok=True)
    records = []
    for name, (src, sha) in INPUTS.items():
        assert digest(src) == sha, f'{src} is not the January stock file'
        dest = out / 'proprietary' / name
        if name == 'ImsService.apk':
            patch_apk(src, dest)
            got = digest(dest)
            assert PATCHED_SHA is None or got == PATCHED_SHA, f'patched APK is {got}, expected {PATCHED_SHA}'
            records.append({'source': str(src), 'source_sha256': sha, 'destination': str(dest), 'sha256': got,
                            'patches': [{'file': p[0], 'pattern': p[1], 'count': p[3]} for p in PATCHES]})
            continue
        if not dest.exists() or digest(dest) != sha:
            shutil.copyfile(src, dest)
        assert digest(dest) == sha
        records.append({'source': str(src), 'destination': str(dest), 'sha256': sha})
    (out / 'Android.bp').write_text(BP)
    record = {'inputs': records, 'android_bp_sha256': digest(out / 'Android.bp'), 'output': str(out),
              'device_accessed': False, 'installed_only_with': 'POCKET_IMS=true'}
    evidence = ROOT / 'evidence/modem'
    evidence.mkdir(parents=True, exist_ok=True)
    (evidence / 'ims-inputs.json').write_text(json.dumps(record, indent=2) + '\n')
    print('Patched stock IMS APK and mediatek-ims-base staged in bulk storage: ' + str(out))


if __name__ == '__main__':
    main()
