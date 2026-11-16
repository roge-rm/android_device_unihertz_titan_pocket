#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Prepare and replay-check the lineage-sdk charging control reconnect, without editing baseline.

ChargingControlController takes vendor.lineage.health IChargingControl/default once at
boot and hands the same proxy to Deadline, Limit and Toggle. When the HAL process dies
and init restarts it, every call gets DeadObjectException until a reboot, so the
charging control setting does nothing (CHARGER_PORT.md). The patch wraps the HAL in a
proxy that fetches the service again when its binder is dead, and retries a call once
after a DeadObjectException.
"""
import pocket_paths
import difflib
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parent.parent
TARGET = 'lineage-sdk'
BASE = pocket_paths.platform_source() / TARGET
PATCH = ROOT / 'patches/android/0008-lineage-health-reconnect.patch'
OUTPUT = ROOT / 'artifacts/build-overrides/lineage-sdk'
RECORD = ROOT / 'evidence/connectivity/lineage-health-patch.json'
CONTROLLER = 'lineage/lib/main/java/org/lineageos/platform/internal/health/ChargingControlController.java'

PROXY = '''
    /**
     * Forwards to the charging control HAL. init restarts the HAL when it dies, so when
     * the binder is dead the service is fetched again (without waiting, so the health
     * thread doesn't block), and a call that hits a dead binder is retried once with a
     * fresh, live service or fails. The providers apply the mode again on the next battery
     * update.
     */
    private static final class ReconnectingChargingControl implements IChargingControl {
        private static final String NAME = IChargingControl.DESCRIPTOR + "/default";

        private interface Call<T> {
            T run(IChargingControl hal) throws RemoteException;
        }

        private IChargingControl mHal;

        ReconnectingChargingControl(IChargingControl hal) {
            mHal = hal;
        }

        private synchronized IChargingControl hal() throws RemoteException {
            if (mHal == null || !mHal.asBinder().isBinderAlive()) {
                IChargingControl fresh =
                        IChargingControl.Stub.asInterface(ServiceManager.checkService(NAME));
                if (fresh == null || !fresh.asBinder().isBinderAlive()) {
                    mHal = null;
                    throw new DeadObjectException("Lineage Health HAL is not running");
                }
                mHal = fresh;
                Log.i(TAG, "Reconnected to the Lineage Health HAL");
            }
            return mHal;
        }

        private synchronized void drop(IChargingControl dead) {
            if (mHal == dead) {
                mHal = null;
            }
        }

        private <T> T call(Call<T> call) throws RemoteException {
            IChargingControl hal = hal();
            try {
                return call.run(hal);
            } catch (DeadObjectException e) {
                drop(hal);
                return call.run(hal());
            }
        }

        @Override
        public boolean getChargingEnabled() throws RemoteException {
            return call(IChargingControl::getChargingEnabled);
        }

        @Override
        public void setChargingEnabled(boolean enabled) throws RemoteException {
            call(hal -> {
                hal.setChargingEnabled(enabled);
                return null;
            });
        }

        @Override
        public void setChargingDeadline(long deadline) throws RemoteException {
            call(hal -> {
                hal.setChargingDeadline(deadline);
                return null;
            });
        }

        @Override
        public int getSupportedMode() throws RemoteException {
            return call(IChargingControl::getSupportedMode);
        }

        @Override
        public long getChargingDeadline() throws RemoteException {
            return call(IChargingControl::getChargingDeadline);
        }

        @Override
        public ChargingLimitInfo getChargingLimit() throws RemoteException {
            return call(IChargingControl::getChargingLimit);
        }

        @Override
        public void setChargingLimit(ChargingLimitInfo limit) throws RemoteException {
            call(hal -> {
                hal.setChargingLimit(limit);
                return null;
            });
        }

        @Override
        public int getInterfaceVersion() throws RemoteException {
            return call(IChargingControl::getInterfaceVersion);
        }

        @Override
        public String getInterfaceHash() throws RemoteException {
            return call(IChargingControl::getInterfaceHash);
        }

        @Override
        public synchronized IBinder asBinder() {
            return mHal == null ? null : mHal.asBinder();
        }
    }
'''


def edit(text, old, new):
    assert text.count(old) == 1, old[:70]
    return text.replace(old, new, 1)


def main():
    old = (BASE / CONTROLLER).read_text()
    new = edit(old, 'import android.os.Handler;\n',
               'import android.os.DeadObjectException;\nimport android.os.Handler;\nimport android.os.IBinder;\n')
    new = edit(new, 'import vendor.lineage.health.IChargingControl;\n',
               'import vendor.lineage.health.ChargingLimitInfo;\nimport vendor.lineage.health.IChargingControl;\n')
    new = edit(new,
               '        mChargingControl = IChargingControl.Stub.asInterface(\n'
               '                ServiceManager.waitForDeclaredService(\n'
               '                        IChargingControl.DESCRIPTOR + "/default"));\n',
               '        IChargingControl hal = IChargingControl.Stub.asInterface(\n'
               '                ServiceManager.waitForDeclaredService(\n'
               '                        IChargingControl.DESCRIPTOR + "/default"));\n'
               '        mChargingControl = hal == null ? null : new ReconnectingChargingControl(hal);\n')
    # Insert the proxy class before the closing brace of the outer class.
    assert new.endswith('}\n')
    new = new[:-2] + PROXY + '}\n'
    files = {CONTROLLER: (old, new)}

    diff, hashes = [], {}
    for name, (a, b) in files.items():
        p = OUTPUT / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(b)
        full = TARGET + '/' + name
        diff += difflib.unified_diff(a.splitlines(True), b.splitlines(True), fromfile='a/' + full, tofile='b/' + full)
        hashes[name] = {'original': hashlib.sha256(a.encode()).hexdigest(), 'modified': hashlib.sha256(b.encode()).hexdigest()}
    for p in OUTPUT.rglob('*'):
        if p.is_file() and str(p.relative_to(OUTPUT)) not in files:
            p.unlink()
    PATCH.write_text(''.join(diff))
    with tempfile.TemporaryDirectory(prefix='lineage-health-patch-') as tmp:
        tree = Path(tmp)
        for name, (a, b) in files.items():
            p = tree / TARGET / name
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(a)
        subprocess.run(['patch', '--batch', '--fuzz=0', '-p1', '-d', tmp, '-i', str(PATCH)], check=True, capture_output=True)
        for name, (a, b) in files.items():
            assert (tree / TARGET / name).read_text() == b
    RECORD.write_text(json.dumps({'files': hashes, 'patch': str(PATCH.relative_to(ROOT)), 'replay_exact': True,
                                  'shared_source_modified': False, 'runtime_tested': False}, indent=2) + '\n')
    print('lineage-sdk charging control reconnect patch replays exactly; shared source unchanged')


if __name__ == '__main__':
    main()
