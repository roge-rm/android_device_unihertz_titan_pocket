#!/usr/bin/env python3
"""Capture only the identified TP-RECOVERY USB serial gadget; no commands sent."""
import argparse
from datetime import datetime, timezone
import errno
import hashlib
import json
import os
from pathlib import Path
import re
import select
import termios
import time
import tty


def find_port():
    matches = []
    for entry in Path('/sys/class/tty').glob('ttyACM*'):
        for ancestor in entry.resolve().parents:
            try:
                identity = tuple((ancestor / field).read_text().strip()
                                 for field in ('idVendor', 'idProduct', 'serial'))
            except OSError:
                continue
            if identity == ('1d6b', '0104', 'TP-RECOVERY'):
                matches.append(Path('/dev') / entry.name)
            break
    if len(matches) > 1:
        raise RuntimeError('Multiple matching gadgets; do not choose an arbitrary port')
    return matches[0] if matches else None


def capture(fd, output, seconds):
    """Read raw bytes with a deadline. Does not transmit or alter modem lines."""
    previous = termios.tcgetattr(fd)
    tty.setraw(fd, termios.TCSANOW)
    started = time.monotonic()
    end_reason = 'deadline'
    try:
        with output.open('xb') as stream:
            os.chmod(output, 0o600)
            while time.monotonic() - started < seconds:
                remaining = seconds - (time.monotonic() - started)
                if not select.select([fd], [], [], max(0, remaining))[0]:
                    break
                try:
                    data = os.read(fd, 65536)
                except OSError as error:
                    if error.errno in (errno.EIO, errno.ENODEV):
                        end_reason = 'disconnected'
                        break
                    if error.errno in (errno.EAGAIN, errno.EINTR):
                        continue
                    raise
                if not data:
                    end_reason = 'disconnected'
                    break
                stream.write(data)
    finally:
        try:
            termios.tcsetattr(fd, termios.TCSANOW, previous)
        except termios.error:
            pass  # Device may have restarted or disconnected.
    data = output.read_bytes()
    banner = re.search(rb'(?:^|\n)TP-RECOVERY Linux (4\.14[^\r\n ]*)', data)
    return {'bytes': len(data), 'sha256': hashlib.sha256(data).hexdigest(),
            'stock_kernel_banner_seen': bool(banner),
            'kernel_release': banner.group(1).decode() if banner else None,
            'end_reason': end_reason, 'commands_sent': False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True,
                        help='New private directory for this attempt')
    parser.add_argument('--wait', type=float, default=90)
    parser.add_argument('--seconds', type=float, default=40)
    args = parser.parse_args()
    if not 0 < args.wait <= 180 or not 0 < args.seconds <= 60:
        parser.error('Wait must be 1–180 seconds; capture must be 1–60 seconds')
    args.output.mkdir(mode=0o700, parents=True, exist_ok=False)
    deadline = time.monotonic() + args.wait
    print('Waiting for 1d6b:0104 / TP-RECOVERY; no phone command will be sent', flush=True)
    while True:
        port = find_port()
        if port:
            break
        if time.monotonic() >= deadline:
            raise SystemExit('No matching gadget appeared; no commands sent')
        time.sleep(0.2)
    fd = os.open(port, os.O_RDWR | os.O_NOCTTY | os.O_NONBLOCK)
    try:
        result = capture(fd, args.output / 'kernel.log', args.seconds)
    finally:
        os.close(fd)
    result.update(port=str(port), recorded_utc=datetime.now(timezone.utc).isoformat())
    (args.output / 'capture.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(result, indent=2))
    if not result['stock_kernel_banner_seen']:
        raise SystemExit('No stock-kernel logger banner: transport test did not pass')


if __name__ == '__main__':
    main()
