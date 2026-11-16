#!/usr/bin/env python3
"""Capture and unpack the pstore reader's ACM stream (USB serial TP510-PSTORE).

Passive: never writes to the port. Reuses capture_firstboot from capture-pocket-diagnostic.py, so
each enumeration goes to its own acm-NNN.log in --output. Then it parses every dump in those logs,
checks each frame's size and sha256, and writes the newest whole copy of each pstore file to
<output>/pstore/<name>, the newest whole kmsg to <output>/kmsg.txt and a summary to pstore.json.

--parse LOG... only parses logs that were already saved (no USB).

To end the reader early, send `reboot-bootloader` and a newline to the port yourself; otherwise it
restarts by itself 300 s after init.
"""
import argparse
import hashlib
import json
import re
import runpy
import signal
import sys
import threading
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SERIAL = 'TP510-PSTORE'      # kernel-upgrade/pstore-reader/init.c LABEL; change both together

DUMP = re.compile(rb'\n=== ' + SERIAL.encode() + rb' dump (\d+) at (\d+) ms ===\n')
FILE = re.compile(rb'=== file ([^ \n/]+) (\d+) sha256=([0-9a-f]{64})( truncated)? ===\n')
KMSG = re.compile(rb'=== kmsg (\d+) sha256=([0-9a-f]{64}) ===\n')
END = re.compile(rb'=== end dump (\d+) files=(\d+) ===\n')


def frame(data, pos, match, name, size, digest, end_marker):
    """Data of one frame starting at match; (record, next position) or (None, None) if cut or wrong."""
    start = match.end()
    body = data[start:start + size]
    tail = data[start + size:start + size + len(end_marker)]
    if len(body) < size or tail != end_marker:
        return None, None
    ok = hashlib.sha256(body).hexdigest() == digest
    return {'name': name, 'bytes': size, 'sha256': digest, 'sha256_ok': ok, 'data': body}, start + size + len(end_marker)


def parse_dump(data, header):
    """One dump from its header; whole is True only when every frame and the end line check out."""
    number, at = int(header.group(1)), int(header.group(2))
    pos = header.end()
    dump = {'dump': number, 'at_ms': at, 'offset': header.start(), 'files': [], 'kmsg': None, 'whole': False,
            'problem': None}
    first = data.find(b'=== ', pos)
    dump['banner'] = data[pos:first if first >= 0 else len(data)][:4096].decode('utf-8', 'replace')
    pos = first if first >= 0 else len(data)
    while True:
        m = FILE.match(data, pos)
        if not m:
            break
        name = m.group(1).decode('ascii', 'replace')
        record, nxt = frame(data, pos, m, name, int(m.group(2)), m.group(3).decode(),
                            b'\n=== end file ' + m.group(1) + b' ===\n')
        if record is None:
            dump['problem'] = 'file %s frame cut short' % name
            return dump
        record['truncated_by_reader'] = bool(m.group(4))
        dump['files'].append(record)
        pos = nxt
    m = KMSG.match(data, pos)
    if not m:
        dump['problem'] = 'no kmsg frame'
        return dump
    record, nxt = frame(data, pos, m, 'kmsg', int(m.group(1)), m.group(2).decode(), b'\n=== end kmsg ===\n')
    if record is None:
        dump['problem'] = 'kmsg frame cut short'
        return dump
    dump['kmsg'] = record
    m = END.match(data, nxt)
    if not m or int(m.group(1)) != number or int(m.group(2)) != len(dump['files']):
        dump['problem'] = 'end line missing or does not match'
        return dump
    bad = [f['name'] for f in dump['files'] + [dump['kmsg']] if not f['sha256_ok']]
    if bad:
        dump['problem'] = 'sha256 mismatch: ' + ', '.join(bad)
        return dump
    dump['whole'] = True
    dump['end'] = m.end()
    return dump


def parse_stream(data):
    """Every dump header in the stream, parsed; partial dumps (late attach, stall restart) are kept as not whole."""
    return [parse_dump(data, m) for m in DUMP.finditer(data)]


def summarize(dumps):
    """Newest whole copy of each file and of kmsg, plus whether the copies agree across dumps."""
    files, versions, kmsg = {}, {}, None
    for d in dumps:
        if not d['whole']:
            continue
        for f in d['files']:
            files[f['name']] = f
            versions.setdefault(f['name'], set()).add(f['sha256'])
        kmsg = d['kmsg']
    return files, versions, kmsg


def unpack(logs, output):
    report = {'logs': [], 'files': {}, 'kmsg': None}
    newest = {}
    newest_kmsg = None
    versions = {}
    for log in logs:
        data = Path(log).read_bytes()
        dumps = parse_stream(data)
        files, v, kmsg = summarize(dumps)
        newest.update(files)
        for k, s in v.items():
            versions.setdefault(k, set()).update(s)
        newest_kmsg = kmsg or newest_kmsg
        report['logs'].append({'log': str(log), 'bytes': len(data), 'sha256': hashlib.sha256(data).hexdigest(),
                               'dumps': [{k: v for k, v in d.items() if k not in ('files', 'kmsg', 'banner')} |
                                         {'files': [f['name'] for f in d['files']]} for d in dumps],
                               'whole_dumps': sum(d['whole'] for d in dumps),
                               'first_banner': next((d['banner'] for d in dumps), None)})
    if output:
        (output / 'pstore').mkdir(parents=True, exist_ok=True)
        for name, f in newest.items():
            (output / 'pstore' / name).write_bytes(f['data'])
        if newest_kmsg:
            (output / 'kmsg.txt').write_bytes(newest_kmsg['data'])
    report['files'] = {n: {'bytes': f['bytes'], 'sha256': f['sha256'], 'truncated_by_reader': f['truncated_by_reader'],
                           'same_in_every_whole_dump': len(versions[n]) == 1} for n, f in sorted(newest.items())}
    report['kmsg'] = {'bytes': newest_kmsg['bytes'], 'sha256': newest_kmsg['sha256']} if newest_kmsg else None
    report['whole_dumps'] = sum(l['whole_dumps'] for l in report['logs'])
    return report


def main():
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument('--output', type=Path)
    p.add_argument('--parse', nargs='+', type=Path, help='parse saved logs only; no USB')
    p.add_argument('--wait', type=float, default=120, help='give up if no gadget has appeared after this long')
    p.add_argument('--seconds', type=float, default=120, help='total run time, across disconnects')
    a = p.parse_args()
    if a.parse:
        result = unpack(a.parse, a.output)
        if a.output:
            a.output.mkdir(parents=True, exist_ok=True)
            (a.output / 'pstore.json').write_text(json.dumps(result, indent=2) + '\n')
        print(json.dumps(result, indent=2))
        sys.exit(0 if result['whole_dumps'] else 1)
    if not a.output:
        p.error('--output is needed for a capture')
    if not 0 < a.wait <= 3600 or not 0 < a.seconds <= 3600:
        p.error('wait and seconds must be 1 to 3600')
    capture = runpy.run_path(str(ROOT / 'tools/capture-pocket-diagnostic.py'), run_name='reader')
    a.output.mkdir(mode=0o700, parents=True, exist_ok=False)
    stop = threading.Event()
    for sig in (signal.SIGINT, signal.SIGTERM):
        signal.signal(sig, lambda *_: stop.set())
    print('Waiting for 1d6b:0104 / %s; passive capture, one file per enumeration, %d s' % (SERIAL, a.seconds), flush=True)
    raw = capture['capture_firstboot'](a.output, a.seconds, a.wait, SERIAL, stop=stop)
    logs = [a.output / e['file'] for e in raw['enumerations']]
    result = unpack(logs, a.output)
    result.update(usb_serial=SERIAL, capture=raw, commands_sent=False, recorded_utc=datetime.now(timezone.utc).isoformat())
    (a.output / 'pstore.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps({k: result[k] for k in ('files', 'kmsg', 'whole_dumps')}, indent=2))
    if not result['whole_dumps']:
        sys.exit('no whole dump received from ' + SERIAL)


if __name__ == '__main__':
    main()
