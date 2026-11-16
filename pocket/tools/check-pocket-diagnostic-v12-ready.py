#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Verify the combined v12 diagnostic's local provenance and the v12 deltas over v11 (the config
delta, the write budget with the RAM-only property file and tmpfs, the never-written list, the
forbidden teed options and the protected-partition compare); never access a phone."""
import hashlib
import json
import re
import runpy
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
EVIDENCE = ROOT / 'evidence/kernel-upgrade'
PACKAGE = EVIDENCE / 'diagnostic-package-v12'
PROBE = ROOT / 'kernel-upgrade/diagnostic-probe-v12'
TKCORE = 'tools/kernel-source/upgrade-5.10/drivers/misc/mediatek/tkcore'
MANIFEST = ROOT / 'backups/stock-20261029T001105.670723Z/manifest.json'
STOCK_HASHES = EVIDENCE / 'stock-partition-hashes-20261030.json'
V11_TRIAL_LOG = EVIDENCE / 'diagnostic-v11-trial-20261031T125837Z/capture1/kernel.log'

# super must stay byte-identical to the stock backup after the mounts and the teed run.
SUPER_BACKUP_SHA = '6f8764f8318282ee6a98b75abd25a1bbf79af9c85a504f2021c41f60ba24fc88'
# The only partition v12 ever writes; the restore returns it to stock.
WRITABLE_PARTITION = 'userdata'
# Nothing else is ever written (draft "Never written").
NEVER_WRITTEN = ['boot', 'super', 'recovery', 'vbmeta', 'dtbo', 'lk', 'preloader', 'proinfo', 'seccfg',
                 'sec1', 'frp', 'otp', 'nvram', 'nvdata', 'nvcfg', 'protect1', 'protect2', 'persist',
                 'md_udc', 'metadata', 'apd', 'expdb', 'para']
# Hashed before and after teed and compared with the stock backup.
PROTECTED = ['protect1', 'protect2', 'persist', 'nvdata', 'nvcfg', 'proinfo']
# The only .config lines that differ from v11.
CONFIG_DELTA = {'CONFIG_LOCALVERSION': ('"-titanpocket-ramdiag-v11"', '"-titanpocket-ramdiag-v12"'),
                'CONFIG_ADVISE_SYSCALLS': (None, 'y'),
                'CONFIG_TRUSTKERNEL_TEE_DIAGNOSTIC_LOGGER': (None, 'y')}
# RAM-only writes on top of v11's userdata budget: the property file on devtmpfs and the tmpfs.
PROPERTY_BYTES = 128 * 1024
TMPFS_BYTES = 16 << 20


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def read(path):
    return json.loads(Path(path).read_text())


def config_values(path):
    values = {}
    for line in Path(path).read_text().splitlines():
        if line.startswith('CONFIG_'):
            key, value = line.split('=', 1)
            values[key] = value
    return values


def protected_compare_checks(tmp):
    """The compare's protected-partition verdicts, through its functions and its command line."""
    tool = runpy.run_path(str(ROOT / 'tools/pocket-partition-hashes.py'), run_name='checked')
    manifest = read(MANIFEST)
    backup = {p['name']: p for p in manifest['partitions']}
    checks = 0
    assert tool['PROTECTED'] == PROTECTED and tool['BACKUP_MAY_DIFFER'] == {'nvcfg'}
    checks += 1

    def log(after=None, before=None, tk=None, drop_after=()):
        lines = ['TP510-RAM-V12: part-hash pass=before-teed partitions=6 t=30.00']
        for name in PROTECTED:
            h = (before or {}).get(name, backup[name]['raw_sha256'])
            lines.append(f'TP510-RAM-V12: part-hash name={name} bytes={backup[name]["bytes"]} sha256={h} seconds=0.20')
        lines.append('TP510-RAM-V12: part-hash pass=after-teed partitions=6 t=80.00')
        for name in PROTECTED:
            if name in drop_after:
                continue
            b = (before or {}).get(name, backup[name]['raw_sha256'])
            h = (after or {}).get(name, b)
            lines.append(f'TP510-RAM-V12: part-hash name={name} bytes={backup[name]["bytes"]} sha256={h} seconds=0.20')
            t = (tk or {}).get(name, (b, h))
            lines.append(f'TP510-RAM-V12: tk-hash name={name} before={t[0]} after={t[1]} match={int(t[0] == t[1])}')
        lines.append('TP510-RAM-V12: tk-hash compared=6 of 6 unchanged=6')
        return '\n'.join(lines) + '\n'

    def verdicts(text):
        passes, tk, _ = tool['parse_protected'](text)
        return {k: v for k, v in tool['compare_protected'](manifest, passes, tk).items()}

    rows = verdicts(log())
    assert all(r['verdict'] == 'unchanged' and r['tk_hash_agrees'] for r in rows.values()), rows
    checks += 1
    other = '0' * 64
    rows = verdicts(log(after={'persist': other}))
    assert rows['persist']['verdict'] == 'changed' and rows['nvdata']['verdict'] == 'unchanged'
    checks += 1
    # nvcfg may differ from the backup; the in-log pair decides.
    rows = verdicts(log(before={'nvcfg': other}))
    assert rows['nvcfg']['verdict'] == 'unchanged' and rows['nvcfg']['backup_after_match'] is False
    checks += 1
    rows = verdicts(log(before={'nvcfg': other}, after={'nvcfg': '1' * 64}))
    assert rows['nvcfg']['verdict'] == 'changed'
    checks += 1
    rows = verdicts(log(before={'protect1': other}))
    assert rows['protect1']['verdict'] == 'backup_mismatch'
    checks += 1
    rows = verdicts(log(drop_after=('proinfo',)))
    assert rows['proinfo']['verdict'] == 'incomplete'
    checks += 1
    rows = verdicts(log(tk={'protect2': (backup['protect2']['raw_sha256'], other)}))
    assert rows['protect2']['verdict'] == 'unchanged' and rows['protect2']['tk_hash_agrees'] is False
    checks += 1
    rows = verdicts('TP510-RAM-V11: part-hash name=persist bytes=1 sha256=' + other + '\n')
    assert all(r['verdict'] == 'missing' for r in rows.values())
    checks += 1
    # Command line on the real v11 trial log relabelled as v12, plus the protected lines.
    base = V11_TRIAL_LOG.read_text(errors='replace').replace('TP510-RAM-V11', 'TP510-RAM-V12')
    candidate = read(EVIDENCE / 'diagnostic-package-v11/candidate-validation.json')['candidate']['sha256']
    cases = [('clean', log(), 0), ('persist changed', log(after={'persist': other}), 1),
             ('nvcfg off backup', log(before={'nvcfg': other}), 0),
             ('protect1 off backup', log(before={'protect1': other}), 1),
             ('tk-hash disagrees', log(tk={'protect2': (backup['protect2']['raw_sha256'], other)}), 1),
             ('after pass missing', log(drop_after=tuple(PROTECTED)), 0)]
    results = []
    for name, extra, expected in cases:
        path = Path(tmp) / 'kernel.log'
        path.write_text(base + extra)
        r = subprocess.run([sys.executable, str(ROOT / 'tools/pocket-partition-hashes.py'), 'compare',
                            '--stock', str(STOCK_HASHES), '--log', str(path), '--candidate-sha256', candidate],
                           capture_output=True, text=True)
        assert r.returncode == expected, (name, r.returncode, r.stderr[-400:])
        out = json.loads(r.stdout)
        assert all(v['verdict'] == 'match' for v in out['compare'].values()), name
        assert set(out['protected']['compare']) == set(PROTECTED), name
        results.append({'case': name, 'returncode': r.returncode})
        checks += 1
    return checks, results


def main():
    checks = 0
    package = read(PACKAGE / 'candidate-validation.json')
    for item in [package['candidate'], package['restore_image']]:
        assert Path(item['path']).stat().st_size == item['bytes'] == 33554432
        assert digest(item['path']) == item['sha256']
    for path, expected in package['components'].items():
        assert digest(path) == expected, path
    assert digest(ROOT / 'tools/package-pocket-diagnostic.py') == package['builder_sha256']
    build = read(EVIDENCE / 'diagnostic-kernel-build-v12.json')
    assert build['returncode'] == 0 and build['engineering_config_unchanged']
    assert digest(ROOT / 'tools/build-pocket-diagnostic-kernel.py') == build['builder_sha256']
    assert digest(ROOT / 'configs/kernel-diagnostic-5.10-v12.fragment') == build['fragment_sha256']
    assert digest(Path(build['output']) / '.config') == build['config_sha256']
    for path, expected in build['source_hashes'].items():
        assert digest(Path(build['source']) / path) == expected, path
    for path, entry in build['artifacts'].items():
        assert digest(path) == entry['sha256'], path
    checks += 1
    ram = read(EVIDENCE / 'diagnostic-ramdisk-v12.json')
    for entry in ram['source_inputs'] + ram['files']:
        assert digest(ROOT / entry['path']) == entry['sha256'], entry['path']
    assert {x['path'] for x in ram['source_inputs']} >= {
        'kernel-upgrade/diagnostic-probe-v12/init.c', 'kernel-upgrade/ram-probe/init.c',
        'kernel-upgrade/ram-probe/ufs-readonly.h', 'kernel-upgrade/tkcore-probe/feature_query.h',
        'kernel-upgrade/diagnostic-probe-v12/probes.h', 'kernel-upgrade/ram-probe/commands.h',
        TKCORE + '/include/linux/tee_ioc.h', TKCORE + '/include/linux/tee_client_api.h'}
    assert '-I' + str(ROOT / TKCORE / 'include') in ram['command']
    # The ramdisk holds only init and three mount points, so the runtime mkdir of /mnt and /apex,
    # the /system and /vendor links and the O_EXCL property file never meet an existing entry.
    assert ram['members'] == ['dev', 'init', 'proc', 'sys']
    checks += 1
    board = read(EVIDENCE / 'diagnostic-board-v12.json')
    assert digest(board['board_dtb']['path']) == board['board_dtb']['sha256']
    for path, expected in board['generator_inputs'].items():
        assert digest(ROOT / path) == expected, path
    assert board['nodes'] == 955 and not board['phone_accessed']
    patches = read(EVIDENCE / 'patch-validation.json')
    assert len(patches) == 13
    replay_sources = {}
    for patch in patches:
        assert digest(patch['path']) == patch['sha256']
        for entry in patch['files']:
            assert digest(Path(build['source']) / entry['path']) == entry['sha256']
            replay_sources[entry['path']] = entry['sha256']
    assert replay_sources == build['source_hashes']
    avb = read(PACKAGE / 'host-avb-check.json')
    assert len(avb['cases']) == 7 and avb['source_hashes_before_and_after_match']
    assert digest(ROOT / 'tools/check-recovery-avb.py') == avb['runner_sha256']
    assert any(c.get('image_sha256') == package['candidate']['sha256'] and
               c.get('observed', {}).get('slot_data') for c in avb['cases'])
    capture = read(EVIDENCE / 'diagnostic-capture-check.json')
    assert capture['cases'] == 84 and capture['echo_cases'] == 12 and not capture['commands_sent']
    for path, expected in capture['source_hashes'].items():
        assert digest(ROOT / path) == expected
    fixup = read(EVIDENCE / 'diagnostic-lk-fixup-check-v12.json')
    assert len(fixup['cases']) == 2 and all(c['insertion_count'] == 19 and c['all_expected_results'] for c in fixup['cases'])
    for case in fixup['cases']:
        assert digest(case['input']) == case['sha256']
    args = read(EVIDENCE / 'lk-bootargs-check-v12.json')
    assert len(args['cases']) == 10
    for path, expected in args['input_hashes'].items():
        assert digest(path) == expected
    guard = read(EVIDENCE / 'tkcore-shm-guard-check-v12.json')
    assert guard['actual_guard_tested'] and guard['scenarios'] == 26
    driver = Path(build['source']) / 'drivers/misc/mediatek/tkcore/armtz/tee_tz_drv.c'
    assert 'of_reserved_mem_lookup(owner)' in driver.read_text()
    assert digest(driver) == guard['driver_sha256']
    assert 'devm_ioremap(dev, res->start' in (Path(build['source']) / 'drivers/usb/mtu3/mtu3_plat.c').read_text()
    checks += 1
    # ---- v12 config delta: v11's config plus madvise and the TEE log reader ----
    v11_build = read(EVIDENCE / 'diagnostic-kernel-build-v11.json')
    assert digest(Path(v11_build['output']) / '.config') == v11_build['config_sha256']
    old = config_values(Path(v11_build['output']) / '.config')
    new = config_values(Path(build['output']) / '.config')
    delta = {k: (old.get(k), new.get(k)) for k in set(old) | set(new) if old.get(k) != new.get(k)}
    assert delta == CONFIG_DELTA, delta
    config = (Path(build['output']) / '.config').read_text().splitlines()
    for entry in ['CONFIG_EXT4_FS=y', 'CONFIG_MD=y', 'CONFIG_BLK_DEV_DM=y', 'CONFIG_TMPFS=y', 'CONFIG_SHMEM=y',
                  'CONFIG_UNIX98_PTYS=y', 'CONFIG_DEVTMPFS=y', 'CONFIG_PROC_FS=y', 'CONFIG_FUTEX=y',
                  'CONFIG_MULTIUSER=y', 'CONFIG_BINFMT_ELF=y', 'CONFIG_ADVISE_SYSCALLS=y',
                  'CONFIG_TRUSTKERNEL_TEE_SUPPORT=y', 'CONFIG_TRUSTKERNEL_TEE_RAM_DIAGNOSTIC=y',
                  'CONFIG_TRUSTKERNEL_TEE_DIAGNOSTIC_LOGGER=y', 'CONFIG_OF_RESERVED_MEM=y',
                  'CONFIG_ARCH_KEEP_MEMBLOCK=y']:
        assert entry in config, entry
    # The SHM guard stays as v11 has it; RPMB stays off, so the kernel answers RPMB RPCs NOT_IMPLEMENTED.
    for banned in ['CONFIG_DM_CRYPT=y', 'CONFIG_DM_VERITY=y', 'CONFIG_DM_DEFAULT_KEY=y',
                   'CONFIG_FS_ENCRYPTION=y', 'CONFIG_F2FS_FS=y', 'CONFIG_SCSI_UFS_CRYPTO=y',
                   'CONFIG_TRUSTKERNEL_TEE_RPMB_SUPPORT=y', 'CONFIG_TEE=y', 'CONFIG_MODULES=y', 'CONFIG_NET=y']:
        assert banned not in config, banned
    assert 'CONFIG_LOCALVERSION="-titanpocket-ramdiag-v12"' in config
    assert 'CONFIG_WATCHDOG_OPEN_TIMEOUT=90' in config
    symbols = {s.split()[-1] for s in (Path(build['output']) / 'System.map').read_text().splitlines()}
    assert {'dm_linear_init', 'ext4_init_fs', 'tee_core_init'} <= symbols
    assert package['watchdog_userspace_ping_seconds'] == 330 and package['return_timer_seconds'] == 300
    assert package['usb_identity']['serial'] == 'TP510-RAM-V12'
    release = (Path(build['output']) / 'include/generated/utsrelease.h').read_text().split('"')[1]
    assert release == '5.10.257-titanpocket-ramdiag-v12+'
    checks += 1
    init = (PROBE / 'init.c').read_text()
    header = (PROBE / 'probes.h').read_text()
    for text in ['#define PROBE_LABEL "TP510-RAM-V12"', '#define PROBE_RETURN_SECONDS 300',
                 '#define PROBE_WATCHDOG_SECONDS (PROBE_RETURN_SECONDS + 30)', '#define PROBE_HASH_DEADLINE_SECONDS 250',
                 '#define PROBE_HASH_BUDGET_SECONDS 260', '#define PROBE_ECHO_SECONDS 60',
                 'tpufs_block_identity(&info, expected)', 'if (tp8_udc_name(entry->d_name))']:
        assert text in init, text
    assert 'V11' not in init and 'tp510-v11' not in init
    checks += 1
    # ---- read-only rule: userdata is the only block device opened writable ----
    opens = re.findall(r'open\(([^;]*?),\s*(O_[A-Z_0-9 |]+)(?:,\s*0[0-7]+)?\)', init)
    writable = sorted((path.strip(), flags) for path, flags in opens if 'O_RDWR' in flags or 'O_WRONLY' in flags)
    assert writable == sorted([
        ('"/dev/watchdog0"', 'O_WRONLY | O_CLOEXEC | O_NOFOLLOW'),
        ('node', 'O_RDWR | O_DIRECT | O_CLOEXEC | O_NOFOLLOW'),                  # userdata
        ('TK_HOST_PROPS', 'O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW'),  # devtmpfs file
        ('TK_PTS_DIR "/ptmx"', 'O_RDWR | O_NOCTTY | O_CLOEXEC'),                 # devpts
        ('path', 'O_RDWR | O_NOCTTY | O_CLOEXEC'),                                # pty slave
        ('path', 'O_RDWR | O_CLOEXEC | O_NOFOLLOW')]), writable                   # tkcore
    assert init.count('O_RDWR') == 4 and init.count('O_WRONLY') == 2 and 'O_RDWR' not in header
    assert '#define TK_HOST_PROPS "/dev/__properties__"' in init
    assert 'open(TK_HOST_PROPS, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0444)' in init
    assert '*slave = open(path, O_RDWR | O_NOCTTY | O_CLOEXEC);' in init and 'snprintf(path, sizeof(path), TK_PTS_DIR "/%u", number);' in init
    # The tkcore open is only taken for the misc device's own node.
    teec_open = init.split('static int tk_teec_open', 1)[1].split('\n}\n', 1)[0]
    assert '/sys/class/misc/tkcoredrv/dev' in teec_open and 'st.st_rdev != expected' in teec_open
    assert 'open(node, O_RDWR | O_DIRECT | O_CLOEXEC | O_NOFOLLOW)' in init
    assert 'open("/dev/mapper/control", O_RDONLY | O_CLOEXEC | O_NOFOLLOW)' in init
    checks += 1
    # Mounts: v11's test mount, the v12 system/vendor mount (exec allowed for teed), tmpfs and devpts.
    mounts = re.findall(r'(?<![\w])mount\(([^;]*?)\)[;,)]', init)
    assert sorted(m.split(',')[0].strip() for m in mounts) == ['"devpts"', '"tmpfs"', 'node', 'node'], mounts
    assert 'mount(node, mountpoint, "ext4", MS_RDONLY | MS_NODEV | MS_NOSUID | MS_NOEXEC, "noload")' in init
    assert 'mount(node, h->mountpoint[i], "ext4", MS_RDONLY | MS_NODEV | MS_NOSUID, "noload")' in init
    assert 'static const char *const tk_host_parts[TK_HOST_MOUNTS] = {"system", "vendor"};' in init
    assert 'mount("tmpfs", TK_HOST_ROOT, "tmpfs", MS_NODEV | MS_NOSUID | MS_NOEXEC, "size=16m,nr_inodes=2048,mode=0770,uid=1000,gid=1000")' in init
    assert 'mount("devpts", TK_PTS_DIR, "devpts", MS_NOSUID | MS_NOEXEC, "newinstance,ptmxmode=0600,mode=0600")' in init
    assert init.count('DM_READONLY_FLAG') == 1 and 'load->flags = DM_READONLY_FLAG' in header and 'DM_SUSPEND_FLAG' not in init
    assert 'BLKDISCARD' not in init and 'BLKDISCARD' not in header and 'mkfs' not in init
    # persist and protect_f stay unmounted, and no RPMB node is named.
    for banned in ['/dev/block/by-name', 'rpmb', 'mmcblk', '"protect1"', '"protect2"', '/protect_f']:
        assert banned not in init, banned
    # "persist" and "protect_f" only name tmpfs subdirectories.
    assert [l for l in init.splitlines() if '"persist"' in l] == [
        'static const char *const tk_host_dirs[] = {"persist", "persist/t6", "protect_f", "protect_f/tee", "fs", "app"};']
    checks += 1
    # ---- teed: stock binary from the read-only vendor mount, no environment, no inherited fds ----
    assert '#define TK_TEED_PATH "/vendor/bin/teed"' in init and 'char *envp[] = {NULL};' in init
    assert 'execve(TK_TEED_PATH, argv, envp);' in init and init.count('execve(') == 1
    assert 'for (int fd = 3; fd < 1024; ++fd) close(fd);' in init
    assert 'static const char *const tp12_teed_forbidden[] = {"--rpmbdev", "--sdrpmbdev", "--prebuilt", "--nofrp", "-p", "-r"};' in header
    assert 'tp12_teed_build(&b, TK_HOST_ROOT)' in init and '#define TK_HOST_ROOT "/mnt/tk-tmp"' in init
    probes = read(EVIDENCE / 'diagnostic-probes-check-v12.json')
    assert probes['checks'] == 178 and not probes['device_accessed']
    assert digest(ROOT / 'evidence/kernel-upgrade/v12-teed-contract/libteec-context-session.txt') == probes['libteec_evidence_sha256']
    # The TEEC client issues what stock libteec does for a context and a no-operation session:
    # the feature query and the open-session ioctl, with a zeroed operation and fd_sess -1, no SHM.
    client = header.split('static int tp12_teec_open_session(', 1)[1].split('\n}\n', 1)[0]
    assert re.findall(r'ops->ioctl\(ctx, fd, (\w+)', client) == ['TP12_TEEC_VERSION_IOC', 'TP12_TEEC_OPEN_SESSION_IOC'], client
    assert 'tee_shm_io' not in client and 'fd_shm' not in client
    fill = header.split('static void tp12_teec_fill_open(', 1)[1].split('\n}\n', 1)[0]
    for line in ['memset(op, 0, sizeof(*op));', 'io->origin = TEEC_ORIGIN_API;', 'io->fd_sess = -1;', 'io->op = op;']:
        assert line in fill, line
    assert digest(PROBE / 'probes.h') == probes['header_sha256']
    assert digest(PROBE / 'init.c') == probes['init_sha256']
    assert digest(ROOT / 'tools/check-pocket-diagnostic-v12-probes.py') == probes['validator_sha256']
    assert digest(ROOT / TKCORE / 'include/linux/tee_ioc.h') == probes['tee_ioc_sha256']
    assert digest(ROOT / TKCORE / 'include/linux/tee_client_api.h') == probes['tee_client_api_sha256']
    # The pinned argv the probe check runs puts every writable path under the tmpfs.
    checker = (ROOT / 'tools/check-pocket-diagnostic-v12-probes.py').read_text()
    argv = re.search(r'EXPECT_ARGV=\[(.*?)\]', checker, re.S).group(1)
    for option in ['--rpmbdev', '--sdrpmbdev', '--prebuilt', '--nofrp', "'-p'", "'-r'"]:
        assert option not in argv, option
    for option in ['--prot', '--datapath', '--sptapath', '--logpath']:
        assert re.search(re.escape(option) + r"',\s*TMPFS_ROOT\+", argv), option
    checks += 1
    # ---- time budget: hosting and teed phases skip themselves when late ----
    assert '#define TK_HOST_LATEST_START_SECONDS 90' in init
    for text in ['#define TP12_TEED_WAIT_SECONDS 30.0', '#define TP12_SESSION_SECONDS 20.0',
                 '#define TP12_STOP_SECONDS 5.0', '#define TP12_SUPER_HASH_SECONDS 139.0']:
        assert text in header, text
    checks += 1
    # ---- write budget: v11's userdata test, plus RAM-only writes ----
    assert '#define TP10_USERDATA_REGION (1ull << 20)' in init
    assert '#define TP10_USERDATA_MIN_BYTES (64ull << 20)' in init
    assert '#define TP10_WRITE_BUDGET ((2ull << 20) + TP10_BLOCK)' in init and '#define TP10_BLOCK 4096u' in init
    assert '#define TP10_WR_BLOCK 4096u' in header
    assert 'r.budget = 2ull * region + TP10_WR_BLOCK;' in header
    assert '(size_t)TP10_USERDATA_REGION, region_offset / 512' in init
    assert 'size_bytes - TP10_USERDATA_REGION' in init
    assert 'if (size_bytes < TP10_USERDATA_MIN_BYTES)' in init
    assert 'tp10_partition_node(disk, part, lbs, controller, "userdata"' in init
    assert '#define TP12_PROP_AREA_SIZE (128u * 1024u)' in header and PROPERTY_BYTES == 128 * 1024
    assert 'size=16m' in init and TMPFS_BYTES == 16 << 20
    checks += 1
    # ---- never written: protected pass around teed inside the mount test, super hashed last ----
    assert '{"lk", "dtbo", "vbmeta", "boot", "recovery"}' in init and '"super"' not in init.split('static const char *const hash_targets', 1)[1].split('}', 1)[0]
    assert 'static const char *const tp12_protected[] = {"protect1", "protect2", "persist", "nvdata", "nvcfg", "proinfo"};' in header
    order = [init.index(s) for s in ['tp8_hash_range(fd, part->name', 'userdata_write_test(disk',
                                     'super_mount_test(disk', 'tp8_hash_range(fd, "super"']]
    assert order == sorted(order), 'super must be hashed last, after the write and mount tests'
    phase = init.split('static void super_mount_test', 1)[1]
    steps = [phase.index(s) for s in ['tk_host_setup(&host, control, dev, &lp)', 'tk_teed_phase(&phase, hash_disk)',
                                      'tk_host_teardown(&host);', 'tk_protected_pass(&phase, hash_disk, "after")']]
    assert steps == sorted(steps)
    tk_phase = init.split('static void tk_teed_phase', 1)[1].split('\n}\n', 1)[0]
    assert tk_phase.index('tk_protected_pass(ph, d, "before")') < tk_phase.index('tk_teed_start')
    limits = ' '.join(package['limits'])
    assert 'last 1 MiB of userdata' in limits and 'restored on exit' in limits
    assert 'one keymaster TA session opened and closed' in limits
    checks += 1
    # ---- protected-partition compare against the stock backup ----
    manifest = read(MANIFEST)
    assert manifest['status'] == 'verified'
    backup = {p['name']: p for p in manifest['partitions']}
    for name in PROTECTED:
        assert backup[name]['verified'] and re.fullmatch('[0-9a-f]{64}', backup[name]['raw_sha256'])
    with tempfile.TemporaryDirectory() as tmp:
        compare_checks, compare_cases = protected_compare_checks(tmp)
    checks += compare_checks
    # ---- probe helper, UFS and ownership-ledger provenance ----
    ufs = read(EVIDENCE / 'ufs-readonly-check.json')
    assert ufs['host_asan_ubsan_passed'] and ufs['actual_functions_tested']
    assert digest(ROOT / 'kernel-upgrade/ram-probe/ufs-readonly.h') == ufs['header_sha256']
    ownership = read(EVIDENCE / 'security-contract-20261030/tee1-inspection/shm-ownership-ledger.json')
    for path, expected in ownership['source_sha256'].items():
        assert digest(ROOT / path) == expected
    assert digest(ROOT / ownership['stock_log']['path']) == ownership['stock_log']['sha256']
    checks += 1
    evidence = [PACKAGE / 'candidate-validation.json', PACKAGE / 'host-avb-check.json', MANIFEST, STOCK_HASHES]
    evidence += [EVIDENCE / n for n in [
        'diagnostic-kernel-build-v12.json', 'diagnostic-ramdisk-v12.json', 'diagnostic-board-v12.json',
        'patch-validation.json', 'diagnostic-capture-check.json', 'diagnostic-lk-fixup-check-v12.json',
        'lk-bootargs-check-v12.json', 'ufs-readonly-check.json', 'tkcore-shm-guard-check-v12.json',
        'security-contract-20261030/tee1-inspection/shm-ownership-ledger.json', 'diagnostic-probes-check-v12.json',
        'diagnostic-kernel-build-v11.json']]
    preflight = None
    preflight_path = PACKAGE / 'host-preflight.json'
    if preflight_path.exists():
        preflight = read(preflight_path)
        assert preflight['host_preflight_passed'] and preflight['variant'] == 'v12'
        assert preflight['stock_hashes']['recovery'] == package['restore_image']['sha256']
        assert preflight['staged'][0]['sha256'] == package['candidate']['sha256']
        for name in ['capture-pocket-diagnostic.py', 'capture-recovery-probe.py', 'collect-pocket-diagnostic-return.py', 'pocket-partition-hashes.py']:
            assert any(Path(e['path']).name == name and e['sha256'] == digest(ROOT / 'tools' / name) for e in preflight['staged'])
        evidence.append(preflight_path)
    record = {
        'utc': datetime.now(timezone.utc).isoformat(), 'offline_preparation_complete': True,
        'checks': checks, 'protected_compare_cases': compare_cases,
        'candidate': package['candidate'], 'stock_restore': package['restore_image'],
        'expected_kernel_release': release,
        'usb_identity': package['usb_identity'], 'host_staged': preflight is not None,
        'host_preflight_utc': preflight['utc'] if preflight else None,
        'writable_partition': WRITABLE_PARTITION, 'never_written': NEVER_WRITTEN,
        'protected_partitions': PROTECTED, 'protected_backup': str(MANIFEST.relative_to(ROOT)),
        'super_backup_sha256': SUPER_BACKUP_SHA, 'write_budget_bytes': (2 << 20) + 4096,
        'ram_only_writes': {'/dev/__properties__': PROPERTY_BYTES, '/mnt/tk-tmp tmpfs': TMPFS_BYTES},
        'config_delta_from_v11': {k: list(v) for k, v in CONFIG_DELTA.items()},
        'kernel_execution_attempted': False, 'ready_for_unattended_flash': False,
        'evidence_sha256': {str(p): digest(p) for p in evidence},
        'validator_sha256': digest(Path(__file__)),
        'remaining': ['Reviewer pass on the v12 diff, then owner approval for the trial',
                      'Fresh host/stock/root/hash/BCB/battery preflight and exact-restore staging',
                      'Owner present for recovery-only write and finite Volume Up sequence',
                      'Phone only: the bootstrap linker starting teed, userinit, the KM TA load and session, and the six protected hashes unchanged before and after',
                      'If the console shows "userdata restore FAILED" or no restore line, wipe data in stock recovery before boot'],
        'limits': ['Static REA establishes the stock teed contract, not its execution under this init',
                   'Kernel configures UFS and negotiates secure SHM/RoT; with the TEE log reader on, it also runs the OS-revision and GET_LOGM_CONFIG SMCs and the log thread; the whole boot is not read-only',
                   'The only writable block-device open is userdata, its last 1 MiB restored on exit; budget 2 MiB + 4 KiB. The property file (128 KiB, devtmpfs) and the 16 MiB tmpfs are RAM only',
                   'teed runs as uid 1000 with CAP_SYS_RAWIO only; devtmpfs block nodes are root 0600, so it cannot open them, but the TEE OS itself may write persistent storage, which only the protected re-hash shows',
                   'nvcfg changed during the stock backup, so its verdict is the in-log before/after pair',
                   'Not a LineageOS ROM or an installation/hardware-parity qualification']}
    (PACKAGE / 'readiness.json').write_text(json.dumps(record, indent=2) + '\n')
    print(f'Combined v12 local provenance, config delta, write budget, never-written list, teed options and '
          f'protected compare pass ({checks} checks); fresh host preflight and attended boot remain')


if __name__ == '__main__':
    main()
