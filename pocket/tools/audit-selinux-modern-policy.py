#!/usr/bin/env python3
"""Audit local platform/kernel capability ABI without changing policy or kernel."""
import pocket_paths
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess

ROOT = Path(__file__).resolve().parent.parent
SHARED = pocket_paths.platform_source()
KERNEL = ROOT / 'tools/kernel-source/upgrade-5.10'


def main():
    output = ROOT / 'evidence/kernel-upgrade/selinux-nlmsg-review'
    output.mkdir(parents=True, exist_ok=True)
    kernel_cap = KERNEL / 'security/selinux/include/policycap.h'
    user_cap = SHARED / 'external/selinux/libsepol/include/sepol/policydb/polcaps.h'
    names_file = SHARED / 'external/selinux/libsepol/src/polcaps.c'
    policy = SHARED / 'system/sepolicy/private/policy_capabilities'
    kernel_ids = {name: i for i,name in enumerate(re.findall(r'\bPOLICYDB_CAPABILITY_(\w+),', kernel_cap.read_text()))}
    user_ids = {name: i for i,name in enumerate(re.findall(r'\bPOLICYDB_CAP_(\w+),', user_cap.read_text()))}
    names = dict(re.findall(r'\[POLICYDB_CAP_(\w+)\]\s*=\s*"([^"]+)"', names_file.read_text()))
    assert all(user_ids[name] == number for name,number in kernel_ids.items())
    assert len(kernel_ids) == 8 and user_ids['NETLINK_XPERM'] == 9 and user_ids['FUNCTIONFS_SECLABEL'] == 12
    enabled = re.findall(r'^\s*policycap\s+(\w+)\s*;', policy.read_text(), re.M)
    by_name = {name: symbol for symbol,name in names.items()}
    missing = [{'name': name, 'id': user_ids[by_name[name]]} for name in enabled if by_name[name] not in kernel_ids]
    rules = []
    for path in sorted((SHARED / 'system/sepolicy/private').glob('*.te')):
        for number,line in enumerate(path.read_text().splitlines(), 1):
            if re.match(r'^\s*(?:allowxperm|auditallowxperm)\b', line) and re.search(r'\bnlmsg\b', line):
                rules.append({'path': str(path.relative_to(SHARED)), 'line': number, 'rule': line.strip()})
    # Check clean upstream patch application on disposable copies, never the
    # engineering kernel or shared Boston tree. A rejected dry run is evidence.
    patch = ROOT / 'tools/kernel-source/selinux-nlmsg-reference/0001-upstream-netlink-xperm.patch'
    paths = re.findall(r'^\+\+\+ b/(.+)$', patch.read_text(), re.M)
    fixture = ROOT / 'tools/kernel-source/selinux-nlmsg-reference/5.10-dry-run'
    hashes = {}
    for name in paths:
        source = KERNEL / name
        destination = fixture / name
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, destination)
        hashes[name] = hashlib.sha256(source.read_bytes()).hexdigest()
    check = subprocess.run(['patch', '--dry-run', '--batch', '--fuzz=0', '-p1', '-d', str(fixture),
                            '--input', str(patch)], capture_output=True, text=True)
    (output / 'upstream-patch-dry-run.txt').write_text(check.stdout + check.stderr)
    assert all(hashlib.sha256((fixture/name).read_bytes()).hexdigest() == digest for name,digest in hashes.items())
    assert all(hashlib.sha256((KERNEL/name).read_bytes()).hexdigest() == digest for name,digest in hashes.items())
    hooks = KERNEL/'security/selinux/hooks.c'
    hooks_text = hooks.read_text()
    assert hooks_text.count('remove functionfs policycap check') == 2
    assert hooks_text.count('!strcmp(sb->s_type->name, "functionfs")') == 2
    inputs = [kernel_cap, user_cap, names_file, policy, hooks,
              KERNEL/'security/selinux/ss/avtab.c', KERNEL/'security/selinux/ss/services.c',
              KERNEL/'security/selinux/avc.c', SHARED/'system/sepolicy/private/net.te', patch]
    result = {'kernel_capabilities': kernel_ids, 'userspace_capabilities': user_ids,
              'inspected_platform_enabled_capabilities': enabled,
              'enabled_but_missing_kernel_capabilities': missing,
              'functionfs_handling': {'capability_enum_missing': True, 'donor_semantics_present_unconditionally': True, 'behavior_check': 'evidence/kernel-upgrade/selinux-nlmsg-review/functionfs-behavior-check.json'},
              'netlink_xperm_enabled_in_inspected_file': 'netlink_xperm' in enabled,
              'nlmsg_extended_rule_examples': rules,
              'naive_append_would_assign_netlink_id': len(kernel_ids),
              'required_netlink_id': user_ids['NETLINK_XPERM'],
              'upstream_dry_run': {'returncode': check.returncode, 'fuzz': 0, 'fixture_unchanged': True},
              'source_hashes': {str(p): hashlib.sha256(p.read_bytes()).hexdigest() for p in inputs},
              'shared_revisions': {name: subprocess.check_output(['git','-C',str(SHARED/name),'rev-parse','HEAD'],text=True).strip()
                                   for name in ['system/sepolicy','external/selinux']},
              'conclusion': 'NLMSG rules exist but the inspected platform capability file does not enable netlink_xperm. Missing runtime semantics alone is not a proven policy-load/boot blocker; FunctionFS capability ID is absent, but this donor already enables its genfs/in-core labeling behavior unconditionally; missing enum does not establish missing semantics.',
              'backport_requirements': ['Preserve numeric capability ABI, including intervening IDs',
                  'Include upstream base-permission cache isolation fix 5e7f0efd23238039bcd4fc72ff28d94f364ec26b',
                  'Preserve Android legacy route permissions and capability-disabled behavior',
                  'Adapt to 5.10 state parameters, audit, datum and socket-blob APIs',
                  'Review FunctionFS labeling and initial-SID prerequisites separately'],
              'limits': ['Static source-file audit, not compiled combined platform/vendor policy analysis',
                         'No complete policy-load, AVC regression or target enforcement test',
                         'No SELinux changes applied to the engineering kernel or shared sources',
                         'Dry run only establishes direct patch compatibility at zero fuzz']}
    (output / 'local-policy-audit.json').write_text(json.dumps(result, indent=2)+'\n')
    print(f'Capability ABI checked: {len(kernel_ids)} kernel, {len(user_ids)} userspace; FunctionFS ID 12 is absent but its donor handling is present unconditionally')
    print(f'Found {len(rules)} single-line NLMSG extended rules; inspected capability file leaves new netlink mode disabled')
    print('Upstream patch zero-fuzz dry-run exit:', check.returncode, '; no kernel or policy files modified')


if __name__ == '__main__':
    main()
