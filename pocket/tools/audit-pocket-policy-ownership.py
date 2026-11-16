#!/usr/bin/env python3
"""Read-only static ownership ledger for saved policy failures and stock services.

Private reports can contain shipped rules/config. Never emits or edits policy.
Attribute evaluation is explicitly bounded to type/alias/set expressions, not a
SELinux compiler, authorization evaluator or proof that a service executes.
"""
import argparse
import collections
import importlib.util
import json
from pathlib import Path
import re
import shlex
import struct

ROOT = Path(__file__).resolve().parent.parent


def module(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / 'tools' / filename)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


CIL = module('ownership_cil', 'audit-pocket-policy-compat.py')
ELF = module('ownership_elf', 'audit-m2-vendor-contract.py')


class TypeSets:
    def __init__(self, documents, omitted_sets=(), omitted_assignments=()):
        self.types = {s[1] for doc in documents.values() for s in doc if s[0] == 'type'}
        self.attributes = {s[1] for doc in documents.values() for s in doc if s[0] == 'typeattribute'}
        self.aliases = {s[1]: s[2] for doc in documents.values() for s in doc if s[0] == 'typealiasactual'}
        self.sets = collections.defaultdict(list)
        for name, doc in documents.items():
            if name in omitted_sets:
                continue
            for s in doc:
                if s[0] == 'typeattributeset' and (name, s[1]) not in omitted_assignments:
                    self.sets[s[1]].append(s[2])
        self.cache = {}

    def expression(self, value, active=()):
        if isinstance(value, str):
            if value == 'all':
                return set(self.types)
            if value in self.types:
                return {value}
            if value in self.cache:
                return set(self.cache[value])
            if value in active:
                raise ValueError('Attribute cycle: ' + ' -> '.join(active + (value,)))
            if value in self.aliases:
                return self.expression(self.aliases[value], active + (value,))
            if value not in self.attributes and value not in self.sets:
                raise ValueError('Unknown type/attribute: ' + value)
            result = set()
            for expr in self.sets[value]:
                result |= self.expression(expr, active + (value,))
            self.cache[value] = result
            return set(result)
        if not value:
            return set()
        if isinstance(value[0], str) and value[0] in {'and', 'or', 'xor', 'not'}:
            op, *operands = value
            if not operands or (op == 'not' and len(operands) != 1):
                raise ValueError('Unsupported operator arity')
            results = [self.expression(x, active) for x in operands]
            if op == 'not':
                return self.types - results[0]
            result = results[0]
            for other in results[1:]:
                result = (result & other if op == 'and' else
                          result | other if op == 'or' else result ^ other)
            return result
        result = set()
        for member in value:
            result |= self.expression(member, active)
        return result

    def summary(self, value):
        try:
            members = sorted(self.expression(value))
            return {'status': 'resolved-static-set', 'count': len(members), 'members': members}
        except ValueError as error:
            return {'status': 'unknown', 'reason': str(error)}


def set_intersection_witness(model, assertion, grant):
    """Type-pair witnesses only; preserve self correlation on either endpoint."""
    try:
        subjects = model.expression(assertion[1]) & model.expression(grant[1])
        if assertion[2] == 'self' or grant[2] == 'self':
            targets = subjects
            if assertion[2] != 'self':
                targets &= model.expression(assertion[2])
            if grant[2] != 'self':
                targets &= model.expression(grant[2])
            pairs = [(t, t) for t in sorted(targets)[:4]]
            count = len(targets)
        else:
            targets = model.expression(assertion[2]) & model.expression(grant[2])
            pairs = [(s, t) for s in sorted(subjects)[:4] for t in sorted(targets)[:4]][:4]
            count = len(subjects) * len(targets)
        same_class = assertion[3][0] == grant[3][0]
        permissions = sorted(set(assertion[3][1]) & set(grant[3][1])) if same_class else []
        return {'status': 'resolved-static-set', 'type_pair_count': count if permissions else 0,
                'example_pairs': pairs if permissions else [], 'overlapping_permissions': permissions}
    except ValueError as error:
        return {'status': 'unknown', 'reason': str(error)}


def section_file(path):
    logical = []
    pending, first = '', 0
    for line, text in enumerate(path.read_text().splitlines(), 1):
        if not pending:
            first = line
        pending += text.rstrip()[:-1] + ' ' if text.rstrip().endswith('\\') else text
        if text.rstrip().endswith('\\'):
            continue
        try:
            shlex.split(pending, comments=True)
        except ValueError as error:
            if str(error) != 'No closing quotation':
                raise
            # Init permits quoted tokens containing physical newlines.
            pending += '\n'
            continue
        logical.append((first, pending))
        pending = ''
    if pending:
        raise ValueError('Unclosed init continuation: ' + str(path))
    sections = []
    current = None
    for line, text in logical:
        parts = shlex.split(text, comments=True)
        if not parts:
            continue
        if not text[0].isspace():
            current = None
            if parts[0] in {'on', 'service'}:
                current = {'file': str(path), 'line': line, 'header': parts, 'body': []}
                sections.append(current)
        elif current is not None:
            current['body'].append({'line': line, 'tokens': parts})
    return sections


def family(name):
    if any(x in name for x in ('keymaster', 'keymanage', 'keyinstall', 'attestation', 'soter', 'tee')):
        return 'tee-key-provisioning'
    if 'camer' in name:
        return 'camera'
    if 'therm' in name:
        return 'thermal'
    if 'charg' in name or 'batterywarning' in name:
        return 'charging'
    if 'ril' in name or 'radio' in name:
        return 'radio'
    return None


def failure_class(statement):
    cls = statement[3][0]
    if cls == 'property_service':
        return 'property-set-ownership'
    if cls in {'service_manager', 'hwservice_manager', 'binder'}:
        return 'ipc-service-boundary'
    if cls == 'process':
        return 'process-isolation'
    if cls in {'capability', 'capability2', 'cap_userns', 'cap2_userns', 'system'}:
        return 'privileged-operations'
    if cls in {'bpf'}:
        return 'bpf-ownership'
    if cls.endswith('socket'):
        return 'socket-network-boundary'
    if cls == 'filesystem':
        return 'filesystem-mount-boundary'
    if cls.endswith('file') or cls == 'dir':
        return 'file-label-ownership'
    return 'other-' + cls


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--compile-record', type=Path, required=True)
    p.add_argument('--stock-compile-record', type=Path,
                   help='Optional hash-verified successful stock split-policy input set')
    p.add_argument('--triage', type=Path, required=True)
    p.add_argument('--stock', type=Path, required=True)
    p.add_argument('--rea-headers', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    a = p.parse_args()
    hashes = {}
    record = json.loads(a.compile_record.read_text())
    documents = {}
    for name, expected in record['input_hashes'].items():
        path = Path(name).resolve()
        if CIL.digest(path) != expected:
            raise ValueError('Changed policy input: ' + str(path))
        hashes[str(path)] = expected
        documents[str(path)] = CIL.forms(path.read_text())
    for path in (a.compile_record, a.triage, a.rea_headers):
        hashes[str(path.resolve())] = CIL.digest(path)
    triage = json.loads(a.triage.read_text())
    log = ROOT / record['log']
    if CIL.digest(log) != triage['log_sha256']:
        raise ValueError('Triage does not describe this saved compile log')
    hashes[str(log.resolve())] = CIL.digest(log)
    snapshot = next(name for name in documents if name.endswith('/plat_pub_versioned.cil'))
    vendor = next(name for name in documents if name.endswith('/vendor_sepolicy.cil'))
    platform = next(name for name in documents if name.endswith('/soong-platform.cil'))
    model = TypeSets(documents)
    stock_model = None
    if a.stock_compile_record:
        stock_record = json.loads(a.stock_compile_record.read_text())
        if stock_record['returncode'] != 0:
            raise ValueError('Stock comparison requires a successful compile record')
        hashes[str(a.stock_compile_record.resolve())] = CIL.digest(a.stock_compile_record)
        stock_documents = {}
        for name, expected in stock_record['input_hashes'].items():
            path = Path(name).resolve()
            if CIL.digest(path) != expected:
                raise ValueError('Changed stock comparison input: ' + str(path))
            hashes[str(path)] = expected
            stock_documents[str(path)] = CIL.forms(path.read_text())
        stock_model = TypeSets(stock_documents)
    # Same complete declaration universe in each model: this isolates set
    # assignment effects and is NOT an independently compilable baseline.
    without_snapshot_sets = TypeSets(documents, {snapshot})
    modern_attrs = {s[1] for s in documents[platform] if s[0] == 'typeattribute'}
    snapshot_assignments = collections.defaultdict(list)
    for ordinal, s in enumerate(documents[snapshot], 1):
        if s[0] == 'typeattributeset':
            snapshot_assignments[s[1]].append({'form': ordinal, 'expression': s[2]})
    deltas, delta_unknowns = [], []
    for attr in sorted(modern_attrs & snapshot_assignments.keys()):
        try:
            before = without_snapshot_sets.expression(attr)
            after = model.expression(attr)
            if before != after:
                deltas.append({'attribute': attr, 'without_snapshot_assignment_count': len(before),
                               'with_snapshot_assignment_count': len(after),
                               'added_members': sorted(after - before), 'removed_members': sorted(before - after),
                               'snapshot_assignments': snapshot_assignments[attr]})
        except ValueError as error:
            delta_unknowns.append({'attribute': attr, 'reason': str(error)})
    recovered = []
    for name in ['base_typeattr_184_30_0', 'base_typeattr_376_30_0', 'base_typeattr_405_30_0',
                 'base_typeattr_476_30_0', 'base_typeattr_480_30_0', 'base_typeattr_502_30_0']:
        uses = []
        for ordinal, s in enumerate(documents[vendor], 1):
            if name in set(CIL.atoms(s)):
                uses.append({'form': ordinal, 'kind': s[0], 'statement': s})
        row = {'symbol': name, 'definition_fragment': snapshot,
               'definitions': snapshot_assignments[name],
               'vendor_uses': uses, 'current_members': model.summary(name)}
        if stock_model:
            row['stock_members'] = stock_model.summary(name)
            if row['stock_members']['status'] == row['current_members']['status'] == 'resolved-static-set':
                row['added_members'] = sorted(set(row['current_members']['members']) - set(row['stock_members']['members']))
                row['removed_members'] = sorted(set(row['stock_members']['members']) - set(row['current_members']['members']))
        recovered.append(row)
    classified = []
    no_changed_shared_assignments = TypeSets(documents, omitted_assignments={
        (snapshot, row['attribute']) for row in deltas})
    for number, failure in enumerate(triage['failures'], 1):
        assertion = CIL.forms(failure['assertion'])[0]
        subject = model.summary(assertion[1])
        target = subject if assertion[2] == 'self' else model.summary(assertion[2])
        witnesses = []
        for grant in failure['reported_allow_rules']:
            parsed = CIL.forms(grant['statement'])[0]
            witnesses.append({'grant_file': grant['file'], 'grant_line': grant['line'],
                              'with_all_assignments': set_intersection_witness(model, assertion, parsed),
                              'without_changed_snapshot_shared_assignments':
                                  set_intersection_witness(no_changed_shared_assignments, assertion, parsed)})
        classified.append({'ordinal': number, 'category': failure_class(assertion),
                           'class': assertion[3][0], 'assertion_location': failure['assertion_location'],
                           'assertion': assertion, 'subject': subject, 'target': target,
                           'reported_allow_rules': failure['reported_allow_rules'],
                           'reported_grant_type_pair_witnesses': witnesses,
                           'compiler_truncated_matches': failure['compiler_truncated_matches']})
    stock = a.stock.resolve()
    init_dirs = [stock / suffix for suffix in ['system/system/etc/init',
                 'system/system/system_ext/etc/init', 'vendor/etc/init',
                 'product/etc/init', 'system/system/product/etc/init']]
    init_files = sorted(set(stock.glob('*.rc')) | {path for directory in init_dirs
                       for path in directory.rglob('*.rc') if path.is_file()})
    sections = []
    for path in init_files:
        sections += section_file(path)
        hashes[str(path)] = CIL.digest(path)
    labels = []
    property_labels = collections.defaultdict(list)
    for directory in [stock / suffix for suffix in ['system/system/etc/selinux',
                      'system/system/system_ext/etc/selinux', 'vendor/etc/selinux',
                      'product/etc/selinux', 'system/system/product/etc/selinux']]:
        for path in sorted(directory.glob('*file_contexts')):
            hashes[str(path)] = CIL.digest(path)
            for line, text in enumerate(path.read_text().splitlines(), 1):
                parts = text.split()
                if not parts or parts[0].startswith('#'):
                    continue
                match = re.search(r'u:object_r:([^:]+):s0', text)
                if match:
                    labels.append({'file': str(path), 'line': line,
                                   'regex': parts[0], 'type': match[1]})
        for path in sorted(directory.glob('*property_contexts')):
            hashes[str(path)] = CIL.digest(path)
            for line, text in enumerate(path.read_text().splitlines(), 1):
                parts = text.split()
                if not parts or parts[0].startswith('#'):
                    continue
                match = re.search(r'u:object_r:([^:]+):s0', text)
                if match:
                    property_labels[match[1]].append({'file': str(path), 'line': line,
                                                     'tokens': parts})
    transitions = []
    for name, doc in documents.items():
        for ordinal, s in enumerate(doc, 1):
            if s[0] == 'typetransition' and len(s) == 5 and s[1] in {'init', 'init_30_0'} and s[3] == 'process':
                transitions.append({'fragment': name, 'form': ordinal,
                                    'exec_type': s[2], 'domain': s[4]})
    stock_transitions = []
    for path in [stock / 'system/system/etc/selinux/plat_sepolicy.cil',
                 stock / 'system/system/system_ext/etc/selinux/system_ext_sepolicy.cil',
                 stock / 'vendor/etc/selinux/vendor_sepolicy.cil']:
        hashes[str(path)] = CIL.digest(path)
        for ordinal, s in enumerate(CIL.forms(path.read_text()), 1):
            if s[0] == 'typetransition' and len(s) == 5 and s[1] in {'init', 'init_30_0'} and s[3] == 'process':
                stock_transitions.append({'fragment': str(path), 'form': ordinal,
                                          'exec_type': s[2], 'domain': s[4]})
    rea = json.loads(a.rea_headers.read_text())
    rea_by_path = {item['evidence']['subject']['local_path']: item['evidence'] for item in rea}
    services = []
    for section in sections:
        header = section['header']
        if header[0] != 'service' or len(header) < 3 or not family(' '.join(header[1:]).lower()):
            continue
        name, executable = header[1:3]
        possible = [stock / executable.lstrip('/')]
        if executable.startswith('/system/'):
            possible.insert(0, stock / 'system/system' / executable.removeprefix('/system/'))
        path = next((x for x in possible if x.is_file()), None)
        elf = ELF.elf_info(path) if path else None
        if elf:
            hashes[str(path)] = elf['sha256']
            raw = path.read_bytes()
            elf['linked_entry'] = hex(struct.unpack_from('<Q' if elf['bits'] == 64 else '<I', raw, 24)[0])
            is64 = elf['bits'] == 64
            phoff = struct.unpack_from('<Q' if is64 else '<I', raw, 32 if is64 else 28)[0]
            entsize, count = struct.unpack_from('<HH', raw, 54 if is64 else 42)
            if entsize < (56 if is64 else 32) or phoff + entsize * count > len(raw):
                raise ValueError('Invalid ELF program-header range')
            interpreters = []
            for at in range(phoff, phoff + entsize * count, entsize):
                if struct.unpack_from('<I', raw, at)[0] != 3:  # PT_INTERP
                    continue
                offset = struct.unpack_from('<Q' if is64 else '<I', raw, at + (8 if is64 else 4))[0]
                size = struct.unpack_from('<Q' if is64 else '<I', raw, at + (32 if is64 else 16))[0]
                if offset + size > len(raw) or not raw[offset:offset + size].endswith(b'\0'):
                    raise ValueError('Invalid ELF interpreter range')
                interpreters.append(raw[offset:offset + size - 1].decode('ascii'))
            elf['interpreters'] = interpreters
            if str(path) in rea_by_path and rea_by_path[str(path)]['subject']['digest']['sha256'] != elf['sha256']:
                raise ValueError('REA header evidence does not match service ELF')
        matches = []
        for label in labels:
            try:
                if re.fullmatch(label['regex'], executable):
                    matches.append(label)
            except re.error:
                raise ValueError('Unsupported context regex: ' + label['regex'])
        matched_types = {label['type'] for label in matches}
        tx = [t for t in transitions if t['exec_type'] in matched_types or
              (t['exec_type'].endswith('_30_0') and t['exec_type'][:-5] in matched_types)]
        stock_tx = [t for t in stock_transitions if t['exec_type'] in matched_types or
                    (t['exec_type'].endswith('_30_0') and t['exec_type'][:-5] in matched_types)]
        options = collections.defaultdict(list)
        for option in section['body']:
            options[option['tokens'][0]].append(option['tokens'][1:])
        domains = {t['domain'] for t in tx + stock_tx}
        if options.get('seclabel'):
            domains = {x[0].split(':')[2] for x in options['seclabel']}
        linked_failures = [f['ordinal'] for f in classified if any(
            domain in f['subject'].get('members', []) or domain in f['target'].get('members', [])
            for domain in domains)]
        registration = []
        direct_properties = []
        for fragment in documents:
            for ordinal, s in enumerate(documents[fragment], 1):
                if s[0] != 'allow':
                    continue
                subjects = model.summary(s[1])
                if not set(subjects.get('members', [])) & domains:
                    continue
                if s[3][0] in {'service_manager', 'hwservice_manager'} and 'add' in s[3][1]:
                    registration.append({'fragment': fragment, 'form': ordinal, 'statement': s})
                if subjects.get('count') == 1 and s[3][0] in {'file', 'property_service'}:
                    targets = model.summary(s[2])
                    matching = {t: property_labels[t] for t in targets.get('members', []) if t in property_labels}
                    if matching:
                        direct_properties.append({'fragment': fragment, 'form': ordinal,
                                                  'statement': s, 'stock_property_labels': matching})
        triggers = [action for action in sections if action['header'][0] == 'on' and any(
            b['tokens'][0] in {'start', 'restart', 'enable', 'exec_start'} and len(b['tokens']) > 1 and
            b['tokens'][1] == name for b in action['body'])]
        services.append({'service': name, 'family': family(' '.join(header[1:]).lower()),
                         'init': section, 'executable': executable, 'elf': elf,
                         'rea_header_evidence': rea_by_path.get(str(path)) if path else None,
                         'context_candidates': matches, 'init_transitions': tx,
                         'stock_reference_init_transitions': stock_tx,
                         'candidate_domains': sorted(domains), 'options': dict(options),
                         'explicit_start_actions': triggers, 'service_registration_rules': registration,
                         'singleton_subject_property_rules': direct_properties,
                         'failures_including_domain': linked_failures,
                         'limits': ['Context candidates do not reproduce Android libselinux precedence',
                                    'Broad assertion membership does not establish this service caused a failure',
                                    'Init declaration/trigger and linked ELF entry are not observed execution']})
    report = {'source_sha256': CIL.digest(Path(__file__)), 'input_hashes': hashes,
              'recovered_cross_fragment_attributes': recovered,
              'modern_shared_attribute_deltas': deltas, 'attribute_delta_unknowns': delta_unknowns,
              'membership_counterfactual': {
                  'omitted_snapshot_assignment_attributes': [r['attribute'] for r in deltas],
                  'declarations_and_rules_held_fixed': True, 'policy_emitted_or_compiled': False},
              'failure_count': len(classified),
              'failure_categories': dict(collections.Counter(x['category'] for x in classified)),
              'failures': classified, 'retained_service_candidates': services,
              'neverallow_disabled': False, 'policy_modified': False, 'device_accessed': False,
              'limits': ['Static CIL type-set algebra, not complete SELinux/AVTAB or permission evaluation',
                         'Attribute-delta comparison holds declarations fixed; not a compilable reduced policy',
                         'Compiler reports at most four grants for some failures; matches are incomplete',
                         'Init parsing covers observed shlex-compatible syntax, not Android import or override precedence',
                         'Property rules enumerate possible access, not actual runtime key reads/writes',
                         'Service selection by declared name/executable covers chosen families, not all firmware services',
                         'No runtime reachability, retention/removal, namespace, symbol ABI or hardware claim']}
    a.output.parent.mkdir(parents=True, exist_ok=True)
    with a.output.open('x') as output:
        json.dump(report, output, indent=2)
        output.write('\n')
    print(json.dumps({'failures': len(classified), 'categories': report['failure_categories'],
                      'membership_deltas': len(deltas), 'delta_unknowns': len(delta_unknowns),
                      'services': len(services)}, indent=2))


if __name__ == '__main__':
    main()
