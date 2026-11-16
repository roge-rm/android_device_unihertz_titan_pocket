#!/usr/bin/env python3
"""Audit type-position vendor references against saved split-policy interfaces.

Produces a private inventory and optional stock-proven identity mapping fixture.
No allow rules or assertions are generated or removed. A syntactic mapping is
not an ABI/runtime proof.
"""
import argparse
import collections
import importlib.util
import json
from pathlib import Path

SPEC = importlib.util.spec_from_file_location(
    'pocket_policy_compat', Path(__file__).with_name('audit-pocket-policy-compat.py'))
COMPAT = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(COMPAT)
DECLARATIONS = {'type', 'typeattribute', 'typealias'}
RULES = {'allow', 'neverallow', 'dontaudit', 'auditallow', 'allowx', 'neverallowx',
         'dontauditx', 'auditallowx'}
OPERATORS = {'and', 'or', 'xor', 'not', 'all', 'self'}


def type_references(statement):
    """Read only CIL type positions; never confuse a path/class/permission.

    Reject unknown forms so a new input cannot silently yield complete coverage.
    The accepted grammar covers the inspected vendor CIL, not all CIL syntax.
    """
    op = statement[0]
    if op in DECLARATIONS:
        return set()
    if op in RULES:
        values = statement[1:3]
    elif op in {'typetransition', 'typechange', 'typemember'}:
        values = statement[1:3] + [statement[-1]]
    elif op == 'typeattributeset':
        values = statement[1:]
    elif op == 'typealiasactual':
        values = statement[1:3]
    elif op == 'roletype':
        values = [statement[2]]
    elif op == 'genfscon':
        # genfscon fs path [optional file-kind] security-context
        values = [statement[-1][2]]
    elif op == 'expandtypeattribute':
        values = [statement[1]]
    else:
        raise ValueError('Unsupported vendor CIL form: ' + op)
    return set(COMPAT.atoms(values)) - OPERATORS


def audit(documents, vendor, snapshot, platform, mappings, oem_mappings):
    declarations = {
        name: {s[1]: s[0] for s in doc if s[0] in DECLARATIONS}
        for name, doc in documents.items()}
    uses = collections.defaultdict(lambda: collections.defaultdict(list))
    for ordinal, statement in enumerate(documents[vendor], 1):
        for symbol in type_references(statement):
            if symbol not in declarations[vendor]:
                uses[symbol][statement[0]].append(ordinal)
    sets = collections.defaultdict(list)
    for name, doc in documents.items():
        for ordinal, statement in enumerate(doc, 1):
            if statement[0] == 'typeattributeset':
                sets[statement[1]].append((name, ordinal, statement[2]))
    # Track signed/compound membership syntactically. A path through a negative
    # expression is still a dependency; this is not an effective grant query.
    graph = collections.defaultdict(set)
    for name in {vendor, snapshot}:
        for statement in documents[name]:
            if statement[0] == 'typeattributeset':
                graph[statement[1]].update(set(COMPAT.atoms(statement[2])) - OPERATORS)
    reachable = collections.defaultdict(set)
    for statement in documents[vendor]:
        if statement[0] not in RULES:
            continue
        pending = list(type_references(statement))
        visited = set()
        while pending:
            symbol = pending.pop()
            if symbol in visited:
                continue
            visited.add(symbol)
            reachable[symbol].add(statement[0])
            pending.extend(graph[symbol] - visited)
    rows = []
    for symbol, references in sorted(uses.items()):
        canonical = [x for x in sets[symbol] if x[0] in mappings]
        oem = [x for x in sets[symbol] if x[0] in oem_mappings]
        if canonical:
            coverage = 'canonical-mapping'
        elif oem:
            coverage = 'oem-mapping'
        elif symbol in declarations[platform]:
            coverage = 'current-platform-declaration'
        elif any(symbol in declarations[name] for name in documents
                 if name not in {snapshot, vendor, platform}):
            coverage = 'extension-declaration'
        elif symbol in declarations[snapshot]:
            coverage = 'snapshot-only'
        else:
            coverage = 'unresolved'
        bindings = []
        for name, ordinal, expression in canonical + oem:
            bindings.append({'fragment': name, 'form': ordinal,
                             'expression': expression})
        rows.append({'symbol': symbol, 'coverage': coverage,
                     'vendor_uses': dict(references),
                     'vendor_rule_kinds_through_snapshot_or_vendor_sets':
                         sorted(reachable[symbol]),
                     'declarations': [name for name, names in declarations.items()
                                      if symbol in names],
                     'bindings': bindings,
                     'snapshot_memberships': [
                         {'form': ordinal, 'expression': expression}
                         for name, ordinal, expression in sets[symbol]
                         if name == snapshot]})
    operations = collections.Counter(s[0] for s in documents[snapshot])
    by_coverage = collections.Counter(row['coverage'] for row in rows)
    direct = [row for row in rows if set(row['vendor_uses']) & RULES]
    return {'external_type_symbols': len(rows), 'coverage': dict(by_coverage),
            'direct_rule_external_symbols': len(direct),
            'direct_rule_coverage': dict(collections.Counter(
                row['coverage'] for row in direct)),
            'snapshot_operations': dict(operations), 'symbols': rows,
            'snapshot_only_symbols': [row['symbol'] for row in rows
                                      if row['coverage'] == 'snapshot-only'],
            'unresolved_symbols': [row['symbol'] for row in rows
                                   if row['coverage'] == 'unresolved']}


def reference_identity_bindings(reference, candidates, current_types):
    """Select observed singleton identities, refusing inferred/dummy aliases."""
    selected = [s for s in reference
                if s[0] == 'typeattributeset' and s[1] in candidates]
    if len({s[1] for s in selected}) != len(selected):
        raise ValueError('Duplicate reference binding')
    for statement in selected:
        symbol, targets = statement[1:]
        if (not isinstance(targets, list) or len(targets) != 1 or
                not isinstance(targets[0], str) or targets[0] not in current_types or
                symbol != targets[0] + '_30_0'):
            raise ValueError('Reference binding is not an observed current-type identity')
    return selected


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--compile-record', type=Path, required=True)
    for argument in ['vendor', 'snapshot', 'platform']:
        parser.add_argument('--' + argument, type=Path, required=True)
    parser.add_argument('--mapping', type=Path, action='append', default=[])
    parser.add_argument('--oem-mapping', type=Path, action='append', default=[])
    parser.add_argument('--reference-mapping', type=Path,
                        help='Optional preserved mapping for comparison only')
    parser.add_argument('--emit-reference-identities', type=Path,
                        help='Private diagnostic fixture of observed missing singleton bindings')
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    record = json.loads(args.compile_record.read_text())
    documents = {}
    hashes = {}
    for name, expected in record['input_hashes'].items():
        path = Path(name).resolve()
        actual = COMPAT.digest(path)
        if actual != expected:
            raise ValueError('Input changed: ' + str(path))
        name = str(path)
        documents[name] = COMPAT.forms(path.read_text())
        hashes[name] = actual
    selected = [args.vendor, args.snapshot, args.platform] + args.mapping + args.oem_mapping
    if any(str(path.resolve()) not in documents for path in selected):
        raise ValueError('Every selected fragment must be in verified compile record')
    report = audit(documents, str(args.vendor.resolve()), str(args.snapshot.resolve()),
                   str(args.platform.resolve()),
                   {str(p.resolve()) for p in args.mapping},
                   {str(p.resolve()) for p in args.oem_mapping})
    if args.reference_mapping:
        path = args.reference_mapping.resolve()
        reference = COMPAT.forms(path.read_text())
        candidates = set(report['snapshot_only_symbols'])
        current_types = {s[1] for s in documents[str(args.platform.resolve())]
                         if s[0] == 'type'}
        report['reference_mapping'] = {
            'path': str(path), 'sha256': COMPAT.digest(path),
            'uncovered_reference_bindings': [
                {'symbol': s[1], 'expression': s[2],
                 'all_literal_targets_current_types':
                     isinstance(s[2], list) and
                     all(isinstance(t, str) and t in current_types for t in s[2])}
                for s in reference if s[0] == 'typeattributeset' and s[1] in candidates],
            'automatic_aliases_generated': False}
        if args.emit_reference_identities:
            selected = reference_identity_bindings(reference, candidates, current_types)
            if not selected:
                raise ValueError('No observed reference identity bindings to emit')
            destination = args.emit_reference_identities
            destination.parent.mkdir(parents=True, exist_ok=True)
            with destination.open('x') as stream:
                stream.write('\n'.join(COMPAT.encode(s) for s in selected) + '\n')
            report['diagnostic_reference_identities'] = {
                'path': str(destination.resolve()), 'sha256': COMPAT.digest(destination),
                'observed_binding_count': len(selected), 'rules_added': 0,
                'rules_removed': 0, 'neverallows_removed': 0,
                'shipping_policy': False,
                'limits': ['Observed stock singleton identities only; same spelling is not ABI equivalence',
                           'New intersections must pass all neverallow checks before integration']}
    elif args.emit_reference_identities:
        raise ValueError('Reference mapping required for identity fixture')
    report.update(input_hashes=hashes, source_sha256=COMPAT.digest(Path(__file__)),
                  policy_modified=False, device_accessed=False, shipping_policy=False,
                  limits=['Type-position static inventory, not execution or enforcement',
                          'Mapping expressions do not prove permission or ABI equivalence',
                          'Snapshot-only symbols require source/implementation review; no automatic aliases',
                          'No rule deletion or service-retention decision follows from symbol coverage'])
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open('x') as stream:
        json.dump(report, stream, indent=2)
        stream.write('\n')
    print(json.dumps({key: report[key] for key in [
        'external_type_symbols', 'coverage', 'direct_rule_external_symbols',
        'direct_rule_coverage', 'snapshot_only_symbols', 'unresolved_symbols']}, indent=2))


if __name__ == '__main__':
    main()
