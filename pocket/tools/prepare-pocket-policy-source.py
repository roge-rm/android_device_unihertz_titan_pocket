#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Reconstruct a bounded private policy interface from reviewed source contracts.

Never imports expanded old-public grants, adds dummy domains, disables checks,
or modifies an input. Outputs are private generated compatibility fixtures until
the complete intended product's enforcing compilation and runtime tests pass.
"""
import pocket_paths
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import subprocess

ROOT = Path(__file__).resolve().parent.parent
SPEC = importlib.util.spec_from_file_location('pocket_cil', ROOT / 'tools/audit-pocket-policy-compat.py')
CIL = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CIL)
DECL = {'type', 'typeattribute', 'typealias'}
ASSERT = {'neverallow', 'neverallowx'}


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def declarations(documents, kinds=DECL):
    return {s[1] for doc in documents for s in doc if s[0] in kinds}


def absent_domain_projection(document, name, actual_types):
    """Map a proved uninhabited atomic domain to empty, fail on any live use.

    An assertion on an empty subject is vacuous. Removing an empty excluded
    domain from a complement preserves the set over every declared target type.
    This does not permit dropping a compound or partially live assertion.
    """
    if name in actual_types:
        raise ValueError('Domain is present; projection forbidden: ' + name)
    edits = []
    set_edits = {}
    removed = set()
    for i, statement in enumerate(document):
        if name not in set(CIL.atoms(statement)):
            continue
        if statement[0] in ASSERT and statement[1] == name and name not in set(CIL.atoms(statement[2:])):
            removed.add(i)
            edits.append({'form': i + 1, 'reason': 'Atomic assertion subject is an empty target domain'})
            continue
        if (statement[0] == 'typeattributeset' and len(statement[2]) == 2 and
                statement[2][0] == 'not' and isinstance(statement[2][1], list) and
                all(isinstance(x, str) for x in statement[2][1])):
            attr = statement[1]
            for other in document:
                if attr not in set(CIL.atoms(other)) or other == statement:
                    continue
                if other[0] not in ASSERT | {'typeattribute', 'expandtypeattribute'}:
                    raise ValueError('Absent-domain set has a nonassertion consumer: ' + attr)
            kept = [x for x in statement[2][1] if x != name]
            if not kept:
                raise ValueError('Unreviewed empty complement expression')
            set_edits[i] = [statement[0], attr, ['not', kept]]
            edits.append({'form': i + 1, 'reason': 'Empty exclusion removed from assertion-only complement'})
            continue
        raise ValueError('Unreviewed absent-domain use: ' + CIL.encode(statement))
    if not removed:
        raise ValueError('Expected reviewed obsolete assertion was not found: ' + name)
    return [set_edits.get(i, s) for i, s in enumerate(document) if i not in removed], edits


def reconstruct_external_attributes(document, stock_platform, prefix):
    """Bind old private predicates by meaning, never by modern generated IDs."""
    own = declarations([document])
    names = {a for a in CIL.atoms(document) if re.fullmatch(r'base_typeattr_[0-9]+', a)} - own
    replacements = {name: name.replace('base_typeattr_', prefix) for name in names}
    if set(replacements.values()) & set(CIL.atoms(document)):
        raise ValueError('External predicate namespace already occupied')
    def visit(value):
        return replacements.get(value, value) if isinstance(value, str) else [visit(x) for x in value]
    output = [visit(x) for x in document]
    evidence = []
    for name in sorted(names):
        definitions = [s for s in stock_platform if s[0] == 'typeattributeset' and s[1] == name]
        if len(definitions) != 1:
            raise ValueError('Expected exactly one shipped predicate definition: ' + name)
        output += [['typeattribute', replacements[name]], visit(definitions[0])]
        evidence.append({'stock_symbol': name, 'source_symbol': replacements[name],
                         'definition': definitions[0][2]})
    return output, evidence


def extended_interface(snapshot, others, contracts):
    available = declarations(others)
    concrete = declarations(others, {'type'})
    rows = [s for s in snapshot if s[0] == 'typeattribute' and s[1] not in available]
    for contract in contracts:
        name = contract['symbol']
        observed = [s[2] for s in snapshot if s[0] == 'typeattributeset' and s[1] == name]
        if observed != [contract['definition']]:
            raise ValueError('Shipped cross-fragment predicate changed: ' + name)
        expression = contract['definition']
        if contract['kind'] == 'retained_stock_app_grant_set':
            expression = contract['retained_members']
            missing = set(expression) - concrete
            if missing:
                raise ValueError('Retained grant member is missing: ' + str(sorted(missing)))
        elif contract['kind'] != 'modern_domain_assertion_predicate':
            raise ValueError('Unknown source contract kind')
        rows.append(['typeattributeset', name, expression])
    if any(s[0] not in {'typeattribute', 'typeattributeset'} for s in rows):
        raise ValueError('Unexpected grant/assertion in extended interface')
    return rows


def modernize_debug_app_assertions(document, debuggable):
    """Apply current app_domain's llkd exception only to its exact debug shape.

    Current public/te_macros app_domain excludes llkd for userdebug/eng. The
    shipped expanded macro predates that exception. No allow is introduced;
    release/user builds retain the original assertion predicate unchanged.
    """
    if not debuggable:
        return document, []
    output = list(document)
    changes = []
    for i, statement in enumerate(document):
        if statement[0] != 'typeattributeset':
            continue
        expression = statement[2]
        # Normalize only redundant list wrappers produced by CIL versioning.
        def unwrap(value):
            while isinstance(value, list) and len(value) == 1 and isinstance(value[0], list):
                value = value[0]
            return value
        expr = unwrap(expression)
        if not (isinstance(expr, list) and len(expr) == 3 and expr[0] == 'and' and
                unwrap(expr[1]) == ['domain']):
            continue
        exclusion = unwrap(expr[2])
        if not (isinstance(exclusion, list) and len(exclusion) == 2 and exclusion[0] == 'not'):
            continue
        members = exclusion[1]
        if not isinstance(members, list) or not all(isinstance(x, str) for x in members):
            continue
        uses = [s for s in document if statement[1] in set(CIL.atoms(s)) and s != statement and
                s[0] not in {'typeattribute', 'expandtypeattribute'}]
        if len(uses) != 1:
            continue
        rule = uses[0]
        if not (rule[0] == 'neverallow' and rule[1] == statement[1] and
                isinstance(rule[2], str) and rule[3] == ['process', ['ptrace']]):
            continue
        domain = rule[2]
        normalized = {x.removesuffix('_30_0') for x in members}
        if normalized != {'crash_dump', 'runas_app', 'simpleperf', domain}:
            continue
        llkd = 'llkd_30_0' if any(x.endswith('_30_0') for x in members) else 'llkd'
        output[i] = ['typeattributeset', statement[1], ['and', ['domain'], ['not', members + [llkd]]]]
        changes.append({'attribute': statement[1], 'app': domain, 'debug_exception': llkd,
                        'source_macro': 'system/sepolicy/public/te_macros:app_domain',
                        'neverallow_statement_retained': True})
    return output, changes


def adapt_owner_permissions(document, reviewed, modern_permissions):
    """Update an exact owner/domain/type/class constraint for modern operations.

    This changes only permissions already allowed by the inspected modern
    component policy. Other domains, target types and denied permissions retain
    their original assertions. An assertion may never be emptied or removed.
    """
    result = list(document)
    changes = []
    for rule in reviewed:
        key = (rule['subject'], rule['target'], rule['class'])
        permit = set(rule['permissions'])
        if not permit <= modern_permissions.get(key, set()):
            raise ValueError('Modern component does not allow reviewed operation: ' + str(key))
        found = [i for i, s in enumerate(result) if s[0] == 'neverallow' and
                 s[1:3] == list(key[:2]) and s[3][0] == key[2]]
        if len(found) != 1:
            raise ValueError('Expected one exact owner assertion: ' + str(key))
        i = found[0]
        statement = result[i]
        if not permit <= set(statement[3][1]):
            raise ValueError('Reviewed denial shape changed: ' + str(key))
        kept = [p for p in statement[3][1] if p not in permit]
        if not kept:
            raise ValueError('Refusing to empty an assertion')
        result[i] = ['neverallow', statement[1], statement[2], [statement[3][0], kept]]
        changes.append({'subject': key[0], 'target': key[1], 'class': key[2],
                        'modern_owner_operations': sorted(permit),
                        'remaining_denials': kept, 'reason': rule['reason'],
                        'assertion_retained': True})
    return result, changes


def project_framework_roles(document, framework_types, framework_attributes, model):
    """Let the selected framework own roles of its concrete types.

    A versioned old public symbol can map to several current concrete types.
    Replaying its old role assignment reclassifies new types (for example an
    OEM boot-animation *file* as fs_type). Keep every vendor-private assignment,
    grant and assertion. Only flat contributions to framework-owned attributes
    whose complete expansion is framework-owned are delegated to that owner.
    Mixed or expression assignments are deliberately not rewritten.
    """
    rows, changes = [], []
    for ordinal, statement in enumerate(document, 1):
        if (statement[0] != 'typeattributeset' or statement[1] not in framework_attributes or
                not isinstance(statement[2], list) or
                not all(isinstance(x, str) and x not in {'all', 'and', 'or', 'not', 'xor'}
                        for x in statement[2])):
            rows.append(statement)
            continue
        kept = []
        for member in statement[2]:
            targets = model.expression(member)
            if targets and targets <= framework_types:
                changes.append({'form': ordinal, 'attribute': statement[1], 'legacy_member': member,
                                'current_owner_types': sorted(targets)})
            else:
                kept.append(member)
        if kept:
            rows.append([statement[0], statement[1], kept])
    return rows, changes


def adapt_predicate_operations(document, reviewed, modern_permissions, namespace='pocket_owner_predicate_'):
    """Partition each denied permission around its reviewed modern owners.

    For each original S x T x P, permissions shared by the same owner set O
    retain an assertion (S-O) x T x P. Unchanged permissions retain S x T x P.
    No target or permission changes outside the reviewed Cartesian pairs.
    """
    groups = {}
    for rule in reviewed:
        key = (rule['owner'], rule['target'], rule['class'])
        permitted = set(rule['permissions'])
        if not permitted or not permitted <= modern_permissions.get(key, set()):
            raise ValueError('Missing inspected modern owner permissions: ' + str(key))
        groups.setdefault((rule['predicate'], rule['target'], rule['class']), []).append(rule)
    rows, changes = list(document), []
    for number, ((predicate, target, cls), rules) in enumerate(groups.items()):
        expected = {rule['expected_assertions'] for rule in rules}
        found = [i for i, s in enumerate(rows) if s[0] == 'neverallow' and
                 s[1:3] == [predicate, target] and s[3][0] == cls]
        if expected != {len(found)}:
            raise ValueError('Reviewed predicate assertion count changed')
        for i in reversed(found):
            statement = rows[i]
            if any(not set(rule['permissions']) <= set(statement[3][1]) for rule in rules):
                raise ValueError('Reviewed predicate denial changed')
            partitions = {}
            for permission in statement[3][1]:
                owners = tuple(sorted({rule['owner'] for rule in rules if permission in rule['permissions']}))
                partitions.setdefault(owners, []).append(permission)
            if () not in partitions:
                raise ValueError('Refusing empty denial remainder')
            replacement = [['neverallow', predicate, target, [cls, partitions.pop(())]]]
            for part, (owners, permissions) in enumerate(partitions.items()):
                name = namespace + str(number) + '_' + str(i) + '_' + str(part)
                if name in set(CIL.atoms(rows)):
                    raise ValueError('Owner predicate namespace collision')
                replacement += [
                    ['typeattribute', name],
                    ['typeattributeset', name, ['and', [predicate], ['not', list(owners)]]],
                    ['neverallow', name, target, [cls, sorted(permissions)]]]
            rows[i:i + 1] = replacement
        changes += [dict(rule, neverallow_scope_preserved_except_reviewed_owner_operations=True) for rule in rules]
    return rows, changes


def protect_modern_isolated_domains(document):
    """Preserve the legacy no-isolated-app intent over modern isolation roles."""
    symbol = 'base_typeattr_562_30_0'
    definitions = [s for s in document if s[0] == 'typeattributeset' and s[1] == symbol]
    expected = CIL.forms('(typeattributeset base_typeattr_562_30_0 ((and (domain) ((not (isolated_app_30_0))))))')[0]
    if definitions != [expected]:
        raise ValueError('Reviewed isolated-domain grant predicate changed')
    consumers = [s for s in document if symbol in set(CIL.atoms(s)) and
                 s[0] not in {'typeattribute', 'typeattributeset', 'expandtypeattribute'}]
    allowed = CIL.forms('(allow base_typeattr_562_30_0 sysfs_devinfo (file (ioctl read getattr lock map open watch watch_reads))) '
                        '(allow base_typeattr_562_30_0 storage_file_30_0 (dir (search)))')
    if consumers != allowed:
        raise ValueError('Reviewed isolated-domain grant consumers changed')
    rows = [['typeattributeset', symbol, ['and', ['domain'], ['not', ['isolated_app_all']]]]]
    return [rows[0] if s == expected else s for s in document], {
        'attribute': symbol, 'old_exclusion': 'isolated_app_30_0',
        'modern_exclusion': 'isolated_app_all', 'grant_statements_changed': 0,
        'reason': 'Extend original isolation exclusion to current SDK sandbox and isolated-compute roles; only removes inherited access.'}


def restrict_protected_owner_grants(document, contracts):
    """Revoke inherited access to current protected labels, never relax checks."""
    rows, changes = list(document), []
    for number, rule in enumerate(contracts):
        found = [i for i, s in enumerate(rows) if s[0] == 'allow' and
                 s[2] == rule['legacy_target'] and s[3][0] == rule['class'] and
                 set(s[3][1]) & set(rule['permissions'])]
        if len(found) != rule['expected_grants']:
            raise ValueError('Protected-owner grant count changed')
        name = 'pocket_legacy_target_' + str(number)
        if name in set(CIL.atoms(rows)):
            raise ValueError('Protected-owner predicate namespace collision')
        for i in reversed(found):
            statement = rows[i]
            revoke = [p for p in statement[3][1] if p in rule['permissions']]
            keep = [p for p in statement[3][1] if p not in rule['permissions']]
            replacement = [['allow', statement[1], name, [rule['class'], revoke]]]
            if keep:
                replacement.insert(0, ['allow', statement[1], statement[2], [rule['class'], keep]])
            rows[i:i+1] = replacement
        rows += [['typeattribute', name], ['typeattributeset', name,
                 ['and', [rule['legacy_target']], ['not', [rule['protected_type']]]]]]
        changes.append(dict(rule, effect='Permission revocation on exact protected target only',
                            runtime_effect_verified=False))
    return rows, changes


def scope_legacy_mls_role(document, excluded, actual_members):
    """Keep current and unselected application domains out of old MLS bypass."""
    expected = CIL.forms('(typeattributeset mlsvendorcompat (and appdomain vendordomain))')[0]
    if sum(s == expected for s in document) != 1 or set(actual_members) != set(excluded):
        raise ValueError('Legacy MLS compatibility scope changed; reopen package/role review')
    replacement = ['typeattributeset', 'mlsvendorcompat',
                   ['and', ['appdomain'], ['and', ['vendordomain'], ['not', sorted(excluded)]]]]
    return [replacement if s == expected else s for s in document]


def revoke_obsolete_framework_grants(document, rules):
    rows, changes = list(document), []
    for rule in rules:
        statement = ['allow', rule['subject'], rule['target'], [rule['class'], rule['permissions']]]
        if rows.count(statement) != 1:
            raise ValueError('Obsolete framework grant changed; review required')
        rows.remove(statement)
        changes.append(dict(rule, effect='Grant removed; modern assertion unchanged'))
    return rows, changes


def modernize_debug_binder_transport(document, debuggable, modern_permissions):
    """Port add_service debug inherited-Binder-TCP use, never network creation."""
    if not debuggable:
        return document, []
    rows, changes = list(document), []
    permissions = {'accept', 'getopt', 'read', 'write'}
    for domain in ['mtk_hal_audio', 'mediacodec']:
        if not permissions <= modern_permissions.get((domain, 'su', 'tcp_socket'), set()):
            raise ValueError('Current add_service debug transport contract changed')
        found = [i for i,s in enumerate(rows) if s[0] == 'neverallow' and
                 s[1:3] == [domain, 'domain'] and s[3][0] == 'tcp_socket']
        if len(found) != 1:
            raise ValueError('Legacy HAL socket constraint shape changed')
        i = found[0]
        statement = rows[i]
        if not permissions <= set(statement[3][1]):
            raise ValueError('Legacy HAL socket permissions changed')
        kept = [p for p in statement[3][1] if p not in permissions]
        if not {'create','bind','connect','listen','name_connect'} <= set(kept):
            raise ValueError('Legacy network-creation protection is missing')
        name = 'pocket_debug_binder_tcp_peers_' + domain
        if name in set(CIL.atoms(rows)):
            raise ValueError('Debug Binder namespace collision')
        rows[i:i+1] = [
            ['neverallow', domain, 'domain', ['tcp_socket', kept]],
            ['typeattribute', name],
            ['typeattributeset', name, ['and', ['domain'], ['not', ['su']]]],
            ['neverallow', domain, name, ['tcp_socket', sorted(permissions)]]]
        changes.append({'domain':domain,'debug_peer':'su','permissions':sorted(permissions),
                        'source_macro':'add_service', 'network_creation_denials_retained':True})
    return rows, changes


def rebind_generic_label_assertions(document, contracts, stock_mapping):
    """Reconstruct generic path-label constraints, not expanded future labels."""
    rows, changes = list(document), []
    for rule in contracts:
        if [s for s in stock_mapping if s[0] == 'typeattributeset' and s[1] == rule['legacy_target']] != [
                ['typeattributeset', rule['legacy_target'], [rule['current_target']]]]:
            raise ValueError('Stock generic label was not an exact singleton')
        found=[i for i,s in enumerate(rows) if s[0]=='neverallow' and
               s[1:3]==[rule['subject'],rule['legacy_target']] and s[3][0]==rule['class']]
        if len(found)!=1:
            raise ValueError('Reviewed generic-label constraint changed')
        i=found[0]
        rows[i]=['neverallow',rows[i][1],rule['current_target'],rows[i][3]]
        changes.append(dict(rule, all_permissions_and_subjects_retained=True,
                            modern_descendant_label_assertions_changed=False))
    return rows,changes


def rebind_property_contexts(text, contracts):
    lines = text.splitlines()
    for rule in contracts:
        old = rule['old_line'].split()
        new = rule['new_line'].split()
        if len(old) != 4 or len(new) != 4 or old[0] != new[0] or old[2:] != new[2:] or old[2] != 'exact':
            raise ValueError('Property context rewrite must preserve exact name and value type')
        found = [i for i,line in enumerate(lines) if line.split() == old]
        if len(found) != 1:
            raise ValueError('Reviewed property selector changed')
        lines[found[0]] = ' '.join(new)
    return '\n'.join(lines) + '\n'


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--compile-record', type=Path, default=ROOT / 'evidence/kernel-upgrade/canonical-modern-oem-namespaced-policy-compile.json')
    p.add_argument('--modern-platform', type=Path)
    p.add_argument('--modern-mapping', type=Path)
    p.add_argument('--modern-compat', type=Path)
    p.add_argument('--product-variables', type=Path,
                   help='Actual Soong product variables; enables current debug app macro semantics only when Debuggable=true')
    p.add_argument('--output', type=Path, required=True)
    p.add_argument('--compile', action='store_true')
    a = p.parse_args()
    record = json.loads(a.compile_record.read_text())
    inputs = {}
    paths = []
    for name, expected in record['input_hashes'].items():
        path = Path(name).resolve()
        if digest(path) != expected:
            raise ValueError('Changed recorded source input: ' + str(path))
        inputs[str(path)] = expected
        paths.append(path)
    snapshot = next(x for x in paths if x.name == 'plat_pub_versioned.cil')
    extension = next(x for x in paths if x.name == 'system_ext-namespaced.cil')
    platform = next(x for x in paths if x.name == 'soong-platform.cil')
    mapping = next(x for x in paths if '/system/etc/selinux/mapping/' in str(x))
    compat = next(x for x in paths if x.name == '30.0.compat.cil')
    replacements = {old: new.resolve() for old, new in [(platform, a.modern_platform),
                    (mapping, a.modern_mapping), (compat, a.modern_compat)] if new}
    paths = [replacements.get(x, x) for x in paths]
    platform = replacements.get(platform, platform)
    compat = replacements.get(compat, compat)
    mapping = replacements.get(mapping, mapping)
    for path in replacements.values():
        inputs[str(path)] = digest(path)
    documents = {path: CIL.forms(path.read_text()) for path in paths}
    ospec = importlib.util.spec_from_file_location('ownership', ROOT / 'tools/audit-pocket-policy-ownership.py')
    ownership = importlib.util.module_from_spec(ospec)
    ospec.loader.exec_module(ownership)
    spec = pocket_paths.DEVICE_TREE / 'sepolicy/compat/30.0/public_contracts.json'
    config = json.loads(spec.read_text())
    if config['schema'] != 1:
        raise ValueError('Unsupported source contract schema')
    inputs[str(spec)] = digest(spec)
    stock_platform = ROOT / 'firmware/installed-20230105/rootfs/system/system/etc/selinux/plat_sepolicy.cil'
    inputs[str(stock_platform)] = digest(stock_platform)
    others = [d for path, d in documents.items() if path != snapshot]
    interface = extended_interface(documents[snapshot], others, config['cross_fragment_contracts'])
    target_types = declarations(others, {'type'})
    target_attributes = declarations(others + [interface], {'typeattribute'})
    role_upgrades = []
    for role in config.get('modern_default_roles', []):
        if role['type'] not in target_types:
            raise ValueError('Retained default HAL domain is missing: ' + role['type'])
        if set(role['attributes']) - target_attributes:
            raise ValueError('Modern HAL-role attribute is missing: ' + str(role))
        upstream = pocket_paths.platform_source() / role['upstream']
        source = upstream.read_text()
        if role['type'] == 'hal_health_default':
            if 'typeattribute hal_health_default bpfdomain;' not in source:
                raise ValueError('Reviewed modern health role changed')
        elif role['type'] == 'hal_vehicle_default':
            if 'hal_client_domain(hal_vehicle_default, hal_can_bus)' not in source:
                raise ValueError('Reviewed modern CAN client role changed')
        else:
            raise ValueError('Unreviewed default HAL role')
        inputs[str(upstream)] = digest(upstream)
        interface += [['typeattributeset', attr, [role['type']]] for attr in role['attributes']]
        role_upgrades.append(role)
    property_classifications = []
    for rule in config.get('property_owner_classifications', []):
        if rule['owner'] != 'vendor' or rule['scope'] != 'public' or not rule['property_name'].startswith('vendor.'):
            raise ValueError('Unreviewed property owner/scope classification')
        context = ROOT / rule['context_path']
        expected = rule['property_name'] + ' u:object_r:' + rule['type'] + ':s0'
        if expected not in [' '.join(line.split()) for line in context.read_text().splitlines()]:
            raise ValueError('Reviewed exact stock property context changed')
        if rule['type'] not in target_types:
            raise ValueError('Property type is missing')
        attributes = ['vendor_property_type', 'vendor_public_property_type']
        if set(attributes) - target_attributes:
            raise ValueError('Modern property ownership taxonomy is missing')
        interface += [['typeattributeset', attr, [rule['type']]] for attr in attributes]
        inputs[str(context)] = digest(context)
        property_classifications.append(rule)
    property_context_rebindings = config.get('property_context_rebindings', [])
    for rule in property_context_rebindings:
        for relative, marker in rule['source_markers'].items():
            path = pocket_paths.platform_source() / relative
            if marker not in path.read_text():
                raise ValueError('Reviewed current property owner contract changed')
            inputs[str(path)] = digest(path)
    ext = documents[extension]
    projection = []
    for name in config['absent_domains']:
        ext, changed = absent_domain_projection(ext, name, target_types)
        projection += changed
    ext, old_predicates = reconstruct_external_attributes(ext, CIL.forms(stock_platform.read_text()), config['external_platform_attribute_prefix'])
    owner_changes = []
    predicate_changes = []
    owner_rules = config.get('owner_permission_adaptations', [])
    product_debuggable = bool(a.product_variables and json.loads(a.product_variables.read_text()).get('Debuggable', False))
    owner_rules = [rule for rule in owner_rules if not rule.get('debug_only') or product_debuggable]
    predicate_rules = config.get('owner_predicate_adaptations', [])
    vendor_predicate_rules = config.get('vendor_owner_predicate_adaptations', [])
    predicate_rules = [rule for rule in predicate_rules if not rule.get('optional_current_owner') or rule['owner'] in target_types]
    vendor_predicate_rules = [rule for rule in vendor_predicate_rules if not rule.get('optional_current_owner') or rule['owner'] in target_types]
    if owner_rules:
        plat = documents[platform]
        model = ownership.TypeSets({str(path):doc for path,doc in documents.items()
                                    if path != snapshot} | {'interface':interface})
        allowed = {}
        debug_transport_rules = ([{'subject':domain,'target':'su','class':'tcp_socket','source_markers':{}}
                                  for domain in ['mtk_hal_audio','mediacodec']] if product_debuggable else [])
        for rule in owner_rules + predicate_rules + vendor_predicate_rules + debug_transport_rules:
            key = (rule.get('subject', rule.get('owner')), rule['target'], rule['class'])
            permissions = set()
            for s in plat:
                if s[0] != 'allow' or s[3][0] != key[2] or s[2] == 'self':
                    continue
                owner_types = model.expression(key[0])
                if owner_types and owner_types <= model.expression(s[1]) and key[1] in model.expression(s[2]):
                    permissions.update(s[3][1])
            allowed[key] = permissions
            for relative, marker in rule['source_markers'].items():
                path = pocket_paths.platform_source() / relative
                if marker not in path.read_text():
                    raise ValueError('Reviewed modern owner implementation changed: ' + relative)
                inputs[str(path)] = digest(path)
        ext, owner_changes = adapt_owner_permissions(ext, owner_rules, allowed)
        ext, predicate_changes = adapt_predicate_operations(ext, predicate_rules, allowed, 'pocket_oem_owner_')
    debug_upgrades = []
    vendor_path = next(x for x in paths if x.name == 'vendor_sepolicy.cil')
    vendor = documents[vendor_path]
    label_mapping = ROOT / 'firmware/installed-20230105/rootfs/system/system/etc/selinux/mapping/30.0.cil'
    inputs[str(label_mapping)] = digest(label_mapping)
    vendor, label_rebindings = rebind_generic_label_assertions(vendor,
        config.get('generic_label_assertion_rebindings', []), CIL.forms(label_mapping.read_text()))
    stock_context = ROOT / 'firmware/installed-20230105/rootfs/system/system/etc/selinux/plat_file_contexts'
    modern_context_dir = pocket_paths.platform_source() / 'system/sepolicy/private'
    root_contexts = [(stock_platform, '(genfscon proc / (u object_r proc ((s0) (s0))))'),
                     (stock_platform, '(genfscon sysfs / (u object_r sysfs ((s0) (s0))))'),
                     (stock_context, '/dev(/.*)? u:object_r:device:s0'),
                     (modern_context_dir / 'genfs_contexts', 'genfscon proc / u:object_r:proc:s0'),
                     (modern_context_dir / 'genfs_contexts', 'genfscon sysfs / u:object_r:sysfs:s0'),
                     (modern_context_dir / 'file_contexts', '/dev(/.*)? u:object_r:device:s0')]
    for path, marker in root_contexts:
        content = path.read_text()
        normalized = '\n'.join(' '.join(line.split()) for line in content.splitlines())
        if marker not in normalized:
            raise ValueError('Generic root path context changed')
        inputs[str(path)] = digest(path)
    vendor, vendor_predicate_changes = adapt_predicate_operations(vendor, vendor_predicate_rules, allowed, 'pocket_vendor_owner_')
    vendor, debug_transport_changes = modernize_debug_binder_transport(vendor, product_debuggable, allowed)
    if 'isolated_app_all' not in target_attributes:
        raise ValueError('Modern isolated-domain owner attribute is missing')
    vendor, isolated_projection = protect_modern_isolated_domains(vendor)
    restrictions = config.get('protected_owner_grant_restrictions', [])
    for rule in restrictions:
        if rule['protected_type'] not in target_types:
            raise ValueError('Protected modern owner target is missing')
        for relative, marker in rule['source_markers'].items():
            path = pocket_paths.platform_source() / relative
            if marker not in path.read_text():
                raise ValueError('Modern protected-owner assertion changed')
            inputs[str(path)] = digest(path)
    vendor, grant_restrictions = restrict_protected_owner_grants(vendor, restrictions)
    obsolete_grants = config.get('obsolete_framework_grants', [])
    obsolete_oem_grants = config.get('obsolete_oem_property_grants', [])
    for rule in obsolete_grants + obsolete_oem_grants:
        for relative, marker in rule['source_markers'].items():
            path = pocket_paths.platform_source() / relative
            if marker not in path.read_text():
                raise ValueError('Reviewed modern framework boundary changed')
            inputs[str(path)] = digest(path)
    vendor, obsolete_grant_changes = revoke_obsolete_framework_grants(vendor, obsolete_grants)
    ext, obsolete_oem_changes = revoke_obsolete_framework_grants(ext, obsolete_oem_grants)
    framework = [doc for path, doc in documents.items()
                 if path not in {snapshot, extension, vendor_path}]
    framework_types = declarations(framework, {'type'})
    framework_attributes = declarations(framework, {'typeattribute'})
    role_model = ownership.TypeSets({str(path): doc for path, doc in documents.items()
                                    if path != snapshot} | {'interface': interface})
    ext, ext_role_changes = project_framework_roles(ext, framework_types, framework_attributes, role_model)
    vendor, vendor_role_changes = project_framework_roles(vendor, framework_types, framework_attributes, role_model)
    if a.product_variables:
        variables = json.loads(a.product_variables.read_text())
        inputs[str(a.product_variables.resolve())] = digest(a.product_variables)
        if type(variables.get('Debuggable', False)) is not bool:
            raise ValueError('Unexpected Debuggable product-variable type')
        ext, changes = modernize_debug_app_assertions(ext, variables.get('Debuggable', False))
        debug_upgrades += [dict(fragment='system_ext', **x) for x in changes]
        vendor, changes = modernize_debug_app_assertions(vendor, variables.get('Debuggable', False))
        debug_upgrades += [dict(fragment='vendor', **x) for x in changes]
        macro = pocket_paths.platform_source() / 'system/sepolicy/public/te_macros'
        inputs[str(macro)] = digest(macro)
    extra = ROOT / 'artifacts/m2/policy/vendor-extra-stock-identities.cil'
    inputs[str(extra)] = digest(extra)
    mls = config.get('legacy_mls_role_scope')
    compat_rows = documents[compat]
    mls_changes = None
    if mls:
        inventory_path = ROOT / 'evidence/product-build/vendor-apk-inventory.json'
        inventory = json.loads(inventory_path.read_text())
        inputs[str(inventory_path)] = digest(inventory_path)
        listed = set()
        for entry in inventory['entries']:
            path = ROOT / entry['path']
            if digest(path) != entry['sha256'] or entry['contains_dex']:
                raise ValueError('Vendor package inventory changed or has executable DEX')
            if any("name='" + package + "'" in entry['package_line'] for package in mls['unselected_packages']):
                raise ValueError('Excluded vendor application is present')
            listed.add(path.resolve())
        actual = {x.resolve() for x in (ROOT / 'firmware/installed-20230105/rootfs/vendor').rglob('*.apk')}
        if listed != actual:
            raise ValueError('Vendor APK inventory is incomplete')
        product_paths = [pocket_paths.DEVICE_TREE / 'lineage_titan_pocket.mk',
                         pocket_paths.private_vendor() / 'unihertz/titan_pocket/titan_pocket-vendor.mk']
        for path in product_paths:
            text = path.read_text()
            if '.apk' in text or any(package in text for package in mls['unselected_packages']):
                raise ValueError('Product selection has changed; review app-domain ownership')
            inputs[str(path)] = digest(path)
        effective = {str(path): (ext if path == extension else vendor if path == vendor_path else doc)
                     for path, doc in documents.items() if path != snapshot} | {'interface': interface}
        current = ownership.TypeSets(effective).expression('mlsvendorcompat')
        compat_rows = scope_legacy_mls_role(compat_rows, mls['excluded_domains'], current)
        mls_changes = dict(mls, pre_projection_members=sorted(current),
                          effect='Revoke legacy MLS bypass only; real domains, contexts and all assertions retained',
                          runtime_effect_verified=False)
    if a.output.exists():
        raise ValueError('Output already exists; preserve previous evidence')
    a.output.mkdir(parents=True)
    public_path = a.output / 'extended-public.cil'
    extension_path = a.output / 'system-ext.cil'
    vendor_output = a.output / 'vendor.cil'
    compat_output = a.output / 'platform-compat.cil'
    for path, rows in [(public_path, interface), (extension_path, ext), (vendor_output, vendor), (compat_output, compat_rows)]:
        path.write_text('\n'.join(CIL.encode(x) for x in rows) + '\n')
    install = a.output / 'install'
    def emit(relative, content):
        target = install / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(content)
        return target
    installed_platform = emit('system/etc/selinux/plat_sepolicy.cil', platform.read_bytes())
    installed_mapping = emit('system/etc/selinux/mapping/30.0.cil', mapping.read_bytes())
    installed_compat = emit('system/etc/selinux/mapping/30.0.compat.cil', compat_output.read_bytes())
    installed_public = emit('vendor/etc/selinux/plat_pub_versioned.cil', public_path.read_bytes() + extra.read_bytes())
    installed_vendor = emit('vendor/etc/selinux/vendor_sepolicy.cil', vendor_output.read_bytes())
    installed_ext = emit('system_ext/etc/selinux/system_ext_sepolicy.cil', extension_path.read_bytes())
    stock_ext_mapping = next(path for path in paths if path != mapping and '/mapping/30.0.cil' in str(path))
    installed_ext_mapping = emit('system_ext/etc/selinux/mapping/30.0.cil', stock_ext_mapping.read_bytes())
    combined = [installed_platform, installed_mapping, installed_compat, installed_public,
                installed_vendor, installed_ext, installed_ext_mapping]
    genfs_version = None
    if a.product_variables:
        genfs_version = variables.get('VendorVars', {}).get('ANDROID', {}).get('BOARD_GENFS_LABELS_VERSION')
        if not genfs_version or not re.fullmatch(r'[0-9]{6}', genfs_version):
            raise ValueError('Actual selected genfs label version is required')
        genfs = pocket_paths.platform_source() / 'system/sepolicy/compat' / ('plat_sepolicy_genfs_' + genfs_version + '.cil')
        inputs[str(genfs)] = digest(genfs)
        combined.append(emit('system/etc/selinux/' + genfs.name, genfs.read_bytes()))
        emit('vendor/etc/selinux/genfs_labels_version.txt', (genfs_version + '\n').encode())
    stock_vendor = ROOT / 'firmware/installed-20230105/rootfs/vendor/etc/selinux'
    version = stock_vendor / 'plat_sepolicy_vers.txt'
    if version.read_text().strip() != '30.0':
        raise ValueError('Retained vendor policy API version changed')
    inputs[str(version)] = digest(version)
    emit('vendor/etc/selinux/plat_sepolicy_vers.txt', version.read_bytes())
    context_moves = [
        'user=system seinfo=platform name=com.gd.mobicore.pa domain=teeregistryd_app',
        'user=system seinfo=platform name=com.trustonic.teeservice domain=teed_app']
    for partition, original in [('vendor', stock_vendor), ('system_ext', stock_ext_mapping.parent.parent)]:
        for context in original.glob('*contexts'):
            if context.name == 'plat_pub_versioned.cil':
                continue
            data = context.read_bytes()
            if context.name == 'vendor_seapp_contexts':
                lines = context.read_text().splitlines()
                if any(lines.count(line) != 1 for line in context_moves):
                    raise ValueError('Core app seapp context move no longer exact')
                data = ('\n'.join(line for line in lines if line not in context_moves) + '\n').encode()
            elif context.name == 'system_ext_seapp_contexts':
                if any(line in context.read_text() for line in context_moves):
                    raise ValueError('Core app context already exists in system_ext')
                data += ('\n' + '\n'.join(context_moves) + '\n').encode()
            elif context.name == 'system_ext_property_contexts':
                data = rebind_property_contexts(context.read_text(), property_context_rebindings).encode()
            inputs[str(context)] = digest(context)
            emit(partition + '/etc/selinux/' + context.name, data)
        mac = original / (partition + '_mac_permissions.xml')
        inputs[str(mac)] = digest(mac)
        emit(partition + '/etc/selinux/' + mac.name, mac.read_bytes())
    result = {'source_tool_sha256': digest(Path(__file__)), 'input_hashes': inputs,
              'combined_input_hashes': {str(x): digest(x) for x in combined},
              'source_contract': str(spec.relative_to(ROOT)),
              'install_shaped_files': {str(path.relative_to(install)):digest(path) for path in install.rglob('*') if path.is_file()},
              'selected_genfs_labels_version': genfs_version,
              'core_app_context_relocations': context_moves,
              'property_context_rebindings': property_context_rebindings,
              'absent_domain_projection': projection, 'external_predicates_reconstructed': old_predicates,
              'old_public_grants_imported': False, 'modern_assertions_changed': False,
              'vendor_assertion_statements_removed': 0, 'debug_app_macro_upgrades': debug_upgrades,
              'debug_Binder_transport_upgrades': debug_transport_changes,
              'modern_default_HAL_roles': role_upgrades,
              'property_owner_classifications': property_classifications,
              'modern_owner_operation_adaptations': owner_changes,
              'modern_owner_predicate_adaptations': predicate_changes,
              'vendor_owner_predicate_adaptations': vendor_predicate_changes,
              'generic_label_assertion_rebindings': label_rebindings,
              'modern_isolation_projection': isolated_projection,
              'protected_owner_grant_restrictions': grant_restrictions,
              'legacy_MLS_role_scope': mls_changes,
              'obsolete_framework_grants_revoked': obsolete_grant_changes,
              'obsolete_OEM_generic_property_grants_revoked': obsolete_oem_changes,
              'framework_role_ownership_projection': {
                  'system_ext': ext_role_changes, 'vendor': vendor_role_changes,
                  'grant_statements_changed': 0, 'assertion_statements_changed': 0},
              'neverallow_disabled': False, 'dummy_domains_added': False, 'device_accessed': False,
              'shipping_policy': False,
              'limits': ['Install-shaped private reconstruction, not target-product Soong policy or installed images',
                         'Actual modern product/system_ext CIL and merged modern contexts are not built yet and are not included',
                         'Reconstructed current predicates and retained service ownership still require full compile and review',
                         'No label, startup, native compatibility or hardware execution proof']}
    rc = 0
    if a.compile:
        compiler = ROOT / 'tools/selinux-host-source/secilc/secilc'
        command = [str(compiler), '-m', '-M', 'true', '-G', '-c', '30',
                   '-o', str(a.output / 'policy'), '-f', str(a.output / 'file_contexts')] + list(map(str, combined))
        completed = subprocess.run(command, capture_output=True, text=True)
        (a.output / 'compile.log').write_text(completed.stdout + completed.stderr)
        rc = completed.returncode
        result.update(command=command, returncode=rc, compiler_sha256=digest(compiler),
                      assertion_failures=(completed.stdout + completed.stderr).count('neverallow check failed'))
        if rc == 0:
            result['binary'] = {'bytes': (a.output / 'policy').stat().st_size,
                                'sha256': digest(a.output / 'policy')}
    (a.output / 'record.json').write_text(json.dumps(result, indent=2) + '\n')
    print('Private source interface written; compile exit', rc,
          'assertion failures', result.get('assertion_failures', 'not compiled'))
    raise SystemExit(rc)


if __name__ == '__main__':
    main()
