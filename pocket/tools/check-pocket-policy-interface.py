#!/usr/bin/env python3
"""Synthetic host controls for the policy interface inventory (no stock rules)."""
import importlib.util
from pathlib import Path
import unittest

SPEC = importlib.util.spec_from_file_location(
    'interface', Path(__file__).with_name('audit-pocket-policy-interface.py'))
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class InterfaceControls(unittest.TestCase):
    def parse(self, text):
        return MODULE.COMPAT.forms(text)

    def test_only_rule_type_positions(self):
        self.assertEqual(MODULE.type_references(
            self.parse('(allow a self (file (read)))')[0]), {'a'})

    def test_genfs_context_not_filesystem_or_path(self):
        self.assertEqual(MODULE.type_references(self.parse(
            '(genfscon debugfs /file (u object_r label ((s0) (s0))))')[0]), {'label'})

    def test_named_transition(self):
        self.assertEqual(MODULE.type_references(self.parse(
            '(typetransition a b file "literal-name" c)')[0]), {'a', 'b', 'c'})

    def test_role_is_not_type(self):
        self.assertEqual(MODULE.type_references(['roletype', 'r', 'a']), {'a'})

    def test_compound_dependencies(self):
        self.assertEqual(MODULE.type_references(self.parse(
            '(typeattributeset a (and b (not (c))))')[0]), {'a', 'b', 'c'})

    def test_unsupported_form_rejected(self):
        with self.assertRaises(ValueError):
            MODULE.type_references(['unknown-op', 'a'])

    def test_coverage_and_local_declaration_exclusion(self):
        docs = {
            'vendor': self.parse('(type local) (allow local old (file (read))) '
                                 '(allow local oem (file (read))) '
                                 '(allow local missing (file (read)))'),
            'snapshot': self.parse('(typeattribute old) (typeattribute oem)'),
            'platform': self.parse('(type current)'),
            'mapping': self.parse('(typeattributeset old (current))'),
            'oem-mapping': self.parse('(typeattributeset oem (local))')}
        report = MODULE.audit(docs, 'vendor', 'snapshot', 'platform',
                              {'mapping'}, {'oem-mapping'})
        self.assertEqual(report['external_type_symbols'], 3)
        self.assertEqual(report['coverage'], {
            'canonical-mapping': 1, 'oem-mapping': 1, 'unresolved': 1})
        self.assertEqual(report['unresolved_symbols'], ['missing'])

    def test_snapshot_set_reachability_includes_negative_members(self):
        docs = {
            'vendor': self.parse('(type local) (allow local old_set (file (read))) '
                                 '(typeattributeset unused (old_type))'),
            'snapshot': self.parse('(typeattribute old_set) (type old_type) '
                                   '(typeattributeset old_set (not (old_type)))'),
            'platform': [], 'mapping': []}
        report = MODULE.audit(docs, 'vendor', 'snapshot', 'platform', {'mapping'}, set())
        row = next(r for r in report['symbols'] if r['symbol'] == 'old_type')
        self.assertEqual(row['vendor_rule_kinds_through_snapshot_or_vendor_sets'], ['allow'])
        self.assertEqual(row['coverage'], 'snapshot-only')

    def test_observed_identity_selection(self):
        reference = self.parse('(typeattributeset old_30_0 (old)) '
                               '(typeattributeset unrelated_30_0 (unrelated))')
        self.assertEqual(MODULE.reference_identity_bindings(
            reference, {'old_30_0'}, {'old'}), reference[:1])

    def test_invented_alias_rejected(self):
        with self.assertRaises(ValueError):
            MODULE.reference_identity_bindings(self.parse(
                '(typeattributeset old_30_0 (replacement))'), {'old_30_0'}, {'replacement'})

    def test_missing_current_type_rejected(self):
        with self.assertRaises(ValueError):
            MODULE.reference_identity_bindings(self.parse(
                '(typeattributeset old_30_0 (old))'), {'old_30_0'}, set())

    def test_compound_reference_rejected(self):
        with self.assertRaises(ValueError):
            MODULE.reference_identity_bindings(self.parse(
                '(typeattributeset old_30_0 (and a b))'), {'old_30_0'}, {'a', 'b'})

    def test_duplicate_reference_rejected(self):
        with self.assertRaises(ValueError):
            MODULE.reference_identity_bindings(self.parse(
                '(typeattributeset old_30_0 (old)) (typeattributeset old_30_0 (old))'),
                {'old_30_0'}, {'old'})


if __name__ == '__main__':
    unittest.main()
