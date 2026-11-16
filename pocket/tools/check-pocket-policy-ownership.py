#!/usr/bin/env python3
"""Synthetic controls for read-only ownership/set/config parsing."""
import importlib.util
from pathlib import Path
import tempfile
import unittest

SPEC = importlib.util.spec_from_file_location(
    'ownership', Path(__file__).with_name('audit-pocket-policy-ownership.py'))
M = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(M)


class OwnershipControls(unittest.TestCase):
    def model(self, text):
        return M.TypeSets({'fixture': M.CIL.forms(text)})

    def test_implicit_union(self):
        m = self.model('(type a) (type b) (typeattribute x) (typeattributeset x (a b))')
        self.assertEqual(m.expression('x'), {'a', 'b'})

    def test_nested_difference(self):
        m = self.model('(type a) (type b) (typeattribute x) '
                       '(typeattributeset x ((and (all) ((not (b))))))')
        self.assertEqual(m.expression('x'), {'a'})

    def test_union_multiple_assignments(self):
        m = self.model('(type a) (type b) (typeattribute x) '
                       '(typeattributeset x (a)) (typeattributeset x (b))')
        self.assertEqual(m.expression('x'), {'a', 'b'})

    def test_xor(self):
        m = self.model('(type a) (type b)')
        self.assertEqual(m.expression(['xor', ['a', 'b'], 'b']), {'a'})

    def test_alias(self):
        m = self.model('(type a) (typealias old) (typealiasactual old a)')
        self.assertEqual(m.expression('old'), {'a'})

    def test_empty_attribute(self):
        self.assertEqual(self.model('(typeattribute empty)').expression('empty'), set())

    def test_unknown_rejected(self):
        with self.assertRaises(ValueError):
            self.model('(type a)').expression('unknown')

    def test_cycle_rejected(self):
        m = self.model('(typeattribute a) (typeattribute b) '
                       '(typeattributeset a (b)) (typeattributeset b (not a))')
        with self.assertRaises(ValueError):
            m.expression('a')

    def test_operator_arity_rejected(self):
        with self.assertRaises(ValueError):
            self.model('(type a)').expression(['not', 'a', 'a'])

    def test_snapshot_delta_holds_declarations_fixed(self):
        docs = {'modern': M.CIL.forms('(type a) (typeattribute x) (typeattributeset x (a))'),
                'old': M.CIL.forms('(type b) (typeattributeset x (b))')}
        before = M.TypeSets(docs, {'old'})
        after = M.TypeSets(docs)
        self.assertEqual(before.types, after.types)
        self.assertEqual(after.expression('x') - before.expression('x'), {'b'})

    def init_sections(self, text):
        with tempfile.TemporaryDirectory() as directory:
            p = Path(directory) / 'fixture.rc'
            p.write_text(text)
            return M.section_file(p)

    def test_init_continuation_and_options(self):
        sections = self.init_sections('service demo /vendor/bin/demo \\\n  --input /data/vendor/demo\n    user system\n')
        self.assertEqual(sections[0]['header'], ['service', 'demo', '/vendor/bin/demo', '--input', '/data/vendor/demo'])
        self.assertEqual(sections[0]['body'][0]['tokens'], ['user', 'system'])

    def test_init_multiline_quote(self):
        sections = self.init_sections('on fs\n    write /dev/example "# owned\n"\n    start demo\n')
        self.assertEqual(sections[0]['body'][0]['tokens'], ['write', '/dev/example', '# owned\n'])
        self.assertEqual(sections[0]['body'][1]['tokens'], ['start', 'demo'])

    def test_init_unclosed_quote_rejected(self):
        with self.assertRaises(ValueError):
            self.init_sections('on fs\n    write /dev/example "unclosed\n')

    def test_categories_use_class(self):
        self.assertEqual(M.failure_class(['neverallow', 'a', 'b', ['property_service', ['set']]]),
                         'property-set-ownership')
        self.assertEqual(M.failure_class(['neverallow', 'a', 'b', ['hwservice_manager', ['add']]]),
                         'ipc-service-boundary')

    def test_self_correlation_rejects_different_target(self):
        m = self.model('(type a) (type b)')
        assertion = ['neverallow', 'a', 'self', ['file', ['read']]]
        grant = ['allow', 'a', 'b', ['file', ['read']]]
        self.assertEqual(M.set_intersection_witness(m, assertion, grant)['type_pair_count'], 0)

    def test_self_correlation_accepts_same_type(self):
        m = self.model('(type a) (type b)')
        assertion = ['neverallow', 'a', 'self', ['file', ['read']]]
        grant = ['allow', 'a', 'a', ['file', ['read']]]
        self.assertEqual(M.set_intersection_witness(m, assertion, grant)['example_pairs'], [('a', 'a')])

    def test_nonoverlapping_permission_is_not_witness(self):
        m = self.model('(type a)')
        assertion = ['neverallow', 'a', 'self', ['file', ['write']]]
        grant = ['allow', 'a', 'a', ['file', ['read']]]
        self.assertEqual(M.set_intersection_witness(m, assertion, grant)['type_pair_count'], 0)

    def test_counterfactual_preserves_other_set_definitions(self):
        docs = {'old': M.CIL.forms('(type a) (type b) (typeattribute shared) (typeattribute needed) '
                                   '(typeattributeset shared (a)) (typeattributeset needed (b))')}
        m = M.TypeSets(docs, omitted_assignments={('old', 'shared')})
        self.assertEqual(m.expression('shared'), set())
        self.assertEqual(m.expression('needed'), {'b'})


if __name__ == '__main__':
    unittest.main()
