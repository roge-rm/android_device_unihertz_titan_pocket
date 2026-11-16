#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Controls for the actual source interface reconstruction functions."""
import importlib.util
from pathlib import Path
import unittest

SPEC = importlib.util.spec_from_file_location('source', Path(__file__).with_name('prepare-pocket-policy-source.py'))
M = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(M)
F = M.CIL.forms


class SourceControls(unittest.TestCase):
    def test_empty_atomic_assertion(self):
        rows, edits = M.absent_domain_projection(F('(neverallow obsolete live (file (read)))'), 'obsolete', {'live'})
        self.assertEqual(rows, [])
        self.assertEqual(len(edits), 1)

    def test_live_domain_cannot_project(self):
        with self.assertRaises(ValueError):
            M.absent_domain_projection(F('(neverallow old live (file (read)))'), 'old', {'old', 'live'})

    def test_grant_cannot_project(self):
        with self.assertRaises(ValueError):
            M.absent_domain_projection(F('(allow old live (file (read)))'), 'old', {'live'})

    def test_transition_cannot_project(self):
        with self.assertRaises(ValueError):
            M.absent_domain_projection(F('(typetransition init old process live)'), 'old', {'live'})

    def test_compound_assertion_cannot_disappear(self):
        with self.assertRaises(ValueError):
            M.absent_domain_projection(F('(neverallow (old live) object (file (read)))'), 'old', {'live', 'object'})

    def test_empty_exclusion_preserves_complement(self):
        doc = F('(typeattribute x) (typeattributeset x (not (live old))) '
                '(neverallow old object (file (read))) (neverallow x object (file (read)))')
        rows, _ = M.absent_domain_projection(doc, 'old', {'live', 'object', 'third'})
        self.assertIn(['typeattributeset', 'x', ['not', ['live']]], rows)
        universe = {'live', 'object', 'third'}
        self.assertEqual(universe - {'live', 'old'}, universe - {'live'})

    def test_exclusion_with_grant_consumer_rejected(self):
        doc = F('(typeattribute x) (typeattributeset x (not (live old))) '
                '(neverallow old object (file (read))) (allow x object (file (read)))')
        with self.assertRaises(ValueError):
            M.absent_domain_projection(doc, 'old', {'live', 'object'})

    def test_unknown_use_rejected(self):
        with self.assertRaises(ValueError):
            M.absent_domain_projection(F('(typeattributeset x (or (old live)))'), 'old', {'live'})

    def test_no_silent_missing_review_target(self):
        with self.assertRaises(ValueError):
            M.absent_domain_projection(F('(neverallow live object (file (read)))'), 'old', {'live', 'object'})

    def test_external_private_predicate_namespaced(self):
        doc = F('(neverallow base_typeattr_7 object (file (read)))')
        stock = F('(typeattribute base_typeattr_7) (typeattributeset base_typeattr_7 (not (init)))')
        rows, report = M.reconstruct_external_attributes(doc, stock, 'pocket_')
        self.assertEqual(rows[0][1], 'pocket_7')
        self.assertIn(['typeattributeset', 'pocket_7', ['not', ['init']]], rows)
        self.assertEqual(report[0]['stock_symbol'], 'base_typeattr_7')

    def test_external_definition_must_be_unique(self):
        with self.assertRaises(ValueError):
            M.reconstruct_external_attributes(F('(neverallow base_typeattr_7 object (file (read)))'), [], 'pocket_')

    def test_namespaced_destination_cannot_collide(self):
        with self.assertRaises(ValueError):
            M.reconstruct_external_attributes(F('(typeattribute pocket_7) (neverallow base_typeattr_7 object (file (read)))'), [], 'pocket_')

    def contract(self, kind='retained_stock_app_grant_set'):
        return {'symbol': 'old_apps', 'kind': kind, 'definition': ['appdomain'], 'retained_members': ['old_app']}

    def test_grant_set_excludes_new_isolated_domain(self):
        snapshot = F('(typeattribute old_apps) (typeattributeset old_apps (appdomain)) '
                     '(allow old_apps object (file (read)))')
        others = [F('(type old_app) (type new_isolated_app) (typeattribute appdomain)')]
        rows = M.extended_interface(snapshot, others, [self.contract()])
        self.assertIn(['typeattributeset', 'old_apps', ['old_app']], rows)
        self.assertFalse(any(s[0] == 'allow' for s in rows))

    def test_retained_grant_member_must_exist(self):
        with self.assertRaises(ValueError):
            M.extended_interface(F('(typeattributeset old_apps (appdomain))'), [], [self.contract()])

    def test_changed_stock_contract_rejected(self):
        with self.assertRaises(ValueError):
            M.extended_interface(F('(typeattributeset old_apps (other))'), [F('(type old_app)')], [self.contract()])

    def test_unknown_contract_kind_rejected(self):
        with self.assertRaises(ValueError):
            M.extended_interface(F('(typeattributeset old_apps (appdomain))'), [F('(type old_app)')], [self.contract('dummy')])

    def test_assertion_predicate_preserved(self):
        c = self.contract('modern_domain_assertion_predicate')
        rows = M.extended_interface(F('(typeattribute old_apps) (typeattributeset old_apps (appdomain))'), [], [c])
        self.assertIn(['typeattributeset', 'old_apps', ['appdomain']], rows)

    def app_macro(self, versioned=False):
        names = 'crash_dump_30_0 runas_app_30_0 simpleperf_30_0 app' if versioned else 'crash_dump runas_app simpleperf app'
        return F('(typeattribute x) (typeattributeset x ((and (domain) ((not (' + names + ')))))) '
                 '(neverallow x app (process (ptrace)))')

    def test_debug_app_macro_retains_assertion(self):
        doc = self.app_macro()
        rows, changes = M.modernize_debug_app_assertions(doc, True)
        self.assertEqual(rows[-1], doc[-1])
        self.assertEqual(changes[0]['debug_exception'], 'llkd')
        self.assertIn('llkd', set(M.CIL.atoms(rows[1])))

    def test_user_build_gets_no_debug_exception(self):
        doc = self.app_macro()
        rows, changes = M.modernize_debug_app_assertions(doc, False)
        self.assertEqual(rows, doc)
        self.assertEqual(changes, [])

    def test_versioned_debug_exception(self):
        rows, changes = M.modernize_debug_app_assertions(self.app_macro(True), True)
        self.assertEqual(changes[0]['debug_exception'], 'llkd_30_0')

    def test_app_set_with_grant_is_not_modified(self):
        doc = self.app_macro() + F('(allow x app (process (getattr)))')
        self.assertEqual(M.modernize_debug_app_assertions(doc, True), (doc, []))

    def test_unreviewed_exclusion_is_not_modified(self):
        doc = self.app_macro()
        doc[1] = F('(typeattributeset x (and (domain) (not (app crash_dump other))))')[0]
        self.assertEqual(M.modernize_debug_app_assertions(doc, True), (doc, []))

    def owner_rule(self):
        return {'subject': 'owner', 'target': 'data', 'class': 'dir',
                'permissions': ['rename'], 'reason': 'Reviewed atomic directory commit'}

    def test_framework_role_projects_whole_owned_member_only(self):
        class Model:
            def expression(self, member):
                return {'old': {'modern', 'new'}, 'private': {'vendor'},
                        'mixed': {'modern', 'vendor'}}[member]
        rows, changes = M.project_framework_roles(
            F('(typeattributeset role (old private mixed)) (allow old object (file (read))) '
              '(neverallow old object (file (write)))'), {'modern', 'new'}, {'role'}, Model())
        self.assertEqual(rows[0], ['typeattributeset', 'role', ['private', 'mixed']])
        self.assertEqual(len(changes), 1)
        self.assertEqual(rows[1:], F('(allow old object (file (read))) (neverallow old object (file (write)))'))

    def test_framework_role_keeps_private_attribute_and_expressions(self):
        class Unused:
            def expression(self, member):
                raise AssertionError('Must not resolve unreviewed shape')
        doc = F('(typeattributeset private_role (old)) (typeattributeset role (not (old)))')
        self.assertEqual(M.project_framework_roles(doc, {'old'}, {'role'}, Unused()), (doc, []))

    def test_predicate_owner_split_preserves_other_domains_and_permissions(self):
        rule = dict(predicate='original', owner='owner', target='data', **{'class':'dir'},
                    permissions=['mounton'], expected_assertions=1)
        doc = F('(neverallow original data (dir (mounton write)))')
        rows, _ = M.adapt_predicate_operations(doc, [rule], {('owner','data','dir'):{'mounton'}})
        self.assertEqual(rows[0], F('(neverallow original data (dir (write)))')[0])
        self.assertEqual(rows[2][2], ['and', ['original'], ['not', ['owner']]])
        self.assertEqual(rows[3][3], ['dir', ['mounton']])
        # Cartesian proof over a small universe: only the reviewed pair changes.
        old={(s,'data',p) for s in ['owner','other'] for p in ['write','mounton']}
        new={(s,'data','write') for s in ['owner','other']}|{('other','data','mounton')}
        self.assertEqual(old-new, {('owner','data','mounton')})

    def test_predicate_owner_rejects_count_drift(self):
        rule = dict(predicate='original', owner='owner', target='data', **{'class':'dir'},
                    permissions=['mounton'], expected_assertions=2)
        with self.assertRaises(ValueError):
            M.adapt_predicate_operations(F('(neverallow original data (dir (mounton write)))'),
                                        [rule], {('owner','data','dir'):{'mounton'}})

    def test_predicate_multiple_owners_partition_overlap(self):
        common=dict(predicate='original',target='data',**{'class':'dir'},expected_assertions=1)
        rules=[dict(common,owner='one',permissions=['read','open']),
               dict(common,owner='two',permissions=['read'])]
        rows,_=M.adapt_predicate_operations(F('(neverallow original data (dir (read open write)))'),rules,
                                            {('one','data','dir'):{'read','open'},('two','data','dir'):{'read'}})
        constraints={tuple(s[2][2][1]):None for s in rows if s[0]=='typeattributeset'}
        self.assertEqual(set(constraints),{('one','two'),('one',)})
        self.assertEqual(rows[0][3],['dir',['write']])

    def test_isolated_domain_projection_rejects_unreviewed_grant(self):
        with self.assertRaises(ValueError):
            M.protect_modern_isolated_domains(F('(typeattributeset base_typeattr_562_30_0 ((and (domain) ((not (isolated_app_30_0)))))) '
                                               '(allow base_typeattr_562_30_0 secret (file (write)))'))

    def test_isolated_domain_projection_only_tightens_grants(self):
        doc=F('(allow base_typeattr_562_30_0 sysfs_devinfo (file (ioctl read getattr lock map open watch watch_reads))) '
              '(allow base_typeattr_562_30_0 storage_file_30_0 (dir (search))) '
              '(typeattributeset base_typeattr_562_30_0 ((and (domain) ((not (isolated_app_30_0))))))')
        rows, change=M.protect_modern_isolated_domains(doc)
        self.assertEqual(rows[:2], doc[:2])
        self.assertEqual(change['modern_exclusion'], 'isolated_app_all')

    def test_protected_owner_revokes_only_selected_permissions(self):
        doc=F('(allow radio old_net (file (read write open))) (neverallow other protected (file (write)))')
        rule=dict(legacy_target='old_net',protected_type='protected',**{'class':'file'},
                  permissions=['write'],expected_grants=1)
        rows,_=M.restrict_protected_owner_grants(doc,[rule])
        self.assertEqual(rows[0],F('(allow radio old_net (file (read open)))')[0])
        self.assertEqual(rows[1][3],['file',['write']])
        self.assertIn(doc[1],rows)
        self.assertEqual(rows[-1][2], ['and',['old_net'],['not',['protected']]])

    def test_protected_owner_requires_exact_count(self):
        rule=dict(legacy_target='old_net',protected_type='protected',**{'class':'file'},
                  permissions=['write'],expected_grants=1)
        with self.assertRaises(ValueError):
            M.restrict_protected_owner_grants([], [rule])

    def test_legacy_mls_scope_retains_rules_and_types(self):
        doc=F('(type old_app) (allow mlsvendorcompat data (file (read))) '
              '(typeattributeset mlsvendorcompat (and appdomain vendordomain))')
        rows=M.scope_legacy_mls_role(doc, ['old_app','modern_app'], {'old_app','modern_app'})
        self.assertEqual(rows[:2],doc[:2])
        self.assertIn('modern_app',set(M.CIL.atoms(rows[-1])))

    def test_legacy_mls_scope_reopens_new_domain_review(self):
        with self.assertRaises(ValueError):
            M.scope_legacy_mls_role(F('(typeattributeset mlsvendorcompat (and appdomain vendordomain))'),
                                   ['old_app'], {'old_app','new_vendor_app'})

    def test_obsolete_grant_revocation_preserves_assertions(self):
        rule=dict(subject='owner',target='self',**{'class':'capability'},permissions=['sys_module'])
        doc=F('(allow owner self (capability (sys_module))) (neverallow owner self (capability (sys_module))) '
              '(allow init self (capability (sys_module)))')
        rows,_=M.revoke_obsolete_framework_grants(doc,[rule])
        self.assertEqual(rows,doc[1:])

    def test_obsolete_grant_revocation_rejects_shape_drift(self):
        rule=dict(subject='owner',target='self',**{'class':'capability'},permissions=['sys_module'])
        with self.assertRaises(ValueError):
            M.revoke_obsolete_framework_grants(F('(allow owner self (capability (sys_module chown)))'),[rule])

    def debug_transport(self):
        return F(' '.join('(neverallow '+d+' domain (tcp_socket (accept getopt read write create bind connect listen name_connect)))'
                          for d in ['mtk_hal_audio','mediacodec']))

    def test_debug_transport_retains_network_creation_denials(self):
        allowed={(d,'su','tcp_socket'):{'accept','getopt','read','write'} for d in ['mtk_hal_audio','mediacodec']}
        rows,_=M.modernize_debug_binder_transport(self.debug_transport(),True,allowed)
        self.assertEqual(rows[0][3],['tcp_socket',['create','bind','connect','listen','name_connect']])
        self.assertEqual(rows[3][2],'pocket_debug_binder_tcp_peers_mtk_hal_audio')

    def test_debug_transport_no_user_exception(self):
        doc=self.debug_transport()
        self.assertEqual(M.modernize_debug_binder_transport(doc,False,{}),(doc,[]))

    def test_debug_transport_requires_modern_source_grant(self):
        with self.assertRaises(ValueError):
            M.modernize_debug_binder_transport(self.debug_transport(),True,{})

    def test_generic_label_rebinding_preserves_denial_and_other_rules(self):
        rule=dict(subject='constraint',legacy_target='proc_old',current_target='proc',**{'class':'file'})
        doc=F('(neverallow constraint proc_old (file (read write))) (neverallow other proc_old (file (write))) '
              '(allow radio proc_old (file (read)))')
        rows,_=M.rebind_generic_label_assertions(doc,[rule],F('(typeattributeset proc_old (proc))'))
        self.assertEqual(rows[0],F('(neverallow constraint proc (file (read write)))')[0])
        self.assertEqual(rows[1:],doc[1:])

    def test_generic_label_rebinding_requires_original_singleton(self):
        rule=dict(subject='constraint',legacy_target='proc_old',current_target='proc',**{'class':'file'})
        with self.assertRaises(ValueError):
            M.rebind_generic_label_assertions(F('(neverallow constraint proc_old (file (write)))'),[rule],
                                              F('(typeattributeset proc_old (proc other))'))

    def test_property_context_rebinding_preserves_exact_name_and_value(self):
        rule=dict(old_line='ro.legacy u:object_r:old:s0 exact int',new_line='ro.legacy u:object_r:new:s0 exact int')
        text='# comment\nro.legacy  u:object_r:old:s0 exact int\nother u:object_r:keep:s0\n'
        self.assertEqual(M.rebind_property_contexts(text,[rule]),
                         '# comment\nro.legacy u:object_r:new:s0 exact int\nother u:object_r:keep:s0\n')

    def test_property_context_rebinding_rejects_name_or_value_change(self):
        with self.assertRaises(ValueError):
            M.rebind_property_contexts('ro.legacy u:object_r:old:s0 exact int\n',[
                dict(old_line='ro.legacy u:object_r:old:s0 exact int',new_line='ro.other u:object_r:new:s0 exact string')])

    def test_owner_adaptation_preserves_other_scope(self):
        doc = F('(neverallow owner data (dir (rename execute))) '
                '(neverallow other data (dir (rename execute))) '
                '(neverallow owner secret (dir (rename execute)))')
        rows, changes = M.adapt_owner_permissions(doc, [self.owner_rule()], {('owner', 'data', 'dir'): {'rename'}})
        self.assertEqual(rows[0], ['neverallow', 'owner', 'data', ['dir', ['execute']]])
        self.assertEqual(rows[1:], doc[1:])
        self.assertTrue(changes[0]['assertion_retained'])

    def test_owner_adaptation_requires_modern_allow(self):
        with self.assertRaises(ValueError):
            M.adapt_owner_permissions(F('(neverallow owner data (dir (rename execute)))'), [self.owner_rule()], {})

    def test_owner_adaptation_cannot_empty_assertion(self):
        with self.assertRaises(ValueError):
            M.adapt_owner_permissions(F('(neverallow owner data (dir (rename)))'), [self.owner_rule()], {('owner', 'data', 'dir'): {'rename'}})

    def test_owner_adaptation_requires_exact_statement(self):
        with self.assertRaises(ValueError):
            M.adapt_owner_permissions(F('(neverallow (owner other) data (dir (rename execute)))'), [self.owner_rule()], {('owner', 'data', 'dir'): {'rename'}})

    def test_owner_adaptation_rejects_changed_denials(self):
        with self.assertRaises(ValueError):
            M.adapt_owner_permissions(F('(neverallow owner data (dir (execute)))'), [self.owner_rule()], {('owner', 'data', 'dir'): {'rename'}})


if __name__ == '__main__':
    unittest.main()
