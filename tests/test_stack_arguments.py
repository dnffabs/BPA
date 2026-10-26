"""Caller-SP / callee-entry-SP mapping, including conservative fallbacks."""
from pathlib import Path
import sys
import unittest

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))
from run_regressions import fixture, read_rows, run_rules


class StackArgumentMapping(unittest.TestCase):
    def case(self, name, bits=64, extra=None, recursive=False, replacements=None):
        word = bits // 8
        callee = 'f' if recursive else 'g'
        data = {
            'function': [('f', 100, 190), ('g', 200, 290),
                         ('alpha', 2000, 2010), ('beta', 3000, 3010)],
            'root': [('f',)], 'block': [('f', 100, 1), ('g', 200, 1)],
            'stack_root': [(1, 'f'), (2, 'g')],
            'constant': [(3, bits, 32), (4, bits, word), (5, bits, 2*word),
                         (6, bits, 2000), (7, bits, 3000),
                         (8, bits, 100 if recursive else 200)],
            'binary': [(10, f'Sub{bits}', bits, 1, 3),
                       (11, f'Add{bits}', bits, 10, 4),
                       (12, f'Add{bits}', bits, 2 if not recursive else 1, 4),
                       (13, f'Add{bits}', bits, 2 if not recursive else 1, 5)],
            'call': [(100, 'f', 100, 150, 8, 0),
                     (101, callee, 100 if recursive else 200, 220, 20, 1),
                     (102, callee, 100 if recursive else 200, 230, 21, 1)],
            'call_stack': [(100, 10)],
            'store': [(110, 'f', 120, word, 10, 6), (111, 'f', 130, word, 11, 7)],
            'load': [(120, callee, 210, word, 12, 20), (121, callee, 215, word, 13, 21)],
        }
        for relation, values in (extra or {}).items():
            data.setdefault(relation, []).extend(values)
        data.update(replacements or {})
        path = fixture('stack_map_' + name, data)
        if bits == 32:
            import json
            metadata = path / 'metadata.json'
            info = json.loads(metadata.read_text())
            info.update(arch='X86', bits=32, sp=24, return_reg=8)
            metadata.write_text(json.dumps(info))
        run_rules(path, analysis=True)
        return path

    def codes(self, path, expression):
        return {int(value) for eid, value in read_rows(path, 'code_value') if int(eid) == expression}

    def test_argument_positions_and_return_address_bias(self):
        for bits in (32, 64):
            with self.subTest(bits=bits):
                path = self.case(str(bits), bits)
                self.assertEqual(self.codes(path, 20), {2000})
                self.assertEqual(self.codes(path, 21), {3000})
                self.assertEqual(read_rows(path, 'call_stack_offset'), [['100', '-32']])
                maps = read_rows(path, 'stack_argument_map')
                self.assertTrue(maps)
                self.assertTrue(all(row[-1] == 'exact' for row in maps))
                self.assertFalse(read_rows(path, 'uncertain_call'))

    def test_incomplete_sp_retains_all_candidates(self):
        path = self.case('unknown_sp', extra={
            'unknown_seed': [(90,)], 'copy': [(90, 10)],
        })
        self.assertFalse(read_rows(path, 'call_stack_offset'))
        self.assertEqual(self.codes(path, 20), {2000, 3000})
        self.assertEqual(self.codes(path, 21), {2000, 3000})
        self.assertTrue(any(row[-1] == 'unknown-sp' for row in read_rows(path, 'stack_argument_map')))
        self.assertEqual({row[0] for row in read_rows(path, 'uncertain_call')}, {'220', '230'})

    def test_all_proven_sp_alternatives_are_mapped(self):
        path = self.case('multiple_sp', extra={
            'constant': [(60, 64, 40)], 'binary': [(61, 'Sub64', 64, 1, 60)],
            'copy': [(61, 10)], 'store': [(112, 'f', 135, 8, 61, 7)],
        })
        self.assertEqual({tuple(row) for row in read_rows(path, 'call_stack_offset')},
                         {('100', '-32'), ('100', '-40')})
        self.assertEqual(self.codes(path, 20), {2000, 3000})

    def test_unknown_source_write_reaches_known_argument(self):
        path = self.case('unknown_source', extra={
            'unknown_seed': [(90,)], 'binary': [(91, 'Add64', 64, 1, 90)],
            'store': [(112, 'f', 135, 8, 91, 7)],
        })
        self.assertEqual(self.codes(path, 20), {2000, 3000})
        self.assertTrue(any(row[-1] == 'unknown-source' for row in read_rows(path, 'stack_argument_map')))
        self.assertIn(['220'], read_rows(path, 'uncertain_call'))

    def test_recursive_mapping_stays_finite(self):
        path = self.case('recursive', recursive=True)
        self.assertEqual(self.codes(path, 20), {2000})
        self.assertEqual(self.codes(path, 21), {3000})
        self.assertLessEqual(len(read_rows(path, 'stack_argument_map')), 4)

    def test_reused_argument_slot_uses_latest_reaching_write(self):
        path = self.case('reused_slot', extra={
            'store': [(112, 'f', 140, 8, 10, 7)],
            'statement': [(110, 'f', 100, 120, 1), (111, 'f', 100, 130, 2),
                          (112, 'f', 100, 140, 3), (100, 'f', 100, 150, 4)],
        })
        self.assertEqual(self.codes(path, 20), {3000})
        self.assertNotIn(['100', '110'], read_rows(path, 'call_stack_store'))
        self.assertIn(['100', '112'], read_rows(path, 'call_stack_store'))

    def test_future_write_does_not_reach_earlier_call(self):
        path = self.case('future_write', extra={
            'store': [(112, 'f', 170, 8, 10, 7)],
            'statement': [(110, 'f', 100, 120, 1), (111, 'f', 100, 130, 2),
                          (100, 'f', 100, 150, 3), (112, 'f', 100, 170, 4)],
        })
        self.assertEqual(self.codes(path, 20), {2000})
        self.assertNotIn(['100', '112'], read_rows(path, 'call_stack_store'))

    def test_branch_reaching_writes_are_unioned(self):
        path = self.case('branch', extra={'store': [(112, 'f', 154, 8, 10, 7)]}, replacements={
            'block': [('f', 100, 1), ('f', 140, 0), ('f', 150, 0), ('f', 160, 0), ('g', 200, 1)],
            'edge': [('f', 100, 140, 'Ijk_Boring'), ('f', 100, 150, 'Ijk_Boring'),
                     ('f', 140, 160, 'Ijk_Boring'), ('f', 150, 160, 'Ijk_Boring')],
            'statement': [(110, 'f', 140, 144, 1), (112, 'f', 150, 154, 1),
                          (100, 'f', 160, 168, 1)],
        })
        self.assertEqual(self.codes(path, 20), {2000, 3000})
        self.assertIn(['100', '110'], read_rows(path, 'call_stack_store'))
        self.assertIn(['100', '112'], read_rows(path, 'call_stack_store'))

    def test_partial_store_keeps_pointer_candidate_and_marks_unknown(self):
        path = self.case('partial_overwrite', extra={
            'constant': [(90, 64, 0), (91, 64, 4)],
            'binary': [(92, 'Add64', 64, 10, 91)],
            'store': [(112, 'f', 140, 4, 92, 90)],
            'statement': [(110, 'f', 100, 120, 1), (111, 'f', 100, 130, 2),
                          (112, 'f', 100, 140, 3), (100, 'f', 100, 150, 4)],
        })
        self.assertEqual(self.codes(path, 20), {2000})
        self.assertIn(['100', '110'], read_rows(path, 'call_stack_store'))
        self.assertIn(['220'], read_rows(path, 'uncertain_call'))

    def test_delayed_vex_stack_alignment_is_not_certified_as_stale_sp(self):
        import archinfo
        import pyvex
        from types import SimpleNamespace
        from vex2Datalog.DatalogFacts import DatalogFacts
        from vex2Datalog.parser import VexParser
        facts = DatalogFacts()
        arch = archinfo.ArchX86()
        # opt_level=1 delays the AND result into CALL's final SP write.
        irsb = pyvex.IRSB(bytes.fromhex('83e4f0e800000000'), 0x1000, arch, opt_level=1)
        block = SimpleNamespace(vex=irsb, addr=0x1000, instruction_addrs=[0x1000, 0x1003],
                                capstone=SimpleNamespace(insns=[SimpleNamespace(
                                    insn=SimpleNamespace(operands=[SimpleNamespace(type=2)]))]))
        VexParser(facts, arch).parse(block, 'f')
        sp = facts.eid(('entry', 'f', arch.sp_offset))
        data = {name: list(rows) for name, rows in facts.rows.items()}
        data.update(function=[('f', 0x1000, 0x1010)], block=[('f', 0x1000, 1)], root=[('f',)],
                    stack_root=[(sp, 'f')], entry_reg=[('f', arch.sp_offset, sp)])
        path = fixture('stack_map_delayed_sp', data)
        import json
        metadata = path / 'metadata.json'
        info = json.loads(metadata.read_text())
        info.update(arch='X86', bits=32, sp=24, return_reg=8)
        metadata.write_text(json.dumps(info))
        run_rules(path, analysis=True)
        self.assertTrue(read_rows(path, 'call_stack'))
        self.assertFalse(read_rows(path, 'call_stack_offset'))
        snapshot = read_rows(path, 'call_stack')[0][1]
        self.assertIn([snapshot], read_rows(path, 'numeric_top'))

    def test_escaped_argument_slot_is_read_in_another_function(self):
        path = self.case('escaped_slot', extra={
            'function': [('h', 400, 490)], 'block': [('h', 400, 1)],
            'constant': [(60, 64, 400)],
            'call': [(140, 'g', 200, 240, 60, 0)],
            'call_input': [(140, 72, 12)], 'entry_reg': [('h', 72, 70)],
            'load': [(141, 'h', 410, 8, 70, 71)],
        })
        self.assertEqual(self.codes(path, 71), {2000})


if __name__ == '__main__':
    unittest.main(verbosity=2)
