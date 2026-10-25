#!/usr/bin/env python3
"""Small semantic counterexamples for finite, conservative offset tracking."""
import sys
from pathlib import Path
import unittest

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))
from run_regressions import fixture, read_rows, run_rules


class OffsetRuleRegressions(unittest.TestCase):
    def heap_case(self, name, additions):
        data = {
            'function': [('f', 100, 500), ('alpha', 2000, 2010), ('beta', 3000, 3010)],
            'root': [('f',)], 'block': [('f', 100, 1)],
            'register': [(16, 'rax'), (48, 'rsp'), (72, 'rdi'), (64, 'rsi')],
            'external': [(1000, 'malloc')],
            'constant': [(1, 64, 1000), (2, 64, 32), (3, 64, 2000),
                         (4, 64, 3000), (5, 64, 8)],
            'call': [(101, 'f', 100, 110, 1, 0)],
            'call_input': [(101, 72, 2)], 'call_output': [(101, 16, 10)],
        }
        for relation, rows in additions.items():
            data.setdefault(relation, []).extend(rows)
        path = fixture('offset_rules_' + name, data)
        run_rules(path, analysis=True)
        return path

    def points(self, path, eid):
        return {tuple(row[1:]) for row in read_rows(path, 'points_to_offset')
                if int(row[0]) == eid}

    def codes(self, path, eid):
        return {int(value) for expression, value in read_rows(path, 'code_value')
                if int(expression) == eid}

    def test_zero_base_and_loop_widening(self):
        path = self.heap_case('zero_base', {
            'binary': [(20, 'Add64', 64, 10, 5), (21, 'Add64', 64, 20, 5),
                       (31, 'Add64', 64, 30, 5)],
            'copy': [(10, 30), (31, 30)],
        })
        self.assertEqual(self.points(path, 20), {('heap_f_110', 'exact', '8')})
        self.assertEqual(self.points(path, 21), {('heap_f_110', 'unknown', '0')})
        loop = self.points(path, 30) | self.points(path, 31)
        self.assertIn(('heap_f_110', 'unknown', '0'), loop)
        self.assertLessEqual(len(loop), 3)
        self.assertFalse(any(kind == 'exact' and int(offset) not in (0, 8)
                             for _, kind, offset in loop))

    def test_mixed_stack_heap_phi_keeps_both_blocks(self):
        path = self.heap_case('mixed_phi', {
            'stack_root': [(40, 'f')], 'constant': [(6, 64, 16)],
            'binary': [(41, 'Sub64', 64, 40, 6)],
            'copy': [(41, 42), (10, 42)],
            'store': [(102, 'f', 120, 8, 41, 3)],
        })
        blocks = {row[0] for row in self.points(path, 42)}
        self.assertEqual(blocks, {'stk_f', 'heap_f_110'})
        self.assertNotIn(['42'], read_rows(path, 'complete_value'))

    def test_unknown_producer_prevents_constant_completeness(self):
        path = self.heap_case('incomplete_literal', {
            'constant': [(50, 64, 4000)], 'unknown_seed': [(51,)],
            'copy': [(51, 50)], 'global_region': [('.data', 4000, 4032)],
            'binary': [(52, 'Add64', 64, 10, 50)],
        })
        self.assertNotIn(['50'], read_rows(path, 'complete_value'))
        self.assertFalse(any(row[0] == '50' for row in read_rows(path, 'offset_literal')))
        self.assertIn(('heap_f_110', 'unknown', '0'), self.points(path, 52))

    def test_partial_operation_result_is_not_complete(self):
        path = self.heap_case('partial_operation', {
            'stack_root': [(40, 'f')], 'constant': [(6, 64, 2)],
            'copy': [(40, 50), (5, 50)],
            'binary': [(51, 'Mul64', 64, 50, 6)],
            'global_region': [('.data', 16, 64)],
        })
        # Multiplication models 8*2, but not the alternative stack address*2.
        # The resulting {16} may-set therefore cannot certify completeness.
        self.assertIn(['51', '16'], read_rows(path, 'scalar'))
        self.assertNotIn(['51'], read_rows(path, 'complete_value'))

    def test_and_preserves_pointer_from_either_operand(self):
        path = self.heap_case('and_operands', {
            'constant': [(6, 64, -16)],
            'binary': [(20, 'And64', 64, 10, 6), (21, 'And64', 64, 6, 10)],
        })
        expected = {('heap_f_110', 'unknown', '0')}
        self.assertEqual(self.points(path, 20), expected)
        self.assertEqual(self.points(path, 21), expected)

    def test_exact_writes_remain_separate(self):
        path = self.heap_case('separate_writes', {
            'binary': [(20, 'Add64', 64, 10, 5)],
            'store': [(102, 'f', 120, 8, 10, 3), (103, 'f', 130, 8, 20, 4)],
            'load': [(104, 'f', 140, 8, 10, 30), (105, 'f', 150, 8, 20, 31)],
        })
        self.assertEqual(self.codes(path, 30), {2000})
        self.assertEqual(self.codes(path, 31), {3000})

    def test_unknown_write_reaches_exact_load(self):
        path = self.heap_case('unknown_write', {
            'unknown_seed': [(90,)], 'binary': [(20, 'Add64', 64, 10, 90)],
            'store': [(102, 'f', 120, 8, 10, 3), (103, 'f', 130, 8, 20, 4)],
            'load': [(104, 'f', 140, 8, 10, 30)],
        })
        self.assertEqual(self.codes(path, 30), {2000, 3000})
        self.assertIn(['heap_f_110', 'unknown', '0', '8', '3000'],
                      read_rows(path, 'memory_code_offset'))

    def test_unknown_load_reaches_all_exact_writes(self):
        path = self.heap_case('unknown_load', {
            'unknown_seed': [(90,)],
            'binary': [(20, 'Add64', 64, 10, 5), (21, 'Add64', 64, 10, 90)],
            'store': [(102, 'f', 120, 8, 10, 3), (103, 'f', 130, 8, 20, 4)],
            'load': [(104, 'f', 140, 8, 21, 30)],
        })
        self.assertEqual(self.codes(path, 30), {2000, 3000})

    def test_partial_memory_access_is_uncertain(self):
        for name, load_offset, store_width, load_width in (
                ('overlap', 4, 8, 8), ('short_load', 0, 8, 4), ('short_store', 0, 4, 8)):
            with self.subTest(case=name):
                path = self.heap_case(name, {
                    'constant': [(6, 64, load_offset)],
                    'binary': [(20, 'Add64', 64, 10, 6)],
                    'store': [(102, 'f', 120, store_width, 10, 3)],
                    'load': [(103, 'f', 130, load_width, 20, 30)],
                    'call': [(104, 'f', 100, 140, 30, 1)],
                })
                self.assertIn(['140'], read_rows(path, 'uncertain_call'))

    def test_stored_pointer_preserves_target_offset(self):
        path = self.heap_case('stored_pointer', {
            'constant': [(70, 64, 4000)], 'global_region': [('.data', 4000, 4032)],
            'binary': [(20, 'Add64', 64, 10, 5)],
            'store': [(102, 'f', 120, 8, 70, 20)],
            'load': [(103, 'f', 130, 8, 70, 30)],
        })
        self.assertEqual(self.points(path, 30), {('heap_f_110', 'exact', '8')})
        self.assertIn(['glb_.data', 'exact', '0', '8', 'heap_f_110', 'exact', '8'],
                      read_rows(path, 'memory_pointer_offset'))


if __name__ == '__main__':
    unittest.main(verbosity=2)
