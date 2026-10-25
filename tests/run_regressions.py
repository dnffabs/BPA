#!/usr/bin/env python3
"""Semantic regression tests, including the native pipeline entry point."""
import json
import os
from pathlib import Path
import subprocess
import sys
import unittest

# Keep source-tree bytecode out of the working diff when run through uv.
sys.dont_write_bytecode = True

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
sys.path.insert(0, str(ROOT / 'compare'))
from generate_facts import INPUTS
from memory_model import affine_values, build, read_rows, write_rows
from run_pipeline import find_souffle, datalog
from extract_dwarf_gt import get_var_size

OUTPUT = ROOT / 'build' / 'regressions'
OUTPUT.mkdir(parents=True, exist_ok=True)
ENV = dict(os.environ, PYTHONDONTWRITEBYTECODE='1', BPA_PYTHON=sys.executable)
ENV['PATH'] = f"{Path.home() / '.local/bin'}:" + ENV.get('PATH', '')
RESULTS = []


def command(args, log, expected=0):
    result = subprocess.run(list(map(str, args)), cwd=ROOT, env=ENV, text=True,
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=60)
    log.write_text(result.stdout)
    if expected is not None and result.returncode != expected:
        raise AssertionError(f"exit {result.returncode}: {args}; see {log}\n{result.stdout}")
    return result


def fixture(name, data):
    directory = OUTPUT / name
    directory.mkdir(exist_ok=True)
    for relation in INPUTS:
        write_rows(directory, relation, data.get(relation, []))
    (directory / 'metadata.json').write_text(json.dumps({
        'arch': 'AMD64', 'bits': 64, 'sp': 48, 'bp': 56, 'return_reg': 16}))
    return directory


def run_rules(directory, analysis=False, memory_model='offset'):
    souffle = find_souffle()
    datalog(directory, 'ssa.dl', souffle, 2, directory / 'ssa.log')
    if analysis:
        build(directory, memory_model)
        for rule in ('stack_boundary.dl', 'global_boundary.dl', 'heap_boundary.dl', 'aloc_gen.dl', 'analysis.dl'):
            datalog(directory, rule, souffle, 2, directory / f'{rule}.log')


class SemanticRegressions(unittest.TestCase):
    def test_read_before_write_and_instruction_order(self):
        path = fixture('ssa_order', {
            'function': [('f', 100, 300)],
            'block': [('f', 100, 1), ('f', 200, 0)],
            'edge': [('f', 100, 200, 'Ijk_Boring')],
            'entry_reg': [('f', 16, 900)],
            'register': [(16, 'rax')],
            'statement': [(1, 'f', 100, 110, 1), (2, 'f', 200, 200, 1),
                          (3, 'f', 200, 210, 2), (4, 'f', 200, 210, 3),
                          (5, 'f', 200, 210, 4)],
            'reg_def': [(1, 'f', 100, 1, 16, 90, 1001),
                        (3, 'f', 200, 2, 16, 91, 1002), (5, 'f', 200, 4, 16, 92, 1003)],
            'reg_read': [(2, 'f', 200, 1, 16, 101), (4, 'f', 200, 3, 16, 102)]})
        run_rules(path)
        edges = {tuple(map(int, r)) for r in read_rows(path, 'def_use')}
        self.assertIn((1001, 101), edges)
        self.assertIn((1002, 102), edges)
        self.assertEqual(len(read_rows(path, 'ssa_def')), 3)

    def test_register_values_do_not_merge_by_physical_name(self):
        path = fixture('ssa_values', {
            'function': [('f', 100, 200), ('alpha', 2000, 2010), ('beta', 3000, 3010)],
            'block': [('f', 100, 1)], 'root': [('f',)],
            'entry_reg': [('f', 16, 900)], 'register': [(16, 'rax')],
            'statement': [(i, 'f', 100, 100+i, i) for i in range(1, 5)],
            'reg_def': [(1, 'f', 100, 1, 16, 90, 1001), (3, 'f', 100, 3, 16, 91, 1002)],
            'reg_read': [(2, 'f', 100, 2, 16, 101), (4, 'f', 100, 4, 16, 102)],
            'copy': [(90, 1001), (91, 1002)],
            'constant': [(90, 64, 2000), (91, 64, 3000)]})
        run_rules(path, analysis=True)
        values = {tuple(map(int, row)) for row in read_rows(path, 'code_value')}
        self.assertEqual({v for e, v in values if e == 101}, {2000})
        self.assertEqual({v for e, v in values if e == 102}, {3000})

    def test_affine_offsets_and_interior_memory(self):
        path = fixture('affine_memory', {
            'function': [('f', 100, 200), ('alpha', 2000, 2010)], 'root': [('f',)],
            'block': [('f', 100, 1)], 'stack_root': [(10, 'f')],
            'constant': [(90, 64, 32), (91, 64, 8), (92, 64, 2000)],
            'binary': [(20, 'Sub64', 64, 10, 90), (21, 'Add64', 64, 20, 91)],
            'store': [(1, 'f', 110, 8, 20, 92)],
            'load': [(2, 'f', 120, 8, 21, 22)]})
        run_rules(path, analysis=True)
        self.assertIn(['21', 'f', '-24'], read_rows(path, 'affine_stack'))
        self.assertNotIn(['22', '2000'], read_rows(path, 'code_value'))
        self.assertIn(['120', '22', 'stk_f'], read_rows(path, 'load_from_aloc'))
        # The block baseline deliberately merges the two nonoverlapping slots.
        run_rules(path, analysis=True, memory_model='block')
        self.assertIn(['22', '2000'], read_rows(path, 'code_value'))

    def test_unary_temporary_and_block_namespace(self):
        import archinfo
        import pyvex
        from vex2Datalog.DatalogFacts import DatalogFacts
        from vex2Datalog.parser import VexParser
        facts = DatalogFacts()
        parser = VexParser(facts, archinfo.ArchAMD64())
        class Block:
            pass
        # A real VEX unary over a temporary, with a normal return terminator.
        for addr in (0x1000, 0x2000):
            irsb = pyvex.IRSB(bytes.fromhex('4889f8c3'), addr, archinfo.ArchAMD64(), opt_level=0)
            irsb.tyenv.types.extend(['Ity_I64', 'Ity_I32'])
            src, dst = len(irsb.tyenv.types)-2, len(irsb.tyenv.types)-1
            irsb.statements = [pyvex.stmt.IMark(addr, 1, 0),
                              pyvex.stmt.WrTmp(dst, pyvex.expr.Unop('Iop_64to32', [pyvex.expr.RdTmp(src)]))]
            block = Block()
            block.vex, block.addr, block.instruction_addrs = irsb, addr, [addr]
            parser.parse(block, 'f')
        self.assertEqual(len(facts.rows['unary']), 2)
        ids = [eid for eid, _, number in facts.rows['temporary'] if number == src]
        self.assertEqual(len(set(ids)), 2)

    def test_widening_unknown_and_stripped_failure(self):
        path = fixture('widen_unknown', {
            'function': [('f', 100, 200)], 'root': [('f',)],
            'block': [('f', 100, 1)], 'constant': [(1, 64, 1)],
            'copy': [(1, 10), (11, 10)], 'binary': [(11, 'Add64', 64, 10, 1)],
            'unknown_seed': [(50,)], 'call': [(20, 'f', 100, 150, 50, 1)]})
        run_rules(path, analysis=True)
        _, top = affine_values(path)
        self.assertIn(10, top)
        self.assertEqual(read_rows(path, 'unresolved_call'), [['150']])
        self.assertEqual(read_rows(path, 'uncertain_call'), [['150']])

        binary = OUTPUT / 'negative_parameter'
        command(['gcc', '-O0', '-fno-pie', '-no-pie', ROOT / 'tests/fixtures/parameter.c', '-o', binary],
                OUTPUT / 'negative_compile.log')
        command([ROOT / 'pipeline/run.sh', binary, '--output', OUTPUT / 'no_debug_analysis', '--compare'],
                OUTPUT / 'no_debug.log')
        gt = json.loads((OUTPUT / 'no_debug_analysis/evaluation/gt_metadata.json').read_text())
        self.assertFalse(gt['has_dwarf'])
        stripped = OUTPUT / 'stripped_parameter'
        # Use objcopy through a sibling of the configured GCC, including its libs.
        compiler = Path.home() / '.local/opt/gcc/usr'
        tool = compiler / 'bin/strip'
        if tool.exists():
            strip_env = dict(ENV, LD_LIBRARY_PATH=f'{compiler}/lib/x86_64-linux-gnu:{compiler}/lib')
            subprocess.run([str(tool), '--strip-all', '-o', str(stripped), str(binary)], env=strip_env, check=True)
        else:
            command(['strip', '--strip-all', '-o', stripped, binary], OUTPUT / 'strip.log')
        result = command([ROOT / 'pipeline/run.sh', stripped, '--output', OUTPUT / 'stripped_analysis'],
                         OUTPUT / 'stripped.log', expected=1)
        self.assertIn('no .symtab', result.stdout)
        summary = json.loads((OUTPUT / 'stripped_analysis/summary.json').read_text())
        self.assertEqual(summary['status'], 'failed')
        self.assertFalse((OUTPUT / 'stripped_analysis/facts/indirect_call_target.facts').exists())

    def test_legacy_plt_address(self):
        source = OUTPUT / 'legacy_plt.c'
        source.write_text('#include <stdlib.h>\nint main(void) { return malloc(16)==0; }\n')
        binary = OUTPUT / 'legacy_plt'
        command(['gcc', '-nostartfiles', '-fno-pie', '-no-pie', '-fcf-protection=none', '-Wl,-e,main',
                 source, '-o', binary], OUTPUT / 'legacy_plt_compile.log')
        from extract_heap_calls import get_plt_addrs
        from elftools.elf.elffile import ELFFile
        with binary.open('rb') as stream:
            elf = ELFFile(stream)
            self.assertIsNone(elf.get_section_by_name('.plt.sec'))
            actual = elf.get_section_by_name('.plt')['sh_addr'] + 16
        self.assertEqual(get_plt_addrs(binary), {actual: 'malloc'})

    def test_native_pipeline(self):
        cases = {
            'parameter': {'invoke': [{'target_true'}]},
            'registers': {'main': [{'alpha'}, {'beta'}]},
            'memory': {'from_global': [{'alpha'}], 'from_table': [{'beta'}],
                       'from_stack': [{'alpha'}], 'from_heap': [{'beta'}]},
            'factory': {'invoke_factory': [{'identity'}, {'alpha'}]},
            'allocators': {'dispatch': [{'alpha'}]},
            'stack_parameter': {'many': [{'alpha'}]},
            'control_flow': {'choose': [{'alpha', 'beta'}]},
            'repository_demo': {'main': [{'add'}, {'sub'}]},
        }
        variants = [(name, arch, False) for name in cases for arch in (64, 32)]
        variants.append(('memory', 64, True))
        for name, arch, pie in variants:
            label = f'{name}_{arch}' + ('_pie' if pie else '')
            with self.subTest(case=label):
                directory = OUTPUT / label
                directory.mkdir(exist_ok=True)
                binary = directory / label
                source = (ROOT / 'pipeline/bin/test.c' if name == 'repository_demo'
                          else ROOT / 'tests/fixtures' / f'{name}.c')
                flags = ['-fPIE', '-pie'] if pie else ['-fno-pie', '-no-pie']
                command(['gcc', '-std=c11', '-O0', '-g', '-fno-inline', '-fno-optimize-sibling-calls',
                         '-fno-omit-frame-pointer', '-fno-stack-protector', f'-m{arch}', *flags,
                         source, '-o', binary], directory / 'compile.log')
                command([binary], directory / 'runtime.log')
                command([ROOT / 'pipeline/run.sh', binary, '--output', directory / 'analysis', '--compare'], directory / 'pipeline.log')
                facts = directory / 'analysis/facts'
                targets = {}
                for site, target in read_rows(facts, 'indirect_call_target'):
                    targets.setdefault(int(site), set()).add(target)
                all_calls = read_rows(facts, 'call')
                tp = fp = fn = 0
                for func, expectations in cases[name].items():
                    calls = sorted([r for r in all_calls if r[1] == func and r[-1] == '1'], key=lambda r: int(r[3]))
                    self.assertEqual(len(calls), len(expectations), f'{label}: machine indirect site count for {func}')
                    for call, expected in zip(calls, expectations):
                        actual = targets.get(int(call[3]), set())
                        tp += len(actual & expected)
                        fp += len(actual - expected)
                        fn += len(expected - actual)
                        self.assertTrue(expected <= actual, f'{label} {func}@{int(call[3]):x}: {actual}, expected {expected}')
                        if name in ('parameter', 'registers'):
                            self.assertEqual(actual, expected)
                summary = json.loads((directory / 'analysis/summary.json').read_text())
                self.assertEqual(summary['status'], 'completed')
                self.assertFalse(summary['unresolved_calls'])
                self.assertTrue(read_rows(facts, 'interproc_edge'))
                if name == 'parameter':
                    from elftools.elf.elffile import ELFFile
                    with binary.open('rb') as stream:
                        elf = ELFFile(stream)
                        sizes = [get_var_size(d, cu) for cu in elf.get_dwarf_info().iter_CUs() for d in cu.iter_DIEs()
                                 if d.tag == 'DW_TAG_formal_parameter' and d.attributes.get('DW_AT_name')
                                 and d.attributes['DW_AT_name'].value == b'cb']
                        self.assertEqual(sizes, [arch // 8])
                if name == 'allocators' and arch == 64:
                    sizes = {r[2]: int(r[3]) for r in read_rows(facts, 'heap_alloc_call')}
                    self.assertEqual(sizes['calloc'], 24)
                    self.assertEqual(sizes['realloc'], 64)
                RESULTS.append({'case': label, 'TP': tp, 'FP': fp, 'FN': fn,
                                'sites': summary['indirect_calls'], 'summary': str(directory / 'analysis/summary.json')})
        (OUTPUT / 'results.json').write_text(json.dumps(RESULTS, indent=2)+'\n')


if __name__ == '__main__':
    unittest.main(verbosity=2)
