#!/usr/bin/env python3
"""Native, end-to-end comparisons for the optional offset memory models.

Run: uv run --locked python tests/test_offsets.py
Reports: build/offset-regressions/results.json

Every binary runs natively before analysis. Expectations are fixture-specific;
the report measures indirect targets, not general memory-access soundness.
"""
import json
import os
from pathlib import Path
import subprocess
import sys
import time
import unittest

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / 'build' / 'offset-regressions'
OUTPUT.mkdir(parents=True, exist_ok=True)
ENV = dict(os.environ, PYTHONDONTWRITEBYTECODE='1', BPA_PYTHON=sys.executable)
ENV['PATH'] = f"{Path.home() / '.local/bin'}:" + ENV.get('PATH', '')
ALPHA = 'offset_alpha'
BETA = 'offset_beta'
BOTH = {ALPHA, BETA}
MODES = ('block', 'heap-offset', 'offset')
RESULTS = []


def command(args, log, timeout=120):
    result = subprocess.run(list(map(str, args)), cwd=ROOT, env=ENV, text=True,
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                            timeout=timeout)
    log.write_text(result.stdout)
    if result.returncode:
        raise AssertionError(f'exit {result.returncode}: {args}; see {log}\n{result.stdout}')
    return result


def rows(directory, relation):
    path = directory / f'{relation}.facts'
    return [line.split('\t') for line in path.read_text().splitlines() if line]


class OffsetEndToEndTests(unittest.TestCase):
    @classmethod
    def tearDownClass(cls):
        # Keep successful evidence even if a later case exposes a regression.
        (OUTPUT / 'results.json').write_text(json.dumps({
            'measurement': 'fixture indirect-call targets; elapsed pipeline wall time',
            'cases': RESULTS,
            'totals': {mode: {
                key: sum(result[key] for result in RESULTS if result['mode'] == mode)
                for key in ('TP', 'FP', 'FN', 'indirect_edges', 'elapsed_seconds')
            } for mode in MODES},
        }, indent=2) + '\n')

    def run_case(self, name, truth, expected, architectures=(64, 32)):
        for bits in architectures:
            label = f'{name}_{bits}'
            directory = OUTPUT / label
            directory.mkdir(parents=True, exist_ok=True)
            binary = directory / label
            command(['gcc', '-std=c11', '-O0', '-g', '-fno-inline',
                     '-fno-optimize-sibling-calls', '-fno-omit-frame-pointer',
                     '-fno-stack-protector', '-fno-pie', '-no-pie', f'-m{bits}',
                     ROOT / 'tests' / 'fixtures' / f'offset_{name}.c', '-o', binary],
                    directory / 'compile.log')
            command([binary], directory / 'runtime.log')
            for mode in MODES:
                with self.subTest(case=label, mode=mode):
                    analysis = directory / mode
                    started = time.perf_counter()
                    command([ROOT / 'pipeline' / 'run.sh', binary,
                             '--output', analysis, '--memory-model', mode],
                            directory / f'{mode}.log')
                    elapsed = time.perf_counter() - started
                    facts = analysis / 'facts'
                    summary = json.loads((analysis / 'summary.json').read_text())
                    self.assertEqual(summary['status'], 'completed')
                    self.assertFalse(summary['unresolved_calls'])
                    targets = {}
                    for site, target in rows(facts, 'indirect_call_target'):
                        targets.setdefault(int(site), set()).add(target)
                    calls = rows(facts, 'call')
                    entries = []
                    tp = fp = fn = 0
                    for function, native_targets in truth.items():
                        sites = [int(r[3]) for r in calls if r[1] == function and r[-1] == '1']
                        self.assertEqual(len(sites), 1, f'{label}: {function} machine call count')
                        actual = targets.get(sites[0], set())
                        tp += len(actual & native_targets)
                        fp += len(actual - native_targets)
                        fn += len(native_targets - actual)
                        entries.append({'function': function, 'site': sites[0],
                                        'expected_native': sorted(native_targets),
                                        'actual': sorted(actual)})
                    report = {'case': name, 'bits': bits, 'mode': mode, 'native_exit': 0,
                              'TP': tp, 'FP': fp, 'FN': fn,
                              'indirect_edges': sum(len(t) for t in targets.values()),
                              'call_graph_edges': len(rows(facts, 'call_graph')),
                              'points_to_offset_rows': len(rows(facts, 'points_to_offset')),
                              'memory_code_offset_rows': len(rows(facts, 'memory_code_offset')),
                              'analysis_resources': summary['analysis_resources'],
                              'elapsed_seconds': round(elapsed, 4),
                              'sites': entries, 'summary': str(analysis / 'summary.json')}
                    RESULTS.append(report)
                    for entry in entries:
                        actual = set(entry['actual'])
                        wanted, exact = expected(entry['function'], mode, bits)
                        self.assertTrue(wanted <= actual, f'{label}/{mode}: {entry}, need {wanted}')
                        if exact:
                            self.assertEqual(actual, wanted, f'{label}/{mode}: {entry}')
                    if name == 'fields' and mode == 'heap-offset':
                        # Heap fields themselves remain precise even when a coarse
                        # spilled stack pointer adds a false alias at the load.
                        functions = {r[0]: int(r[1]) for r in rows(facts, 'function')}
                        heap_writes = {(r[1], int(r[2]), int(r[4]))
                                       for r in rows(facts, 'memory_code_offset')
                                       if r[0].startswith('heap_')}
                        self.assertEqual(heap_writes, {
                            ('exact', 0, functions[ALPHA]),
                            ('exact', bits // 8, functions[BETA]),
                        })
                    if name == 'loop' and mode != 'block':
                        unknown_heap = [r for r in rows(facts, 'points_to_offset')
                                        if r[1].startswith('heap_') and r[2] == 'unknown']
                        self.assertTrue(unknown_heap, 'loop-carried pointer must widen its offset')
                    if name == 'interproc' and mode != 'block' and bits == 64:
                        interior_pointers = [r for r in rows(facts, 'memory_pointer_offset')
                                             if r[0].startswith('heap_')
                                             and r[4].startswith('heap_')
                                             and r[5] == 'exact' and int(r[6]) == bits // 8]
                        self.assertTrue(interior_pointers,
                                        'heap-stored interior pointer lost its target offset')

    def test_separate_fields(self):
        truth = {name: {ALPHA} for name in ('heap_fields', 'stack_fields', 'global_fields')}

        def expected(function, mode, bits):
            # In heap-offset, loading pair from a coarse frame also picks up the
            # saved caller frame pointer. Stores through this false alias merge
            # both callbacks in that stack frame, despite exact heap offsets.
            precise = mode == 'offset'
            return ({ALPHA} if precise else BOTH), True

        self.run_case('fields', truth, expected)

    def test_heap_only_ablation(self):
        # x86 main performs additional stack alignment; the independent x86
        # driver fixtures above cover that architecture without this confounder.
        self.run_case('heap_only', {'main': {ALPHA}},
                      lambda function, mode, bits: (BOTH if mode == 'block' else {ALPHA}, True),
                      architectures=(64,))

    def test_same_field_weak_updates(self):
        self.run_case('overwrite', {'overwrite_field': {BETA}},
                      lambda function, mode, bits: (BOTH, True))

    def test_loop_offset_widening(self):
        self.run_case('loop', {'loop_fields': BOTH},
                      lambda function, mode, bits: (BOTH, True))

    def test_interior_pointer_across_functions_and_memory(self):
        def expected(function, mode, bits):
            if mode == 'block':
                return BOTH, True
            # x86 stack arguments still use conservative frame transfer.
            return {BETA}, bits == 64 and mode == 'offset'

        self.run_case('interproc', {'invoke_slot': {BETA}}, expected)


if __name__ == '__main__':
    unittest.main(verbosity=2)
