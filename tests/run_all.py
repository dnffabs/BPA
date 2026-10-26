#!/usr/bin/env python3
"""Run every semantic/native suite and save a machine-readable validation result."""
from datetime import datetime, timezone
import json
from pathlib import Path
import subprocess
import sys
import time
import unittest

sys.dont_write_bytecode = True

import run_regressions
import test_memory_model
import test_offset_rules
import test_pipeline_resources
import test_offsets

ROOT = Path(__file__).resolve().parents[1]


def main():
    modules = (run_regressions, test_memory_model, test_offset_rules,
               test_pipeline_resources, test_offsets)
    suite = unittest.TestSuite(unittest.defaultTestLoader.loadTestsFromModule(module)
                               for module in modules)
    started = time.perf_counter()
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    destination = ROOT / 'build' / 'validation' / 'results.json'
    destination.parent.mkdir(parents=True, exist_ok=True)
    head = subprocess.run(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True,
                          stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    state = subprocess.run(['git', 'status', '--porcelain'], cwd=ROOT, text=True,
                           stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    report = {
        'status': 'passed' if result.wasSuccessful() else 'failed',
        'finished_at_utc': datetime.now(timezone.utc).isoformat(),
        'git_head': head.stdout.strip() if head.returncode == 0 else None,
        'working_tree_dirty': bool(state.stdout.strip()) if state.returncode == 0 else None,
        'tests_run': result.testsRun,
        'skipped': [{'test': str(test), 'reason': reason} for test, reason in result.skipped],
        'failures': [{'test': str(test), 'traceback': trace} for test, trace in result.failures],
        'errors': [{'test': str(test), 'traceback': trace} for test, trace in result.errors],
        'elapsed_seconds': round(time.perf_counter() - started, 4),
        'baseline_native_analyses': len(run_regressions.RESULTS),
        'offset_native_analyses': len(test_offsets.RESULTS),
        'offset_totals': {mode: test_offsets.mode_totals(mode) for mode in test_offsets.MODES},
        'reports': ['build/regressions/results.json', 'build/offset-regressions/results.json'],
    }
    destination.write_text(json.dumps(report, indent=2, ensure_ascii=False) + '\n')
    print(f'Validation report: {destination}')
    return 0 if result.wasSuccessful() else 1


if __name__ == '__main__':
    raise SystemExit(main())
