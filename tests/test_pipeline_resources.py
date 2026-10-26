"""Check that solver RSS does not include the angr/Python parent's peak."""
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
from run_pipeline import measured_command


class ProcessResources(unittest.TestCase):
    @unittest.skipUnless(Path('/usr/bin/time').is_file(), 'GNU time is optional')
    def test_child_peak_excludes_large_parent(self):
        payload = bytearray(64 * 1024 * 1024)
        with tempfile.TemporaryDirectory() as directory:
            log = Path(directory) / 'child.log'
            code, resources = measured_command([sys.executable, '-c', "print('child completed')"], log)
            self.assertEqual(code, 0)
            self.assertEqual(log.read_text().strip(), 'child completed')
            self.assertEqual(resources['rss_method'], 'gnu-time')
            self.assertGreater(resources['peak_rss_kib'], 0)
            self.assertLess(resources['peak_rss_kib'], len(payload) // 1024)

    def test_missing_timer_reports_unavailable_and_preserves_exit(self):
        with tempfile.TemporaryDirectory() as directory:
            log = Path(directory) / 'child.log'
            with patch('run_pipeline.Path.is_file', return_value=False):
                code, resources = measured_command([sys.executable, '-c', 'raise SystemExit(7)'], log)
            self.assertEqual(code, 7)
            self.assertIsNone(resources['peak_rss_kib'])
            self.assertEqual(resources['rss_method'], 'unavailable')


if __name__ == '__main__':
    unittest.main(verbosity=2)
