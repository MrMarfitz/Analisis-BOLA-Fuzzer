import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from server import BolaFuzzerHandler
from bola_fuzzer.reporter import write_reports
from bola_fuzzer.academic_reporter import write_academic_report


class DashboardRegressionTests(unittest.TestCase):
    def test_static_files_cannot_escape_into_sibling_with_same_prefix(self):
        with tempfile.TemporaryDirectory(dir=Path(__file__).parent) as folder:
            root = Path(folder) / 'web'
            root.mkdir()
            sibling = Path(folder) / 'web-backup'
            sibling.mkdir()
            (sibling / 'audit.txt').write_text('non-secret audit marker')
            handler = object.__new__(BolaFuzzerHandler)
            handler.send_json = lambda data, status=200: setattr(handler, 'answer', (status, data))
            with patch('server.WEB_ROOT', root):
                handler.serve_static('/../web-backup/audit.txt')
            self.assertEqual(handler.answer[0], 404)

    def test_fast_report_writes_preserve_each_run(self):
        with tempfile.TemporaryDirectory(dir=Path(__file__).parent) as folder:
            first = write_reports([], folder)
            second = write_reports([], folder)
            self.assertNotEqual(first, second)
            self.assertTrue(all(p.exists() for p in first + second))
            first_academic = write_academic_report([], [], output_dir=folder)
            second_academic = write_academic_report([], [], output_dir=folder)
            self.assertNotEqual(first_academic, second_academic)
            self.assertTrue(first_academic.exists() and second_academic.exists())
