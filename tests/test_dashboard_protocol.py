import unittest
from unittest.mock import patch
from server import BolaFuzzerHandler
from test_evaluation_protocol import config
from dataclasses import asdict


class DashboardProtocol(unittest.TestCase):
    def handler(self, truth):
        cfg=config()
        payload={'target':asdict(cfg.target),'auth':asdict(cfg.auth),
            'users':{'user_a':asdict(cfg.user_a),'user_b':asdict(cfg.user_b)},
            'tests':[asdict(t) for t in cfg.tests], 'ground_truth':truth}
        h=object.__new__(BolaFuzzerHandler)
        h.read_json=lambda:payload
        h.send_json=lambda data,status=200:setattr(h,'answer',(status,data))
        return h

    def test_endpoint_keyed_truth_rejected_before_scanning(self):
        h=self.handler({'/items/1':True})
        with patch('server.BolaScanner') as scanner:
            h.handle_scan(); scanner.assert_not_called()
        self.assertEqual(h.answer[0],400)

    def test_invalid_label_rejected_before_scanning(self):
        h=self.handler({'case-A-to-B':'false'})
        with patch('server.BolaScanner') as scanner:
            h.handle_scan(); scanner.assert_not_called()
        self.assertEqual(h.answer[0],400)

    def test_failed_case_has_coverage_without_false_negative(self):
        from bola_fuzzer.scanner import BolaScanner
        cfg=config(); f=BolaScanner(cfg).failed(cfg.tests[0],'Login failed')
        h=self.handler({'case-A-to-B':True})
        with patch('server.BolaScanner') as scanner, patch('server.write_reports',return_value=('a','b')), patch('server.write_academic_report',return_value='c'):
            scanner.return_value.run.return_value=[f]; h.handle_scan()
        self.assertEqual(h.answer[0],200)
        m=h.answer[1]['metrics']
        self.assertEqual(m['false_negative'],0)
        self.assertEqual(m['unresolved_cases'],['case-A-to-B'])
        self.assertIsNone(m['recall'])
