import io
import json
import tempfile
import unittest
from dataclasses import asdict
from pathlib import Path
from unittest.mock import patch
from test_evaluation_protocol import config, response
from bola_fuzzer.preflight import check_target
from bola_fuzzer.scanner import BolaScanner
from bola_fuzzer.baselines import baseline_decision, paired_summary
from bola_fuzzer.run_record import write_run_record
from server import BolaFuzzerHandler
from compare_methods import verify, save, sha


class ReleaseWorkflows(unittest.TestCase):
    def test_preflight_checks_owner_but_never_cross_user_object(self):
        scanner = BolaScanner(config()); scanner.auth.login = lambda u: 'TOKEN-'+u.username
        calls = []
        def request(method, path, token=None, prefix='Bearer'):
            calls.append((path,token))
            if path == '/me': return response({'id':token[-1]})
            if path == '/items': return response([{'id':1}])
            return response({'id':1,'secret':'private'})
        scanner.http.request = request
        with patch('bola_fuzzer.preflight.BolaScanner', return_value=scanner):
            result = check_target(config())
        self.assertTrue(result['ready'])
        self.assertNotIn(('/items/1','TOKEN-b'),calls)
        self.assertNotIn('TOKEN',json.dumps(result))

    def test_preflight_login_failure_is_actionable_and_redacted(self):
        scanner = BolaScanner(config())
        scanner.auth.login = lambda u: (_ for _ in ()).throw(ValueError('failed secret-a'))
        with patch('bola_fuzzer.preflight.BolaScanner', return_value=scanner):
            result = check_target(config())
        self.assertFalse(result['ready']); self.assertIn('akun A',result['checks'][0]['name'])
        self.assertNotIn('secret-a',json.dumps(result))

    def finding(self, body, policy='private'):
        scanner = BolaScanner(config()); scanner.auth.login = lambda u:'TOKEN-'+u.username
        def request(method,path,token=None,prefix='Bearer'):
            if path == '/me': return response({'id':token[-1]})
            if path == '/items': return response([{'id':1}])
            return response(body if token=='TOKEN-b' else {'id':1,'secret':'private'})
        scanner.http.request = request
        from dataclasses import replace
        test = replace(config().tests[0], access_policy=policy)
        return scanner.run_test(test,'TOKEN-a','TOKEN-b')

    def test_diagnostic_baselines_expose_tradeoffs_without_truth(self):
        public = self.finding({'id':1,'secret':'private'}, 'public')
        self.assertEqual(baseline_decision(public,'http-status-v1'),'Potential BOLA')
        self.assertEqual(baseline_decision(public,'object-identity-v1'),'Potential BOLA')
        self.assertEqual(baseline_decision(public,'contextual-v1'),'No BOLA')
        error = self.finding({'error':'denied'})
        self.assertEqual(baseline_decision(error,'http-status-v1'),'Potential BOLA')
        self.assertEqual(baseline_decision(error,'object-identity-v1'),'Inconclusive')
        self.assertEqual(baseline_decision(error,'contextual-v1'),'No BOLA')
        error.evidence['sessions_valid'] = False
        self.assertEqual(baseline_decision(error,'http-status-v1'),'Inconclusive')

    def test_paired_abstention_is_not_scored_as_improvement_in_accuracy(self):
        result = paired_summary([{'case_id':'a','status':'Inconclusive'}],
                                [{'case_id':'a','status':'No BOLA'}],{'a':False})
        self.assertEqual(result['right_only_conclusive'],1)
        self.assertEqual(result['left_wrong_right_correct'],0)

    def test_main_gate_rejects_unreviewed_and_modified_datasets(self):
        with tempfile.TemporaryDirectory(dir=Path(__file__).parent) as temp:
            folder = Path(temp)
            save(folder/'ground-truth.json',{'a':True})
            save(folder/'manifest.json',{'files':{'ground-truth.json':sha(folder/'ground-truth.json')},
                'fixture_source_sha256':sha(Path(__file__).resolve().parents[1]/'labs/mechanism_fixture.py')})
            save(folder/'review.json',{'status':'pending'})
            verify(folder,'pilot')
            with self.assertRaisesRegex(ValueError,'human review'): verify(folder,'main')
            save(folder/'ground-truth.json',{'a':False})
            with self.assertRaisesRegex(ValueError,'Frozen input'): verify(folder,'pilot')

    def test_download_refuses_traversal_and_serves_exact_report(self):
        with tempfile.TemporaryDirectory(dir=Path(__file__).parent) as temp:
            root=Path(temp); (root/'reports').mkdir()
            (root/'reports'/'sample.json').write_text('{"ok":true}')
            handler=object.__new__(BolaFuzzerHandler); handler.wfile=io.BytesIO()
            handler.send_response=lambda status:setattr(handler,'status',status)
            handler.send_header=lambda *args:None; handler.end_headers=lambda:None
            handler.send_json=lambda data,status=200:setattr(handler,'status',status)
            with patch('server.ROOT',root):
                for path in ('../config.json','..\\config.json','/sample.json'):
                    handler.serve_report(path); self.assertEqual(handler.status,404)
                handler.serve_report('sample.json')
            self.assertEqual(handler.status,200); self.assertEqual(handler.wfile.getvalue(),b'{"ok":true}')

    def test_run_record_contains_cost_but_no_passwords(self):
        with tempfile.TemporaryDirectory(dir=Path(__file__).parent) as temp:
            root=Path(temp); (root/'bola_fuzzer').mkdir()
            path=write_run_record(root,config(),[],{'attempted_requests':3,'elapsed_seconds':0.2})
            raw=path.read_text(); record=json.loads(raw)
            self.assertNotIn('secret-a',raw); self.assertNotIn('secret-b',raw)
            self.assertEqual(record['telemetry']['attempted_requests'],3)
            self.assertNotIn('password',record['configuration_without_passwords']['users']['user_a'])

    def test_out_of_scope_mutation_is_rejected(self):
        from bola_fuzzer.config import parse_config
        cfg=config(); payload={'target':asdict(cfg.target),'auth':asdict(cfg.auth),
           'users':{'user_a':asdict(cfg.user_a),'user_b':asdict(cfg.user_b)},'tests':[asdict(cfg.tests[0])]}
        payload['tests'][0]['method']='DELETE'
        with self.assertRaisesRegex(ValueError,'GET'): parse_config(payload)


if __name__ == '__main__': unittest.main()
