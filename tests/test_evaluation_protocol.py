import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from bola_fuzzer.analyzer import analyze_bola
from bola_fuzzer.case_evaluator import evaluate_cases
from bola_fuzzer.evaluator import evaluate_findings
from bola_fuzzer.config import parse_config
from bola_fuzzer.models import HttpResult
from bola_fuzzer.scanner import BolaScanner, redact

def response(body, status=200, path='/items/1'):
    return HttpResult('GET','http://127.0.0.1'+path,status,{},body,json.dumps(body))

def config():
    return parse_config({'target':{'base_url':'http://127.0.0.1'},'auth':{'login_endpoint':'/login'},
        'users':{'user_a':{'username':'a','password':'secret-a'},'user_b':{'username':'b','password':'secret-b'}},
        'tests':[{'name':'case-A-to-B','source_endpoint':'/items','source_id_path':'$[0].id',
            'target_endpoint':'/items/{id}','access_policy':'private','identity_paths':['$.id'],
            'private_paths':['$.secret'],'session_endpoint':'/me'}]})

class AnalyzerProtocol(unittest.TestCase):
    def decide(self, cross, owner=None, **overrides):
        kwargs=dict(access_policy='private',identity_paths=['$.id'],private_paths=['$.secret'],
                    sessions_valid=True,expected_object_id='1')
        kwargs.update(overrides)
        return analyze_bola(owner or response({'id':1,'secret':'private'}),cross,[],[],**kwargs)[0]

    def test_private_object_leak(self):
        self.assertEqual(self.decide(response({'id':1,'secret':'private'})),'Potential BOLA')
    def test_public_and_shared_do_not_leak(self):
        for policy in ['public','shared']:
            self.assertEqual(self.decide(response({'id':1,'secret':'private'}),access_policy=policy),'No BOLA')
    def test_error_200_is_negative(self):
        self.assertEqual(self.decide(response({'error':'denied'})),'No BOLA')
    def test_different_object_is_negative(self):
        self.assertEqual(self.decide(response({'id':2,'secret':'private'})),'No BOLA')
    def test_expired_or_server_error_inconclusive(self):
        for code in [401,429,500,503]:
            self.assertEqual(self.decide(response({'error':'failed'},code)),'Inconclusive')
    def test_blocked_object_negative(self):
        for code in [403,404]: self.assertEqual(self.decide(response({},code)),'No BOLA')
    def test_empty_or_missing_private_fields_inconclusive(self):
        for body in [{'id':1},{'id':1,'secret':None},{'id':1,'secret':''}]:
            self.assertEqual(self.decide(response(body)),'Inconclusive')
    def test_unknown_policy_or_missing_identity_inconclusive(self):
        for kwargs in [dict(access_policy='unknown'),dict(identity_paths=[]),dict(sessions_valid=False)]:
            self.assertEqual(self.decide(response({'id':1,'secret':'private'}),**kwargs),'Inconclusive')
    def test_wrong_owner_object_does_not_prove_bola(self):
        self.assertEqual(self.decide(response({'id':2,'secret':'private'}),owner=response({'id':2,'secret':'private'})),'Inconclusive')
    def test_error_owner_baseline_inconclusive(self):
        self.assertEqual(self.decide(response({},403),owner=response({'error':'denied'})),'Inconclusive')

class MetricProtocol(unittest.TestCase):
    def test_missing_and_failed_cases_never_negative(self):
        m=evaluate_cases([{'case_id':'a','status':'Inconclusive'}],{'a':False,'b':True})
        self.assertEqual([m[x] for x in ['TP','FP','TN','FN']],[0]*4)
        self.assertIsNone(m['precision']); self.assertIsNone(m['recall']); self.assertIsNone(m['f1'])
        self.assertEqual(m['case_completion'],0); self.assertEqual(m['operational_recall'],0)
    def test_duplicate_unknown_or_nonboolean_truth_rejected(self):
        for rows,truth in [([{'case_id':'a','status':'No BOLA'}]*2,{'a':False}),
                           ([{'case_id':'x','status':'No BOLA'}],{'a':False}),([] ,{'a':'false'})]:
            with self.assertRaises(ValueError): evaluate_cases(rows,truth)
    def test_exact_confusion_matrix(self):
        rows=[{'case_id':str(i),'status':s} for i,s in enumerate(['Potential BOLA','Potential BOLA','No BOLA','No BOLA'])]
        m=evaluate_cases(rows,{'0':True,'1':False,'2':True,'3':False})
        self.assertEqual([m[x] for x in ['TP','FP','TN','FN']],[1,1,1,1])
        self.assertEqual(m['f1'],0.5)

class ScannerProtocol(unittest.TestCase):
    def scanner(self):
        s=BolaScanner(config()); s.auth.login=lambda user:'TOKEN-'+user.username
        return s
    def test_timeout_retains_owner_and_source_evidence(self):
        s=self.scanner()
        def request(method,path,token=None,token_prefix='Bearer'):
            if path=='/items': return response([{'id':1}])
            if token=='TOKEN-b': raise TimeoutError('timed out')
            return response({'id':1,'secret':'private'})
        s.http.request=request
        f=s.run()[0]
        self.assertEqual(f.status,'Inconclusive'); self.assertEqual(f.owner_status_code,200)
        self.assertIn('source',f.evidence); self.assertIn('owner',f.evidence)
        self.assertEqual(f.evidence['failure']['stage'],'cross_user')
        self.assertEqual(f.object_id,'1'); self.assertEqual(f.endpoint,'/items/1')
    def test_login_failure_returns_unresolved_case(self):
        s=self.scanner(); s.auth.login=lambda user: (_ for _ in ()).throw(RuntimeError('secret-a'))
        f=s.run()[0]; self.assertEqual(f.status,'Inconclusive'); self.assertNotIn('secret-a',f.reason)
    def test_two_tokens_for_same_identity_not_independent(self):
        s=self.scanner()
        def request(method,path,token=None,token_prefix='Bearer'):
            return response([{'id':1}] if path=='/items' else {'id':1,'secret':'private','time':token})
        s.http.request=request
        self.assertEqual(s.run()[0].status,'Inconclusive')
    def test_valid_distinct_sessions_and_export_redaction(self):
        s=self.scanner()
        def request(method,path,token=None,token_prefix='Bearer'):
            body=([{'id':1}] if path=='/items' else {'id':token[-1]} if path=='/me' else
                {'id':1,'secret':'private','access_token':token,'echo':token})
            return response(body)
        s.http.request=request
        f=s.run()[0]; self.assertEqual(f.status,'Potential BOLA')
        exported=json.dumps(f.evidence)+f.owner_response_preview+f.attacker_response_preview+f.poc_curl
        for secret in ['TOKEN-a','TOKEN-b','secret-a','secret-b']: self.assertNotIn(secret,exported)
        self.assertEqual(evaluate_findings([f],{f.test_name:True}).true_positive,1)
    def test_invalid_source_identity_inconclusive(self):
        for object_id in [None,'',{},[],True]:
            s=self.scanner(); s.http.request=lambda *a,**k: response([{'id':object_id}])
            self.assertEqual(s.run()[0].status,'Inconclusive')

class FrozenInputProtocol(unittest.TestCase):
    def test_modified_input_is_rejected(self):
        from experiment import verify_inputs,sha,save
        with tempfile.TemporaryDirectory(dir=Path(__file__).resolve().parents[1]) as directory:
            p=Path(directory)
            save(p/'ground-truth.json',{'a':True}); save(p/'catalog.json',[{'case_id':'a'}])
            save(p/'ground-truth-manifest.json',{'truth_sha256':sha(p/'ground-truth.json'),'catalog_sha256':sha(p/'catalog.json')})
            verify_inputs(p)
            save(p/'ground-truth.json',{'a':False})
            with self.assertRaises(ValueError): verify_inputs(p)
