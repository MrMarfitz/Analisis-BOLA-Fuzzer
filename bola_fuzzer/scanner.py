"""Dual-context checks with explicit identity/policy and partial execution evidence."""
from urllib.parse import quote, urljoin
import shlex
from bola_fuzzer.analyzer import analyze_bola, preview_body
from bola_fuzzer.auth import AuthManager
from bola_fuzzer.http_client import HttpClient
from bola_fuzzer.json_path import extract_json_path
from bola_fuzzer.models import ScanFinding


def redact(value, secrets=()):
    if isinstance(value, dict):
        return {k: ('[REDACTED]' if k.lower() in {'token','access_token','refresh_token','password','authorization'}
                    else redact(v, secrets)) for k,v in value.items()}
    if isinstance(value, list): return [redact(v, secrets) for v in value]
    if isinstance(value, str):
        for secret in sorted(set(s for s in secrets if s), key=len, reverse=True):
            value = value.replace(secret, '[REDACTED]')
    return value


def build_curl(method, url, token='', token_prefix='Bearer'):
    # URL is shell quoted; token stays an environment variable, never embedded.
    return f'curl --max-time 10 -i -X {shlex.quote(method.upper())} {shlex.quote(url)} -H "Authorization: {token_prefix} $TOKEN_OTHER"'


def evidence_response(result, token_variable, token_prefix='Bearer', secrets=()):
    return {'request': {'method': result.method, 'url': result.url,
            'headers': {'Authorization': token_prefix + ' ${' + token_variable + '}'}},
            'response': {'status': result.status_code, 'body': redact(result.body, secrets)}}


class BolaScanner:
    def __init__(self, config):
        self.config = config
        self.http = HttpClient(config.target)
        self.auth = AuthManager(self.http, config.auth)

    def run(self):
        secrets = (self.config.user_a.password, self.config.user_b.password)
        try:
            a = self.auth.login(self.config.user_a)
            secrets += (a,)
            b = self.auth.login(self.config.user_b)
        except Exception as exc:
            return [self.failed(t, 'Login failed: '+redact(str(exc), secrets)) for t in self.config.tests]
        return [self.run_test(t, a, b) for t in self.config.tests]

    def failed(self, test, reason, evidence=None, endpoint=None, object_id='-'):
        evidence = evidence or {}
        owner = evidence.get('owner', {}).get('response', {})
        cross = evidence.get('cross_user', {}).get('response', {})
        url = urljoin(self.config.target.base_url+'/', (endpoint or test.target_endpoint).lstrip('/'))
        return ScanFinding(test.name, endpoint or test.target_endpoint, object_id,
            'Inconclusive', 'Info', 'Low', reason, owner.get('status',0), cross.get('status',0),
            build_curl(test.method,url,token_prefix=self.config.auth.token_prefix),
            preview_body(owner.get('body','-')), preview_body(cross.get('body','-')), evidence)

    def run_test(self, test, token_a, token_b):
        evidence = {'policy': test.access_policy, 'identity_paths': test.identity_paths,
                    'private_paths': test.private_paths, 'session_id_path': test.session_id_path}
        secrets = (token_a,token_b,self.config.user_a.password,self.config.user_b.password)
        endpoint = test.target_endpoint; object_id = '-'; stage = 'source'
        prefix = self.config.auth.token_prefix
        def request(role,method,path,token,var):
            r = self.http.request(method,path,token,prefix)
            evidence[role] = evidence_response(r,var,prefix,secrets)
            return r
        try:
            source = request('source','GET',test.source_endpoint,token_a,'TOKEN_OWNER')
            if source.status_code != 200:
                raise ValueError(f'Source request failed: HTTP {source.status_code}')
            raw_id = extract_json_path(source.body,test.source_id_path)
            if type(raw_id) not in (str,int) or raw_id == '':
                raise ValueError('Source object identity must be a nonempty string or integer')
            object_id = str(raw_id)
            endpoint = test.target_endpoint.replace('{'+test.object_parameter+'}',quote(object_id,safe=''))
            stage = 'owner'
            owner = request('owner',test.method,endpoint,token_a,'TOKEN_OWNER')
            stage = 'cross_user'
            cross = request('cross_user',test.method,endpoint,token_b,'TOKEN_OTHER')
            # Token inequality alone does not prove separate users. Verify stable identity.
            valid = False
            if test.session_endpoint:
                ids = []
                for role,token,var in [('session_owner',token_a,'TOKEN_OWNER'),('session_other',token_b,'TOKEN_OTHER')]:
                    stage = role
                    r = request(role,'GET',test.session_endpoint,token,var)
                    if r.status_code != 200: raise ValueError('Session identity request failed')
                    identity = extract_json_path(r.body,test.session_id_path)
                    if type(identity) not in (str,int) or identity == '': raise ValueError('Invalid session identity')
                    ids.append(str(identity))
                valid = token_a != token_b and ids[0] != ids[1]
            stage = 'analysis'
            status,severity,confidence,reason = analyze_bola(owner,cross,test.expected_owner_markers,
                test.sensitive_fields,access_policy=test.access_policy,identity_paths=test.identity_paths,
                private_paths=test.private_paths,sessions_valid=valid,expected_object_id=object_id)
            evidence['sessions_valid'] = valid
            return ScanFinding(test.name,endpoint,object_id,status,severity,confidence,reason,
                owner.status_code,cross.status_code,build_curl(test.method,owner.url,token_prefix=prefix),
                preview_body(redact(owner.body,secrets)),preview_body(redact(cross.body,secrets)),evidence)
        except Exception as exc:
            reason = redact(f'{stage}: {type(exc).__name__}: {exc}', secrets)
            evidence['failure'] = {'stage':stage,'reason':reason}
            return self.failed(test,reason,evidence,endpoint,object_id)
