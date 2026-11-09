"""Evaluation-only fixture. Never imported by the application or scanner.

Every scenario uses the same neutral routes. Ownership and ACL are declared
in the fixture before any HTTP observation or scanner prediction.
"""
import json
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

SCENARIOS = {
    'S01': dict(description='Objek privat bocor', visibility='private', readers=[], behavior='bypass', vulnerable=True, expected='Potential BOLA'),
    'S02': dict(description='Objek privat terlindungi', visibility='private', readers=[], behavior='enforce', vulnerable=False, expected='No BOLA'),
    'S03': dict(description='Objek publik untuk pengguna terautentikasi', visibility='public', readers=['A','B'], behavior='enforce', vulnerable=False, expected='No BOLA'),
    'S04': dict(description='Objek dibagikan kepada akun pasangan', visibility='shared', readers=['A','B'], behavior='enforce', vulnerable=False, expected='No BOLA'),
    'S05': dict(description='Penolakan dalam envelope HTTP 200', visibility='private', readers=[], behavior='error200', vulnerable=False, expected='No BOLA'),
    'S06': dict(description='HTTP 200 mengembalikan objek pengguna sendiri', visibility='private', readers=[], behavior='other', vulnerable=False, expected='No BOLA'),
    'S07': dict(description='Simulasi kegagalan sesi saat akses silang', visibility='private', readers=[], behavior='unauthorized', vulnerable=False, expected='Inconclusive'),
    'S08': dict(description='Kebocoran tertunda melewati anggaran pemindai', visibility='private', readers=[], behavior='delay', vulnerable=True, expected='Inconclusive'),
}

def snapshot(scenario):
    return {'scenario_id':scenario, 'rule':'read allowed iff caller is owner or visibility is public or caller is in readers',
            'scenario':SCENARIOS[scenario], 'accounts':{'A':{'id':'A','role':'user'}, 'B':{'id':'B','role':'user'}},
            'objects':{f'obj-{u}':{'id':f'obj-{u}','owner_id':u,'private_note':f'synthetic-note-{u}'} for u in ('A','B')}}

def make_server(fixture):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self,*args): pass
        def send(self,code,body):
            raw=json.dumps(body).encode(); self.send_response(code)
            self.send_header('Content-Type','application/json'); self.send_header('Content-Length',str(len(raw)))
            self.end_headers()
            try:self.wfile.write(raw)
            except (BrokenPipeError,ConnectionResetError,ConnectionAbortedError):pass
        def do_POST(self):
            body=json.loads(self.rfile.read(int(self.headers.get('Content-Length',0))))
            u=body.get('username')
            if self.path=='/login' and u in fixture['accounts'] and body.get('password')=='synthetic-lab-only':
                return self.send(200,{'token':'fixture-session-'+u})
            return self.send(401,{'error':'invalid credentials'})
        def do_GET(self):
            token=self.headers.get('Authorization','').removeprefix('Bearer ')
            who=token.removeprefix('fixture-session-') if token.startswith('fixture-session-') else None
            if who not in fixture['accounts']:return self.send(401,{'error':'invalid session'})
            if self.path=='/me':return self.send(200,fixture['accounts'][who])
            parts=self.path.strip('/').split('/')
            if parts[0] not in ('objects','resources') or len(parts)>2:return self.send(404,{'error':'not found'})
            if len(parts)==1:
                return self.send(200,[o for o in fixture['objects'].values() if o['owner_id']==who])
            obj=fixture['objects'].get(parts[1])
            if obj is None:return self.send(404,{'error':'not found'})
            policy=fixture['scenario']
            allowed=who==obj['owner_id'] or policy['visibility']=='public' or who in policy['readers']
            if not allowed:
                behavior=policy['behavior']
                if behavior=='enforce':return self.send(403,{'error':'access denied'})
                if behavior=='error200':return self.send(200,{'error':'access denied'})
                if behavior=='other':return self.send(200,fixture['objects']['obj-'+who])
                if behavior=='unauthorized':return self.send(401,{'error':'simulated session failure'})
                if behavior=='delay':time.sleep(4)
                # bypass/delay deliberately return the prohibited object.
            return self.send(200,obj)
    server=ThreadingHTTPServer(('127.0.0.1',0),Handler); server.daemon_threads=True
    return server
