"""Start the existing localhost crAPI containers without pull/reset/recreation."""
from pathlib import Path
import argparse, json, subprocess, sys, time
from urllib.request import urlopen

APP = Path(__file__).resolve().parent
SERVICES = ['postgresdb','mongodb','mailhog','api.mypremiumdealership.com','chromadb',
            'crapi-identity','crapi-community','crapi-workshop','crapi-chatbot','crapi-web']

def docker(*args):
    r = subprocess.run(['docker',*args],capture_output=True,text=True,timeout=30)
    if r.returncode: raise RuntimeError('Docker gagal: '+r.stderr.strip())
    return r.stdout

def ready(name):
    info = json.loads(docker('inspect',name))[0]
    state = info['State']
    return state['Running'] and state.get('Health',{}).get('Status','healthy')=='healthy'

def wait(name):
    print('Menunggu '+name+'...',flush=True)
    deadline = time.monotonic()+150
    while time.monotonic()<deadline:
        if ready(name): return
        time.sleep(2)
    raise RuntimeError(name+' belum sehat. Periksa Docker Desktop; data tidak direset.')

def main():
    parser=argparse.ArgumentParser();parser.add_argument('--check',action='store_true')
    args=parser.parse_args()
    docker('info','--format','{{.ServerVersion}}')
    # Check all containers and loopback bindings before any start operation.
    infos=json.loads(docker('inspect',*SERVICES))
    for info in infos:
        for bindings in (info['HostConfig'].get('PortBindings') or {}).values():
            for binding in bindings or []:
                if binding.get('HostIp') not in ('127.0.0.1','::1'):
                    raise RuntimeError('Port bukan loopback: '+info['Name']+'. Tinjau konfigurasi dahulu.')
    if not args.check:
        for name in SERVICES[:5]:
            if not ready(name): docker('start',name)
        for name in SERVICES[:5]: wait(name)
        for name in SERVICES[5:]:
            if not ready(name): docker('start',name)
            if name!='crapi-chatbot': wait(name)
    for name in SERVICES:
        ok=ready(name); print(name+': '+('siap' if ok else 'BELUM SIAP'),flush=True)
        if not ok: raise RuntimeError(name+' belum siap')
    with urlopen('http://127.0.0.1:8888/identity/health_check',timeout=10) as r:
        if r.status!=200: raise RuntimeError('API login crAPI belum siap')
    print('crAPI asli: http://127.0.0.1:8888/ | Dashboard: http://127.0.0.1:8081/',flush=True)
    if not args.check:
        subprocess.run([sys.executable,str(APP/'run_lab.py'),'--open'],cwd=APP,check=True)

if __name__=='__main__':
    try:main()
    except Exception as exc:
        print('Gagal memulai demo: '+str(exc),file=sys.stderr)
        print('Pastikan Docker Desktop aktif. Launcher ini memakai container crAPI yang sudah terpasang; tidak menghapus data.',file=sys.stderr)
        sys.exit(1)
