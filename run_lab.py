"""Start local dashboard and existing real HTTP lab fixtures; no fake results."""
import argparse
import json
import threading
import urllib.request
import webbrowser
from http.server import ThreadingHTTPServer
from pathlib import Path
from server import BolaFuzzerHandler
from bola_fuzzer.run_record import VERSION
from labs.mock_api.mock_vulnerable_api import MockApiHandler
from labs.control.service import Handler as ControlHandler

SERVICES = [
    ('Dashboard',8081,'/api/health',lambda d:d.get('service')=='bola-fuzzer' and d.get('version')==VERSION,BolaFuzzerHandler),
    ('Lab kendaraan',8890,'/health',lambda d:d.get('service')=='mock-vulnerable-api',MockApiHandler),
    ('Lab kontrol',8899,'/openapi.json',lambda d:d.get('info',{}).get('title')=='BOLA control',ControlHandler),
]
def healthy(port,path,predicate):
    try:
        with urllib.request.urlopen(f'http://127.0.0.1:{port}{path}',timeout=3) as r:
            return r.status==200 and predicate(json.load(r))
    except (OSError,ValueError):return False
def main():
    parser=argparse.ArgumentParser();parser.add_argument('--open',action='store_true');parser.add_argument('--check',action='store_true');args=parser.parse_args()
    owned=[]
    try:
        for name,port,path,predicate,handler in SERVICES:
            if healthy(port,path,predicate):print(f'{name}: siap di http://127.0.0.1:{port} (layanan yang sudah aktif)',flush=True);continue
            if args.check:raise RuntimeError(f'{name} belum siap pada port {port}. Jalankan Mulai-Lab.cmd.')
            try:server=ThreadingHTTPServer(('127.0.0.1',port),handler)
            except OSError as e:raise RuntimeError(f'Port {port} dipakai layanan lain atau tidak dapat dibuka. Tidak ada proses yang dihentikan.') from e
            server.daemon_threads=True;owned.append(server);threading.Thread(target=server.serve_forever,daemon=True).start()
            if not healthy(port,path,predicate):raise RuntimeError(f'Pemeriksaan {name} gagal.')
            print(f'{name}: siap di http://127.0.0.1:{port}',flush=True)
        print('Buka http://127.0.0.1:8081/ | Laporan: '+str(Path(__file__).resolve().parent/'reports'),flush=True)
        if args.open:webbrowser.open('http://127.0.0.1:8081/')
        if not args.check and owned:
            print('Biarkan jendela ini aktif selama demo. Ctrl+C untuk menghentikan layanan yang dimulai jendela ini.',flush=True)
            threading.Event().wait()
    except KeyboardInterrupt:print('\nMenghentikan layanan milik launcher.',flush=True)
    finally:
        for server in owned:server.shutdown();server.server_close()
if __name__=='__main__':main()
