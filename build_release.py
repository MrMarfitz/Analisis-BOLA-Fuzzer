"""Build the local application ZIP from an explicit source allowlist."""
import argparse
import hashlib
import json
from pathlib import Path
from zipfile import ZipFile, ZipInfo, ZIP_DEFLATED

ROOT = Path(__file__).resolve().parent
NAME = 'BOLA-Fuzzer-1.0.0'
TOP = ('.gitattributes','.gitignore','README.md','PANDUAN_UJI.md','requirements.txt',
       'main.py','server.py','run_lab.py','run_crapi_lab.py','experiment.py','compare_methods.py',
       'build_release.py','Mulai-Lab.cmd','Mulai-Lab.ps1','Mulai-crAPI-Lab.cmd')
FOLDERS = ('bola_fuzzer','web','tests','docs','examples','labs/control','labs/mock_api')


def build(out):
    files = [ROOT/p for p in TOP] + [ROOT/'labs/mechanism_fixture.py']
    for folder in FOLDERS:
        files.extend(p for p in (ROOT/folder).rglob('*') if p.is_file()
                     and '__pycache__' not in p.parts and p.suffix not in ('.pyc','.pyo'))
    payload = {p.relative_to(ROOT).as_posix(): p.read_bytes() for p in sorted(set(files))}
    manifest = {'application_version':'1.0.0', 'requires':'Python 3.10+',
                'excluded':'runtime reports, research datasets, accounts, tokens, Git metadata',
                'files':{name:hashlib.sha256(data).hexdigest() for name,data in payload.items()}}
    manifest_bytes = json.dumps(manifest, indent=2).encode()
    # Keep the unpacked package manifest aligned with the archive manifest.
    (ROOT/'release-manifest.json').write_bytes(manifest_bytes)
    payload['release-manifest.json'] = manifest_bytes
    out.parent.mkdir(parents=True,exist_ok=True)
    with ZipFile(out,'w',compression=ZIP_DEFLATED) as archive:
        for name,data in sorted(payload.items()):
            info=ZipInfo(NAME+'/'+name,date_time=(2026,11,9,0,0,0))
            info.compress_type=ZIP_DEFLATED; info.external_attr=0o644 << 16
            archive.writestr(info,data)
    with ZipFile(out) as archive:
        for name,digest in manifest['files'].items():
            if hashlib.sha256(archive.read(NAME+'/'+name)).hexdigest()!=digest:
                raise ValueError('Archive hash mismatch: '+name)
    print(json.dumps({'archive':str(out.resolve()),'source_files':len(manifest['files']),
                      'sha256':hashlib.sha256(out.read_bytes()).hexdigest()}))


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out',type=Path,required=True)
    build(parser.parse_args().out)
