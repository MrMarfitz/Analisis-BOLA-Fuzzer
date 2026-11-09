"""Portable, credential-free records for inspecting and repeating local scans."""
import hashlib
import json
import platform
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4
from bola_fuzzer.scanner import redact

VERSION = '1.0.0'


def source_hashes(root):
    paths = list((root / 'bola_fuzzer').glob('*.py')) + [root/'server.py', root/'compare_methods.py']
    return {p.relative_to(root).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest()
            for p in sorted(paths) if p.is_file()}


def write_run_record(root, config, findings, telemetry, metrics=None):
    # Usernames are intentionally retained as case context; secrets are omitted.
    public_config = {'target': asdict(config.target), 'auth': asdict(config.auth),
                     'users': {'user_a': {'username': config.user_a.username},
                               'user_b': {'username': config.user_b.username}},
                     'tests': [asdict(t) for t in config.tests]}
    canonical = json.dumps(public_config, sort_keys=True).encode()
    data = {'schema_version': 1, 'application_version': VERSION,
            'recorded_at': datetime.now(timezone.utc).isoformat(),
            'python_version': platform.python_version(), 'scope': 'GET/JSON horizontal object access',
            'configuration_without_passwords': public_config,
            'configuration_sha256': hashlib.sha256(canonical).hexdigest(),
            'code_sha256': source_hashes(root), 'telemetry': telemetry,
            'findings': [asdict(f) for f in findings],
            'metrics': asdict(metrics) if metrics else None,
            'interpretation': 'Local scan evidence. Configuration and source hashes support traceability; human policy review remains necessary.'}
    path = root/'reports'/('run-record-'+uuid4().hex+'.json')
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(redact(data, [config.user_a.password, config.user_b.password]),
                               indent=2, ensure_ascii=False), encoding='utf-8')
    return path
