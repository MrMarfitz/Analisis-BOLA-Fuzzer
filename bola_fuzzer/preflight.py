"""Check credentials, distinct sessions and owner mapping without cross-user reads."""
from urllib.parse import quote
from bola_fuzzer.analyzer import SUCCESS_CODES
from bola_fuzzer.json_path import extract_json_path
from bola_fuzzer.scanner import BolaScanner, redact


def check_target(config):
    scanner = BolaScanner(config)
    checks = []
    secrets = [config.user_a.password, config.user_b.password]
    stage = 'Autentikasi akun A'
    try:
        a = scanner.auth.login(config.user_a); secrets.append(a)
        checks.append({'name': stage, 'ok': True})
        stage = 'Autentikasi akun B'
        b = scanner.auth.login(config.user_b); secrets.append(b)
        checks.append({'name': stage, 'ok': True})
        for test in config.tests:
            stage = 'Identitas dua sesi: ' + test.name
            if not test.session_endpoint:
                raise ValueError('Endpoint identitas sesi belum dikonfigurasi.')
            identities = []
            for token in (a, b):
                r = scanner.http.request('GET', test.session_endpoint, token, config.auth.token_prefix)
                if r.status_code != 200:
                    raise ValueError(f'Endpoint identitas merespons HTTP {r.status_code}.')
                identity = extract_json_path(r.body, test.session_id_path)
                if type(identity) not in (str, int) or identity == '':
                    raise ValueError('Lokasi ID pengguna tidak menghasilkan identitas yang valid.')
                identities.append(str(identity))
            if a == b or identities[0] == identities[1]:
                raise ValueError('Dua akun mengarah ke identitas sesi yang sama.')
            checks.append({'name': stage, 'ok': True})
            stage = 'Sumber dan pembacaan objek pemilik: ' + test.name
            source = scanner.http.request('GET', test.source_endpoint, a, config.auth.token_prefix)
            if source.status_code != 200:
                raise ValueError(f'Daftar objek merespons HTTP {source.status_code}.')
            raw_id = extract_json_path(source.body, test.source_id_path)
            if type(raw_id) not in (str, int) or raw_id == '':
                raise ValueError('Lokasi ID objek tidak menghasilkan ID yang valid.')
            endpoint = test.target_endpoint.replace('{'+test.object_parameter+'}', quote(str(raw_id), safe=''))
            owner = scanner.http.request('GET', endpoint, a, config.auth.token_prefix)
            if owner.status_code not in SUCCESS_CODES:
                raise ValueError(f'Pembacaan pemilik merespons HTTP {owner.status_code}.')
            ids = [extract_json_path(owner.body, path) for path in test.identity_paths]
            if not ids or str(ids[0]) != str(raw_id):
                raise ValueError('Identitas respons pemilik tidak cocok dengan sumber objek.')
            if test.access_policy == 'private':
                if not test.private_paths:
                    raise ValueError('Atribut privat belum dikonfigurasi.')
                for path in test.private_paths:
                    if extract_json_path(owner.body, path) in (None, '', {}, []):
                        raise ValueError('Atribut privat kosong pada respons pemilik.')
            checks.append({'name': stage, 'ok': True})
        return {'ready': True, 'checks': checks,
                'message': 'Target, dua sesi, dan pemetaan objek siap. Kebijakan serta kepemilikan tetap perlu ditinjau. Belum ada akses silang yang diuji.'}
    except Exception as exc:
        checks.append({'name': stage, 'ok': False, 'detail': redact(str(exc), secrets)})
        return {'ready': False, 'checks': checks,
                'message': 'Target belum siap. Periksa layanan, kredensial, dan pemetaan pada tahap yang gagal.'}
