"""Prepare independently observed fixtures, then compare fixed decision rules.

Only loopback synthetic fixtures are started. Ground truth is frozen before
production scanner imports. Main runs require recorded human case reviews;
pilot runs remain explicitly labelled and cannot establish external superiority.
"""
import argparse
import hashlib
import json
import platform
import threading
import time
import urllib.error
import urllib.request
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
from labs.mechanism_fixture import SCENARIOS, snapshot, make_server

ROOT = Path(__file__).resolve().parent


def now():
    return datetime.now(timezone.utc).isoformat()


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def save(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding='utf-8')


def read(path):
    return json.loads(path.read_text(encoding='utf-8'))


def serve(fixture):
    server = make_server(fixture)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server, f'http://127.0.0.1:{server.server_port}'


def direct(base, path, principal):
    req = urllib.request.Request(base+path, headers={'Authorization': 'Bearer fixture-session-'+principal})
    started = time.perf_counter()
    try:
        response = urllib.request.urlopen(req, timeout=8)
    except urllib.error.HTTPError as exc:
        response = exc
    with response:
        return {'principal': principal, 'path': path, 'status': response.code,
                'body': json.loads(response.read()), 'elapsed_seconds': round(time.perf_counter()-started, 6)}


def prepare(folder):
    folder.mkdir(parents=True, exist_ok=False)
    plan = []
    for scenario, config in SCENARIOS.items():
        fixture = snapshot(scenario)
        fixture['scenario'].pop('expected', None)
        save(folder/'fixtures'/f'{scenario}.json', fixture)
        for owner, other in (('A', 'B'), ('B', 'A')):
            plan.append({'case_id': f'MECH-{scenario}-{owner}-to-{other}', 'scenario': scenario,
                         'owner': owner, 'other': other, 'object_id': 'obj-'+owner,
                         'policy': config['visibility'], 'description': config['description']})
    truth = {c['case_id']: bool(SCENARIOS[c['scenario']]['vulnerable']) for c in plan}
    save(folder/'plan.json', plan)
    save(folder/'ground-truth.json', truth)
    save(folder/'protocol.json', {
        'version': 1, 'created_at': now(), 'unit': 'scenario and direction; 8 scenario clusters, 16 directional cases',
        'route': '/objects/{id}', 'scanner_timeout_seconds': 3,
        'independent_timeout_seconds': 8, 'delayed_response_seconds': 4,
        'methods': {
            'http-status-v1': 'Shared acquisition gates; HTTP success => positive, 403/404 => negative; otherwise inconclusive.',
            'object-identity-v1': 'Shared gates; successful matching object identities => positive; different object => negative; missing identity => inconclusive. Ignores policy and private fields.',
            'contextual-v1': 'Production analyzer uses configured policy, identity, private fields and verified sessions.'},
        'hypothesis': 'Contextual rules may reduce false positives on permitted access and successful error envelopes; examine recall and coverage trade-offs.',
        'comparison': 'Paired post-processing of exactly the same HTTP observations; not an end-to-end external-tool benchmark.',
        'metrics': ['TP','FP','TN','FN','precision','recall','f1','case_completion','operational_recall'],
        'interpretation': 'Controls already used during development. Repetitions and directions are not independent API samples. No population significance or external superiority claim.'})
    # Phase one uses only stdlib HTTP and fixture ACL, without scanner/evaluator.
    for scenario in SCENARIOS:
        fixture = read(folder/'fixtures'/f'{scenario}.json')
        server, base = serve(fixture)
        try:
            for case in (c for c in plan if c['scenario'] == scenario):
                owner, other = case['owner'], case['other']
                obj = fixture['objects'][case['object_id']]
                policy = fixture['scenario']
                allowed = other == obj['owner_id'] or policy['visibility'] == 'public' or other in policy['readers']
                a = direct(base, '/objects/'+case['object_id'], owner)
                b = direct(base, '/objects/'+case['object_id'], other)
                ids = [direct(base, '/me', u)['body']['id'] for u in (owner, other)]
                if a['body'] != obj or ids[0] == ids[1]:
                    raise ValueError('Invalid independent owner/session evidence')
                exposed = (b['status'] == 200 and b['body'] == obj)
                independent_label = not allowed and exposed
                if independent_label != truth[case['case_id']]:
                    raise ValueError('Source label differs from direct evidence: '+case['case_id'])
                save(folder/'independent-http'/(case['case_id']+'.json'), {
                    'case_id': case['case_id'], 'owner': a, 'cross_user_long_budget': b,
                    'distinct_identity_verified': True, 'allowed_by_acl': allowed,
                    'label': independent_label, 'scanner_used': False, 'human_review': 'pending'})
        finally:
            server.shutdown(); server.server_close()
    files = {p.relative_to(folder).as_posix(): sha(p) for p in sorted(folder.rglob('*')) if p.is_file()}
    manifest = {'frozen_at': now(), 'files': files,
                'fixture_source_sha256': sha(ROOT/'labs/mechanism_fixture.py'),
                'human_review': 'pending; procedural independence only'}
    save(folder/'manifest.json', manifest)
    save(folder/'review.json', {'status': 'pending', 'reviewer': '', 'reviewed_at': '',
          'manifest_sha256': sha(folder/'manifest.json'),
          'case_reviews': {c['case_id']: {'accepted': False, 'basis': ''} for c in plan}})
    print('Prepared candidate dataset:', folder, flush=True)


def verify(folder, purpose):
    manifest = read(folder/'manifest.json')
    for relative, digest in manifest['files'].items():
        path = (folder/relative).resolve()
        if not path.is_relative_to(folder.resolve()) or sha(path) != digest:
            raise ValueError('Frozen input changed: '+relative)
    if sha(ROOT/'labs/mechanism_fixture.py') != manifest['fixture_source_sha256']:
        raise ValueError('Fixture implementation changed; prepare and review a new dataset')
    if purpose == 'main':
        review = read(folder/'review.json')
        truth = read(folder/'ground-truth.json')
        if (review.get('status') != 'approved' or not review.get('reviewer', '').strip()
                or not review.get('reviewed_at', '').strip()
                or review.get('manifest_sha256') != sha(folder/'manifest.json')
                or set(review.get('case_reviews', {})) != set(truth)
                or any(v.get('accepted') is not True or not v.get('basis', '').strip()
                       for v in review['case_reviews'].values())):
            raise ValueError('Main evaluation requires a named human review of every frozen case. Use --purpose pilot for unreviewed development checks.')
    return manifest


def run(folder, out, repetitions, purpose):
    verify(folder, purpose)  # Before scanner import and all HTTP execution.
    from bola_fuzzer.baselines import METHODS, baseline_decision, paired_summary
    from bola_fuzzer.case_evaluator import evaluate_cases
    from bola_fuzzer.config import parse_config
    from bola_fuzzer.scanner import BolaScanner, redact
    from bola_fuzzer.run_record import source_hashes
    if repetitions < 1:
        raise ValueError('repetitions must be positive')
    out.mkdir(parents=True, exist_ok=False)
    plan, truth = read(folder/'plan.json'), read(folder/'ground-truth.json')
    if {c['case_id'] for c in plan} != set(truth) or len(plan) != len(truth):
        raise ValueError('Plan and truth IDs differ')
    save(out/'execution.json', {'started_at': now(), 'purpose': purpose,
         'testbed': 'synthetic same-path mechanism controls; separate from main 40+16 dataset',
         'repetitions': repetitions, 'python': platform.python_version(),
         'dataset': str(folder.resolve()), 'manifest_sha256': sha(folder/'manifest.json'),
         'review_snapshot': read(folder/'review.json'), 'code_sha256': source_hashes(ROOT),
         'harness_sha256': sha(Path(__file__)), 'fixture_sha256': sha(ROOT/'labs/mechanism_fixture.py')})
    summaries = []
    for rep in range(1, repetitions+1):
        predictions = {m: [] for m in METHODS}
        total_requests, total_elapsed = 0, 0
        for scenario in SCENARIOS:
            server, base = serve(read(folder/'fixtures'/f'{scenario}.json'))
            try:
                for case in (c for c in plan if c['scenario'] == scenario):
                    payload = {'target': {'base_url': base, 'timeout_seconds': 3},
                        'auth': {'login_endpoint': '/login'},
                        'users': {key: {'username': case[role], 'password': 'synthetic-lab-only'}
                                  for key, role in (('user_a','owner'), ('user_b','other'))},
                        'tests': [{'name': case['case_id'], 'source_endpoint': '/objects',
                          'source_id_path': '$[0].id', 'target_endpoint': '/objects/{id}',
                          'access_policy': case['policy'], 'identity_paths': ['$.id'],
                          'private_paths': ['$.private_note'], 'session_endpoint': '/me'}]}
                    scanner = BolaScanner(parse_config(payload))
                    original = scanner.http.request
                    trace = []
                    def record_request(*args, **kwargs):
                        entry = {'method': kwargs.get('method', args[0] if args else 'GET'),
                                 'endpoint': kwargs.get('endpoint', args[1] if len(args)>1 else '')}
                        trace.append(entry)
                        try:
                            response = original(*args, **kwargs)
                            entry['status'] = response.status_code
                            return response
                        except Exception as exc:
                            entry['failure'] = type(exc).__name__; raise
                    scanner.http.request = record_request
                    started = time.perf_counter()
                    finding = scanner.run()[0]
                    elapsed = time.perf_counter()-started
                    if finding.object_id not in (case['object_id'], '-'):
                        finding.status = 'Inconclusive'
                        finding.evidence['failure'] = {'stage': 'catalog', 'reason': 'Wrong source object'}
                    observation = redact(asdict(finding), ['synthetic-lab-only','fixture-session-A','fixture-session-B'])
                    observation.update({'case_id': case['case_id'], 'http_trace': trace,
                                        'attempted_requests': len(trace), 'elapsed_seconds': round(elapsed, 6)})
                    evidence_path = out/f'run-{rep}'/'evidence'/(case['case_id']+'.json')
                    save(evidence_path, observation)
                    if not trace:
                        raise RuntimeError('No HTTP requests were attempted; inspect the retained evidence before rerunning')
                    for method in METHODS:
                        predictions[method].append({'case_id': case['case_id'],
                            'status': baseline_decision(finding, method), 'observation_sha256': sha(evidence_path)})
                    total_requests += len(trace); total_elapsed += elapsed
            finally:
                server.shutdown(); server.server_close()
        metrics = {m: evaluate_cases(predictions[m], truth) for m in METHODS}
        for method in METHODS:
            m = metrics[method]
            m['false_positive_rate'] = round(m['FP']/(m['FP']+m['TN']), 6) if m['FP']+m['TN'] else None
            save(out/f'run-{rep}'/(method+'.json'), predictions[method])
        pairs = {m+'-vs-contextual-v1': paired_summary(predictions[m], predictions['contextual-v1'], truth)
                 for m in METHODS if m != 'contextual-v1'}
        summary = {'repetition': rep, 'metrics': metrics, 'paired_comparisons': pairs,
                   'shared_http_requests': total_requests, 'shared_scan_seconds': round(total_elapsed, 6)}
        save(out/f'run-{rep}'/'summary.json', summary); summaries.append(summary)
        verify(folder, purpose)
        print('Completed paired run', rep, flush=True)
    consistent = all(read(out/f'run-{rep}'/(m+'.json')) and
                     [(r['case_id'],r['status']) for r in read(out/f'run-{rep}'/(m+'.json'))] ==
                     [(r['case_id'],r['status']) for r in read(out/'run-1'/(m+'.json'))]
                     for rep in range(2,repetitions+1) for m in METHODS)
    save(out/'summary.json', {'purpose': purpose, 'runs': summaries, 'decisions_consistent': consistent,
                             'completed_at': now(), 'independent_scenario_clusters': 8})
    lines = ['# Perbandingan aturan keputusan BOLA', '',
       f'Status: {purpose}. Dataset kontrol sintetis pada path yang sama. Tinjauan manusia: '+read(folder/'review.json')['status']+'.',
       'Ini perbandingan diagnostik aturan keputusan pada observasi HTTP yang sama, bukan benchmark tool eksternal atau evaluasi utama 40+16 kasus.', '',
       '|Run|Metode|TP|FP|TN|FN|Precision|Recall konklusif|F1|Cakupan|Recall operasional|',
       '|---|---|---|---|---|---|---|---|---|---|---|']
    for s in summaries:
        for method, m in s['metrics'].items():
            lines.append('|'+ '|'.join(str(v) for v in [s['repetition'], method, m['TP'],m['FP'],m['TN'],m['FN'],
                m['precision'],m['recall'],m['f1'],m['case_completion'],m['operational_recall']])+'|')
    lines += ['', '## Interpretasi dan batas', '',
       'Aturan pembanding ditetapkan dalam protocol.json sebelum run. Label dibekukan dan diverifikasi lewat HTTP langsung sebelum scanner diimpor.',
       'B0 menggunakan status, B1 menambah kecocokan identitas, dan M memakai analyzer produksi lengkap. Ketiganya berbagi prasyarat akuisisi dan identitas sesi valid.',
       'Setiap prediksi menyimpan hash observasi yang sama. Biaya HTTP dilaporkan sekali sebagai biaya akuisisi bersama; tidak digunakan untuk mengklaim metode tertentu lebih cepat.',
       'Kasus tidak konklusif dilaporkan terpisah dan tidak dianggap negatif. Nilai null berarti pembagi nol.',
       'Delapan kondisi diuji dua arah. Arah berlawanan dan pengulangan bukan sampel API independen. Kontrol sudah digunakan selama pengembangan; hasil ini tidak membuktikan generalisasi atau kebaruan terhadap penelitian terdahulu.',
       'Dampak gabungan kebijakan dan atribut privat belum dipisahkan sepenuhnya oleh B1 versus M. Diperlukan ablation tambahan jika klaim ingin mengatribusikan manfaat ke setiap komponen secara terpisah.',
       'Persetujuan reviewer dalam berkas adalah rekaman proses manual, bukan verifikasi identitas reviewer secara digital.',
       '', f'Konsistensi keputusan antar-pengulangan: {consistent}.']
    (out/'HASIL.md').write_text('\n'.join(lines)+'\n', encoding='utf-8')
    print('Comparison saved:', out, flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='command', required=True)
    p = sub.add_parser('prepare'); p.add_argument('--out', type=Path, required=True)
    p = sub.add_parser('run'); p.add_argument('--dataset', type=Path, required=True)
    p.add_argument('--out', type=Path, required=True); p.add_argument('--repetitions', type=int, default=3)
    p.add_argument('--purpose', choices=('pilot','main'), default='pilot')
    args = parser.parse_args()
    if args.command == 'prepare': prepare(args.out)
    else: run(args.dataset, args.out, args.repetitions, args.purpose)


if __name__ == '__main__':
    main()
