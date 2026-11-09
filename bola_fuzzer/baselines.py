"""Predeclared diagnostic baselines, not implementations of external tools.

All methods share successful owner acquisition and distinct-session gates.
Predictions never receive labels. B0 ignores response bodies and policy; B1
checks object identity but ignores policy/private fields; M uses the production
contextual analyzer. These isolate decision rules, not discovery performance.
"""
from bola_fuzzer.analyzer import SUCCESS_CODES
from bola_fuzzer.json_path import extract_json_path

METHODS = ('http-status-v1', 'object-identity-v1', 'contextual-v1')


def baseline_decision(finding, method):
    if method not in METHODS:
        raise ValueError('Unknown method')
    if method == 'contextual-v1':
        return finding.status
    evidence = finding.evidence
    owner = evidence.get('owner', {}).get('response', {})
    cross = evidence.get('cross_user', {}).get('response', {})
    if (evidence.get('failure') or evidence.get('sessions_valid') is not True
            or owner.get('status') not in SUCCESS_CODES or not cross):
        return 'Inconclusive'
    # Shared acquisition gate: the owner baseline must be the requested object.
    try:
        paths = evidence.get('identity_paths', [])
        if not paths or str(extract_json_path(owner.get('body'), paths[0])) != finding.object_id:
            return 'Inconclusive'
    except (KeyError, IndexError, ValueError, TypeError):
        return 'Inconclusive'
    code = cross.get('status')
    if code in (403, 404):
        return 'No BOLA'
    if code not in SUCCESS_CODES:
        return 'Inconclusive'
    if method == 'http-status-v1':
        return 'Potential BOLA'
    paths = evidence.get('identity_paths', [])
    if not paths:
        return 'Inconclusive'
    try:
        owner_ids = [extract_json_path(owner.get('body'), p) for p in paths]
        cross_ids = [extract_json_path(cross.get('body'), p) for p in paths]
        if any(type(v) not in (str, int) or v == '' for v in owner_ids + cross_ids):
            return 'Inconclusive'
    except (KeyError, IndexError, ValueError, TypeError):
        return 'Inconclusive'
    return 'Potential BOLA' if owner_ids == cross_ids else 'No BOLA'


def paired_summary(left, right, truth):
    """Report matched cases and abstentions; never impute failed tests as safe."""
    a = {r['case_id']: r['status'] for r in left}
    b = {r['case_id']: r['status'] for r in right}
    if set(a) != set(truth) or set(b) != set(truth):
        raise ValueError('Paired comparison requires identical planned case IDs')
    conclusive = {'Potential BOLA', 'No BOLA'}
    result = {'same_decision': 0, 'different_decision': 0,
              'both_conclusive': 0, 'left_only_conclusive': 0,
              'right_only_conclusive': 0, 'both_inconclusive': 0,
              'left_wrong_right_correct': 0, 'left_correct_right_wrong': 0,
              'changed_cases': []}
    for case_id, expected in truth.items():
        x, y = a[case_id], b[case_id]
        result['same_decision' if x == y else 'different_decision'] += 1
        xc, yc = x in conclusive, y in conclusive
        bucket = ('both_conclusive' if xc and yc else 'left_only_conclusive' if xc
                  else 'right_only_conclusive' if yc else 'both_inconclusive')
        result[bucket] += 1
        if xc and yc:
            xok = (x == 'Potential BOLA') == expected
            yok = (y == 'Potential BOLA') == expected
            if not xok and yok: result['left_wrong_right_correct'] += 1
            if xok and not yok: result['left_correct_right_wrong'] += 1
        if x != y:
            result['changed_cases'].append({'case_id': case_id, 'left': x, 'right': y,
                                            'ground_truth': expected})
    return result
