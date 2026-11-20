"""Evaluate frozen classifiers on all eligible rows of pinned public test suites."""
import argparse
from collections import Counter, defaultdict
from hashlib import sha256
import json
from math import sqrt
import random
from time import perf_counter
from urllib.request import urlopen

import joblib
import numpy as np
import pyarrow.parquet as pq

from scripts.train_candidates import RAW, ROOT, group, metrics, scores
from security_middleware.verified_detector import POLICY, VerifiedDetector


def read_json(path):
    return json.loads(path.read_text(encoding='utf-8'))


def digest(data):
    return sha256(data).hexdigest()


def load_suites():
    suites = {}
    inputs = {}
    development_groups = set()
    sources = {r['source'].replace('/', '__')+'/'+r['file']: r
               for r in read_json(RAW/'manifest.json')['files']}
    horizon_manifest = read_json(RAW/'horizon_eval/manifest.json')

    def load(path):
        relative = path.relative_to(RAW).as_posix()
        checksum = digest(path.read_bytes())
        expected = sources.get(relative)
        if relative.startswith('horizon_eval/'):
            expected = next((r for r in horizon_manifest['files'] if r['file'].endswith(path.name)), None)
        if expected is None or expected['sha256'] != checksum:
            raise ValueError(f'Unpinned or modified source: {relative}')
        inputs[relative] = expected
        if path.suffix == '.parquet':
            return pq.read_table(path).to_pylist()
        if path.suffix == '.jsonl':
            return [json.loads(line) for line in path.read_text(encoding='utf-8').splitlines() if line]
        return read_json(path)

    for folder, source in (('hendzh__PromptShield', 'PromptShield'),
                           ('deepset__prompt-injections', 'deepset')):
        for path in sorted((RAW/folder).rglob('*')):
            if path.suffix not in ('.json', '.parquet'):
                continue
            rows = load(path)
            if path.name.startswith('test'):
                suites[source] = [(r.get('prompt', r.get('text')), int(r['label']), None, 'published_test')
                                  for r in rows]
            else:
                development_groups.update(group(r.get('prompt', r.get('text'))) for r in rows)
    suites['Horizon boundary pairs (English)'] = [
        (r['text'], int(r['label']), None, r['lang'])
        for r in load(RAW/'horizon_eval/boundary_pairs_test.parquet') if r['lang'] == 'en'
    ]
    suites['NotInject'] = [
        (r['prompt'], 0, None, r['category'])
        for path in sorted((RAW/'leolee99__NotInject/data').glob('NotInject_*.parquet'))
        for r in load(path)
    ]
    for variant in ('base', 'enhanced'):
        suites['InjecAgent '+variant] = [
            (r['Tool Response'], 1, r['User Instruction'], r['Attack Type'])
            for path in sorted((RAW/'uiuc-kang-lab__InjecAgent/data').glob(f'test_cases_*_{variant}.json'))
            for r in load(path)
        ]
    for category in ('code', 'email', 'table'):
        rows = load(RAW/'microsoft__BIPIA/benchmark'/category/'test.jsonl')
        suites['BIPIA clean '+category] = [
            (r['context'] if isinstance(r['context'], str) else json.dumps(r['context'], ensure_ascii=False),
             0, 'Explain the cause of this error in the provided code: '+str(r['error'])
             if category == 'code' else r['question'], category)
            for r in rows
        ]
    return suites, inputs, development_groups


def prepare(suites, development_groups):
    memberships = defaultdict(set)
    for name, rows in suites.items():
        for content, label, task, _ in rows:
            memberships[(group(content), task)].add((name, label))
    audits, cases = {}, []
    for name, rows in suites.items():
        reasons = Counter()
        seen = set()
        support = Counter()
        for content, label, task, category in rows:
            indirect = name.startswith(('InjecAgent', 'BIPIA'))
            identity = (group(content), task)
            if not identity[0] or (indirect and (not isinstance(task, str) or not task.strip())):
                reasons['missing_text_or_task'] += 1
            elif len({lab for _, lab in memberships[identity]}) > 1:
                reasons['conflicting_labels'] += 1
            elif identity[0] in development_groups:
                reasons['development_group_overlap'] += 1
            elif identity in seen:
                reasons['within_suite_duplicate_group'] += 1
            else:
                seen.add(identity)
                channel = 'retrieved_data' if indirect else 'direct_user'
                encoded = json.dumps(dict(channel=channel, trusted_task=task, content=content), ensure_ascii=False)
                if len(content) > 20000 or len(task or '') > 4000 or len(encoded.encode()) > 24000:
                    reasons['outside_verifier_input_limits'] += 1
                    continue
                support[label] += 1
                cases.append((name, content, label, task, category))
        audits[name] = dict(published_rows=len(rows), eligible=sum(support.values()),
                            eligible_labels=dict(support), exclusions=dict(reasons))
    return cases, audits


def wilson(success, total):
    if not total:
        return None
    z = 1.95996398454
    p = success / total
    scale = 1 + z*z/total
    center = (p + z*z/(2*total)) / scale
    half = z * sqrt(p*(1-p)/total + z*z/(4*total*total)) / scale
    return [max(0, center-half), min(1, center+half)]


def summarize(rows, threshold, categorical):
    decisions = [r for r in rows if r['score'] is not None]
    report = dict(evaluated=len(rows), scored=len(decisions), unavailable=len(rows)-len(decisions))
    if not decisions:
        return report
    report.update(metrics([('', r['label'], r['category']) for r in decisions],
                          np.array([r['score'] for r in decisions]), threshold))
    negatives = sum(r['label'] == 0 for r in decisions)
    positives = len(decisions)-negatives
    report.update(benign=negatives, injections=positives)
    tn, fp = report['confusion_matrix'][0]
    fn, tp = report['confusion_matrix'][1]
    if not tp+fp:
        report['precision'] = None
    if not positives or not negatives:
        for field in ('accuracy', 'precision', 'f1'):
            report[field] = None
    if not positives:
        report['recall'] = None
    report['wilson_95_row_level'] = dict(
        recall=wilson(tp, positives), false_positive_rate=wilson(fp, negatives),
        precision=wilson(tp, tp+fp) if positives and negatives else None,
        accuracy=wilson(tn+tp, len(decisions)) if positives and negatives else None,
    )
    if categorical:
        report.update(pr_auc=None, roc_auc=None,
                      uncertain=sum(r['risk'] == 'suspicious' for r in decisions))
    if 'ms' in decisions[0]:
        report['p95_ms'] = float(np.percentile([r['ms'] for r in decisions], 95))
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('backend', choices=('word_char', 'verifier'))
    parser.add_argument('--max-new', type=int, help='Stop after this many new cases and retain progress.')
    args = parser.parse_args()
    categorical = args.backend == 'verifier'
    if args.max_new is not None and (not categorical or args.max_new < 1):
        parser.error('--max-new requires the verifier and a positive limit')
    suites, inputs, development = load_suites()
    cases, audits = prepare(suites, development)
    rng = random.Random(617251)
    grouped = defaultdict(list)
    for case in cases:
        grouped[case[0]].append(case)
    for rows in grouped.values():
        rng.shuffle(rows)
    # Interleave sources so a partial run is not dominated by the largest suite.
    cases = [rows[index] for index in range(max(map(len, grouped.values())))
             for rows in grouped.values() if index < len(rows)]
    case_ids = [digest(json.dumps([name, content, label, task, category], ensure_ascii=False).encode())
                for name, content, label, task, category in cases]
    if categorical:
        with urlopen('http://127.0.0.1:11434/api/tags', timeout=10) as response:
            tags = json.load(response)
        model = dict(name='qwen3.5:4b', digest=next(r['digest'] for r in tags['models'] if r['name']=='qwen3.5:4b'),
                     policy_sha256=digest(POLICY.encode()))
        detector = VerifiedDetector()
        threshold = .5
    else:
        path = ROOT/'models/candidates/word_char.joblib'
        artifact = joblib.load(path)
        model = dict(name='word_char', sha256=digest(path.read_bytes()))
        threshold = artifact['review_threshold']

    fingerprint = digest(json.dumps([model, case_ids, threshold], sort_keys=True).encode())
    runtime = ROOT/'runtime_data'
    runtime.mkdir(exist_ok=True)
    checkpoint = runtime/f'full_corpora_{args.backend}_{fingerprint[:16]}.jsonl'
    output = ROOT/f'docs/full_corpora_{args.backend}.json'
    prior = {}
    if categorical and checkpoint.exists():
        with checkpoint.open(encoding='utf-8') as handle:
            for line in handle:
                record = json.loads(line)
                prior[record['id']] = record
    remaining = [(case_id, case) for case_id, case in zip(case_ids, cases) if case_id not in prior]
    if args.max_new is not None:
        remaining = remaining[:args.max_new]

    report = dict(model=model, threshold=threshold, fingerprint=fingerprint, source_files=inputs,
                  suite_audit=audits, total_eligible=len(cases), completed=0, complete=False, suites={})

    def save():
        by_source = defaultdict(list)
        slices = defaultdict(list)
        for row in prior.values():
            by_source[row['suite']].append(row)
            slices[(row['suite'], row['category'])].append(row)
        report.update(completed=len(prior), complete=len(prior)==len(cases),
                      suites={name: summarize(rows, threshold, categorical) for name, rows in by_source.items()},
                      slices={name: {category: summarize(rows, threshold, categorical)
                                     for (suite, category), rows in slices.items() if suite == name}
                              for name in by_source})
        staged = output.with_suffix('.tmp')
        staged.write_text(json.dumps(report, indent=2)+'\n', encoding='utf-8')
        staged.replace(output)

    print(f'{args.backend}: {len(cases):,} eligible, {len(prior):,} already recorded.', flush=True)
    save()
    if not categorical:
        start = perf_counter()
        probabilities = scores(artifact['pipeline'], [(r[1], r[2], r[4]) for _, r in remaining], chunked=True)
        report['batch_mean_ms'] = (perf_counter()-start)*1000/len(remaining)
    with checkpoint.open('a' if categorical else 'w', encoding='utf-8', buffering=1) as handle:
        for index, (case_id, (name, content, label, task, category)) in enumerate(remaining):
            row = dict(id=case_id, suite=name, label=label, category=category)
            if categorical:
                result = detector.detect_with_context(content, task)
                row.update(score=None if result.risk=='unavailable' else int(result.risk!='benign'),
                           risk=result.risk, ms=result.duration_ms)
                if result.risk == 'unavailable':
                    save()
                    raise RuntimeError('Verifier unavailable. Check Ollama and resume; the failed case will retry.')
            else:
                row['score'] = float(probabilities[index])
            handle.write(json.dumps(row)+'\n')
            prior[case_id] = row
            if categorical and len(prior) % 10 == 0:
                save()
                print(f'{len(prior):,}/{len(cases):,}', flush=True)
    save()
    print(f'Saved {len(prior):,}/{len(cases):,} results to {output}', flush=True)


if __name__ == '__main__':
    main()
