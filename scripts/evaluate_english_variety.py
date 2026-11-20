"""Measure the English verifier directly using labeled, local benchmark samples."""
import hashlib
import json
import random
from collections import defaultdict
from urllib.request import urlopen

import numpy as np
import pyarrow.parquet as pq

from scripts.train_candidates import RAW, ROOT, metrics
from security_middleware.verified_detector import POLICY, VerifiedDetector


def digest(text):
    return hashlib.sha256(text.encode()).hexdigest()


def sample(rows, count, rng):
    groups = defaultdict(list)
    seen = set()
    for content, task, source, category in rows:
        encoded = json.dumps(dict(channel='retrieved_data', trusted_task=task, content=content), ensure_ascii=False)
        identity = ' '.join(content.casefold().split())
        if (not identity or identity in seen or len(content) > 20000
                or len(task or '') > 4000 or len(encoded.encode()) > 24000):
            continue
        seen.add(identity)
        groups[category].append((content, task, source, category))
    categories = sorted(groups)
    rng.shuffle(categories)
    for group in groups.values():
        rng.shuffle(group)
    selected = []
    while len(selected) < count:
        for category in categories:
            if groups[category]:
                selected.append(groups[category].pop())
                if len(selected) == count:
                    return selected
        if not any(groups.values()):
            raise ValueError('Insufficient eligible examples')


def main():
    seed = 617250
    rng = random.Random(seed)
    previous = json.loads((ROOT/'docs/verified_boundary_holdout.json').read_text(encoding='utf-8'))
    prior = {row['text_sha256'] for row in previous['predictions']}
    direct_positive = [
        (r['text'], None, 'Horizon-Labs boundary pairs', r['source'])
        for r in pq.read_table(RAW/'horizon_eval/boundary_pairs_test.parquet').to_pylist()
        if r['label'] == 1 and r['lang'] == 'en' and digest(r['text']) not in prior
    ]
    direct_negative = [
        (r['prompt'], None, 'NotInject', r['category'])
        for path in sorted((RAW/'leolee99__NotInject/data').glob('NotInject_*.parquet'))
        for r in pq.read_table(path).to_pylist()
    ]
    indirect_positive = [
        (r['Tool Response'], r['User Instruction'], 'InjecAgent base', r['Attack Type'])
        for path in sorted((RAW/'uiuc-kang-lab__InjecAgent/data').glob('test_cases_*_base.json'))
        for r in json.loads(path.read_text(encoding='utf-8'))
        if r['User Instruction'].strip()
    ]
    indirect_negative = []
    for category in ('code', 'email', 'table'):
        path = RAW/'microsoft__BIPIA/benchmark'/category/'test.jsonl'
        for line in path.read_text(encoding='utf-8').splitlines():
            row = json.loads(line)
            content = row['context']
            if not isinstance(content, str):
                content = json.dumps(content, ensure_ascii=False)
            task = ('Explain the cause of this error in the provided code: ' + str(row['error'])
                    if category == 'code' else str(row['question']))
            indirect_negative.append((content, task, 'BIPIA clean test contexts', category))

    datasets = dict(direct=(direct_negative, direct_positive), indirect=(indirect_negative, indirect_positive))
    cases = []
    for channel, pools in datasets.items():
        for label, pool in enumerate(pools):
            cases.extend((channel, label, *row) for row in sample(pool, 12, rng))
    rng.shuffle(cases)

    with urlopen('http://127.0.0.1:11434/api/tags', timeout=10) as response:
        tags = json.load(response)
    model_digest = next(row['digest'] for row in tags['models'] if row['name'] == 'qwen3.5:4b')
    report = dict(seed=seed, model='qwen3.5:4b', model_digest=model_digest,
                  policy_sha256=digest(POLICY), complete=False, predictions=[], metrics={},
                  limitations=[
                      'Classifies benchmark inputs only, with no answering model or tools.',
                      'Public samples may overlap upstream training or earlier development datasets.',
                      'Positive and negative classes use different sources. Balanced accuracy here is not a field estimate.',
                  ])
    path = ROOT/'docs/english_variety_evaluation.json'
    detector = VerifiedDetector()
    for index, (channel, label, content, task, source, category) in enumerate(cases, 1):
        output = detector.detect_with_context(content, task)
        report['predictions'].append(dict(channel=channel, label=label, source=source, category=category,
                                          text_sha256=digest(content), task_sha256=digest(task) if task else None,
                                          risk=output.risk, duration_ms=output.duration_ms))
        path.write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
        print(index, '/', len(cases), channel, label, output.risk, flush=True)

    for channel in ('direct', 'indirect', 'overall'):
        relevant = [r for r in report['predictions'] if channel in (r['channel'], 'overall')]
        scored = [r for r in relevant if r['risk'] != 'unavailable']
        stats = dict(total=len(relevant), unavailable=len(relevant)-len(scored),
                     uncertain=sum(r['risk'] == 'suspicious' for r in relevant))
        if scored:
            result = metrics(
                [('', r['label'], r['category']) for r in scored],
                np.array([r['risk'] != 'benign' for r in scored], dtype=float), .5,
            )
            result.pop('pr_auc')
            result.pop('roc_auc')
            stats.update(result, p95_ms=float(np.percentile([r['duration_ms'] for r in scored], 95)))
        report['metrics'][channel] = stats
    report['complete'] = True
    path.write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(report['metrics'], indent=2), flush=True)


if __name__ == '__main__':
    main()
