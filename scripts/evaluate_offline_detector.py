"""Evaluate the local classifier and inspection policy without executing inputs."""

import argparse
import json
from collections import Counter, defaultdict
from pathlib import Path
from statistics import quantiles
from time import perf_counter

import pyarrow.parquet as pq

from scripts.train_candidates import RAW, key
from security_middleware.content_protection import ContentEnvelope, ContentInspector
from security_middleware.horizon_detector import HorizonDetector, REVISION


def datasets(root):
    boundary = root / 'horizon_eval/boundary_pairs_test.parquet'
    for row in pq.read_table(boundary).to_pylist():
        if row['lang'] == 'en':
            yield 'Horizon boundary pairs', 'direct_user', int(row['label']), row['text']
    notinject = sorted((root / 'leolee99__NotInject/data').glob('NotInject_*.parquet'))
    injecagent = sorted((root / 'uiuc-kang-lab__InjecAgent/data').glob('test_cases_*_base.json'))
    if not notinject or not injecagent:
        raise FileNotFoundError('NotInject and InjecAgent base test files are required')
    for path in notinject:
        for row in pq.read_table(path).to_pylist():
            yield 'NotInject', 'direct_user', 0, row['prompt']
    for path in injecagent:
        for row in json.loads(path.read_text(encoding='utf-8')):
            yield 'InjecAgent base', 'retrieved_data', 1, row['Tool Response']
    for category in ('code', 'email', 'table'):
        path = root / 'microsoft__BIPIA/benchmark' / category / 'test.jsonl'
        with path.open(encoding='utf-8') as handle:
            for line in handle:
                content = json.loads(line)['context']
                if not isinstance(content, str):
                    content = json.dumps(content, ensure_ascii=False)
                yield 'BIPIA clean contexts', 'retrieved_data', 0, content


def metrics(rows):
    scored = [(label, flagged) for label, flagged, _, _, _ in rows]
    tn, fp, fn, tp = (sum(pair == target for pair in scored)
                      for target in ((0, False), (0, True), (1, False), (1, True)))

    def ratio(numerator, denominator):
        return numerator / denominator if denominator else None

    return dict(total=len(rows), detector_unavailable=sum(row[4] for row in rows),
                tn=tn, fp=fp, fn=fn, tp=tp, accuracy=ratio(tp + tn, len(scored)),
                precision=ratio(tp, tp + fp), recall=ratio(tp, tp + fn),
                f1=ratio(2 * tp, 2 * tp + fp + fn), false_positive_rate=ratio(fp, fp + tn),
                sanitized=sum(row[2] for row in rows),
                p95_ms=round(quantiles([row[3] for row in rows], n=100, method='inclusive')[94], 3)
                if len(rows) >= 2 else None)


def evaluate(detector, root):
    inspectors = {
        'rules': ContentInspector(),
        'offline': ContentInspector(detector=detector, classify_sanitized_text=True),
    }
    grouped = defaultdict(list)
    exclusions = Counter()
    source_counts = Counter()
    candidates = defaultdict(list)
    for source, channel, label, content in datasets(root):
        if not content.strip() or len(content) > 20_000:
            exclusions['empty_or_oversized'] += 1
            continue
        candidates[(channel, key(content))].append((source, channel, label, content))

    for duplicate_group in candidates.values():
        if len({row[2] for row in duplicate_group}) != 1:
            exclusions['conflicting_labels'] += len(duplicate_group)
            continue
        exclusions['repeat'] += len(duplicate_group) - 1
        source, channel, label, content = duplicate_group[0]
        source_counts[source] += 1
        envelope = ContentEnvelope(source_id=source, content_id=str(sum(source_counts.values())),
                                   origin_trust='untrusted', data_sensitivity='public',
                                   content=content, input_channel=channel)
        for name, inspector in inspectors.items():
            start = perf_counter()
            result = inspector.inspect(envelope)
            row = (label, result.decision != 'PASS', result.decision == 'SANITIZE',
                   (perf_counter() - start) * 1000,
                   any(output.risk == 'unavailable' for output in result.detector_outputs))
            for split in (source, channel, 'overall'):
                grouped[(name, split)].append(row)
        if sum(source_counts.values()) % 100 == 0:
            print(f'Scored {sum(source_counts.values())} inputs', flush=True)

    return dict(revision=REVISION, source_counts=dict(source_counts), exclusions=dict(exclusions),
                positive_decisions=['SANITIZE', 'HOLD_FOR_REVIEW'],
                review_threshold=detector.review_threshold, window_tokens=detector.window_tokens,
                overlap_tokens=detector.overlap_tokens,
                limitations=['Previously used public suites are regression evidence, with unknown upstream overlap.',
                             'Indirect labels come from separate clean and positive sources.',
                             'Sanitized counts measure policy behavior, not semantic preservation.'],
                metrics={name: {split: metrics(rows) for (mode, split), rows in grouped.items()
                                if mode == name} for name in inspectors})


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--model-dir', type=Path, required=True)
    parser.add_argument('--dataset-root', type=Path, default=RAW)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    detector = HorizonDetector.from_advisory_profile(args.model_dir)
    if detector.detect('Summarize the quarterly report.').risk == 'unavailable':
        parser.error('The offline model could not run. Check local artifacts and runtime dependencies.')
    report = evaluate(detector, args.dataset_root)
    args.output.write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(report['metrics']['offline']['overall'], indent=2))


if __name__ == '__main__':
    main()
