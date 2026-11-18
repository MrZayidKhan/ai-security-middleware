"""Audit raw snapshots; do not infer binary labels from benchmark success fields."""
import csv
import json
import re
import unicodedata
from collections import Counter, defaultdict
from pathlib import Path
import pyarrow.parquet as pq

ROOT = Path(__file__).resolve().parents[1]
RAW = ROOT / 'datasets/public_raw'


def normalize(text):
    return re.sub(r'\s+', ' ', unicodedata.normalize('NFKC', text).casefold()).strip()


def main():
    files, seen = [], defaultdict(list)
    for path in sorted(RAW.rglob('*')):
        if not path.is_file() or path.suffix not in ('.json', '.jsonl', '.csv', '.parquet') or path.name == 'manifest.json':
            continue
        if path.suffix == '.parquet':
            rows = pq.read_table(path).to_pylist()
        elif path.suffix == '.csv':
            with path.open(encoding='utf-8-sig', newline='') as handle:
                rows = list(csv.DictReader(handle))
        elif path.suffix == '.jsonl':
            rows = [json.loads(line) for line in path.read_text(encoding='utf-8-sig').splitlines() if line.strip()]
        else:
            rows = json.loads(path.read_text(encoding='utf-8-sig'))
        entry = {'file': str(path.relative_to(RAW)), 'container': type(rows).__name__, 'rows': len(rows)}
        if isinstance(rows, list) and rows and isinstance(rows[0], dict):
            entry['columns'] = list(rows[0])
            column = next((key for key in ('prompt', 'text', 'User Prompt') if key in rows[0]), None)
            label = next((key for key in ('label', 'Prompt injection') if key in rows[0]), None)
            if label:
                entry['labels'] = dict(Counter(str(row.get(label)) for row in rows))
            if column:
                values = [normalize(str(row.get(column, ''))) for row in rows]
                entry.update(empty_prompts=values.count(''), unique_normalized_prompts=len(set(values)),
                             duplicate_rows=len(values)-len(set(values)))
                for row, text in zip(rows, values):
                    if text:
                        seen[text].append((entry['file'], str(row.get(label)) if label else None))
        files.append(entry)
    cross = [locations for locations in seen.values() if len({item[0] for item in locations}) > 1]
    report = {'files': files, 'unique_normalized_texts': len(seen),
              'prompts_present_in_multiple_files': len(cross),
              'overlap_file_pairs': dict(Counter('|'.join(sorted({item[0] for item in loc})) for loc in cross)),
              'limitations': ['Exact normalized text audit only; semantic/template duplicates require a separate pass.',
                              'BIPIA contexts and attacks need reconstruction; InjecAgent cases need context-aware parsing.',
                              'NotInject alternate files overlap; retain one layout only.',
                              'Original test splits remain evaluation-only. No training performed.']}
    out = ROOT / 'docs/public_dataset_audit.json'
    out.write_text(json.dumps(report, indent=2), encoding='utf-8')
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    main()
