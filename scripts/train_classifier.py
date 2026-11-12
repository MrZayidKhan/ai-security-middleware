"""Download pinned public data, group near duplicates, train and evaluate locally."""
import hashlib
import json
import re
import unicodedata
from collections import Counter
from pathlib import Path
from time import perf_counter
from urllib.request import urlretrieve

ROOT = Path(__file__).resolve().parents[1]
REVISION = '4f61ecb'
FILES = {'train': 'train-00000-of-00001-9564e8b05b4757ab.parquet',
         'test': 'test-00000-of-00001-701d16158af87368.parquet'}
EXPECTED_HASHES = {
    FILES['train']: '2e10bc7ab30f542c97e4e83e2a5683000b5057d25ec10908784c631d44124c04',
    FILES['test']: '39ac797cabc157eeed58435a08593b2952bb6cb16fc394a2d383f447cc7b246e',
}


def verify_source(path):
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    if digest != EXPECTED_HASHES[path.name]:
        raise ValueError(f'Dataset checksum mismatch: {path.name}')
    return digest


def normalize(text):
    return re.sub(r'\s+', ' ', unicodedata.normalize('NFKC', text).casefold()).strip()


def main():
    import joblib
    import numpy as np
    import pyarrow.parquet as pq
    import sklearn
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.linear_model import LogisticRegression
    from sklearn.metrics import classification_report, confusion_matrix
    from sklearn.model_selection import GroupShuffleSplit
    from sklearn.pipeline import Pipeline

    raw = ROOT / 'data/raw'
    raw.mkdir(parents=True, exist_ok=True)
    rows, hashes = [], {}
    for split, filename in FILES.items():
        path = raw / filename
        if not path.exists():
            urlretrieve(f'https://huggingface.co/datasets/deepset/prompt-injections/resolve/{REVISION}/data/{filename}', path)
        hashes[filename] = verify_source(path)
        rows.extend(pq.read_table(path).to_pylist())
    # Conflicting duplicate labels are discarded rather than arbitrarily resolved.
    labels = {}
    for row in rows:
        labels.setdefault(normalize(row['text']), set()).add(row['label'])
    clean = [(text, next(iter(labs))) for text, labs in labels.items() if text and len(labs) == 1]
    texts, y = zip(*clean)
    # Group normalized character n-gram cosine neighbors before splitting.
    near = TfidfVectorizer(analyzer='char_wb', ngram_range=(3, 5)).fit_transform(texts)
    similarity = (near @ near.T).toarray()
    parents = list(range(len(texts)))
    def find(i):
        while parents[i] != i:
            parents[i] = parents[parents[i]]
            i = parents[i]
        return i
    pairs = np.argwhere(np.triu(similarity >= .8, k=1))
    for a, b in pairs:
        parents[find(int(b))] = find(int(a))
    groups = [find(i) for i in range(len(texts))]
    indices = np.arange(len(texts))
    train, rest = next(GroupShuffleSplit(n_splits=1, test_size=.3, random_state=42).split(indices, y, groups))
    vi, ti = next(GroupShuffleSplit(n_splits=1, test_size=.5, random_state=43).split(rest, groups=[groups[i] for i in rest]))
    splits = {'train': train, 'validation': rest[vi], 'test': rest[ti]}
    pipeline = Pipeline([('tfidf', TfidfVectorizer(ngram_range=(1, 2), sublinear_tf=True, max_features=30000)),
                         ('classifier', LogisticRegression(C=1, class_weight='balanced', max_iter=1000, random_state=42))])
    start = perf_counter()
    pipeline.fit([texts[i] for i in train], [y[i] for i in train])
    report = {'source': 'deepset/prompt-injections', 'revision': REVISION, 'sha256': hashes,
        'sklearn_version': sklearn.__version__, 'original_rows': len(rows), 'clean_rows': len(clean),
        'near_duplicate_pairs': len(pairs), 'training_seconds': perf_counter()-start, 'splits': {}}
    for name, ids in splits.items():
        start = perf_counter()
        pred = pipeline.predict([texts[i] for i in ids])
        elapsed = (perf_counter()-start)*1000/len(ids)
        truth = [y[i] for i in ids]
        matrix = confusion_matrix(truth, pred, labels=[0, 1])
        report['splits'][name] = {'count': len(ids), 'labels': dict(Counter(map(str, truth))),
            'metrics': classification_report(truth, pred, output_dict=True, zero_division=0),
            'confusion_matrix': matrix.tolist(), 'false_positive_rate': float(matrix[0,1]/max(1,matrix[0].sum())),
            'batch_ms_per_sample': elapsed}
    model_dir = ROOT / 'models'
    model_dir.mkdir(exist_ok=True)
    artifact = model_dir / 'prompt_classifier.joblib'
    joblib.dump({'format_version': 1, 'labels': [0, 1], 'pipeline': pipeline}, artifact)
    report['artifact_bytes'] = artifact.stat().st_size
    processed = ROOT / 'data/processed'
    processed.mkdir(parents=True, exist_ok=True)
    (processed / 'splits.json').write_text(json.dumps({name: [{'text': texts[i], 'label': y[i], 'group': groups[i]} for i in ids] for name, ids in splits.items()}), encoding='utf-8')
    (ROOT / 'docs/ml_training_results.json').write_text(json.dumps(report, indent=2), encoding='utf-8')
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    main()
