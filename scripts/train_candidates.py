"""Reproducible CPU candidates with validation selection and separate external tests."""
import csv
import hashlib
import json
import re
import unicodedata
from collections import Counter, defaultdict
from pathlib import Path
from time import perf_counter

import joblib
import numpy as np
import pyarrow.parquet as pq
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (accuracy_score, average_precision_score, confusion_matrix,
                             precision_recall_fscore_support, roc_auc_score)
from sklearn.pipeline import FeatureUnion, Pipeline

ROOT = Path(__file__).resolve().parents[1]
RAW = ROOT / 'datasets/public_raw'
OUT = ROOT / 'models/candidates'


def key(text):
    return re.sub(r'\s+', ' ', unicodedata.normalize('NFKC', text).casefold()).strip()


def group(text):
    # Conservative template grouping also joins digit/punctuation variants.
    return re.sub(r'[^\w]+', ' ', re.sub(r'\d+', '0', key(text))).strip()


def load():
    pools = defaultdict(list)
    for source in ('hendzh__PromptShield', 'deepset__prompt-injections'):
        for path in (RAW / source).rglob('*'):
            if path.suffix not in ('.json', '.parquet'):
                continue
            rows = json.loads(path.read_text(encoding='utf-8')) if path.suffix == '.json' else pq.read_table(path).to_pylist()
            split = 'validation' if path.name.startswith('validation') else 'test' if path.name.startswith('test') else 'train'
            for row in rows:
                text = row.get('prompt', row.get('text'))
                pools[split if split != 'test' else source + '_test'].append((text, int(row['label']), source))
    for path in (RAW / 'leolee99__NotInject/data').glob('NotInject_*.parquet'):
        for row in pq.read_table(path).to_pylist():
            pools['notinject'].append((row['prompt'], 0, row['category']))
    for path in (RAW / 'uiuc-kang-lab__InjecAgent/data').glob('test_cases_*.json'):
        setting = 'enhanced' if 'enhanced' in path.name else 'base'
        for row in json.loads(path.read_text(encoding='utf-8')):
            pools['injecagent_' + setting].append((row['Tool Response'], 1, row['Attack Type']))
    with (RAW / 'reshabhs__SPML_Chatbot_Prompt_Injection/spml_prompt_injection.csv').open(encoding='utf-8-sig', newline='') as handle:
        for row in csv.DictReader(handle):
            if row['User Prompt'].strip():
                pools['spml_context_dependent'].append((row['User Prompt'], int(row['Prompt injection']), 'SPML'))
    # BIPIA clean contexts are safe external-content controls, not attack samples.
    for path in (RAW / 'microsoft__BIPIA/benchmark').glob('*/test.jsonl'):
        for line in path.read_text(encoding='utf-8').splitlines():
            row = json.loads(line)
            context = row['context']
            if not isinstance(context, str):
                context = json.dumps(context, ensure_ascii=False)
            pools['bipia_clean_contexts'].append((context, 0, path.parent.name))
    # Preserve original external tests; purge their template identities upstream.
    blocked = {group(t) for name, rows in pools.items() if name not in ('train', 'validation') for t, _, _ in rows}
    exclusions = {}
    for name in ('validation', 'train'):
        labels = defaultdict(set)
        for text, label, _ in pools[name]:
            labels[group(text)].add(label)
        unique, clean = set(), []
        for row in pools[name]:
            fingerprint = group(row[0])
            if fingerprint and fingerprint not in blocked and fingerprint not in unique and len(labels[fingerprint]) == 1:
                clean.append(row)
                unique.add(fingerprint)
        exclusions[name] = len(pools[name]) - len(clean)
        pools[name] = clean
        blocked.update(unique)
    return pools, exclusions


def scores(model, rows, chunked=False):
    texts = [row[0] for row in rows]
    if not chunked:
        return model.predict_proba(texts)[:, 1]
    chunks, owners = [], []
    for index, text in enumerate(texts):
        for start in range(0, len(text), 1800):
            chunks.append(text[start:start+2000])
            owners.append(index)
    result = np.zeros(len(texts))
    for start in range(0, len(chunks), 256):
        probabilities = model.predict_proba(chunks[start:start+256])[:, 1]
        np.maximum.at(result, owners[start:start+256], probabilities)
    return result


def metrics(rows, probabilities, threshold):
    truth = np.array([row[1] for row in rows])
    predicted = probabilities >= threshold
    tn, fp, fn, tp = confusion_matrix(truth, predicted, labels=[0, 1]).ravel()
    precision, recall, f1, _ = precision_recall_fscore_support(truth, predicted, average='binary', zero_division=0)
    return dict(n=len(rows), accuracy=float(accuracy_score(truth, predicted)), precision=float(precision),
                recall=float(recall), f1=float(f1), confusion_matrix=[[int(tn), int(fp)], [int(fn), int(tp)]],
                false_positive_rate=float(fp/(tn+fp)) if tn+fp else None,
                false_negative_rate=float(fn/(fn+tp)) if fn+tp else None,
                pr_auc=float(average_precision_score(truth, probabilities)) if len(set(truth)) == 2 else None,
                roc_auc=float(roc_auc_score(truth, probabilities)) if len(set(truth)) == 2 else None)


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    pools, exclusions = load()
    report = dict(seed=42, exclusions=exclusions, counts={k:len(v) for k,v in pools.items()}, candidates={},
                  limitations=['Template normalization removes exact/digit/punctuation variants; semantic paraphrase leakage remains possible.',
                               'SPML is evaluated without system context and is a context-dependent diagnostic.',
                               'Single-class suites measure FPR or recall, not both precision and recall.',
                               'BIPIA clean controls are not a reconstructed BIPIA attack benchmark.',
                               'No multilingual/fairness guarantee; external suites must not drive further tuning.'])
    train, val = pools['train'], pools['validation']
    texts, labels = [r[0] for r in train], [r[1] for r in train]
    for name in ('word', 'word_char'):
        word = TfidfVectorizer(ngram_range=(1,2), sublinear_tf=True, min_df=2, max_features=40000)
        features = word if name == 'word' else FeatureUnion([('word', word), ('char', TfidfVectorizer(
            analyzer='char_wb', ngram_range=(3,5), min_df=3, max_features=60000, sublinear_tf=True))])
        model = Pipeline([('tfidf', features), ('classifier', LogisticRegression(C=1,
                          class_weight='balanced', max_iter=500, random_state=42, solver='liblinear'))])
        start = perf_counter()
        model.fit(texts, labels)
        fit_seconds = perf_counter()-start
        pval = scores(model, val, chunked=True)
        choices = [(float(t), metrics(val, pval, t)) for t in np.linspace(.1,.99,90)]
        acceptable = [(t,m) for t,m in choices if m['false_positive_rate'] <= .02]
        threshold, valid = max(acceptable or choices, key=lambda item: (item[1]['f1'], item[0]))
        result = dict(fit_seconds=fit_seconds, threshold=threshold, validation=valid,
                      train=metrics(train, scores(model, train), threshold))
        artifact = OUT / (name + '.joblib')
        joblib.dump(dict(format_version=1, labels=[0,1], pipeline=model,
                         review_threshold=threshold, high_risk_threshold=max(.9,threshold), candidate=name), artifact)
        result['artifact_bytes'] = artifact.stat().st_size
        report['candidates'][name] = result
        print(name, json.dumps(result), flush=True)
    selected = max(report['candidates'], key=lambda name: report['candidates'][name]['validation']['f1'])
    report['selected_by_validation'] = selected
    artifact = joblib.load(OUT / (selected + '.joblib'))
    model, threshold = artifact['pipeline'], artifact['review_threshold']
    # Only selected model sees external tests; no retuning after these results.
    report['external_evaluation'] = {}
    for name, rows in pools.items():
        if name in ('train', 'validation'):
            continue
        p = scores(model, rows, chunked=True)
        report['external_evaluation'][name] = metrics(rows, p, threshold)
        print(name, json.dumps(report['external_evaluation'][name]), flush=True)
    report['baseline_comparison'] = {}
    baseline = joblib.load(ROOT / 'models/prompt_classifier.joblib')['pipeline']
    for name in ('notinject', 'injecagent_base', 'bipia_clean_contexts'):
        p = scores(baseline, pools[name], chunked=True)
        report['baseline_comparison'][name] = metrics(pools[name], p, .3)
    report['promoted'] = False
    report['data_fingerprint'] = hashlib.sha256(json.dumps(pools, sort_keys=True).encode()).hexdigest()
    (ROOT / 'docs/candidate_training_results.json').write_text(json.dumps(report, indent=2), encoding='utf-8')
    print('Report saved; deployment unchanged.', flush=True)


if __name__ == '__main__':
    main()
