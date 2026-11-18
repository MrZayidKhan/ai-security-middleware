"""Train an experimental indirect-content classifier with grouped BIPIA development data."""
import hashlib
import json
from collections import Counter
from time import perf_counter

import joblib
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline, FeatureUnion

from train_candidates import ROOT, RAW, OUT, group, load, metrics, scores


def contexts(split):
    result = []
    for task in ('email', 'code', 'table'):
        path = RAW / f'microsoft__BIPIA/benchmark/{task}/{split}.jsonl'
        for line in path.read_text(encoding='utf-8').splitlines():
            row = json.loads(line)
            text = row['context']
            if not isinstance(text, str):
                text = json.dumps(text, ensure_ascii=False)
            result.append((task, text))
    return result


def attacks(split):
    rows = json.loads((RAW / f'microsoft__BIPIA/benchmark/text_attack_{split}.json').read_text(encoding='utf-8'))
    return [(family, text) for family, variants in rows.items() for text in variants]


def build(context_rows, payloads):
    result = []
    for i, (task, text) in enumerate(context_rows):
        result.append((text, 0, task))
        # Three placements, same clean context control. Avoid full Cartesian repetition.
        for position in range(3):
            family, attack = payloads[(i*3+position) % len(payloads)]
            boundary = 0 if position == 0 else len(text) if position == 1 else len(text)//2
            result.append((text[:boundary]+'\n'+attack+'\n'+text[boundary:], 1, family))
    return result


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    pools, _ = load()
    test_context_keys = {group(c) for _, c in contexts('test')}
    context_train = [(t,c) for t,c in contexts('train') if group(c) not in test_context_keys]
    # Deterministic split of entire clean contexts and attack families.
    held = lambda s: int(hashlib.sha256(group(s).encode()).hexdigest()[:8], 16) % 5 == 0
    family_names = sorted({f for f, _ in attacks('train')})
    val_families = set(family_names[::4])
    fit_contexts = [(t,c) for t,c in context_train if not held(c)]
    val_contexts = [(t,c) for t,c in context_train if held(c)]
    fit_attacks = [(f,a) for f,a in attacks('train') if f not in val_families]
    val_attacks = [(f,a) for f,a in attacks('train') if f in val_families]
    assert not {group(c) for _,c in fit_contexts} & {group(c) for _,c in val_contexts}
    assert not {f for f,_ in fit_attacks} & {f for f,_ in val_attacks}
    indirect_train = build(fit_contexts, fit_attacks)
    indirect_val = build(val_contexts, val_attacks)
    # Both direct and indirect examples are input as content. Task semantics are
    # not represented: this candidate is not a context-aware semantic model.
    train = pools['train'] + indirect_train
    val = pools['validation'] + indirect_val
    excluded_test_contexts = {group(c) for _,c in contexts('test')}
    blocked = excluded_test_contexts | {group(t) for t,_,_ in val}
    train = [r for r in train if group(r[0]) not in blocked]
    model = Pipeline([('tfidf', FeatureUnion([
        ('word', TfidfVectorizer(ngram_range=(1,2), min_df=2, max_features=40000, sublinear_tf=True)),
        ('char', TfidfVectorizer(analyzer='char_wb', ngram_range=(3,5), min_df=3, max_features=60000, sublinear_tf=True))])),
        ('classifier', LogisticRegression(C=.5, class_weight='balanced', max_iter=500, solver='liblinear', random_state=42))])
    # Balance contribution of sources as well as classes; synthetic variants
    # from one BIPIA context must not dominate the model.
    indirect_keys = {group(r[0]) for r in indirect_train}
    sources = ['bipia' if group(r[0]) in indirect_keys else 'direct' for r in train]
    counts = Counter(sources)
    weights = np.array([len(train)/(2*counts[source]) for source in sources])
    start = perf_counter()
    model.fit([r[0] for r in train], [r[1] for r in train], classifier__sample_weight=weights)
    seconds = perf_counter()-start
    vp = scores(model, val, chunked=True)
    n = len(pools['validation'])
    # Macro F1 across sources; apply FPR constraint separately to each source.
    choices = []
    for threshold in np.linspace(.1,.95,86):
        direct = metrics(pools['validation'], vp[:n], threshold)
        indirect = metrics(indirect_val, vp[n:], threshold)
        choices.append((float(threshold), direct, indirect))
    acceptable = [c for c in choices if max(c[1]['false_positive_rate'], c[2]['false_positive_rate']) <= .05]
    selected = max(acceptable or choices, key=lambda c: (c[1]['f1']+c[2]['f1'])/2)
    threshold, direct, indirect = selected
    report = dict(training_rows=len(train), fit_seconds=seconds, threshold=threshold,
                  validation_direct=direct, validation_indirect=indirect,
                  held_out_development_attack_families=sorted(val_families),
                  train_context_count=len(fit_contexts), validation_context_count=len(val_contexts),
                  validation_fpr_constraint_met=bool(acceptable),
                  training=metrics(train, scores(model, train, chunked=True), threshold), evaluations={},
                  limitations=['Experimental text-only model; no semantic comparison with trusted task.',
                               'BIPIA reconstruction uses deterministic character-midpoint insertion, not official sentence-middle insertion.',
                               'Previously inspected external suites are regression evidence, not fresh blind tests.',
                               'Source balancing and exact/template separation do not establish semantic deduplication or demographic fairness.',
                               'Synthetic BIPIA variants share contexts and payloads; counts are not independent observations.'])
    print('Validation', json.dumps(report), flush=True)
    joblib.dump(dict(format_version=1, labels=[0,1], pipeline=model, review_threshold=threshold,
                     high_risk_threshold=max(.9,threshold), candidate='indirect_v2'), OUT/'indirect_v2.joblib')
    # Previously unexamined BIPIA test payloads used only after fitting/selection.
    final_bipia = build(contexts('test'), attacks('test'))
    suites = {'bipia_reconstructed_test': final_bipia}
    suites.update({k:pools[k] for k in ('notinject','injecagent_base','injecagent_enhanced','hendzh__PromptShield_test')})
    for name, rows in suites.items():
        report['evaluations'][name] = metrics(rows, scores(model, rows, chunked=True), threshold)
        print(name, json.dumps(report['evaluations'][name]), flush=True)
    report['promoted'] = False
    (ROOT/'docs/indirect_training_results.json').write_text(json.dumps(report, indent=2), encoding='utf-8')


if __name__ == '__main__':
    main()
