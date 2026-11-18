"""CPU adaptation: frozen semantic/lexical scores, benign counterexamples, low-FPR calibration.

This is a small learned combination, not a reproduction of MOF or neural fine-tuning.
"""
import hashlib
import json
import random
from time import perf_counter

import joblib
import numpy as np
import onnxruntime as ort
from tokenizers import Tokenizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler

from evaluate_semantic import DEST, EXPECTED_MODEL_SHA256
from train_candidates import ROOT, load, group, metrics, scores
from train_indirect_candidate import contexts, attacks, build


def hard_benign():
    # Authored safe requests. No NotInject test text is used or transformed.
    train = [
        'Explain the meaning of the word "{word}" in an English dictionary.',
        'Create a spelling exercise for the vocabulary word "{word}".',
        'Count the letters in the quoted string "{word}".',
        'Write a unit test for a text search that matches the literal string "{word}".',
        'Translate only the quoted word "{word}" into French.',
        'Sort these words alphabetically: garden, {word}, paper.',
        'What part of speech can the word "{word}" have?',
        'Return the quoted string "{word}" as a JSON string literal.'
    ]
    validation = [
        'Find a rhyme for the dictionary word "{word}".',
        'How many vowels occur in the quoted word "{word}"?',
        'Give the pronunciation of the vocabulary word "{word}".',
        'Convert the text string "{word}" to uppercase.'
    ]
    words = ['ignore','override','system','instructions','bypass','secret','uncensored','administrator']
    return [[(template.format(word=w),0,'authored_hard_benign') for template in templates for w in words] for templates in (train, validation)]


def main():
    with (DEST/'model.onnx').open('rb') as handle:
        assert hashlib.file_digest(handle,'sha256').hexdigest() == EXPECTED_MODEL_SHA256
    options = ort.SessionOptions()
    options.intra_op_num_threads = 4
    session = ort.InferenceSession(str(DEST/'model.onnx'),sess_options=options,providers=['CPUExecutionProvider'])
    tokenizer = Tokenizer.from_file(str(DEST/'tokenizer.json'))
    tokenizer.enable_truncation(max_length=512,stride=64)
    cache_path = ROOT/'data/processed/semantic_score_cache.json'
    cache_path.parent.mkdir(parents=True,exist_ok=True)
    cache = json.loads(cache_path.read_text()) if cache_path.exists() else {}
    prior = json.loads((ROOT/'docs/semantic_evaluation.json').read_text())
    for entries in prior['sample_predictions'].values():
        cache.update({r['text_sha256']:r['probability'] for r in entries})
    lexical = joblib.load(ROOT/'models/candidates/indirect_v2.joblib')
    def features(rows):
        semantic = []
        for i,(text,_,_) in enumerate(rows):
            digest = hashlib.sha256(text.encode()).hexdigest()
            if digest not in cache:
                enc = tokenizer.encode(text)
                probabilities = []
                for window in [enc]+enc.overflowing:
                    values = dict(input_ids=window.ids,attention_mask=window.attention_mask,token_type_ids=window.type_ids)
                    logits = session.run(None,{v.name:np.array([values[v.name]],dtype=np.int64) for v in session.get_inputs()})[0][0]
                    exp = np.exp(logits-logits.max())
                    probabilities.append(float((exp/exp.sum())[1]))
                cache[digest] = max(probabilities)
            semantic.append(cache[digest])
            if i % 32 == 0:
                cache_path.write_text(json.dumps(cache),encoding='utf-8')
                print('Scored',i+1,'/',len(rows),flush=True)
        cache_path.write_text(json.dumps(cache),encoding='utf-8')
        values = np.column_stack([semantic,scores(lexical['pipeline'],rows,chunked=True)])
        clipped = np.clip(values,1e-7,1-1e-7)
        return np.log(clipped/(1-clipped))
    pools,_ = load()
    rng = random.Random(5317)
    # Base lexical model never trained on this validation partition. Divide it
    # into head-fit and calibration partitions, preserving class representation.
    fit,cal = [],[]
    for label in (0,1):
        rows = [r for r in pools['validation'] if r[1]==label and len(r[0])<=20000]
        rng.shuffle(rows)
        fit.extend(rows[:128]); cal.extend(rows[128:256])
    hf,hc = hard_benign()
    fit += hf
    cal += hc
    # Reuse only development contexts/families withheld from the frozen lexical
    # model, divided by original context before constructing paired variants.
    test_keys = {group(c) for _,c in contexts('test')}
    available = [(t,c) for t,c in contexts('train') if group(c) not in test_keys and int(hashlib.sha256(group(c).encode()).hexdigest()[:8],16)%5==0]
    unique_contexts = {}; [unique_contexts.setdefault(group(c),(t,c)) for t,c in available]
    available = list(unique_contexts.values())
    rng.shuffle(available)
    families = set(sorted({f for f,_ in attacks('train')})[::4])
    payloads = [(f,a) for f,a in attacks('train') if f in families]
    fit += build(available[:16],payloads)
    cal += build(available[16:32],payloads)
    assert not {group(r[0]) for r in fit}&{group(r[0]) for r in cal}
    start = perf_counter()
    xf,xc = features(fit),features(cal)
    head = make_pipeline(StandardScaler(),LogisticRegression(C=.1,class_weight='balanced',random_state=42))
    head.fit(xf,[r[1] for r in fit])
    probabilities = head.predict_proba(xc)[:,1]
    # Threshold calibration strictly uses development labels. Document empirical
    # FPR and denominator; do not claim reliable sub-1% FPR from this small sample.
    candidates = np.unique(np.r_[0,probabilities,np.nextafter(probabilities,np.inf),1.000001])
    operating_points = {}
    for target in (.05,.01):
        allowed = [(float(t),metrics(cal,probabilities,t)) for t in candidates]
        allowed = [item for item in allowed if item[1]['false_positive_rate']<=target]
        threshold,result = max(allowed,key=lambda item:(item[1]['recall'],-item[1]['false_positive_rate']))
        operating_points[str(target)] = dict(threshold=threshold,development=result)
    threshold = operating_points['0.01']['threshold']
    report = dict(method='Frozen semantic + lexical score head; authored hard-benign augmentation; validation-only FPR calibration',
                  trained_neural_encoder=False, head_training_rows=len(fit), calibration_rows=len(cal),
                  operating_points=operating_points,fit_and_score_seconds=perf_counter()-start,
                  training=metrics(fit,head.predict_proba(xf)[:,1],threshold),external_regressions={},promoted=False,
                  limitations=['Small development and evaluation samples; no production-quality claim.',
                               'Authored lexical exercises are narrow counterexamples, not a full MOF reproduction.',
                               'All external suites have been inspected in prior work and are regression evidence.',
                               'The pretrained encoder remains frozen; no semantic task/content comparison is learned.',
                               'Maximum token-window probability may inflate long-document false positives.'])
    print('Head trained',json.dumps(report),flush=True)
    # Reconstruct exactly the prior sampled regression inputs by SHA-256.
    for name, predictions in prior['sample_predictions'].items():
        identities = {p['text_sha256'] for p in predictions}
        rows = [r for r in pools[name] if hashlib.sha256(r[0].encode()).hexdigest() in identities]
        seen=set(); rows=[r for r in rows if not (r[0] in seen or seen.add(r[0]))]
        assert len(rows)==len(identities)
        p = head.predict_proba(features(rows))[:,1]
        report['external_regressions'][name] = metrics(rows,p,threshold)
        print(name,json.dumps(report['external_regressions'][name]),flush=True)
    joblib.dump(dict(head=head,threshold=threshold,semantic_revision=prior['revision'],lexical_artifact='indirect_v2.joblib'),ROOT/'models/candidates/guardrail_head_v1.joblib')
    (ROOT/'docs/guardrail_head_results.json').write_text(json.dumps(report,indent=2),encoding='utf-8')


if __name__ == '__main__':
    main()
