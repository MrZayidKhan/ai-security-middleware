"""Pinned official ONNX model: download or reproducible sampled CPU evaluation."""
import argparse
import hashlib
import json
import random
from pathlib import Path
from time import perf_counter
from urllib.request import urlopen, Request
from concurrent.futures import ThreadPoolExecutor

from train_candidates import ROOT, load, metrics, scores

MODEL = 'protectai/deberta-v3-base-prompt-injection-v2'
REVISION = '90c9989b1a342275dd0d1a95aad283c04e075671'
EXPECTED_MODEL_SHA256 = 'f0ea7f239f765aedbde7c9e163a7cb38a79c5b8853d3f76db5152172047b228c'
DEST = ROOT / 'models/pretrained/protectai-v2'


def ranged_download(url, temporary):
    with urlopen(Request(url+'&probe=1', headers={'Range':'bytes=0-0'}), timeout=30) as response:
        total = int(response.headers['Content-Range'].split('/')[-1])
    size = 4*1024*1024
    parts = list(range(0,total,size))
    def part(start):
        end = min(total,start+size)-1
        path = temporary.with_name(temporary.name+f'.{start}')
        if path.exists() and path.stat().st_size == end-start+1:
            return path
        for attempt in range(3):
            try:
                with urlopen(Request(url+f'&range_start={start}', headers={'Range':f'bytes={start}-{end}'}), timeout=90) as response:
                    if response.status != 206:
                        raise ValueError('Server did not honor byte range')
                    payload = response.read()
                if len(payload) != end-start+1:
                    raise ValueError('Incomplete range')
                path.write_bytes(payload)
                return path
            except Exception:
                if attempt == 2:
                    raise
    print('Downloading model bytes:',total,flush=True)
    with ThreadPoolExecutor(max_workers=16) as executor:
        paths = list(executor.map(part,parts))
    with temporary.open('wb') as output:
        for path in paths:
            with path.open('rb') as handle:
                while chunk := handle.read(1024*1024):
                    output.write(chunk)
    assert temporary.stat().st_size == total


def download():
    DEST.mkdir(parents=True, exist_ok=True)
    manifest = []
    for name in ('README.md', 'LICENSE', 'onnx/config.json', 'onnx/tokenizer.json', 'onnx/model.onnx'):
        path = DEST / Path(name).name
        url = f'https://huggingface.co/{MODEL}/resolve/{REVISION}/{name}?download=true'
        if not path.exists():
            temporary = path.with_suffix(path.suffix+'.partial')
            if name.endswith('model.onnx'):
                ranged_download(url, temporary)
            else:
                with urlopen(url, timeout=120) as response, temporary.open('wb') as handle:
                    while chunk := response.read(1024*1024):
                        handle.write(chunk)
            temporary.replace(path)
        with path.open('rb') as handle:
            digest = hashlib.file_digest(handle, 'sha256').hexdigest()
        if name.endswith('model.onnx') and digest != EXPECTED_MODEL_SHA256:
            raise ValueError('Model differs from upstream SHA-256')
        if name.endswith('model.onnx'):
            # Exact generated range parts only, after upstream checksum validation.
            for part in DEST.glob('model.onnx.partial.*'):
                if part.name.rsplit('.',1)[-1].isdigit():
                    part.unlink()
        manifest.append(dict(file=path.name, sha256=digest, bytes=path.stat().st_size, url=url))
        print(path.name, path.stat().st_size, flush=True)
    (DEST/'manifest.json').write_text(json.dumps(dict(model=MODEL, revision=REVISION, files=manifest), indent=2), encoding='utf-8')


def main():
    import numpy as np
    import onnxruntime as ort
    from tokenizers import Tokenizer
    with (DEST/'model.onnx').open('rb') as handle:
        if hashlib.file_digest(handle,'sha256').hexdigest() != EXPECTED_MODEL_SHA256:
            raise ValueError('Model checksum mismatch')
    config = json.loads((DEST/'config.json').read_text())
    print('Labels:', config['id2label'], flush=True)
    positive = next(int(k) for k,v in config['id2label'].items() if v.upper() == 'INJECTION')
    options = ort.SessionOptions()
    options.intra_op_num_threads = 4
    session = ort.InferenceSession(str(DEST/'model.onnx'), sess_options=options, providers=['CPUExecutionProvider'])
    tokenizer = Tokenizer.from_file(str(DEST/'tokenizer.json'))
    tokenizer.enable_truncation(max_length=512, stride=64)
    pools, _ = load()
    rng = random.Random(20261115)
    suites = {}
    for name in ('notinject','injecagent_base','injecagent_enhanced','hendzh__PromptShield_test'):
        rows = pools[name]
        # Balance the general binary test; single-class suites sample 64 each.
        if name == 'hendzh__PromptShield_test':
            suites[name] = sum([rng.sample([r for r in rows if r[1]==label and len(r[0])<=20000], 64) for label in (0,1)], [])
        else:
            eligible = [r for r in rows if len(r[0])<=20000]
            suites[name] = rng.sample(eligible, min(64,len(eligible)))
    report = dict(model=MODEL, revision=REVISION, trained_here=False, threshold=.5, seed=20261115,
                  onnxruntime=ort.__version__, providers=session.get_providers(), evaluations={},
                  limitations=['Small sampled regression evaluation; pretrained training overlap has not been ruled out.',
                               'Balanced PromptShield sample does not represent deployment prevalence.',
                               'Full token-window coverage with maximum window probability can inflate document false positives.',
                               'Text-only detector does not compare trusted task semantics; inputs above 20000 characters excluded.'])
    for name, rows in suites.items():
        probabilities, times, window_counts = [], [], []
        for text, _, _ in rows:
            start = perf_counter()
            encoded = tokenizer.encode(text)
            windows = [encoded]+encoded.overflowing
            values = []
            for window in windows:
                inputs = {'input_ids':np.array([window.ids],dtype=np.int64),
                          'attention_mask':np.array([window.attention_mask],dtype=np.int64),
                          'token_type_ids':np.array([window.type_ids],dtype=np.int64)}
                logits = session.run(None, {i.name:inputs[i.name] for i in session.get_inputs()})[0][0]
                exp = np.exp(logits-np.max(logits))
                values.append(float((exp/exp.sum())[positive]))
            probabilities.append(max(values))
            times.append((perf_counter()-start)*1000)
            window_counts.append(len(windows))
        result = metrics(rows, np.array(probabilities), .5)
        result.update(mean_ms=float(np.mean(times)), p95_ms=float(np.percentile(times,95)), total_windows=sum(window_counts))
        report['evaluations'][name] = result
        report.setdefault('sample_predictions',{})[name] = [dict(text_sha256=hashlib.sha256(r[0].encode()).hexdigest(),label=r[1],probability=p) for r,p in zip(rows,probabilities)]
        print(name, json.dumps(result), flush=True)
        (ROOT/'docs/semantic_evaluation.json').write_text(json.dumps(report,indent=2),encoding='utf-8')
    import joblib
    previous = joblib.load(ROOT/'models/candidates/indirect_v2.joblib')
    report['previous_candidate_same_samples'] = {name:metrics(rows, scores(previous['pipeline'],rows,chunked=True),previous['review_threshold']) for name,rows in suites.items()}
    report['complete'] = True
    (ROOT/'docs/semantic_evaluation.json').write_text(json.dumps(report,indent=2),encoding='utf-8')


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--download', action='store_true')
    args = parser.parse_args()
    download() if args.download else main()
