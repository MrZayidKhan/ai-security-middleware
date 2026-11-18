"""Live English classifier check; no answering-model call or tool execution."""
import hashlib
import json
import sys
from pathlib import Path
import numpy as np
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from security_middleware.verified_detector import VerifiedDetector,POLICY
from scripts.train_candidates import ROOT,metrics


def main():
    source=ROOT/'sample_data/english_injection_examples.json'
    cases=json.loads(source.read_text(encoding='utf-8'))['cases']
    detector=VerifiedDetector()
    report=dict(language='English',backend='local-semantic-verifier',
                example_file_sha256=hashlib.sha256(source.read_bytes()).hexdigest(),
                policy_sha256=hashlib.sha256(POLICY.encode()).hexdigest(),cases=[],complete=False,
                limitations=['24 authored diagnostic examples, not an independent production benchmark.'])
    truth=[];predictions=[]
    for row in cases:
        output=detector.detect_with_context(row['content'],row.get('trusted_task'))
        prediction=int(output.risk!='benign')
        truth.append((row['content'],row['label'],row['type']))
        predictions.append(prediction)
        report['cases'].append(dict(id=row['id'],type=row['type'],label=row['label'],prediction=prediction,
                                   risk=output.risk,duration_ms=output.duration_ms,reason=output.reason))
        (ROOT/'docs/english_example_results.json').write_text(json.dumps(report,indent=2),encoding='utf-8')
        print(row['id'],'expected',row['label'],'actual',output.risk,flush=True)
    report['metrics']=metrics(truth,np.array(predictions),.5)
    report['metrics']['pr_auc']=None;report['metrics']['roc_auc']=None
    report['unavailable']=sum(r['risk']=='unavailable' for r in report['cases'])
    report['complete']=True
    (ROOT/'docs/english_example_results.json').write_text(json.dumps(report,indent=2),encoding='utf-8')
    print(json.dumps(report['metrics']),flush=True)


if __name__=='__main__':main()
