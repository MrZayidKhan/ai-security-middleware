"""Local dry-run verification; no external tools, messages, or model calls."""
import json
import sys
import numpy as np
from train_candidates import ROOT, metrics
sys.path.insert(0,str(ROOT))
from validate_horizon_readiness import fresh_cases
from evaluate_horizon import DEST
from security_middleware.horizon_detector import HorizonDetector
from security_middleware.content_protection import ContentInspector, ContentEnvelope


def main():
    detector=HorizonDetector.from_advisory_profile(DEST)
    if detector._session is None:
        raise RuntimeError(detector._error)
    inspector=ContentInspector(detector=detector)
    rows=fresh_cases()
    probabilities=[]; decisions=[]; cases=[]
    for index,(text,label,category) in enumerate(rows):
        output=detector.detect(text)
        assert output.probability is not None
        result=inspector.inspect(ContentEnvelope(source_id='readiness-dry-run',content_id=str(index),
            origin_trust='untrusted',data_sensitivity='public',content=text))
        probabilities.append(output.probability)
        decisions.append(int(result.decision.value!='PASS'))
        cases.append(dict(category=category,label=label,model_risk=output.risk,
                          model_probability=output.probability,middleware_decision=result.decision.value,reason=result.reason))
    path=ROOT/'docs/horizon_readiness.json'
    report=json.loads(path.read_text(encoding='utf-8'))
    report['advisory_stress']=metrics(rows,np.array(probabilities),detector.review_threshold)
    report['middleware_stress']=metrics(rows,np.array(decisions),.5)
    report['advisory_dry_run_cases']=cases
    report['middleware_dry_run_scope']='Rules plus Horizon only, no Qwen assessor, no live tool execution; synthetic 32-case diagnostic.'
    path.write_text(json.dumps(report,indent=2,ensure_ascii=False),encoding='utf-8')
    print('Advisory model',json.dumps(report['advisory_stress']))
    print('Rules + model',json.dumps(report['middleware_stress']))
    print('Profile load and middleware interface verified; default unchanged.')


if __name__=='__main__':
    main()
