# Horizon Small CPU setup

Current Windows bundles include the pinned detector files and install their
runtime offline. See the [bundle guide](../packaging/OFFLINE_DETECTOR.md) for
normal installation and the [current regression report](offline_detector_evaluation.json)
for the release policy results. The commands below reproduce separate
source-level experiments.

Downloaded the official quantized ONNX release:
`Horizon-Labs/prompt-injection-guard-small`, revision
`2efc2ed5abecd21eb45c2506d231a65d6e392b85`. License: Apache-2.0.
Weights (268,409,234 bytes) and tokenizer (34,387,555 bytes) were verified against
upstream SHA-256 values. Download source URLs, hashes and sizes are recorded in
`models/pretrained/horizon-small/manifest.json`.

No neural retraining was performed. Existing optional CPU dependencies are listed
in `requirements-semantic.txt`. No remote Python model code is executed.

## Reproduction

From the project directory:

```powershell
.\.venv\Scripts\python.exe scripts\evaluate_horizon.py --download
.\.venv\Scripts\python.exe scripts\evaluate_horizon.py
.\.venv\Scripts\python.exe scripts\evaluate_horizon.py --extended
```

The first evaluation uses exactly the same 320 prompt identities as the previous
DeBERTa evaluation, at the fixed author default threshold 0.5. Extended evaluation
uses all eligible NotInject and InjecAgent examples plus the same balanced
128-example PromptShield sample. Scores are the maximum over overlapping token
windows (512 tokens, 64-token overlap). No input within the 20,000-character
limit is silently truncated. The native 8k context is not exercised by this run.

Results: `docs/horizon_evaluation.json` and
`docs/horizon_extended_evaluation.json`. `complete: true` marks finished reports.
Each report stores prompt hashes and probabilities for reproducibility.

## Optional detector adapter

`security_middleware.horizon_detector.HorizonDetector` implements the existing
detector protocol and accepts the downloaded model directory. Its default review
threshold is 0.5 and high-risk threshold is 0.9; both suspicious and high-risk
outputs remain advisory review signals. It checks the pinned weights/tokenizer
checksums, uses CPU only, and returns `unavailable` on missing/corrupt files or
inference errors. The app's default detector has not been changed.

```python
from pathlib import Path
from security_middleware.horizon_detector import HorizonDetector

detector = HorizonDetector(
    Path('D:/Mini_project/ai-security-middleware/models/pretrained/horizon-small')
)
assessment = detector.detect('Untrusted document text here')
```

## Interpretation limits

PromptShield is listed among upstream training sources, so its score is a
compatibility result rather than independent generalization evidence. Other
public suites are previously inspected regression tests; all training overlap
cannot be ruled out. Attack-only suites cannot establish precision against benign
traffic, and benign-only accuracy is not an overall detector accuracy. No
multilingual performance was measured locally. Do not infer deployment readiness
from a single aggregate score.

After checksum validation, redundant generated download-range parts were removed;
the complete verified weights and dataset sources remain available.

Source model card: https://huggingface.co/Horizon-Labs/prompt-injection-guard-small

## Measured results and decision

Fixed threshold 0.5, without local fine-tuning or test-driven threshold changes:

| Evaluation | Count | Measured result |
|---|---:|---|
| Full NotInject | 339 | 326 benign prompts passed; 13 false positives (3.83% FPR) |
| Full InjecAgent base | 1,054 | 814 attacks detected; 77.23% recall (240 missed) |
| Full InjecAgent enhanced | 1,054 | 1,054 attacks detected; 100% recall |
| Balanced PromptShield sample | 128 | Accuracy 80.47%, precision 86.79%, recall 71.88%, F1 78.63%, FPR 10.94% |

PromptShield sample PR-AUC: 0.9407, ROC-AUC: 0.9421. It is not an independent
benchmark because the source appears in upstream training metadata. Do not merge
single-class suites into one headline accuracy. Enhanced attacks share a common
reinforcement strategy and related underlying cases; 100% recall here does not
imply detection of all attack types.

Mean CPU inference latency in the extended run: NotInject 34 ms, base 67 ms,
enhanced 185 ms, PromptShield sample 268 ms. Enhanced p95: 716 ms; PromptShield
p95: 893 ms. Model initialization is excluded. Timings vary with document length
and CPU load; the earlier short run was faster.

Keep Horizon as the strongest staged candidate so far. It materially improves on
the custom classifiers in indirect attack detection, but missed base attacks and
benign false positives prevent default automatic-blocking promotion. The adapter
is available for explicit advisory evaluation; the production default is unchanged.
No PIGuard download was needed in this step.

Further context/calibration tests and the controlled-pilot verdict are documented
in `docs/HORIZON_READINESS.md`; the staged model is not ready for unattended blocking.

Verification: six detector tests passed. A real-model adapter smoke check matched
the evaluator probability within 1e-6 and confirmed empty/oversized inputs return
`unavailable`. Full extended report has `complete: true`.
