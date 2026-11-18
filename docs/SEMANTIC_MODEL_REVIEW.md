# Pretrained semantic baseline

Evaluated `protectai/deberta-v3-base-prompt-injection-v2` at pinned revision
`90c9989b1a342275dd0d1a95aad283c04e075671`, using its official ONNX export.
No local retraining was performed. The 738,563,188-byte model matches upstream
SHA-256 `f0ea7f239f765aedbde7c9e163a7cb38a79c5b8853d3f76db5152172047b228c`.

CPU evaluation uses 512-token windows with 64-token overlap and the maximum
injection probability across windows. No text is silently truncated. Prompts
above the deployed detector's 20,000-character limit are excluded. Fixed threshold
0.5; no external-test threshold tuning. Seed: 20261115. NotInject and the two
InjecAgent suites each sample 64 rows; PromptShield samples 64 per class.

Initial observations: 42/64 base attacks and 64/64 enhanced attacks were detected.
NotInject had 29/64 false positives (45.31%). Precision is not informative on
attack-only suites. These small samples are not sufficient to claim production
accuracy. Pretrained training-data overlap has not been excluded.

On the balanced 128-row PromptShield sample: accuracy 52.34%, precision 80.00%,
recall 6.25%, F1 11.59%, PR-AUC 0.7588, ROC-AUC 0.7678. Mean per-document
CPU latency was 918 ms (95th percentile 2,965 ms). This additional failure means
improved InjecAgent detection does not establish general superiority.

Decision: reject the unchanged baseline as a deployment candidate due to benign
false positives. Keep the verified checkpoint for semantic representation and
future development-set calibration experiments. The deployed detector is unchanged.

The upstream model card describes English injection detection, excludes jailbreak
and multilingual coverage, and warns of system-prompt false positives. This is
a text classifier, not a semantic comparison between a trusted task and untrusted
instructions. Source: https://huggingface.co/protectai/deberta-v3-base-prompt-injection-v2

Results and latency: `docs/semantic_evaluation.json`. Sample identities are stored
as text SHA-256 values. `complete: true` marks completion including comparison
against the previous candidate on identical samples.

Optional environment: `requirements-semantic.txt`. Reproduce with
`.venv/Scripts/python.exe scripts/evaluate_semantic.py --download`, then
`.venv/Scripts/python.exe scripts/evaluate_semantic.py`. Download range parts were
removed after the complete model passed checksum verification; the verified model
and source snapshots remain available.
