# Candidate classifier review

Two CPU classifiers were trained on 19,090 cleaned PromptShield/deepset examples:
word TF-IDF logistic regression and word plus character TF-IDF logistic regression.
The 996-example validation set selected thresholds with a false-positive target of
at most 2%. A conservative normalized-template filter removed 365 training and
4 validation rows (duplicates, conflicts, or overlaps with reserved suites).
An independent assertion verified disjoint normalized-template identities across
training, validation and external evaluation. Semantic near-duplicate separation
has not yet been established.

| Candidate | Validation accuracy | Precision | Recall | F1 | FPR |
|---|---:|---:|---:|---:|---:|
| Word, threshold 0.65 | 89.26% | 97.80% | 80.36% | 88.23% | 1.81% |
| Word + character, threshold 0.69 | 89.86% | 98.07% | 81.36% | 88.94% | 1.61% |

Validation chose word + character. Its external results prevent promotion:

| Evaluation | Count | Result |
|---|---:|---|
| PromptShield original test | 23,516 | Accuracy 71.93%; precision 47.66%; recall 18.09%; F1 26.22%; PR-AUC 0.4694; FPR 7.56% |
| deepset original test | 116 | Accuracy 57.76%; precision 100%; recall 18.33%; F1 30.99% |
| NotInject benign controls | 339 | 0 false positives |
| InjecAgent base attacks | 1,054 | 0% recall |
| InjecAgent enhanced attacks | 1,054 | 51.90% recall |
| BIPIA clean contexts | 200 | 0 false positives |
| SPML user-only diagnostic | 16,011 | 2.47% attack recall; omits required system context |

Precision/F1 on benign-only suites are not meaningful; attack-only suites cannot
establish a benign false-positive rate. Base/enhanced InjecAgent cases are related.
Evaluations score the maximum over overlapping 2,000-character chunks. The harness
also scores documents beyond the deployed detector's 20,000-character limit, so
these are classifier measurements, not complete middleware behavior measurements.
Training metrics score full text; train/validation gaps are therefore not directly
comparable as an overfitting measurement.

Assessment: the validation operating point does not generalize across datasets.
The classifier suppresses benign false alarms but misses unacceptable numbers of
attacks. The deployment artifact and runtime thresholds were left unchanged.
There is no evidence here of a dependable improvement in attack detection.

Next development should include context-aware training, varied indirect attacks,
and source/family-separated development validation. These external results are
now known; future iterations need a fresh untouched final holdout to avoid tuning
to this benchmark. Existing original tests remain excluded from training.

Reproduce: `.venv/Scripts/python.exe scripts/train_candidates.py`. Artifacts are
under `models/candidates/`; all metrics and data fingerprint are recorded in
`docs/candidate_training_results.json`. Detector regression tests: 3 passed.
