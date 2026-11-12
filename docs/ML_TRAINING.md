# Local classifier training

Latest review: [implementation review](IMPLEMENTATION_REVIEW.md). The expanded regression suite has 40 tests. Dataset hashes are now enforced before training; model cache reloads when the artifact changes. Evaluation refuses metrics on required-detector failure and writes `docs/detector_comparison_latest.json` by default; the earlier full comparison is historical evidence.

## Current status

Implementation checkpoint, not completion: the classifier trained and produced measured held-out results. The original 27 tests passed before changes; the expanded suite currently has 30 passing tests. Full comparison, broader evaluation and hardening remain open.

Measured binary test results on 99 examples: injection precision 0.8824, recall 0.7692, F1 0.8219, false-positive rate 0.0667. Confusion matrix (benign/injection row and column order): [[56,4],[9,30]]. Training used 464 examples, validation 99, test 99; 74 near-duplicate pairs were grouped. Fit time was 0.031 seconds, test batch prediction averaged 0.039 milliseconds per example, and artifact size is 359,813 bytes. Batch timing excludes startup, loading, normalization and UI work. See `ml_training_results.json` for the full measured report.

## Dataset audit

| Candidate | Labels and use | License and selection |
|---|---|---|
| [PromptShield v2](https://data.mendeley.com/datasets/n6wdvz5n3d/2) | Describes benign/suspicious/malicious, annotator votes and attack types; metadata page currently exposes no files. Contents and duplicates cannot yet be verified. | Metadata lists CC BY 4.0; deferred until files are available. |
| [Radda v2](https://huggingface.co/datasets/Radda/prompt-injection-dataset-v2) | Binary text/label examples; synthetic-looking paraphrases and obfuscations; public viewer reports a schema mismatch involving statistics files. Duplicate/leakage audit remains pending. | No clear dataset license established in reviewed card; deferred. |
| [deepset](https://huggingface.co/datasets/deepset/prompt-injections) | Binary `text`, `label`; 0 benign, 1 injection. Training file inspected: 546 examples, 343 benign, 203 injection. Primarily direct prompts with role-play and override examples; includes ambiguous labels and benign topic/style differences. | Apache-2.0; selected as a small reproducible baseline. Not sufficient evidence of generalization to indirect attacks. |
| [Microsoft BIPIA](https://github.com/microsoft/BIPIA) | Indirect attacks paired with external contexts across email, web, table, summarization and code tasks. Evaluation resource, not a ready-made binary training set. Actual context/template duplicate analysis remains pending. | Repository MIT; source datasets have separate MIT/CC BY-SA and other source-specific terms. Do not infer all data is MIT. |

No candidates are blindly combined. Source pages and dataset-specific terms govern use. Downloads and artifacts stay in ignored local directories. Dataset attribution does not imply project authorship.

## Commands

From the repository root in PowerShell:

```powershell
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe -m scripts.train_classifier
.\.venv\Scripts\python.exe -m scripts.evaluate_detectors
.\.venv\Scripts\python.exe -m scripts.evaluate_detectors --qwen
.\.venv\Scripts\python.exe -m pytest -q --basetemp .pytest-tmp
.\.venv\Scripts\python.exe -m streamlit run app.py --server.address 127.0.0.1
```

Training downloads two pinned deepset Parquet files into `data/raw`, records SHA-256 values, removes normalized exact duplicates, discards conflicting duplicate labels, and groups character-ngram cosine neighbors at similarity >=0.8 before seed-42 train/holdout splitting and seed-43 validation/test splitting. Connected near-duplicate groups remain in one split. This recombines upstream splits: the reported test is a project group split, not the official benchmark test. Same-template leakage below that threshold can remain. Vectorizer learning uses training rows only; similarity grouping uses unlabeled corpus text solely for split construction.

The pipeline uses word TF-IDF unigrams/bigrams, sublinear TF, up to 30,000 features, and balanced Logistic Regression with C=1, max_iter=1000 and seed=42. Training writes split provenance to `data/processed/splits.json`, the trusted local artifact to `models/prompt_classifier.joblib`, and measured reports to `docs/ml_training_results.json` when successful. Rerunning retrains the model; restart Streamlit to reload its cached instance.

The trained target is binary. Injection probability >=0.7 yields high risk; [0.3,0.7) yields suspicious; below 0.3 yields benign. These are provisional fixed thresholds, not a learned suspicious class or calibrated safety confidence. The training report uses the classifier's binary decision boundary; policy-level metrics require separate evaluation. Long inputs use 2,000-character chunks with 200-character overlap and maximum injection probability. No fabricated spans are produced.

## Policy and deployment limitations

Measured exploratory comparison on 10 independent synthetic carriers (5 benign/5 injection):

| Configuration | Precision | Recall | F1 | False-positive rate | Mean milliseconds |
|---|---:|---:|---:|---:|---:|
| Rules | .667 | .400 | .500 | .200 | .014 |
| Rules + Qwen | .833 | 1.000 | .909 | .200 | 13909 |
| Rules + ML | .500 | 1.000 | .667 | 1.000 | .720 |
| Rules + ML + Qwen | .500 | 1.000 | .667 | 1.000 | 12621 |

Any non-PASS counts as detected; these metrics do not certify safe sanitization. Small-set timing includes synchronous inspection and model runtime; run order, model warming and CPU scheduling affect the figures. The current ML uncertainty band holds every independent example, so the apparent perfect recall is operationally unhelpful. Qwen remains the default while threshold selection, better training coverage and broader testing proceed. Qwen has useful recall in this small experiment, but it is slow and its output is manipulable. Full per-case reasons and carrier categories are in `detector_comparison.json`; no memory benchmark was collected. These ten examples must remain excluded from training and cannot support general benchmark claims.

The dashboard loads the classifier once. Joblib may execute Python while loading; load only artifacts trained locally from trusted code. Missing, malformed or incompatible artifacts yield unavailable. Any configured ML result other than benign requires HOLD, with no released content. Rules/Qwen retain their existing decisions when ML is benign. Sanitized remainder receives an additional ML check. Original content stays in the caller's envelope and held review item. Source trust and sensitivity remain separate fields.

The current detector wrapper runs ML after the existing inspection path, rather than implementing the final planned execution order. Rules and Qwen still use their existing interfaces; migration to one common detector protocol remains pending. Qwen comparison, independent indirect evaluation, calibrated thresholds, detailed resource profiling, review hardening, and full detector failure tests remain outstanding. PASS is advisory and sanitization preserves untrusted status. Classifiers never grant action permissions.
