# Indirect classifier iteration

Trained a word/character TF-IDF logistic regression candidate on 22,314 rows,
mixing cleaned direct prompts with paired clean/poisoned BIPIA contexts. Sources
were weighted equally. SPML was excluded after reviewing its author's training
recommendation. Raw downloads remain available for reproducibility.

The BIPIA release has 13 normalized context identities shared between original
train and test. All training contexts with those identities were removed before
generating attacks. Of the 986 remaining context rows, 806 were used for fitting
and 180 for validation. Four entire development attack families were held out.
The validation procedure selected threshold 0.54 under a 5% per-source FPR cap.

| Evaluation | Accuracy | Precision | Recall | F1 | FPR |
|---|---:|---:|---:|---:|---:|
| Direct validation (996) | 88.76% | 96.18% | 80.76% | 87.80% | 3.22% |
| Indirect validation (720) | 52.50% | 95.83% | 38.33% | 54.76% | 5.00% |
| Reconstructed BIPIA test (800) | 67.25% | 97.21% | 58.00% | 72.65% | 5.00% |
| PromptShield test (23,516) | 70.59% | 46.11% | 39.25% | 42.41% | 17.47% |

NotInject: 338/339 benign prompts passed (0.295% FPR). InjecAgent base:
33/1,054 attacks detected (3.13% recall). Enhanced: 942/1,054 detected
(89.37% recall), compared with 51.90% for the first candidate. Attack-only suites
cannot measure false positives, and their precision should not be interpreted as
general deployment precision.

Decision: reject this candidate for deployment. The base/enhanced gap indicates
remaining sensitivity to explicit attack wording. BIPIA supplies useful development
data, but this experiment does not establish broad attack coverage. The deployed
artifact and thresholds remain unchanged.

This is an experiment in indirect-content training, not a context-aware semantic
model. TF-IDF does not compare an untrusted instruction's purpose with the user's
trusted task. BIPIA construction uses start/end/character-middle placement, which
differs from official sentence-middle placement. Context/payload variants are
correlated; sample counts overstate the number of independent scenarios. Previously
seen external suites provide regression evidence; they are not fresh blind tests.
No demographic or multilingual fairness claim is supported.

Reproduction: `.venv/Scripts/python.exe scripts/train_indirect_candidate.py`.
Full metrics are in `docs/indirect_training_results.json`; artifact:
`models/candidates/indirect_v2.joblib`. The paired-data construction and source
context separation assertions passed; detector regression tests: 3 passed.

Next architecture experiment should use semantic representations and trusted task
context. Retire TF-IDF candidates from promotion consideration unless future
independent evidence resolves their indirect-attack weakness. Reserve new final
evaluation data before tuning that architecture.
