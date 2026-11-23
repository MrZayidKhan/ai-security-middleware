# Prompt injection classifier evaluation

## Current Windows detector

The offline bundle uses pretrained Horizon Small plus deterministic rules.
The [saved English regression report](offline_detector_evaluation.json) scored
1,811 examples after removing 22 repeats: 240 Horizon boundary pairs, 339
NotInject prompts, 1,054 InjecAgent base cases and 178 BIPIA clean contexts.

| Backend | Accuracy | Precision | Recall | F1 |
| --- | ---: | ---: | ---: | ---: |
| Rules only | 36.33% | 81.82% | 2.30% | 4.47% |
| Rules + Horizon | 84.32% | 95.50% | 79.56% | 86.80% |

Holds and sanitizations count as detections. There were no combined
sanitizations in that report. Separate fixtures demonstrate redaction.
The 90% overall accuracy target is open. Upstream training overlap is
unknown, and the benign and positive indirect samples come from different
sources. Reproduction commands are in the [project README](../README.md).

## Earlier classifier and verifier experiments

An earlier demo used the pretrained Qwen 3.5 4B English verifier. Its weights were
**not trained or fine-tuned in this project**. The project developed the
classification policy and structured verdict format. Qwen's upstream training
corpus is outside the scope of this audit.

## Project training history

| Model | Project training data | Status |
|---|---|---|
| Word and character TF-IDF with logistic regression | 19,090 retained examples from the published training splits of hendzh/PromptShield and deepset/prompt-injections. Another 996 retained PromptShield validation examples were used for model and threshold selection. | Rejected candidate |
| Original word TF-IDF with logistic regression | deepset/prompt-injections, 662 rows. The project grouped near duplicates and split them into 464 training, 99 validation, and 99 test rows. | Historical baseline |
| Indirect TF-IDF | 22,314 combined direct and BIPIA-based indirect training examples. BIPIA contexts were grouped before variants were generated. | Rejected candidate |

The Hugging Face PromptShield binary dataset is distinct from the locally
supplied three-class Mendeley dataset. SPML labels depend on the original
system context and are excluded from the main evaluation. The
[direct candidate report](candidate_training_results.json),
[original baseline report](ml_training_results.json), and
[indirect candidate report](indirect_training_results.json) preserve training details.

## Full-split results for the trained word and character classifier

The frozen classifier at threshold 0.69 was evaluated on **all 26,317 eligible
rows out of 26,519 available** in nine suites. Injection is the positive class.

| Dataset | Scored | Accuracy | Precision | Recall | F1 | Benign flagged |
|---|---:|---:|---:|---:|---:|---:|
| PromptShield test | 23,314 | 71.9% | 48.9% | 18.1% | 26.4% | 1,228 / 16,828 |
| deepset test | 116 | 57.8% | 100% | 18.3% | 31.0% | 0 / 56 |
| Horizon English boundary pairs | 240 | 50.0% | Undefined | 0.0% | 0.0% | 0 / 120 |
| NotInject | 339 | — | — | — | — | 0 / 339 |
| InjecAgent base | 1,054 | — | — | 0.0% | — | — |
| InjecAgent enhanced | 1,054 | — | — | 51.9% | — | — |
| BIPIA clean tables | 100 | — | — | — | — | 0 / 100 |
| BIPIA clean code | 50 | — | — | — | — | 0 / 50 |
| BIPIA clean emails | 50 | — | — | — | — | 0 / 50 |

Single-class suites measure either attack recall or benign false-positive
rate. Precision is undefined on Horizon because there were zero flags.
This classifier scored 89.9% accuracy, 98.1% precision, 81.4% recall, and
88.9% F1 during validation. It then missed 5,313 PromptShield injections
and all 1,054 base InjecAgent cases. The large change across sources is why
it was rejected. The [full-split JSON](full_corpora_word_char.json) preserves
the artifact hash, source revisions and hashes, confusion matrices, exclusions,
category metrics, and row-level uncertainty intervals.

## Historical Qwen verifier

| Completed check | Cases | Accuracy | Precision | Recall | F1 |
|---|---:|---:|---:|---:|---:|
| [Horizon direct boundary-pair sample](verified_boundary_holdout.json) | 48 | 95.8% | 95.8% | 95.8% | 95.8% |
| [Four-source direct and indirect sample](english_variety_evaluation.json) | 48 | 93.8% | 92.0% | 95.8% | 93.9% |
| [Project-authored diagnostic fixtures](english_example_results.json) | 24 | 100% | 100% | 100% | 100% |

The four-source run caught 23 of 24 injections and flagged two of 24 benign
prompts. The missed case was indirect. The [full-split verifier JSON](full_corpora_verifier.json)
is a partial checkpoint. At roughly 6–10 seconds per case, 26,317 serial inferences take
an estimated 44–73 hours before allowing for longer contexts or downtime.

## How the data was audited

- Inputs are checked against pinned SHA-256 hashes. Training and validation
  splits are used to identify overlaps and are excluded from test metrics.
- The runner removes normalized duplicates within each suite, conflicting
  label groups, groups matching direct development examples, and rows
  outside the verifier input limits. PromptShield accounted for all 202
  exclusions: 190 duplicate rows, 10 development overlaps, and two
  out-of-bounds inputs. Paraphrases can escape the normalization heuristic.
- The runner counts the alternate layouts of NotInject once. InjecAgent
  base and enhanced variants share scenarios and are reported separately.
  BIPIA covers all locally available clean test contexts with their questions
  or code errors. It does not include BIPIA attack variants or unavailable tasks.
- The verifier receives the original user task separately for retrieved text.
  The TF-IDF candidate uses text only. Uncertain verifier verdicts count as
  flags. Unavailable verdicts pause the full run and retry on resume.
- Per-source and per-category results expose blind spots, but cannot prove
  absence of bias or unknown upstream training overlap. The public suites may
  contain related examples or differing label definitions. Row-level intervals
  do not account for correlations from shared templates. The report makes
  no multilingual or real-world prevalence claim.

## Reproduce

From the repository root, run either backend using the project environment:

    .\.venv\Scripts\python.exe -m scripts.evaluate_full_corpora word_char
    .\.venv\Scripts\python.exe -m scripts.evaluate_full_corpora verifier

The verifier needs Ollama on port 11434 with qwen3.5:4b installed. It resumes
from hashed prediction records in runtime_data when the model digest, policy,
and test identities match. Use --max-new N for a bounded batch. Evaluation
runs the classifiers only, without an answering model or agent tools.
