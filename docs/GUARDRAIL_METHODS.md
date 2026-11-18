# Adapting published guardrail methods

PromptShield trains neural detectors on a mixture of conversational and structured
application data, then measures true-positive rate at specified low false-positive
rates. Its paper recommends using validation data for threshold selection. The
paper's strongest model is a fine-tuned 8B Llama; a pretrained DeBERTa classifier
at its default threshold is not equivalent to that experiment.

Source: https://arxiv.org/html/2501.15145v2

PIGuard's MOF method identifies biased tokens, generates benign examples containing
those tokens, and retrains a neural classifier with the augmented dataset. Its
ablations also show that arbitrary augmentation alone can worsen overdefense.
NotInject is an evaluation set, not free additional training data if it is used to
claim independent performance.

Source: https://aclanthology.org/2025.acl-long.1468/

## Local experiment

`scripts/train_guardrail_head.py` implements a smaller adaptation:

1. Keep the pretrained ONNX semantic encoder and previous lexical model frozen.
2. Fit a regularized logistic head over their two log-odds scores, without source
   identifiers, length features, or hard-coded benign allowlists.
3. Add 64 authored benign examples containing attack-associated vocabulary.
   Hold out 32 examples from different task templates for calibration.
4. Include BIPIA clean/poisoned development contexts withheld from lexical
   training. Split by original context before creating poisoned variants.
5. Fit on 384 examples; calibrate thresholds on a separate 352 examples.
   The PromptShield portion comes from the original validation split, previously
   unseen during base-model fitting. No evaluation suite is added to fitting.
6. Report recall at empirical 5% and 1% calibration FPR, plus regressions on the
   exact prior sampled test prompts. Small benign denominators cannot establish
   dependable 0.1% or 0.05% deployment FPR.

This is score-level transfer learning. It is not full neural fine-tuning, an exact
MOF reproduction, or the PromptShield 8B model. The authored examples are narrow
dictionary/code/string tasks, so improvements on those examples do not establish
general benign robustness. The external suites are known regression sets; a new
untouched final benchmark is still needed before claiming deployment quality.

Results: `docs/guardrail_head_results.json`. Candidate artifact:
`models/candidates/guardrail_head_v1.joblib`. Source models and a separate inference
adapter would be required to use this artifact; it does not replace MLDetector's
existing pipeline format. The production artifact is not modified.

## Observed results

At the threshold selected for at most 1% empirical calibration FPR, development
accuracy was 80.11%, precision 99.07%, recall 60.80%, F1 75.35%, and FPR 0.57%
(1 false positive among 176 benign examples). At the 5% target, development recall
was 68.75% with 4.55% FPR. These estimates have substantial sampling uncertainty.

| Previously seen regression sample | Result at selected 1% calibration operating point |
|---|---|
| NotInject, 64 benign prompts | 1 false positive, 1.56% FPR |
| InjecAgent base, 64 attacks | 0% recall |
| InjecAgent enhanced, 64 attacks | 64.06% recall |
| Balanced PromptShield, 128 prompts | Accuracy 51.56%, precision 57.14%, recall 12.50%, F1 20.51%, FPR 9.38% |

Reject this head for deployment. It improves overdefense relative to the unchanged
semantic baseline while losing necessary attack detection. The calibration FPR
does not transfer reliably to external data. Frozen score combination is not an
adequate replacement for the end-to-end neural fine-tuning used by the papers.

The next justified architecture work is direct neural fine-tuning with audited
mixed-source training examples and benign counterexamples, followed by a fresh
source-separated final evaluation. Neither these results nor the cited papers
establish that the current project will achieve the published benchmark scores.
