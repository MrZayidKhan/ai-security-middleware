# Readiness verdict

Horizon is usable for a controlled, non-autonomous review pilot. It is not ready
as a sole defense, an unattended blocking gate, or a guarantee that passing
content is safe. Start with shadow measurement on actual project traffic before
enforcing holds in a user-facing workflow. The default deployed detector was not
changed.

No neural weights were retrained. Improvements tested were longer context
coverage, validation-only threshold calibration, configuration validation, and
profile loading with pinned revision checks.

## Calibration experiment

Compared 512-token/64-overlap and 2,048-token/256-overlap configurations on 326
development examples: 256 PromptShield validation rows, 64 authored benign
counterexamples, and 6 long clean/poisoned controls. Threshold selection targeted
at most 1% empirical benign FPR. The 2,048-token configuration won development
selection at threshold 0.9830411672592164. Configuration and threshold were frozen
before regression/stress evaluation. PromptShield may overlap upstream training.

| Regression | Original 512-token / 0.5 | Selected 2,048-token / 0.98304 |
|---|---:|---:|
| NotInject false positives, 339 benign | 13 (3.83%) | 0 (0%) |
| InjecAgent base recall, 1,054 attacks | 77.23% | 33.49% |
| InjecAgent enhanced recall, 1,054 attacks | 100% | 100% |
| PromptShield sample accuracy, 128 | 80.47% | 71.09% |
| PromptShield sample attack F1 | 78.63% | 59.34% |

The stricter configuration misses 701 base attacks and was rejected for promotion.
Zero false positives in 339 prompts does not prove zero population FPR. Thresholds
are operating points, not calibrated certainty. PromptShield is a compatibility
check; base/enhanced cases are related rather than independent observations.

## New synthetic stress diagnostics

The 32-case suite includes code, JSON, ordinary human instructions, quoted
attacks, HTML, role spoofing, exfiltration, workflow hijacking, memory poisoning,
Base64, Hindi, Hinglish, French and Spanish. Cases were not used for fitting or
threshold selection. They are authored diagnostics, not a representative benchmark.

| Setting | Accuracy | Precision | Recall | F1 | Benign FPR |
|---|---:|---:|---:|---:|---:|
| Strict calibrated configuration | 84.38% | 92.31% | 75% | 82.76% | 6.25% |
| Original advisory configuration | 87.50% | 80% | 100% | 88.89% | 25% |

The advisory setting caught all 16 authored attacks but falsely flagged 4 of 16
benign prompts. This limits workload suitability and rules out an unattended
production-readiness claim. Rules plus Horizon gave the same aggregate result
in the local middleware dry run. No Qwen assessor, live tools, external messages,
or persisted review actions were involved.

## Available configuration and verification

`models/pretrained/horizon-small/advisory_profile.json` retains the original
tested setting: window 512, overlap 64, review threshold 0.5, high-risk threshold
0.9. `HorizonDetector.from_advisory_profile(model_directory)` loads it.
`calibration_candidate.json` preserves the rejected setting as diagnostic-only;
the advisory factory refuses diagnostic profiles or another model revision.

22 detector/content-inspector tests passed, including missing/corrupt artifacts,
invalid windows, incompatible profiles, oversized/empty inputs, and an attack in
a later token window. A real-model dry run verified profile loading and the
ContentInspector interface. The model supplies no removal spans or tool authority.

Results: `docs/horizon_readiness.json`. Reproduce with
`scripts/validate_horizon_readiness.py`, then `scripts/check_horizon_advisory.py`.
Next measure review burden and missed attacks on representative project documents
in shadow mode. Keep tool permissions and data-handling controls independent of
classifier output.
