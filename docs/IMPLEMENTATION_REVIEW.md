# Implementation review — 2026-11-13

## Verification

Baseline: 30 passing tests. After fixes: 40 passing tests. Dependency consistency passed. Both downloaded sources match recorded SHA-256 hashes. Saved splits contain 464/99/99 examples with no exact-text or recorded duplicate-group overlap. Reloaded model reproduces test confusion matrix [[56,4],[9,30]]. This does not rule out undetected semantic/template overlap.

Rules and rules+ML were rerun on ten synthetic carriers: rules recall .4, false-positive rate .2; rules+ML recall 1.0, false-positive rate 1.0. Holding everything is not effective detection. Earlier binary classifier precision/recall/F1 (.8824/.7692/.8219) describe a different decision boundary from the deployed policy.

Streamlit AppTest verified four tabs, benign rules PASS, result persistence on rerun, stale-result clearing after a mode change, and real ML HOLD without exceptions. This is interaction testing, not browser visual inspection. Full Qwen comparison and memory benchmarking were not rerun in this review.

## Fixes

- Revalidate normalized input for blankness and size expansion.
- Merge original offsets when removing repeated/overlapping model spans; reject whitespace-only spans.
- Recheck sanitized remainder for recognized rule/encoded attacks; hold if unresolved.
- Hold on detector exceptions or malformed output; preserve the original high-risk reason alongside ML uncertainty.
- Distinguish inference failure from missing artifact errors.
- Enforce expected dataset hashes, including cached training inputs.
- Refuse effectiveness metrics when a required detector is unavailable. New comparisons write a separate latest report, preserving the earlier complete comparison.
- Reload cached classifier when artifact timestamp/size changes; preserve UI results across reruns, show progress, and record selected configuration/duration.

## Recommended priorities

1. **Dataset coverage and threshold selection.** Add independently labeled indirect attacks and realistic benign negatives from appropriately licensed sources. Select thresholds on validation data against explicit false-positive/missed-attack targets, then evaluate untouched test data. Do not tune on the ten examples already used during development. See [scikit-learn threshold guidance](https://scikit-learn.org/stable/modules/classification_threshold.html).
2. **Deployment-matched evaluation.** Compare actual chunked three-band decisions, review burden, benign pass rate, sanitization correctness, family-level recall and cold/warm p50/p95 latency. Current training metrics use whole-text binary predictions. Preserve source/template groups and record artifact/runtime versions. Ten examples cannot establish general accuracy.
3. **Common detector interface.** Rules, Qwen and ML still expose different interfaces. Standardize identity/version/status/timing/evidence and explicit unavailable states. Run cheap checks before expensive inference. Qwen currently receives classifier instructions and untrusted content together in one user message; investigate system-role separation and constrained structured output with adversarial tests.
4. **Content boundaries and provenance.** HOLD clears `content_for_model`, but `SecureRetrievalResult.action.result` retains original raw text. Define an explicit released-content object before future integration. Review storage currently drops origin-trust/sensitivity fields; add a compatible migration and persist these labels with inspection versions.
5. **Gateway hardening in its own milestone.** Search traverses the fixed corpus even when custom gateway policy narrows allowed document IDs. Enforce the subset during search. Bound file reads, retention, concurrency, execution time and total tool calls. The demonstration loop bounds rounds rather than total calls; fresh UI task IDs also mean counters are not per-user rate limits. These architecture changes were reviewed, not implemented here.
6. **Reproducibility and documentation.** Consolidate historical completion claims into a current feature matrix. Pin a tested environment and artifact/runtime schema. Unify training and inference normalization. Keep suspicious explicitly documented as a policy band over a binary model.

Keep Qwen available: earlier small-set evidence favors its recall over rules alone, but at substantial latency. The current evidence does not justify replacing it with the baseline classifier. The prompt-injection module remains in development.
