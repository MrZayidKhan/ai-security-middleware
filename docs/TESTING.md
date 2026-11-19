# Testing Plan

## Installed agent guard

The wheel and generated hook commands passed a Windows rules-mode smoke test. From a clean source snapshot, `python -m pytest tests/test_agent_hooks.py tests/test_middleware.py tests/test_middleware_policy.py -q` passed 18 tests. These checks cover command responses and middleware decisions. The [project scope](PROJECT_SCOPE.md) defines the remaining live-agent and platform acceptance tests.

Live local timing observation: one fresh Qwen assessment took 41,504 ms; an identical cached assessment on the same instance took 0.090 ms. A deterministic credential-exfiltration hold took 0.581 ms without inference. These are single observations, not throughput or percentile benchmarks. Cold/new content and answering-model generation remain expensive; cache benefits apply to exact repeats on a surviving instance.

Current performance/refactoring checkpoint: 94 tests pass. New checks cover cache expiry/capacity, independent return values, distinct content keys, uncached invalid output and no assessor invocation for deterministic holds. Older counts below identify earlier checkpoints. These are functional tests, not general detection accuracy measurements.

HTTP middleware verification: 86 tests passed in the verified execution environment. 16 API tests cover released/sanitized forwarding, attacks in all caller-controlled roles, unsupported fields/roles/models/streaming, size limits, browser-origin rejection, detector/storage/upstream failure, and concurrency. A real loopback HTTP request also returned an Ollama answer. The restricted runner stalled on HTTP tests; those runs were stopped and the suite rerun successfully outside that runner.

Explicit review-continuation verification: 70 tests pass. Added zero-call checks for pending/rejected review, current-policy rejection of a malicious task or approved excerpt, and approved-only forwarding with provenance. Recording-client tests verify enforcement; no fresh live Qwen continuation was run in this checkpoint.

Review-release verification: 65 tests pass. Added migration idempotence/content-preservation, label round-trip, approved-only excerpt release, rejected/missing/legacy-invalid refusal, and raw action-result suppression checks. Existing 62 tests remain passing.

Latest middleware-policy verification: 62 tests passed. Live local rules+ML+Qwen assessment returned PASS for an educational photosynthesis request (ML probability .409, Qwen benign), and HOLD for a credential-exfiltration instruction. This two-case check verifies the intended policy, not general detector accuracy. Qwen response time was approximately 44 seconds and 19 seconds respectively.

Protected-model checkpoint: 52 tests pass. Streamlit AppTest verified five tabs, zero answering-client calls for held context, and one call for released context using a patched client. See [manual test guide](MANUAL_TESTING.md) for current acceptance cases. These checks verify forwarding enforcement, not detection accuracy.

Latest verification (2026-11-15): 46 tests passed, source hashes and saved model test results reproduced, model-boundary blocking verified, and dashboard rules-only interaction verified without exceptions. See [implementation review](IMPLEMENTATION_REVIEW.md) for scope and remaining gaps. Earlier counts below are historical checkpoints.

## Status

The current suite has 27 automated tests and four verified local demonstrations. The hybrid assessor, audit store, and dashboard smoke path have also been checked. End-to-end model-to-gateway tests, broad accuracy evaluation, and complete human-review interaction coverage remain pending.

## Verified Milestone 2 results

On 2026-11-08, `pytest -q` completed with **4 passed**. The tests cover the normal tool-result path, tool-round limit, malformed model message, and invalid limit configuration.

The local demonstration also completed with one `get_project_status` proposal and a final model response. It did not access files, databases, or external network resources.

## Verified Milestone 3 results

On 2026-11-08, `pytest -q --basetemp .pytest-tmp` completed with **9 passed**. The new tests cover approved document search/read, unknown document rejection, fixed SQLite lookup, local outbox storage, and unapproved-recipient rejection.

The local controlled-tools demonstration searched and read the synthetic documents, returned record 1 from SQLite, and stored one `DRAFT` in the local outbox. No message was sent.

## Verified Milestone 4 results

On 2026-11-08, `pytest -q --basetemp .pytest-tmp` completed with **14 passed**. The new tests cover allowed execution, unknown tools, malformed/extra arguments, out-of-scope document and recipient requests, and repeated-call limits.

The gateway demonstration allowed an approved document read and blocked an out-of-scope recipient before any outbox write.

## Verified Milestone 5 results

On 2026-11-08, `pytest -q --basetemp .pytest-tmp` completed with **21 passed**. The new tests cover benign content, targeted sanitization, high-risk hold decisions, review approval requirements, and the secure retrieval path.

The secure retrieval demonstration returned `PASS` for benign content, `SANITIZE` for an override instruction, and `HOLD_FOR_REVIEW` for a sensitive-data directive.

## Method

Tests should verify both outcomes and enforcement boundaries: valid calls execute only through approved functions; denied/invalid proposals do not execute; audit entries describe decisions and actual outcomes. Keep fixtures local and deterministic. Include benign text that resembles an attack to measure false positives. Do not use external services or download datasets without approval.

## Test categories and cases

| Category | Cases | Expected outcome |
|---|---|---|
| Schema/parser | Valid, malformed, missing fields, wrong types, oversized arguments | Valid structure accepted; invalid rejected before execution |
| Allowlist/policy | Known allowed tool, unknown tool, prohibited action | Correct ALLOW/BLOCK; unknown/prohibited never dispatched |
| Filesystem | Approved document ID, invalid ID, traversal, missing file, symlink escape if applicable | Only approved resource readable |
| Database | Valid fixed query, bad ID/type, injection-like value | Parameterized function returns scoped records or safe denial |
| Outbox | Approved draft, unauthorized destination, oversized message | Only allowed draft stored locally; no real send |
| Content | Injection examples, benign similar phrases, source/sensitivity metadata | Decision and rationale recorded; labels preserved |
| Sanitization/review | Clear span, ambiguous span, reviewer reject, excerpt approval | Clear span isolated; ambiguous held; decision scoped and recorded |
| Limits/failures | Call cap, repeated call cap, timeout, tool exception, storage failure | Bounded operation; fail closed where required; accurate audit |
| Integration | Full proposed call and content-return path | No bypass path; result and audit outcome agree |

## Evaluation comparisons

When the system exists, compare the same task corpus across baseline agent, sanitization-only, and full middleware configurations. Measure unsafe tool executions, benign task success, false positives, false negatives where labels permit, review burden, and latency. Report corpus, configuration, counts, and limitations. Do not fabricate results or claim a complete AgentDojo/InjecAgent evaluation from a subset.

## Current command

Run `python -m pytest -q` from the activated project environment. Use `--basetemp .pytest-tmp` if the default Windows temporary directory is unavailable.

## Hybrid inspection and UI checks

The local model assessor was verified on a synthetic injection and returned `high_risk` with exact suspicious spans. The automated suite covers local-model signal handling with a fake assessor, Unicode obfuscation, encoded payloads, blank input, and local audit storage. The dashboard module compiles and imports; run it through Streamlit for interactive use.

On 2026-11-12, 27 tests passed. Streamlit AppTest rendered all four tabs without exceptions and verified blank-input handling through the Analyze text button. The local Streamlit server started successfully on 127.0.0.1:8501. Broad accuracy, evasion resistance, and complete human-review UI coverage remain unverified.
# ML detector development checkpoint (2026-11-13)

The local TF-IDF/Logistic Regression baseline now trains from pinned deepset data and saves an ignored local model artifact. Analyze text offers detector configuration selection and classifier probability/duration output. Required ML failure or uncertainty holds content; classification does not grant action permissions. Current verification: 30 tests pass, dependency consistency passes, and held-out binary precision/recall/F1 are 0.8824/0.7692/0.8219. These do not measure final pipeline effectiveness. See [ML training guide](ML_TRAINING.md) for commands, licensing, measured results, provisional thresholds and unfinished work. The prompt-injection module remains in development.
