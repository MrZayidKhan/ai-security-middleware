# Testing Plan

Latest verification (2026-11-13): 40 tests passed, source hashes and saved model test results reproduced, and dashboard interactions verified. See [implementation review](IMPLEMENTATION_REVIEW.md) for scope and remaining gaps. Earlier counts below are historical checkpoints.

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
