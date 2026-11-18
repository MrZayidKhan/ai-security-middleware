# English verifier: tested scope and results

The opt-in English backend passes the current controlled-test acceptance gates.
It is suitable for an English application-integration pilot with review and
independent tool authorization. It is not proof of universal detection or a
standalone production security boundary. No multilingual readiness is claimed.
The existing backend remains the default; select the new backend explicitly.

## What changed

- Direct user requests and retrieved/tool data have separate host-supplied
  channels. Retrieved text cannot supply or replace its own trusted task.
- The local Qwen model describes the text's purpose before producing a bounded
  verdict. There are no phrase-specific benign allowlists or test-label rules.
- Policy is a system message; candidate content is JSON-encoded data in a separate
  user message. No classifier tools are available. Invalid output, timeouts,
  unsupported context and missing retrieved-task metadata produce unavailable
  evidence, which the middleware withholds.
- The application client sends only the supported gateway fields and never
  falls back to direct Ollama calls after a hold or outage.
- Existing deterministic checks, audit-before-forwarding and independent action
  permissions remain in place. The dashboard is unnecessary for HTTP operation.

The neural weights were not retrained. This iteration improves the classification
contract, semantic policy, integration and verification.

## Measured results

| Check | Count | Accuracy | Precision | Recall | F1 |
|---|---:|---:|---:|---:|---:|
| Authored English direct/indirect examples and benign controls | 24 | 100% | 100% | 100% | 100% |
| Separately sourced English boundary-pair holdout | 48 | 95.83% | 95.83% | 95.83% | 95.83% |

The holdout confusion matrix is `[[23,1],[1,23]]` in benign/injection order: one
false positive and one missed attack. FPR: 4.17%. No unavailable verdicts. P95
latency: 19.37 seconds on the tested machine. The frozen gates were recall at
least 90%, FPR at most 5%, no unavailable verdicts and p95 below 30 seconds.
Those point estimates passed; small sample sizes still imply substantial uncertainty.

The 48 holdout texts were not inspected while designing this policy. The source
is Horizon's boundary-pair evaluation set, pinned in its local manifest. Unknown
upstream training overlap cannot be ruled out. The 24 authored examples are
diagnostic fixtures. Do not combine these into a claimed real-world accuracy.

Both runs used the same policy SHA-256:
`b881eed59d4ba589cf5a0dd4c4c4fea3e24ea844f6361f6eb68a6d4363174c4b`.
Ollama model: `qwen3.5:4b`, observed digest:
`d8b0f5e9760cd1682034f292d7ef72ec46f432149be0df7574bf2d6e92e38c04`.
Changing model weights or policy requires reevaluation.

## Application and software verification

123 software tests passed. Live loopback checks against the opt-in HTTP backend:

- Direct injection: HTTP 403, no answering-model forwarding event.
- Indirect injection: HTTP 403, no answering-model forwarding event.
- Harmless English request: HTTP 200, recorded forwarding and successful outcome.

These checks logged only synthetic activity. No tools were executed. The 24-case
file tests the classifier separately; the live HTTP test covers three cases, not
all possible interactions with deterministic sanitization/hold rules. A benign
classifier score never cancels an independent hard hold or authorizes an action.

Earlier failed Horizon calibration and mixed-language verifier experiments are
retained as research history, not promoted readiness evidence. In particular,
raising the Horizon threshold was rejected because it lost attack recall.

## Use and reproduce

See `docs/APPLICATION_CONNECTION_ENGLISH.md`. Start the selected backend with:

```powershell
.\.venv\Scripts\python.exe -m scripts.run_middleware --detector english-verifier
```

Machine-readable evidence:

- `docs/english_example_results.json`
- `docs/verified_boundary_holdout.json`
- `docs/english_gateway_smoke.json`

Example inputs: `sample_data/english_injection_examples.json`.
Use `MiddlewareChatClient` for supported tool-free answering requests. Keep the
classifier's own connection on Ollama port 11434 to avoid recursion. Review false
positives and measure representative project traffic before wider rollout.
