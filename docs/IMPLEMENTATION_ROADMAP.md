# Implementation Roadmap

## Current position

The Windows x64 bundle contains local Rules + Horizon screening, native
workspace hooks, protected ACP editor chat, a one-shot CLI launcher, the
sanitizer API, Rust review dashboard, and uninstall. ACP setup needs no
workspace path. The editor supplies the workspace at runtime.

| Phase | Status and acceptance |
| --- | --- |
| Offline inspection and packaging | Implemented and locally verified: detector and model files load from an extracted Windows bundle, and ACP setup registers no workspace hooks. |
| Persistent protected editor chat | Implemented and tested through the Windows stdio bridge with real Horizon and a simulated ACP agent. Accepted and sanitized prompts retain their original session ID. |
| Dashboard-reviewed release | Implemented and tested in the adapter. Edited drafts are rechecked before forwarding. Canceled, expired, and still-flagged drafts cannot be sent. |
| Protected Send for Antigravity | Windows x64 GUI installer and bundled sanitizer verified locally. Live overlay and native-composer interception and delivery still need acceptance testing. |
| Live Antigravity and Codex ACP acceptance | Pending. Verify sign-in, pass, clean-and-send, hold, review, cancel, and follow-up in a live editor thread for each agent. |
| Tool-call authorization | Next implementation phase. Add pre-execution enforcement only where the integration exposes a supported permission or tool boundary. Measure it separately from prompt classification. |
| Additional coverage and validation | Pending. Expand indirect-content checks and audit retention controls. Evaluate fresh independent English data, then revisit other OS and language targets. |

The [project tracker](PROJECT_TRACKER.md) records current evidence. The
[saved regression report](offline_detector_evaluation.json) reports 84.32%
accuracy and 95.50% precision for Rules + Horizon. The 90% overall accuracy
goal remains open.

## Historical delivery sequence

The following milestones document the earlier local prototype and native hook
work. The current Windows release and remaining work are described above.

| Milestone | Deliverable | Depends on | Completion evidence |
|---|---|---|---|
| 1 | Local Python environment and Ollama connection | Milestone 0 approval | A real local model response and recorded setup steps |
| 2 | Small model loop with one harmless tool | Milestone 1 | A bounded loop handles a proposal and a tool result |
| 3 | Approved document, database, and outbox tools | Milestone 2 | Each tool performs a real local action through a narrow interface |
| 4 | Action security gateway | Milestone 3 | Invalid, unknown, and unauthorized requests are blocked before execution |
| 5 | Content inspection, sanitization, and review queue | Milestone 4 | Content decisions preserve source metadata and review behavior is tested |
| 6 | End-to-end integration and audit records | Milestones 2–5 | A complete request has matching decision and execution records |
| 7 | FastAPI service and dashboard hardening | Milestone 6 | API and interface show actual stored data without bypass |
| 8 | Evaluation corpus and comparison | Milestone 6 | Reproducible measurements for baseline, sanitization-only, and full middleware |
| 9 | Optional benchmark subset | Milestone 8 | Scope, method, and results are documented |
| 10 | Final verification and demonstration | Milestone 8 | Fresh setup and repeatable demonstration succeed |
| 11 | Installable agent guard and live validation | Reusable inspector and host hooks | Windows install, live prompt blocking in both agents, and supported Codex tool-result withholding |

## How a feature is added

Each feature starts with a small contract: inputs, outputs, allowed resources, limits, and rejected cases. Implement the smallest useful version, add focused tests, then connect it to the next layer. The tracker records the result before work moves forward.

For the local application, full model-to-controlled-tool routing and comprehensive auditing remain separate milestones. For installed agents, run the acceptance checks in [Project Objectives and Scope](PROJECT_SCOPE.md) and record differences across host versions or platforms.
# ML detector development checkpoint (2026-11-13)

The local TF-IDF/Logistic Regression baseline now trains from pinned deepset data and saves an ignored local model artifact. Analyze text offers detector configuration selection and classifier probability/duration output. Required ML failure or uncertainty holds content; classification does not grant action permissions. Current verification: 30 tests pass, dependency consistency passes, and held-out binary precision/recall/F1 are 0.8824/0.7692/0.8219. These do not measure final pipeline effectiveness. See [ML training guide](ML_TRAINING.md) for commands, licensing, measured results, provisional thresholds and unfinished work. The prompt-injection module remains in development.
