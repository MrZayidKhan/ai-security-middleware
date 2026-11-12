# Implementation Roadmap

## Current position

Milestones 0 through 5 are implemented at their documented scope. The current checkpoint adds hybrid prompt inspection, concise local security events, and a working Streamlit dashboard. The next major gap is connecting model proposals to the gateway in one end-to-end path, followed by API and evaluation work.

## Delivery sequence

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

## How a feature is added

Each feature starts with a small contract: inputs, outputs, allowed resources, limits, and rejected cases. Implement the smallest useful version, add focused tests, then connect it to the next layer. The tracker records the result before work moves forward.

The immediate next milestone is end-to-end integration: route model proposals through validation, the action gateway, controlled execution, content inspection, and accurate audit records. The current local model is available and the dashboard already exercises protected text and retrieval paths.
# ML detector development checkpoint (2026-11-13)

The local TF-IDF/Logistic Regression baseline now trains from pinned deepset data and saves an ignored local model artifact. Analyze text offers detector configuration selection and classifier probability/duration output. Required ML failure or uncertainty holds content; classification does not grant action permissions. Current verification: 30 tests pass, dependency consistency passes, and held-out binary precision/recall/F1 are 0.8824/0.7692/0.8219. These do not measure final pipeline effectiveness. See [ML training guide](ML_TRAINING.md) for commands, licensing, measured results, provisional thresholds and unfinished work. The prompt-injection module remains in development.
