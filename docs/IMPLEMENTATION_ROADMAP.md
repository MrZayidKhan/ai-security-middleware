# Implementation Roadmap

## Current position

Milestone 0 is in review. The repository has planning documentation only. No runtime code or dependencies have been added.

## Delivery sequence

| Milestone | Deliverable | Depends on | Completion evidence |
|---|---|---|---|
| 1 | Local Python environment and Ollama connection | Milestone 0 approval | A real local model response and recorded setup steps |
| 2 | Small model loop with one harmless tool | Milestone 1 | A bounded loop handles a proposal and a tool result |
| 3 | Approved document, database, and outbox tools | Milestone 2 | Each tool performs a real local action through a narrow interface |
| 4 | Action security gateway | Milestone 3 | Invalid, unknown, and unauthorized requests are blocked before execution |
| 5 | Content inspection, sanitization, and review queue | Milestone 4 | Content decisions preserve source metadata and review behavior is tested |
| 6 | End-to-end integration and audit records | Milestones 2–5 | A complete request has matching decision and execution records |
| 7 | FastAPI service and Streamlit dashboard | Milestone 6 | The interface shows actual stored data |
| 8 | Evaluation corpus and comparison | Milestone 6 | Reproducible measurements for baseline, sanitization-only, and full middleware |
| 9 | Optional benchmark subset | Milestone 8 | Scope, method, and results are documented |
| 10 | Final verification and demonstration | Milestone 8 | Fresh setup and repeatable demonstration succeed |

## How a feature is added

Each feature starts with a small contract: inputs, outputs, allowed resources, limits, and rejected cases. Implement the smallest useful version, add focused tests, then connect it to the next layer. The tracker records the result before work moves forward.

The immediate next milestone is environment verification. It will determine compatible package versions and whether the local model can run acceptably on the available machine.
