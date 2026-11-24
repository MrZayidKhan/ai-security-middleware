# Project Tracker

## Current progress

| Workstream | State | Evidence |
| --- | --- | --- |
| Offline Rules + Horizon | Implemented and measured | [Saved report](offline_detector_evaluation.json): 1,811 English cases, 84.32% accuracy, 95.50% precision, 79.56% recall, 86.80% F1. |
| ACP chat | Implemented and locally tested | Original session ID retained on pass, sanitize, and reviewed release. Windows stdio bridge exercised real Horizon with a simulated agent. |
| Rust dashboard review | Implemented and adapter-tested | Shows original prompt, rule matches, and cleaned text when available. Queues edited drafts for a waiting ACP turn. |
| Windows distribution | Locally verified | Fresh extraction, workspace-free ACP choice, offline dependency installation, audit initialization, and no workspace hook registration. Native workspace setup remains an option. |
| Protected Send GUI installer | Bundled worker and installer locally verified | Rebuilt with the current sanitizer. The bundled Rules + Horizon worker matched all 15 [demo prompts](PROMPT_SECURITY_DEMO.txt), including exact cleaned text for each sanitize case. |
| Antigravity native composer | Experimental | Tries the editor's Select All action when accessibility selection fails and verifies the draft before sending. Live interception and delivery remain open. |
| Live editor acceptance | Open | A signed-in Antigravity or Codex ACP conversation in Zed has not been verified. |
| Third-party tool-call authorization | Next implementation phase | Controlled prototype exists. Pre-execution enforcement in supported third-party surfaces remains open. |

The focused checkpoint had 23 passing Python tests and 2 passing Rust tests.
See [Testing Plan](TESTING.md) for how to reproduce that checkpoint and
[Implementation Roadmap](IMPLEMENTATION_ROADMAP.md) for the next phases.

## Historical checkpoints

Local cleanup checkpoint: 94 tests passed. Local HTTP middleware, Python adapter, dashboard, review release, and explicit continuation were implemented at their documented scope.

HTTP middleware checkpoint: local FastAPI text gateway `/api/chat` and loopback launcher implemented, with bounded non-streaming requests, required Qwen assessment, role-spoofing inspection, forwarding receipts and dashboard-visible events. 86 tests pass including 16 HTTP boundary tests. Live local HTTP benign request returned a real Ollama answer. Browser extension and full Ollama/OpenAI protocol compatibility remain pending. See MIDDLEWARE_USAGE.md.

Explicit continuation checkpoint: 70 tests pass. Approved excerpts can be rechecked and sent to local Ollama through a tool-free CLI, with forwarding receipt and concise event. Approval does not automatically call a model. Suspended-session recovery, browser interception and full controlled-agent integration remain pending.

Review-release checkpoint: 65 tests pass. Trust/sensitivity labels persist with backward-compatible migration; approved-excerpt release API and CLI refuse unresolved/rejected/invalid reviews. Protected retrieval removes the raw executor result from returned action objects and adds an explicit released-content envelope. Automatic resumption and gateway history minimization remain pending.

Middleware tuning checkpoint: 62 tests pass. Combined mode can resolve ML uncertainty with benign Qwen evidence only when the base inspection passes. Required failures and high-risk findings still hold. Local benign/attack verification succeeded. Model training and threshold calibration remain separate work.

Current model-test checkpoint: protected local model dashboard flow, forwarding receipts, and manual acceptance guide added; 52 automated tests pass. ML files remain with the ML workstream. Browser interception, approved-review resumption, comprehensive detector evaluation and full controlled-tool integration remain pending.

The entries below preserve the earlier delivery log. Use the table above for
the current implementation and verification state.

## Earlier progress summary

Earlier model-boundary checkpoint (2026-11-15): 46 tests passed then. Current verification is recorded at the top of this file. Full agent/tool integration and detector effectiveness remain pending.

- **Overall:** Milestones 0 through 5 complete.
- **Current milestone:** Distributable Windows agent guard and live acceptance.
- **Completed:** Repository audit, initial documentation, Python virtual environment, dependency installation, Ollama installation, model verification, structured tool-call check, bounded agent loop, fixed harmless tool, controlled local tools, action security gateway, content inspection, sanitization, and review queue.
- **In progress:** Hybrid detector evaluation and UI workflow refinement.
- **Pending:** Full model-to-tool integration, complete execution audit, broader detector evaluation and final demo.
- **Blocked:** No runtime blocker identified. Detection effectiveness remains an open research limitation.
- **Next recommended action:** Run the live agent and platform checks defined in the project scope.

## Repository audit (2026-11-08)

- The Git repository is on branch `main`. Before the initial documentation edits, it contained only a minimal README.
- No application code, dependency manifest, tests, or existing docs were found.
- Python 3.14 is installed. The project virtual environment has FastAPI 0.136.3, Pydantic 2.14.3, Uvicorn 0.54.0, Streamlit 1.67.0, and Pytest 9.2.0. Their imports and dependency consistency were checked. Ollama 0.40.15 runs `qwen3.5:4b` locally; the model is 4.2B Q4, uses 3.3 GB on disk, and used 97% CPU / 3% GPU during the local check.

## Status definitions

- **NOT STARTED** — work has not begun.
- **IN PROGRESS** — active work is underway.
- **BLOCKED** — a specific dependency prevents progress; record the reason.
- **REVIEW REQUIRED** — implementation is ready for review but acceptance is not yet confirmed.
- **COMPLETED** — implementation works as intended, relevant tests pass, docs are updated, limitations are recorded, and changes are committed or ready for review.

## Feature checklist

- [x] Ollama installed and working locally.
- [x] Qwen3.5 4B availability, compatibility, and resource use checked.
- [x] Python client makes a real local Ollama request.
- [x] Model produces parseable structured tool-call proposals.
- [x] Agent loop handles results, malformed output, and maximum iterations.
- [x] Harmless initial tool works through the proposed loop.
- [x] Approved document search implemented.
- [x] Approved document read by ID implemented.
- [x] Fixed SQLite query functions implemented with parameterized SQL.
- [x] Simulated local outbox implemented; no real message sending.
- [x] Pydantic schemas and argument bounds implemented.
- [x] Explicit tool allowlist implemented.
- [x] Permission and resource-scope checks implemented.
- [ ] Gateway is the sole route to model-controlled tool execution (pending integration).
- [x] Unauthorized and malformed operations are blocked before execution.
- [x] Provenance and sensitivity labels preserved.
- [x] Rule-based content inspection implemented and documented.
- [x] PASS / SANITIZE / HOLD decisions implemented and justified.
- [x] Sanitization isolates clear spans; sanitized content remains untrusted.
- [x] Human review queue and excerpt-scoped decision implemented.
- [ ] Audit records decisions, reasons, outcomes, and duration without needless sensitive content.
- [x] Limited local FastAPI text middleware implemented (not full protocol compatibility).
- [x] Python package and workspace hook installer for Codex and Antigravity implemented.
- [x] Windows wheel install and generated rules-mode hook commands smoke-tested.
- [ ] Verify live hook enforcement with both agents and the default Ollama assessor.
- [ ] Revisit macOS and Linux packaging after the Windows workflow is stable.
- [x] Streamlit dashboard displays actual application data.
- [ ] Automated tests cover normal, malformed, unauthorized, traversal, injection, review, limits, and audit cases.
- [ ] Baseline, sanitization-only, and full-middleware comparison performed.
- [ ] Selected AgentDojo subset evaluated (scope/results documented).
- [ ] InjecAgent subset considered/evaluated if time permits.
- [ ] Documentation and reproducible final demonstration completed.

## Task register

| ID | Task and description | Status | Priority | Dependencies | Acceptance criteria | Relevant files | Testing requirements |
|---|---|---|---|---|---|---|---|
| M0-01 | Audit repository and record baseline | COMPLETED | High | None | Existing files, Git state, code/docs/dependencies, and unknowns recorded | `docs/PROJECT_TRACKER.md` | Read-only audit; findings accurately reported |
| M0-02 | Create and revise initial public documentation | COMPLETED | High | M0-01 | Required documents exist, contain no personal information, and distinguish design from implementation | `README.md`, `docs/*.md` | Documentation scan and consistency review completed |
| M0-03 | Approve the environment milestone | COMPLETED | High | M0-02 | Scope and order accepted before installation or model download | Tracker | Approval recorded in project conversation |
| M1-01 | Select compatible Python and dependency versions | COMPLETED | High | M0-03 | Versions selected with rationale and documentation updated | `requirements.txt`, setup docs | Environment package imports and dependency check pass |
| M1-02 | Verify Ollama and Qwen3.5 4B on Windows hardware | COMPLETED | High | M1-01 | Local model response verified; CPU/GPU distribution recorded | `docs/SETUP_AND_INSTALLATION.md`, tracker | Ollama list, local API response, and processor report verified |
| M1-03 | Verify Python-to-Ollama request and structured proposal | COMPLETED | High | M1-02 | Local call succeeds and structured tool response is confirmed | `scripts/verify_ollama.py`, tests/docs | Real local response and expected proposal verified |
| M2-01 | Implement bounded agent loop and harmless tool interface | COMPLETED | High | M1-03 | Loop parses proposal, receives result, and stops at iteration cap | `security_middleware/`, `scripts/run_agent_demo.py`, `tests/test_agent_loop.py` | Four unit tests and local Ollama demonstration passed |
| M3-01 | Implement approved document search/read tools | COMPLETED | High | M2-01, interface reviewed | ID-based reads/search stay in approved corpus | `controlled_tools.py`, `sample_data/documents/` | Search/read, invalid ID, and traversal-style input tests pass |
| M3-02 | Implement fixed SQLite functions | COMPLETED | Medium | M2-01, schema agreed | Only approved parameterized queries exposed | `controlled_tools.py` | Fixed query and invalid-record tests pass |
| M3-03 | Implement simulated outbox | COMPLETED | Medium | M2-01, destination policy agreed | Draft stored locally; no actual delivery | `controlled_tools.py` | Stored draft and denied-recipient tests pass |
| M4-01 | Define schemas, allowlist, permissions, resource scopes, and limits | COMPLETED | Critical | M3 interfaces stable | Policy contract implemented and reviewed in code | `action_gateway.py`, `controlled_tools.py` | Positive and negative cases pass |
| M4-02 | Implement gateway and controlled executor dispatch | COMPLETED | Critical | M4-01, M3 tools | Authorized requests reach only fixed dispatch branches | `action_gateway.py`, `run_gateway_demo.py` | Allowed and blocked demo requests verified |
| M4-03 | Add gateway security tests | COMPLETED | Critical | M4-02 | Unknown, malformed, unauthorized, traversal, and limits tested | `tests/test_action_gateway.py` | Fourteen total tests pass |
| M5-01 | Add content metadata and transparent inspection | COMPLETED | High | M4 interfaces | Provenance/sensitivity retained; decisions explainable | `content_protection.py`, synthetic documents | Benign, sanitize, and hold tests pass |
| M5-02 | Add sanitization and review workflow | COMPLETED | High | M5-01 | Clear spans isolated; high-risk content held; reviewer decision excerpt-scoped | `review_queue.py`, `secure_retrieval.py` | Review and end-to-end retrieval tests pass |
| M6-01 | Integrate model, tools, inspection, gateway, executor, and audit | NOT STARTED | High | M2-M5 | End-to-end flow uses the gateway and accurate audit records | Future app modules | Integration and failure tests |
| M7-01 | Add FastAPI and Streamlit interfaces | NOT STARTED | Medium | M6-01 | UI/API expose actual application data without bypass | Future API/dashboard | Endpoint/UI smoke and authorization tests |
| M8-01 | Build evaluation corpus and compare configurations | NOT STARTED | High | M6-01 | Reproducible metrics and limitations reported | Future eval assets, `docs/TESTING.md` | Repeatable runs; results recorded |
| M9-01 | Evaluate selected benchmark subset if practical | NOT STARTED | Low | M8-01, licensing/scope review | Exact subset and outcomes documented | Evaluation docs | Reproducibility and scope recorded |
| M10-01 | Final hardening, documentation, and demo | NOT STARTED | Medium | M8-01, M9 decision | Reproducible demo and final documentation | Project docs/demo | Fresh setup and documented run-through |

## Workstream ownership and parallel work

Tasks remain unassigned in public documentation. Once tool/schema interfaces are stable, independent tool modules, isolated security tests, and dashboard presentation can proceed in parallel. Do not edit shared schemas, gateway/dispatcher, dependency manifest, or tracker concurrently without coordination. Integration order: agree interfaces → implement tools/tests → gateway → content/review → integration → API/dashboard → evaluation.

## Definition of done

A task is COMPLETED only when its implementation exists, works as intended, relevant tests pass, documentation is updated, limitations are recorded, and changes are committed or ready for review. A file existing is not sufficient.

## Change log

| Date | Change | Type |
|---|---|---|
| 2026-11-08 | Audited the empty application repository; established target architecture, security model, development/testing plans, team workflow, and milestone tracker. No application feature or dependency was added. | Planning/documentation |
| 2026-11-08 | Created a Python 3.14 virtual environment, installed the selected project dependencies, and verified imports. | Environment |
| 2026-11-08 | Installed Ollama 0.40.15 and verified local `qwen3.5:4b` responses, structured tool proposals, and CPU/GPU distribution. | Environment/model verification |
| 2026-11-08 | Added a bounded local agent loop, Pydantic message validation, one fixed harmless tool, unit tests, and a successful local demonstration. | Agent loop |
| 2026-11-08 | Added approved document tools, a parameterized SQLite record lookup, a simulated local outbox, synthetic sample data, and successful tests/demonstration. | Controlled tools |
| 2026-11-08 | Added an action gateway with allowlists, argument validation, scopes, limits, fixed dispatch, and successful security tests/demonstration. | Action gateway |
| 2026-11-08 | Added rule-based content inspection, sanitization, held-content review queue, and an end-to-end secure document retrieval demonstration. | Content protection |
| 2026-11-12 | Added hybrid inspection, local Qwen assessment, concise SQLite events, and Streamlit UI. Verified 27 tests, UI rendering and blank-input interaction, and local server startup. Full detector evaluation remains pending. | Hybrid protection/UI |

## Earlier UI checkpoint

Run `python -m streamlit run app.py` from the project environment. Four tabs expose text analysis, gateway-protected retrieval, pending reviews, and persisted security events. The local assessor was checked with a real synthetic injection request; it returned high risk. The UI rendered without exceptions and held blank input. These checks establish functionality, not detector accuracy. The assessor can itself be manipulated, and obfuscated or unfamiliar attacks can evade current checks. Sanitized text remains untrusted. Complete execution-outcome and duration auditing remains pending.
# ML detector development checkpoint (2026-11-13)

The local TF-IDF/Logistic Regression baseline now trains from pinned deepset data and saves an ignored local model artifact. Analyze text offers detector configuration selection and classifier probability/duration output. Required ML failure or uncertainty holds content; classification does not grant action permissions. Current verification: 30 tests pass, dependency consistency passes, and held-out binary precision/recall/F1 are 0.8824/0.7692/0.8219. These do not measure final pipeline effectiveness. See [ML training guide](ML_TRAINING.md) for commands, licensing, measured results, provisional thresholds and unfinished work. The prompt-injection module remains in development.
