# Project Tracker

This is the source of truth for project progress. Statuses describe verified state; the existence of documentation alone does not complete an application feature.

## Progress summary

- **Overall:** Milestones 0 through 5 complete.
- **Current milestone:** Ready for Milestone 6 — integration and audit storage.
- **Completed:** Repository audit, initial documentation, Python virtual environment, dependency installation, Ollama installation, model verification, structured tool-call check, bounded agent loop, fixed harmless tool, controlled local tools, action security gateway, content inspection, sanitization, and review queue.
- **In progress:** None.
- **Pending:** Model-to-gateway integration, persistent audit storage, API/dashboard, evaluation, final demo.
- **Blocked:** None identified. Model/hardware feasibility remains unverified, not blocked.
- **Next recommended action:** Review and approve secure-path integration with persistent audit storage.

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
- [ ] FastAPI integration implemented.
- [ ] Streamlit dashboard displays actual application data.
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
