# Security Model

## Status and scope

The action gateway, fixed executor, argument validation, scopes, limits, hybrid content inspection, sanitization, local review queue, concise event storage, and dashboard are implemented and tested at their current scope. Model-to-gateway integration, complete execution auditing, and evaluation remain pending. The MVP is a local application-level gateway. It is not a hardened OS sandbox and does not defend a compromised host, administrator, Python process, or dependency.

## Current enforced controls

- Only four controlled-tool names are allowlisted by the gateway.
- Each tool has a Pydantic argument contract that rejects extra fields.
- Document IDs, record IDs, and draft recipients have separate permitted scopes.
- Calls are limited per task and per repeated tool name.
- The executor dispatches fixed functions only; it cannot run a proposed command, Python code, arbitrary SQL, or real message delivery.
- Concise inspection and UI security events are persisted locally; gateway execution records are not yet fully unified with that event store.
- Retrieved documents carry source, content, origin-trust, and sensitivity metadata before inspection.
- Content may pass, be sanitized, or be held in the local review queue. Review decisions cannot change action permissions.

## Assets

- Approved local documents and their provenance/sensitivity metadata.
- Approved SQLite records.
- Simulated outbox drafts.
- User tasks and model context.
- Policy configuration, reviewer decisions, and audit records.
- Local model/runtime availability and integrity.

## Threat actors and assumptions

Consider malicious instructions embedded in retrieved content, a user submitting unsafe requests, malformed or manipulated model output, and accidental developer mistakes. Assume local files and tool responses can be untrusted. Do not assume model output or its explanations are reliable. Host-level compromise and malicious administrators are out of scope.

## Trust boundaries and attack surfaces

Boundaries include user input to agent; model response to parser; parsed call to gateway; gateway to executor/resources; retrieved content back to model; review UI to approved excerpts; and local API/dashboard to backend. Attack surfaces include JSON parsing, argument validation, document IDs/paths, SQL parameters, outbox destination fields, content inspection, review controls, and audit data.

## Required policies

1. Every tool call passes through the action gateway.
2. Explicit allowlist; validate tool name and arguments independently.
3. Least privilege and resource scopes; default deny for unknown/invalid requests.
4. Fixed database functions and parameterized queries; no model-generated SQL.
5. Prefer document IDs mapped to approved files. If paths are necessary, canonicalize, enforce root containment correctly, account for symlinks, and handle failures.
6. No arbitrary shell/Python, unrestricted filesystem/SQL/network, real email, or cloud inference in MVP.
7. Bound tool calls, repeated calls, execution time, and input sizes.
8. Content inspection does not grant tool authority. Sanitized content remains untrusted.
9. Human review resolves content uncertainty only; it cannot override prohibited actions. Approvals identify a reviewed excerpt.
10. Log decisions and actual outcomes, minimizing sensitive values and content.

## Content labels

Keep origin trust (`trusted`/`untrusted`) separate from data sensitivity (`public`/`internal`/`confidential`), and record source and content identifiers. These labels are descriptive metadata for the MVP, not a complete information-flow enforcement system.

## Threat scenarios and intended response

| Scenario | Required control | Planned test |
|---|---|---|
| Retrieved document asks agent to reveal secrets or call tools | Inspect content; preserve untrusted provenance; gateway independently checks any proposal | Injection and benign lookalike corpus |
| Model invents an unknown tool | Allowlist rejects it; no executor dispatch | Unknown tool test |
| Model supplies malformed/oversized arguments | Schema and bounds reject before execution | Malformed and size-boundary tests |
| Document ID/path attempts traversal | ID mapping or canonical root containment denies it | Traversal and invalid ID tests |
| Model tries arbitrary SQL | No SQL tool; use fixed parameterized functions | Invalid query-argument tests |
| Draft targets prohibited recipient | Validate destination against policy; write only to simulated outbox | Unauthorized destination test |
| Inspector or reviewer store unavailable | Fail closed for unresolved content | Failure injection test |
| Tool times out or raises error | Record failed execution; never report success | Timeout/error audit test |

## Known weaknesses

Rule-based detection cannot reliably identify every injection and may flag benign text. A local model may generate malformed or unsafe proposals. The gateway and executor share an application process. A developer mistake or compromised process can bypass in-process controls. Local storage permissions and audit tamper resistance are not solved by this MVP.

## Out of scope

Host/OS hardening, defending against a malicious administrator, arbitrary code containment, remote/cloud deployment, unrestricted network tools, real email delivery, full information-flow tracking, and claims of benchmark-level security without completed evaluation.

## Hybrid prompt inspection

The implemented inspector applies input-size and blank-content checks, canonical Unicode normalization, invisible-character removal, and encoded-payload checks before inspecting the readable content. It then combines transparent patterns with a structured local-model assessment. The model is an advisory signal and never grants access or overrides action policy.

The system holds content if a high-risk directive, encoded malicious payload, high-risk model classification, or unresolved suspicious result is found. It sanitizes only known override lines or exact local-model spans. Sanitized content remains untrusted.
# ML detector development checkpoint (2026-11-13)

The local TF-IDF/Logistic Regression baseline now trains from pinned deepset data and saves an ignored local model artifact. Analyze text offers detector configuration selection and classifier probability/duration output. Required ML failure or uncertainty holds content; classification does not grant action permissions. Current verification: 30 tests pass, dependency consistency passes, and held-out binary precision/recall/F1 are 0.8824/0.7692/0.8219. These do not measure final pipeline effectiveness. See [ML training guide](ML_TRAINING.md) for commands, licensing, measured results, provisional thresholds and unfinished work. The prompt-injection module remains in development.
