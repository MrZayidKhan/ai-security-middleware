# Architecture

## Status

Milestone 5 implements a local model client, validated message shapes, a bounded agent loop, controlled local tools, an action gateway, content inspection, and a local review queue. Persistent audit storage, API, dashboard, and model integration with the controlled tools remain planned.

## Current demonstration flow

```mermaid
flowchart LR
    U[User task] --> L[Agent loop]
    L --> M[Local Ollama model]
    M -->|get_project_status proposal| E[Fixed demonstration executor]
    E -->|fixed status text| L
    L --> M
    M --> R[Final response]
```

`get_project_status` has no arguments and returns a fixed string. It does not read files, query a database, send a message, or invoke a command. The loop accepts at most three tool rounds. This is a controlled teaching step; the policy gateway will replace the simple dispatcher in milestone 4.

## Controlled local tools

Milestone 3 implements tools independently from the model loop:

- `search_documents` searches the two approved synthetic documents.
- `read_document` accepts a document ID and maps it to a fixed file name.
- `get_project_record` uses one parameterized SQLite query.
- `draft_message` creates a local `DRAFT` record for an approved synthetic recipient.

These tools are genuine local operations but are not yet connected to the model. The action gateway validates, authorizes, and dispatches requests to them; model integration will use that route in a later milestone.

## Action gateway

`ActionGateway` receives a structured task ID, tool name, and argument object. It blocks malformed requests, unknown tools, invalid arguments, out-of-scope resources, and calls that exceed configured limits. Only an allowed request reaches `ControlledToolExecutor`.

The gateway returns an authorization decision and a separate execution outcome. It keeps an in-memory decision history during this milestone. The model is not yet connected to the controlled tools; that integration will route every model proposal through this gateway.

## Secure document retrieval

`SecureDocumentRetrieval` implements one complete security path for a document ID:

```mermaid
flowchart LR
    R[Document ID] --> G[Action gateway]
    G -->|ALLOW| D[Controlled document read]
    D --> I[Content inspector]
    I -->|PASS| P[Return content]
    I -->|SANITIZE| S[Return changed content]
    I -->|HOLD FOR REVIEW| Q[Local review queue]
```

The inspector uses transparent rules. A direct instruction to expose sensitive data is held for review. A clear instruction override is replaced with `[Suspicious instruction removed.]`. Text that merely discusses security concepts passes. Sanitized content remains untrusted.

## Components and responsibilities

1. **Interface** — eventually accepts a user task and presents results/review items.
2. **Agent loop** — sends the task and relevant context to a local Ollama model, parses a proposed structured tool call, and continues with a result or produces a final response. The model proposes; it does not execute.
3. **Schema validation** — Pydantic models validate the tool name and shape/types/limits of arguments. Valid shape alone does not grant permission.
4. **Content inspection** — labels source and sensitivity, applies transparent initial rules, and returns PASS, SANITIZE, or HOLD FOR REVIEW. It is a risk signal, not the action authorization mechanism.
5. **Policy and permission checks** — independently checks the allowlisted tool, caller permissions, resource scope, and operation limits. A prohibited action is blocked; human content review cannot override this.
6. **Controlled executor** — maps approved tool names to fixed Python functions. No shell, arbitrary Python, model-provided SQL, or arbitrary path access.
7. **Audit store** — records decisions and outcomes while minimizing sensitive content.
8. **Local resources** — approved document corpus, SQLite records through fixed parameterized functions, and a simulated outbox.
9. **Human review** — stores unresolved content and a reviewer decision, including the exact excerpt approved for use.

## Tool-call flow

```mermaid
sequenceDiagram
  participant User
  participant Agent
  participant Validator
  participant Gateway
  participant Executor
  participant Audit
  User->>Agent: Task
  Agent->>Validator: Structured proposal
  Validator-->>Audit: Invalid proposal and reason
  Validator->>Gateway: Validated proposal
  Gateway->>Gateway: Allowlist, permission, scope, limits
  alt Denied
    Gateway-->>Audit: BLOCK decision
    Gateway-->>Agent: Safe denial result
  else Allowed
    Gateway->>Executor: Approved tool + validated arguments
    Executor->>Audit: Actual outcome and duration
    Executor-->>Agent: Tool result
  end
```

Every execution path must go through the gateway, including API and dashboard initiated actions. Unknown tools and malformed arguments fail closed. Tool-call count, repeated calls, input size, and execution time need explicit limits.

## Content-protection flow

Returned or retrieved text keeps separate metadata fields: `source_id`, `content_id`, `origin_trust` (trusted/untrusted), and `data_sensitivity` (public/internal/confidential). The MVP is not a full information-flow tracking system. Inspection decisions and transformations should record a reason and retain provenance. Clearly isolated suspicious spans may be sanitized; ambiguous cases are held. Sanitized material remains untrusted. A reviewer may reject it or approve a specific excerpt after inspection; approval does not grant tool permissions.

## Failure handling

- Parse/schema errors: do not execute; return a bounded error and record the decision.
- Unknown tool, denied permission, or out-of-scope resource: block and log.
- Tool exception or timeout: record the failed outcome; do not represent it as success.
- Inspector/review storage unavailable: fail closed for unresolved content rather than silently pass it.
- Ollama unavailable or malformed model output: stop the loop safely; enforce a maximum iteration count.
- Logs: store argument summaries and reason codes where possible, not full sensitive content or secrets.

## Boundaries and trade-offs

The gateway is an application-level control. It cannot contain arbitrary code running in the same compromised process, stop a hostile administrator, or replace OS permissions. Rule-based prompt-injection detection will miss attacks and may flag benign text. The MVP favors fixed tools and understandable controls over broad capabilities. Detection never substitutes for action authorization.

## Planned integration order

Milestone 1 verifies local runtime/model feasibility; milestone 2 builds a minimal agent loop with one harmless tool; milestone 3 adds controlled tools; milestone 4 establishes the action gateway; milestone 5 adds content protection and review; milestone 6 integrates; milestone 7 adds API/dashboard; milestones 8–10 evaluate and finalize. Details and statuses are in the tracker.
