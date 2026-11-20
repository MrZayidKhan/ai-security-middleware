# Prompt Security Middleware

**Status: experimental — English and Windows are the current supported focus.**

This project places a security boundary between an agent application and the
model or tools that the agent uses. It inspects untrusted prompts, retrieved
text, and proposed tool calls before they are forwarded. The middleware can
allow safe content, sanitize a removable suspicious span, or hold content for
review.

The current implementation is a working research prototype. It is useful for
local demonstrations and controlled testing, but it is not yet a complete
security product. Detection quality, coverage, and performance must continue
to be measured on independent data before production use.

## Current phase

The near-term target is a fast, dependable English/Windows path:

- Windows installation and launch instructions are the primary supported path.
- English direct and indirect prompt-injection cases are the primary evaluation
  set.
- Deterministic rules and structural validation run before any model-assisted
  assessment.
- Suspicious text can be withheld or replaced with a marked sanitized value.
- Tool and action permissions remain separate from text classification.
- The Rust dashboard is the primary local event viewer.

Other languages, additional operating systems, broad protocol compatibility,
and production deployment controls are planned but not claimed as complete.

## How it works

```text
Agent request
    -> validation and normalization
    -> rules and encoding checks
    -> optional local risk assessment
    -> sanitation or hold decision
    -> tool/action policy checks
    -> release to the configured model or agent
    -> SQLite audit event and receipt
```

The detector is not allowed to execute the text it evaluates. A detector result
does not grant tool access. Tool calls must pass their own schema, allowlist,
argument, path, network, and confirmation checks.

When a local verifier is enabled, the middleware connects to the locally
configured inference service. The verifier is an advisory signal inside the
policy engine; deterministic holds and detector failures remain fail-closed.
The answering model is not bundled in this repository, and its responses are
not cached by the middleware.

## Connections

The middleware is designed around adapters rather than one particular agent.
The current repository provides:

- a bounded HTTP gateway for applications that can send requests to a local
  endpoint;
- Python interfaces for embedding inspection in a custom agent;
- generated Codex and Antigravity hook handlers for the inputs those hosts
  expose;
- a separate action gateway for the small set of controlled operations covered
  by the prototype.

For another CLI or desktop application, choose an adapter based on the
interface it exposes:

1. Use an HTTP adapter when the application can target a configurable local
   endpoint.
2. Use a hook adapter when it exposes pre-prompt or pre-tool hooks.
3. Use the Python interface when the application is Python-based.
4. Add a new adapter when none of those interfaces are available.

The official desktop application for a model provider is not automatically
intercepted. It must be configured to use the gateway or an available hook.

## Windows quick start

Download `distribution-all-in-one-windows-x64` from a successful
[GitHub Actions run](https://github.com/MrZayidKhan/ai-security-middleware/actions).
Extract the artifact and its inner ZIP, run **Setup.cmd**, and choose your
agent and workspace. **Open Dashboard.cmd** shows local decisions.
**Open Sanitizer.cmd** starts the local sanitation API for clients that
can substitute screened text. The workspace hooks can withhold text that
requires sanitation. **Uninstall.cmd** disconnects workspaces recorded by
Setup and removes its managed files.

Use Python 3.10 or newer. From a PowerShell window in the repository:

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install .
```

Install the gateway dependencies before running it from source:

```powershell
.\.venv\Scripts\python.exe -m pip install ".[gateway]"
.\.venv\Scripts\python.exe -m scripts.run_middleware --detector english-verifier
```

The HTTP endpoint is `http://127.0.0.1:8787`. Interactive API documentation is
available at `http://127.0.0.1:8787/docs`.

The optional local verifier is installed and configured separately. It is not
part of the wheel and its model files are not committed to this repository.
See [the standalone setup guide](docs/STANDALONE_SETUP.md) and
[the agent hook guide](docs/AGENT_HOOKS.md) for the supported configuration.

## Dashboard

The Rust dashboard is a read-only local viewer for the SQLite audit database.
It can run without Python, a browser, or a running gateway:

```powershell
.\rust-dashboard\target\release\security-dashboard.exe --summary
```

Open the executable without `--summary` for the desktop view. The dashboard
reads the path passed with `--db`, then the
`AI_SECURITY_MIDDLEWARE_AUDIT_DB` environment variable, then the local runtime
database locations described in [standalone setup](docs/STANDALONE_SETUP.md).

The cards show recorded events and inspection outcomes; they are not a claim
that every withheld event is a confirmed attack.

## Current functionality

| Area | Current behavior |
|---|---|
| Inspection | Validation, normalization, encoding checks, rules, and optional local risk evidence |
| Sanitation | Removes a supported suspicious excerpt or withholds unresolved content |
| Tool safety | Separate schemas, allowlists, argument checks, and bounded operations |
| Agent hooks | Codex and Antigravity paths covered where their host interfaces expose the required event |
| HTTP gateway | Bounded non-streaming text requests with receipts and audit events |
| Audit | Local SQLite records for inspections, decisions, and forwarding outcomes |
| Dashboard | Native Rust viewer with filters, event details, and summary mode |
| Evaluation | Reproducible tests and reports; no detector is accepted solely from a published score |

## Testing

Run the local test suite from PowerShell:

```powershell
.\.venv\Scripts\python.exe -m pytest -q --basetemp .pytest-tmp
cargo test --locked --manifest-path rust-dashboard/Cargo.toml
```

Use [manual testing](docs/MANUAL_TESTING.md) for benign, direct-injection,
indirect-injection, sanitation, and review cases. Report accuracy, precision,
recall, F1, false-positive rate, false-negative rate, and latency on a held-out
set. Do not tune thresholds on the final test set.

Run the shipped detector and rules-only baseline side by side with
`python -m scripts.evaluate_offline_detector --model-dir models/pretrained/horizon-small --output offline-evaluation.json`.
The report lists input sources and counts, direct and indirect results,
accuracy, precision, recall, F1, and latency. The evaluator reads local
datasets. See [dataset import](docs/DATASET_IMPORT.md) and
[Horizon setup](docs/HORIZON_SETUP.md).

## What remains to be done

- Replace the current experimental risk signal with a separately evaluated,
  compact prompt-injection classifier.
- Add a dedicated action-risk policy dataset and test tool calls independently
  from prompt text.
- Improve sanitation for more content formats while preserving provenance.
- Add a guided setup screen for choosing an agent type, endpoint, and audit
  database.
- Expand adapter coverage for additional CLI and desktop applications.
- Verify macOS and Linux packaging after the Windows path is stable.
- Add authentication, signed audits, deployment guidance, and recovery for
  interrupted agent sessions.
- Re-run independent English evaluation after every detector or policy change.

## Documentation

- [Standalone setup](docs/STANDALONE_SETUP.md)
- [Agent hooks](docs/AGENT_HOOKS.md)
- [Application connection guide](docs/APPLICATION_CONNECTION_ENGLISH.md)
- [Architecture](docs/ARCHITECTURE.md)
- [Security model](docs/SECURITY_MODEL.md)
- [Manual testing](docs/MANUAL_TESTING.md)
- [Evaluation report](docs/PROMPT_INJECTION_EVALUATION.md)
- [Project scope](docs/PROJECT_SCOPE.md)

## Contribution and branch policy

Changes are made on a new branch, tested, and pushed for review. The main
branch is updated only after the change has been reviewed and explicitly
approved for merging.

Keep local datasets, credentials, model weights, and runtime databases out of
commits. See [development](docs/DEVELOPMENT.md) for the repository workflow.
