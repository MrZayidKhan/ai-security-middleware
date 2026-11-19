# AI Agent Security Middleware

AI Agent Security Middleware screens untrusted text before it reaches an AI agent's answering model. Install it as a Python package from a Git clone or wheel for supported Codex and Google Antigravity workspaces. You can also integrate the inspector into your own Python agent or use the local Ollama HTTP gateway.

For an installable prompt guard for Codex and Google Antigravity, see the
[cross-platform agent setup](docs/AGENT_HOOKS.md). The hooks use the agent's own
answering model and can be installed independently of the dashboard and gateway.

The Rust desktop dashboard reads security events from a local SQLite file. It
can run without Python, Streamlit, a running gateway, or Ollama. See
[downloads and standalone setup](docs/STANDALONE_SETUP.md) for the dashboard,
installable gateway, and shared audit configuration.

## Objectives

- Make prompt-injection screening installable on another machine without copying development paths, local datasets, or model artifacts.
- Screen user prompts and retrieved text at the model boundary where the integration exposes them. Pass benign text, sanitize when the interface can forward replacement text, and withhold unresolved content.
- Keep tool permissions independent of classifier decisions. Demonstrate bounded tool execution, excerpt review, and security events in the local application.
- Measure enforcement and detector effectiveness separately. Document coverage, false positives, misses, and runtime limitations.

See [project scope and acceptance criteria](docs/PROJECT_SCOPE.md) for what ships today and what still needs verification.

## Install for Codex or Antigravity

From the clone, use Python 3.10 or newer and run `python -m pip install .` in a virtual environment. From the workspace to protect, run `ai-security-middleware install codex` or `ai-security-middleware install antigravity`. The default classifier uses local Ollama with `qwen3.5:4b`. Use `--detector rules` for a smoke test without Ollama. Follow the [agent setup guide](docs/AGENT_HOOKS.md) to enable the generated hooks.

## Run the local Ollama demo on Windows

From the repository root, create an environment if needed and install dependencies:

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements-test.txt
```

Keep Ollama running with `qwen3.5:4b` installed. Start the middleware:

```powershell
.\.venv\Scripts\python.exe -m scripts.run_middleware
```

Send supported agent requests to `http://127.0.0.1:8787/api/chat` instead of Ollama directly. Open `http://127.0.0.1:8787/docs` for interactive API documentation.

For the separately tested English contextual verifier, start with
`.\.venv\Scripts\python.exe -m scripts.run_middleware --detector english-verifier`.
Use the [application connection guide](docs/APPLICATION_CONNECTION_ENGLISH.md)
and [English test results](docs/ENGLISH_VERIFIER_READINESS.md). The supplied
`MiddlewareChatClient` handles the gateway's limited protocol without bypass fallback.
The dashboard is optional for viewing logs; the HTTP service performs inspection.

In another terminal, start the dashboard:

```powershell
.\.venv\Scripts\python.exe -m streamlit run app.py --server.address 127.0.0.1 --browser.gatherUsageStats false
```

Open the local URL printed by Streamlit. Stop either service with Ctrl+C.

## Current functionality

| Component | Implemented behavior |
|---|---|
| Codex hooks | Block typed prompts and replace withheld results on supported tool paths |
| Antigravity hook | Stop a model invocation based on the latest typed prompt |
| HTTP middleware | Bounded non-streaming text gateway; fixed local model; all supplied roles inspected |
| Python adapter | `PromptSecurityMiddleware` and `SecureChatClient` screen context before model calls |
| Inspection | Validation, normalization, encoding checks, rules, optional ML/Qwen evidence |
| Dashboards | Rust desktop viewer for security events and analytics. The legacy Streamlit dashboard provides analysis, retrieval, and review controls. |
| Human review | Exact-excerpt approval, provenance/sensitivity preservation, explicit rechecked continuation |
| Controlled tools | Independent gateway for fixed document/SQLite/draft-only operations |
| Evaluation | Reproducible research experiments; candidates do not automatically replace deployed models |

```text
Agent request → validation/inspection → hold OR released/sanitized context → local model
                                     → receipt and security event
```

The HTTP service uses rules plus required local Qwen assessment. Clear deterministic holds skip model inference. Successful Qwen assessments are cached per instance for up to 60 seconds and 128 entries; failures are never cached. Answering-model responses are not cached. New-content Qwen CPU inference can remain slow.

## Verify and test

```powershell
.\.venv\Scripts\python.exe -m pytest -q --basetemp .pytest-tmp
```

Use the [HTTP integration guide](docs/MIDDLEWARE_USAGE.md) for request examples, limits and error responses, and the [manual test guide](docs/MANUAL_TESTING.md) for benign, injected, sanitized and reviewed-excerpt cases. Recording-client tests prove held content makes no answering-model call; detection effectiveness needs separate evaluation.

## Scope and limits

- Workspace installation is opt-in. Hook coverage is limited to the inputs each agent exposes. Antigravity's native hook cannot screen tool results. Attachments and unhooked context are outside coverage.
- The hook package targets Windows, macOS, and Linux. The Windows wheel and generated commands passed rules-mode fixtures, and the installed hook handlers passed benign fixtures with local Ollama. Live host sessions and macOS/Linux execution still need verification.
- Limited user/assistant/tool text API; no streaming, system messages, images, supplied tools or arbitrary generation options. Not a full Ollama/OpenAI protocol replacement.
- PASS does not guarantee safety. Sanitized/reviewed content remains untrusted. Required detector failure holds content.
- The optional ML baseline is binary. Suspicious is a policy band, and each detector configuration can produce false positives and misses.
- Full model-controlled-tool integration, authentication, remote deployment, signed audits and suspended-agent recovery remain pending.

## Repository

- `security_middleware/`: inspection, adapters, API, review, retrieval and tool controls.
- `app.py`: local dashboard.
- `scripts/`: launchers, review commands, demos and research scripts.
- `tests/`: enforcement/regression tests; `sample_data/`: synthetic documents.
- `data/`, `models/`, `runtime_data/`: ignored local datasets, artifacts and runtime data. Keep credentials, personal information and weights out of public commits.

## Documentation

- [Setup](docs/SETUP_AND_INSTALLATION.md) · [Development](docs/DEVELOPMENT.md)
- [Agent hooks](docs/AGENT_HOOKS.md) · [Project scope](docs/PROJECT_SCOPE.md)
- [Architecture](docs/ARCHITECTURE.md) · [Security model](docs/SECURITY_MODEL.md)
- [Tracker](docs/PROJECT_TRACKER.md) · [Testing](docs/TESTING.md)
- [ML training](docs/ML_TRAINING.md) · [Implementation review](docs/IMPLEMENTATION_REVIEW.md)
