# AI Agent Security Middleware

A local Python connector that inspects model-bound text before forwarding it to Ollama. It provides PASS, SANITIZE or HOLD decisions, a local HTTP gateway, a Streamlit dashboard, excerpt review and SQLite security events.

## Start on Windows

From the repository root, create an environment if needed and install dependencies:

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements-test.txt
```

Keep Ollama running with `qwen3.5:4b` installed. Start the middleware:

```powershell
.\.venv\Scripts\python.exe -m scripts.run_middleware
```

Send supported agent requests to `http://127.0.0.1:8787/api/chat` instead of Ollama directly. Open `http://127.0.0.1:8787/docs` for interactive API documentation. In another terminal start the dashboard:

```powershell
.\.venv\Scripts\python.exe -m streamlit run app.py --server.address 127.0.0.1 --browser.gatherUsageStats false
```

Open the local URL printed by Streamlit. Stop either service with Ctrl+C.

## Current functionality

| Component | Implemented behavior |
|---|---|
| HTTP middleware | Bounded non-streaming text gateway; fixed local model; all supplied roles inspected |
| Python adapter | `PromptSecurityMiddleware` and `SecureChatClient` screen context before model calls |
| Inspection | Validation, normalization, encoding checks, rules, optional ML/Qwen evidence |
| Dashboard | Text analysis, protected model tests, retrieval, review queue, security events |
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

- Opt-in local connector; no browser extension or automatic interception of unrelated apps.
- Limited user/assistant/tool text API; no streaming, system messages, images, supplied tools or arbitrary generation options. Not a full Ollama/OpenAI protocol replacement.
- PASS does not guarantee safety. Sanitized/reviewed content remains untrusted. Required detector failure holds content.
- The deployed ML baseline is binary; suspicious is a policy band. Research candidates may have substantial false positives and misses.
- Full model-controlled-tool integration, authentication, remote deployment, signed audits and suspended-agent recovery remain pending.

## Repository

- `security_middleware/`: inspection, adapters, API, review, retrieval and tool controls.
- `app.py`: local dashboard.
- `scripts/`: launchers, review commands, demos and research scripts.
- `tests/`: enforcement/regression tests; `sample_data/`: synthetic documents.
- `data/`, `models/`, `runtime_data/`: ignored local datasets, artifacts and runtime data. Keep credentials, personal information and weights out of public commits.

## Documentation

- [Setup](docs/SETUP_AND_INSTALLATION.md) · [Development](docs/DEVELOPMENT.md)
- [Architecture](docs/ARCHITECTURE.md) · [Security model](docs/SECURITY_MODEL.md)
- [Tracker](docs/PROJECT_TRACKER.md) · [Testing](docs/TESTING.md)
- [ML training](docs/ML_TRAINING.md) · [Implementation review](docs/IMPLEMENTATION_REVIEW.md)
