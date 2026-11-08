# Development Guide

## Current state

The repository includes a bounded local agent loop and one fixed demonstration tool. A Python 3.14 virtual environment, selected project dependencies, Ollama, and the local `qwen3.5:4b` model are installed and verified.

## Run and test Milestone 2

From `D:\Mini_project\ai-security-middleware`:

```powershell
.\.venv\Scripts\python.exe -m scripts.run_agent_demo
.\.venv\Scripts\python.exe -m pytest -q
```

The first command requires Ollama to be running locally. The second uses a fake client and does not need the model service.

## Run and test Milestone 3

```powershell
.\.venv\Scripts\python.exe -m scripts.run_controlled_tools_demo
.\.venv\Scripts\python.exe -m pytest -q
```

The demonstration creates synthetic SQLite files in `runtime_data`, which Git ignores. If Windows blocks Pytest's default temporary folder, use `python -m pytest -q --basetemp .pytest-tmp`.

## Run and test Milestone 4

```powershell
.\.venv\Scripts\python.exe -m scripts.run_gateway_demo
.\.venv\Scripts\python.exe -m pytest -q --basetemp .pytest-tmp
```

The gateway demonstration runs one allowed document read and one blocked message request. It does not need Ollama.

## Run and test Milestone 5

```powershell
.\.venv\Scripts\python.exe -m scripts.run_secure_retrieval_demo
.\.venv\Scripts\python.exe -m pytest -q --basetemp .pytest-tmp
```

The demonstration shows a passing document, a sanitized instruction, and a held document with a local review ID.

## Planned Windows setup

Milestone 1 uses Python 3.14 with Pydantic v2. FastAPI, Streamlit, and Pydantic support this Python version. The exact setup and verification commands are in [SETUP_AND_INSTALLATION.md](SETUP_AND_INSTALLATION.md).

## Development principles

- Work one milestone at a time and keep the application runnable after each code milestone.
- Use a virtual environment once its version/dependency plan is approved.
- Keep local data and secrets out of Git; add ignore rules when runtime files are introduced.
- Use fixed functions for filesystem/database/outbox access; no arbitrary shell, Python, SQL, real messaging, or unrestricted network execution.
- Validate inputs, authorize independently, bound time and size, and audit decisions/outcomes.
- Update docs and tracker with every meaningful code or policy change.

## Adding a tool (planned process)

1. Write down its purpose, exact schema, allowed resources, limits, and denial cases.
2. Implement a narrow function that performs only that operation.
3. Add it to the explicit allowlist and permission mapping.
4. Route it through the same gateway and controlled executor as every other tool.
5. Add tests for valid, malformed, unauthorized, and boundary inputs.
6. Update architecture, security model, learning guide, run instructions, and tracker.

## Adding a security rule (planned process)

Describe the threat and policy first. Add positive and negative examples, including benign content that resembles an attack. Keep content classification separate from action authorization. Do not claim effectiveness beyond the cases actually tested; log the rule/reason without unnecessarily storing private text.

## Git basics

Work in the repository root `D:\Mini_project\ai-security-middleware`. Use the branch and review process in [TEAM_WORKFLOW.md](TEAM_WORKFLOW.md). Do not commit model files, local databases, credentials, or generated private content.
