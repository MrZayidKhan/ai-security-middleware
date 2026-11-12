# AI Agent Security Middleware

College mini-project: **Development of AI Agent Security Middleware for Prompt Injection Detection and Unsafe Action Prevention**.

## Purpose

This project will build a local security layer between an AI agent and a small set of approved tools. The model may propose an operation, but the application must validate and authorize it before execution. Retrieved text is treated as untrusted input and can be passed, sanitized, or held for review.

The project has a working local security path and dashboard. See [the project tracker](docs/PROJECT_TRACKER.md) for verified status and acceptance criteria.

## Intended architecture

```mermaid
flowchart TD
  U[User interface] --> A[Local agent]
  A --> P[Parse and validate proposal]
  P --> G[Action security gateway]
  G -->|Block| L[Audit record]
  G -->|Allow| E[Controlled executor]
  E --> L
  E --> C[Content inspection of returned data]
  C -->|Pass / sanitize| A
  C -->|Hold| H[Human review queue]
  H --> A
```

The model will not receive direct access to the filesystem, database, or message delivery. Initial tools are intended to search/read approved documents, query records through fixed functions, and save drafts to a simulated local outbox. This is an application-level gateway, not an operating-system sandbox.

## Intended technology stack

Python, Ollama with `qwen3.5:4b`, Pydantic, FastAPI, SQLite, Streamlit, and Pytest. The local environment, model, security components, and dashboard are implemented for the current checkpoint. FastAPI integration, full model-to-tool integration, and measured detector evaluation remain pending.

## Repository contents

```text
ai-security-middleware/
├── README.md
├── app.py
├── security_middleware/
│   ├── agent_loop.py
│   ├── action_gateway.py
│   ├── audit_log.py
│   ├── content_assessor.py
│   ├── content_protection.py
│   ├── controlled_tools.py
│   ├── demo_tools.py
│   ├── models.py
│   ├── review_queue.py
│   ├── ollama_client.py
│   └── secure_retrieval.py
├── docs/
│   ├── ARCHITECTURE.md
│   ├── CONTRIBUTION_GUIDELINES.md
│   ├── DEVELOPMENT.md
│   ├── GIT_AND_GITHUB_GUIDE.md
│   ├── IMPLEMENTATION_ROADMAP.md
│   ├── LEARNING_GUIDE.md
│   ├── PROJECT_TRACKER.md
│   ├── SECURITY_MODEL.md
│   ├── SETUP_AND_INSTALLATION.md
│   ├── TEAM_WORKFLOW.md
│   └── TESTING.md
├── scripts/
│   ├── run_agent_demo.py
│   ├── run_controlled_tools_demo.py
│   ├── run_gateway_demo.py
│   ├── run_secure_retrieval_demo.py
│   ├── verify_content_assessor.py
│   └── verify_ollama.py
├── sample_data/
│   └── documents/
└── tests/
    ├── test_action_gateway.py
    ├── test_agent_loop.py
    ├── test_audit_log.py
    ├── test_content_protection.py
    ├── test_controlled_tools.py
    └── test_secure_retrieval.py
```

## Prerequisites and setup

See [Setup and installation](docs/SETUP_AND_INSTALLATION.md) for the verified local environment commands.

## Current status

- Implemented: local environment, controlled tools, action gateway, hybrid prompt inspection, sanitization, secure document retrieval, local audit storage, and a Streamlit dashboard.
- Verified: Python 3.14; Ollama 0.40.15; `qwen3.5:4b` (4.2B Q4, 3.3 GB); a Python request and structured tool proposal.
- Not implemented: FastAPI API layer, end-to-end model access to controlled tools, complete execution-duration/outcome audit coverage, and broad detector evaluation.

## Run the current demonstration

From the repository root:

```powershell
.\.venv\Scripts\python.exe -m scripts.run_agent_demo
```

The demonstration has one fixed tool, `get_project_status`. It returns text stored in the program and cannot access external resources. Run the current tests with:

```powershell
.\.venv\Scripts\python.exe -m pytest -q
```

Run the controlled local-tool demonstration with:

```powershell
.\.venv\Scripts\python.exe -m scripts.run_controlled_tools_demo
```

Run the gateway demonstration with:

```powershell
.\.venv\Scripts\python.exe -m scripts.run_gateway_demo
```

Run the secure document retrieval demonstration with:

```powershell
.\.venv\Scripts\python.exe -m scripts.run_secure_retrieval_demo
```

Run the local dashboard with:

```powershell
.\.venv\Scripts\python.exe -m streamlit run app.py
```

Open the local address Streamlit prints in PowerShell, usually `http://localhost:8501`.

## Documentation

- [Architecture](docs/ARCHITECTURE.md)
- [Learning guide](docs/LEARNING_GUIDE.md)
- [Implementation roadmap](docs/IMPLEMENTATION_ROADMAP.md)
- [Setup and installation](docs/SETUP_AND_INSTALLATION.md)
- [Git and GitHub guide](docs/GIT_AND_GITHUB_GUIDE.md)
- [Contribution guidelines](docs/CONTRIBUTION_GUIDELINES.md)
- [Security model](docs/SECURITY_MODEL.md)
- [Testing plan](docs/TESTING.md)
- [Team workflow](docs/TEAM_WORKFLOW.md)
- [Project tracker](docs/PROJECT_TRACKER.md)
