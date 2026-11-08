# Setup and Installation

## Status

The Python environment is verified. Ollama installation and local-model verification are in progress.

## Verified Python setup

Run these commands from the repository root in PowerShell:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python -m pip check
```

The virtual environment keeps this project's packages separate from other Python work on the computer. The dependency check confirms that installed packages have compatible requirements.

The verified environment uses Python 3.14 and these direct dependencies:

- FastAPI 0.136.3
- Pydantic 2.14.3
- Uvicorn 0.54.0
- Streamlit 1.67.0
- Pytest 9.2.0

## Ollama installation and model download

After the downloaded Ollama installer completes, install it and open a new PowerShell window. From the repository root, verify the command and download the required local model:

```powershell
ollama --version
ollama pull qwen3.5:4b
ollama list
```

`ollama pull qwen3.5:4b` downloads the model once. It may take time depending on the internet connection. Do not use a cloud-tagged model for this project.

The model is verified on the development computer: Ollama 0.40.15 lists `qwen3.5:4b` as a 4.2B Q4 model using 3.3 GB of disk space. A local Python request returned `LOCAL_MODEL_OK`, and the model generated a `get_document` proposal with the expected `document_id`. During the check, Ollama reported 97% CPU and 3% GPU use. This confirms it runs locally; it does not establish a performance benchmark.

To repeat the project verification:

```powershell
.\.venv\Scripts\python.exe scripts\verify_ollama.py
```

## Planned prerequisites

The confirmed guide will cover Windows, Git, VS Code, a compatible Python release, Ollama, and sufficient disk space for the chosen model. It will link only to official download pages and explain the purpose of each dependency.

## Planned setup flow

1. Clone the repository and inspect its files.
2. Create and activate a Python virtual environment.
3. Install pinned project dependencies.
4. Install and verify Ollama.
5. Download and verify the selected local model.
6. Configure local paths and non-secret settings.
7. Initialize synthetic sample data.
8. Run the backend, interface, and test suite.

Commands for the backend, dashboard, local data initialization, and tests will be added with the components that introduce them.

## Repository hygiene

Never commit credentials, local databases containing private data, model files, or `.env` files. The project will use synthetic data for demonstrations and security tests.
