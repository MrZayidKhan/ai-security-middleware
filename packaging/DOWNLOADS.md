# Install the middleware and Windows dashboard

The middleware is a Python package. The Rust dashboard is a separate native
Windows application that reads local SQLite audit logs. Either can be used
without a repository checkout.

## Choose a download

For the combined Windows x64 package, download
`distribution-all-in-one-windows-x64` from a successful GitHub Actions run.
Extract the inner ZIP and run **Setup.cmd**. It includes the detector,
dashboard, sanitation service, and uninstaller. The package uses Python 3.14.

- For a versioned build, open the repository's **Releases** and download the
  Python wheel and a `security-dashboard-windows-*` ZIP archive.
- For a branch build, open **Actions → Build, test, and package**, choose a
  successful Windows run, and download `distribution-python` and the Windows
  dashboard artifact.

The current release workflow produces Windows x64 and Windows ARM64 dashboard
archives. macOS and Linux builds are intentionally disabled while the Windows
workflow is being stabilized and will be added back later.

## Install the middleware

Use Python 3.10 or newer. In PowerShell, create a virtual environment and use
the exact wheel filename you downloaded:

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install .\ai_security_middleware-0.1.0-py3-none-any.whl
```

For the local HTTP gateway, install the gateway extra instead:

```powershell
.\.venv\Scripts\python.exe -m pip install ".\ai_security_middleware-0.1.0-py3-none-any.whl[gateway]"
```

The optional local verifier and its model files are installed separately. The
wheel contains no model weights or datasets.

In the workspace you want to protect, configure the applicable agent:

```powershell
ai-security-middleware install codex
ai-security-middleware install antigravity
```

Approve the generated command hooks in the agent's UI before using them. The
guard screens only the text exposed by those hooks. See the repository's
[agent setup guide](https://github.com/MrZayidKhan/ai-security-middleware/blob/main/docs/AGENT_HOOKS.md)
for coverage and verification status.

To include hook decisions in the dashboard, add
`--audit-db <absolute-path-to-security_events.db>` to the install command and
use the same file when launching the dashboard.

## Run the gateway and dashboard

Start the installed local gateway in PowerShell:

```powershell
ai-security-middleware-serve --detector english-verifier
```

Unpack and open **security-dashboard.exe**. The dashboard can read the
installed gateway's per-user database at
`%USERPROFILE%\.ai-security-middleware\security_events.db`. Use the dashboard's
database selector or launch it with `--db PATH` if you configured a different
location.

From a Windows checkout with a compiled dashboard, double-click
**Start Security Dashboard.cmd**. The dashboard reads events but does not
enforce screening itself.

## Validate a Windows build

- Confirm `/health` on the local gateway returns the intended detector.
- Send a benign message through the protected application and check for an
  inspection and forwarding event in the dashboard.
- Send a harmless injection fixture and verify that it produces a hold event
  with no forwarding event.
- Use only Windows artifacts from a successful Windows workflow run.
- Verify downloaded files with PowerShell:

```powershell
Get-FileHash .\security-dashboard-windows-x64.zip -Algorithm SHA256
```

Versioned releases include `SHA256SUMS.txt` when release publishing is enabled.
