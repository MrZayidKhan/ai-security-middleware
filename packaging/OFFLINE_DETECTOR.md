# Offline detector bundle for Windows

The bundle contains the Python package, its installation wheels, and the pinned
Horizon Small model. After extraction, detector installation and inference run
locally. The connected agent still uses its usual answering model.

## Install from an extracted bundle

Extract the entire ZIP to a permanent folder and double-click **Setup.cmd**.
Choose **Codex** or **Antigravity** and enter the existing workspace folder.
Setup installs dependencies from the ZIP, checks that the classifier runs,
and writes the agent's workspace hook configuration. Reopen the workspace
and enable the generated hooks in your agent. Run Setup again to connect
another workspace. Keep the extracted files in place because the hooks refer
to them.

Double-click **Open Dashboard.cmd** in the same folder. Setup configures
each workspace to record new screening decisions in the shared audit database
at `runtime_data/security_events.db`. Run Setup again for any workspace
configured with an earlier bundle to update its hooks.

The launcher requires the Windows CPython version listed in
`python-version.txt`, the Python launcher, and a wheelhouse matching the
machine architecture. For scripted setup, run
`setup_detector.ps1 -Agent codex -Workspace 'C:\path\to\workspace'`.

### Manual installation

Use the Python version and processor architecture used to build the wheelhouse.
The example targets 64-bit Windows with CPython 3.13. Open PowerShell in the
extracted folder and replace the package version with the version shipped in
`wheels`, if different:

```powershell
py -3.13 -m venv .venv
.\.venv\Scripts\python.exe -m pip install --no-index --find-links .\wheels 'ai-security-middleware[gateway]==0.1.0' onnxruntime tokenizers numpy
```

Keep the extracted folder in a stable location. Resolve the model folder and
installed command before changing into your agent workspace:

```powershell
$detectorModel = (Resolve-Path .\model).Path
$detectorCommand = (Resolve-Path .\.venv\Scripts\ai-security-middleware.exe).Path
Set-Location 'C:\path\to\agent-workspace'
& $detectorCommand install codex --detector offline --model-dir $detectorModel
```

Use `antigravity` in place of `codex` for that integration. Follow the agent's
workspace hook enablement flow. The archive includes the model license and
upstream model card in `model`. Horizon Small is an experimental classifier.

## Sanitize or uninstall

Run **Open Sanitizer.cmd** to start the loopback screening service. Clients
that can replace model-bound text can use `POST /api/sanitize` and forward the
returned messages only after a successful response. The native workspace
hooks withhold requests that require sanitation.

Close the agent, dashboard and sanitizer, then run **Uninstall.cmd**. It
disconnects the workspaces recorded by this installation and removes managed
bundle files. Your audit database remains in `runtime_data`. For workspaces
configured by an older installer, rerun Setup first to register them.

## Build a bundle from the repository

On a connected Windows packaging machine with Python 3.13, build a clean
middleware wheel and use an empty wheelhouse directory. Supply the checked-out
version of the wheel and the pinned Horizon directory. Consult the repository's
Horizon setup guide for the model provenance and download procedure. Add the
[upstream base-model attribution notice](https://huggingface.co/Horizon-Labs/prompt-injection-guard-small/blob/1b7c40f/NOTICE)
as `NOTICE` in that directory before packaging. Preserve its attribution and
license terms when distributing the bundle.

```powershell
py -3.13 -m build --wheel --outdir .\dist\offline-build
py -3.13 -m pip wheel --wheel-dir .\dist\offline-wheelhouse --only-binary=:all: '.\dist\offline-build\ai_security_middleware-0.1.0-py3-none-any.whl[gateway]' 'onnxruntime==1.32.0' 'tokenizers==0.23.3' numpy
py -3.13 .\packaging\package_offline_detector.py --model-dir .\models\pretrained\horizon-small --wheelhouse .\dist\offline-wheelhouse --dashboard .\rust-dashboard\target\release\security-dashboard.exe --output .\dist\offline-detector-windows-x64-py313.zip
```

Use clean repository wheel output and verify the wheelhouse with the offline
install command in a fresh virtual environment before distribution. The packager
checks the model and tokenizer against pinned SHA-256 hashes and retains the
upstream license, model card, and notice. Build separately
on each supported architecture and Python version.
