# Offline detector bundle for Windows

The bundle contains the Python package, its installation wheels, and the pinned
Horizon Small model. After extraction, detector installation and inference run
locally. The connected agent still uses its usual answering model.

## Install from an extracted bundle

Extract the entire ZIP to a permanent folder and double-click **Setup.cmd**.
Setup installs dependencies from the ZIP and verifies local classifier
inference. It requires no menu selection or workspace. It registers user-level
hooks for detected Antigravity and Codex installs, and attempts to install the
Antigravity panel if `agy` is available. Restart the agent and review the hook
trust prompt if the app requires it. **Configure Workspace Hooks.cmd** remains
available for explicit project-level setup. Keep the extracted files in place because the integrations
refer to their paths.

Double-click **Open Dashboard.cmd** in the same folder. Setup configures
each workspace to record new screening decisions in the shared audit database
at `runtime_data/security_events.db`. Run **Configure Workspace Hooks.cmd**
again for any workspace configured with an earlier bundle to update its hooks.

The launcher requires the Windows CPython version listed in
`python-version.txt`, the Python launcher, and a wheelhouse matching the
machine architecture. For scripted setup, use `setup_detector.ps1`, pass
`-Acp` to install the runtime without touching user hooks, or use
`setup_detector.ps1 -Agent codex -Workspace 'C:\path\to\workspace'`.

## Experimental Antigravity Protected Send

Setup looks for the Antigravity CLI in its standard Windows install folder
and on PATH. When it is missing, Setup still registers the native hook.
**Install Antigravity Panel.cmd** can retry that step later. In the official Antigravity app, open
**Protected Send** beside a conversation from its Plugins menu. See
[the panel guide](antigravity-panel/README.md). The panel was tested against
simulated hosts, and live Antigravity delivery remains unverified.
Disable or uninstall the panel in Antigravity before uninstalling the bundle.

### Manual installation

Use the Python version and processor architecture used to build the wheelhouse.
The example targets 64-bit Windows with CPython 3.14. Open PowerShell in the
extracted folder and replace the package version with the version shipped in
`wheels`, if different:

```powershell
py -3.14 -m venv .venv
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

For automatic submission, install and sign in to the Codex or Antigravity CLI
and make `codex` or `agy` available on PATH. Open **Open Protected Agent.cmd**,
choose the CLI and workspace, paste your prompt, and enter `/send` on its own
line. The launcher screens locally and starts a fresh CLI turn with the
accepted text. When redaction succeeds, it sends the cleaned text. A hold
stops before starting the CLI. The launcher writes its decision to the same
database as the dashboard. Native desktop hooks still offer a cleaned preview.

## Protected chat in an ACP editor

Use an ACP editor such as Zed for a conversation that stays open across turns.
Install and sign in to the Antigravity CLI first. For Codex, install the
Codex ACP adapter as `codex-acp` on PATH and authenticate as required by that
adapter. Run **Setup.cmd** in the extracted bundle. This installs the Python
dependencies without asking for a
workspace. The editor supplies the project folder when you start a chat.
Add a custom agent in the editor. In Zed, merge this entry into the existing
`agent_servers` settings, replacing the sample path with your extracted folder:

```json
{
  "agent_servers": {
    "Protected Antigravity": {
      "type": "custom",
      "command": "C:/Prompt-Security/.venv/Scripts/python.exe",
      "args": [
        "-m", "security_middleware.acp_guard", "--agent", "antigravity",
        "--model-dir", "C:/Prompt-Security/model",
        "--audit-db", "C:/Prompt-Security/runtime_data/security_events.db"
      ]
    }
  }
}
```

Choose **Protected Antigravity** in the agent panel. For Codex, give the entry a
different name and change the agent argument to `codex`. Open the Rust
dashboard from that same bundle. Passes and successful redactions are forwarded
automatically. When a message is held, select its dashboard event, enter revised
text, and click **Recheck and send** within two minutes. The guard rechecks
the draft and keeps the original conversation ID. Cancelling the turn or
closing the connection prevents a later release. Only text prompt blocks are
supported. Other ACP traffic, including tool results and permissions, uses the
agent's existing handling. Held and redacted text is stored locally for review.

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
