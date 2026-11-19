# Install the guard and dashboard

The guard runs as a Python package. The Rust dashboard is a separate native
application that reads local audit logs. Either can be installed without a
repository checkout.

## Choose your downloads

- For a versioned build, open the repository's **Releases** and download the
  Python wheel and dashboard archive for your OS and architecture.
- For a branch build, open **Actions → Build, test, and package**, choose a
  successful run, and download **distribution-python** and your platform's
  **distribution-dashboard** artifact. Unpack the Actions ZIP before unpacking
  the dashboard archive inside it.

Dashboard archives target Windows, macOS, and Linux on x64 and ARM64. Linux
builds target Ubuntu 22.04 or compatible newer desktop distributions using
glibc and an OpenGL-capable X11 or Wayland session. macOS builds target macOS
12 or newer. The archive contains an unsigned build. Follow your
organization's software-verification policy if the OS shows a publisher
warning.

## Install the guard

Use Python 3.10 or newer. Create and activate a virtual environment and run
the following with the exact wheel filename you downloaded:

    python -m pip install ai_security_middleware-0.1.0-py3-none-any.whl

For the local HTTP gateway, install the gateway extra instead:

    python -m pip install "ai_security_middleware-0.1.0-py3-none-any.whl[gateway]"

Download and start Ollama separately for Qwen-backed screening. Install the
local model with `ollama pull qwen3.5:4b`. The guard's default setup uses the
local model. The wheel contains no model weights or datasets.

In the workspace you want to protect, configure the applicable agent:

    ai-security-middleware install codex
    ai-security-middleware install antigravity

Approve the generated command hooks in the agent's UI before using them.
The guard screens only text the agent exposes to those hooks. See the
repository's [agent setup guide](https://github.com/MrZayidKhan/ai-security-middleware/blob/main/docs/AGENT_HOOKS.md)
for hook coverage and verification status.

To include hook decisions in the dashboard, add
`--audit-db <absolute-path-to-security_events.db>` to the install command.
Choose the same file that the dashboard reads.

## Run the gateway and view its audit log

Start the installed local gateway:

    ai-security-middleware-serve --detector english-verifier

Unpack and open **security-dashboard.exe** on Windows, **Security
Dashboard.app** on macOS, or **security-dashboard** on Linux. The dashboard
can read the installed gateway's per-user database at
`~/.ai-security-middleware/security_events.db`. Use the dashboard's database
selector or launch the binary with `--db PATH` if you configured a different
location. The gateway creates the database on startup. Events appear after
clients submit requests through the gateway. The dashboard reads events and
does not enforce screening.

On supported Debian or Ubuntu desktops, install `libgl1`, `libxkbcommon0`,
`libwayland-client0`, `libx11-6`, `libx11-xcb1`, `libxi6`, `libxcursor1`, and
`libxrandr2` if your installation does not already provide those libraries.

Only versioned releases include **SHA256SUMS.txt**. On Linux you can verify
downloaded archives against that file using `sha256sum -c SHA256SUMS.txt`.
Verify individual files on Windows with `Get-FileHash -Algorithm SHA256`
or on macOS with `shasum -a 256`, and compare against the corresponding
entries in the manifest.
