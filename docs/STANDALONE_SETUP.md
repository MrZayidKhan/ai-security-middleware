# Standalone gateway and desktop analytics

The Rust dashboard is a separate desktop program that reads the same SQLite
audit file as the gateway or an opted-in agent hook. Open it to review
screening and forwarding decisions, even after the agent or gateway exits.
The dashboard opens the database read-only. Its counts describe recorded
events and screening decisions, not ground-truth attack detection accuracy.

## Download the dashboard and middleware

1. Open the repository's [GitHub Actions runs](https://github.com/MrZayidKhan/ai-security-middleware/actions)
   and choose a successful Windows build. Download the Windows dashboard archive
   matching your CPU. Versioned downloads are also available on
   the [Releases page](https://github.com/MrZayidKhan/ai-security-middleware/releases)
   after a release workflow succeeds.
2. Extract the archive and run **security-dashboard.exe**. Run binaries only
   from a release or build you trust.
3. Select the SQLite database if the dashboard has not already found it. To
   specify it when launching, use **security-dashboard --db PATH**. An empty
   dashboard is normal before anything writes events.

From a Windows checkout with a compiled dashboard, double-click
**Start Security Dashboard.cmd**. The launcher starts in the repository so
the dashboard can find checkout audit events. For a source build, see
[the Rust dashboard README](../rust-dashboard/README.md).

The dashboard alone needs no model. To create events, install the middleware
wheel using Python 3.10 or later and choose one or both routes below.

## Route 1. Run the gateway outside a checkout

Install the downloaded wheel with its **gateway** extra in a Python virtual
environment. Substitute the path to the wheel you downloaded.

    python -m pip install "/path/to/ai_security_middleware-0.1.0-py3-none-any.whl[gateway]"

Start Ollama and make sure it has qwen3.5:4b. In the activated environment run:

    ai-security-middleware-serve --detector english-verifier

The installed gateway listens on **127.0.0.1:8787** and records events to
**.ai-security-middleware/security_events.db** in your home directory. Use
**--audit-db PATH** to write a different file. A checkout launched via
**python -m scripts.run_middleware** defaults to the checkout's
**runtime_data/security_events.db**. The gateway stays local, and the
dashboard can read either file.

Use the Python application client or POST a supported text request to the
gateway. For the graphical Qwen screening demo in the checkout on Windows,
open **Start Protected Qwen Demo.cmd** with Ollama running. The dashboard
does not proxy official Ollama chat messages. See the
[gateway guide](APPLICATION_CONNECTION_ENGLISH.md).

## Route 2. Log agent hook decisions to the dashboard

Activate an environment with the middleware wheel installed. In the agent
workspace, install the appropriate hook using the same absolute database path
that the gateway or dashboard uses:

    ai-security-middleware install codex --audit-db "/absolute/path/to/security_events.db"
    ai-security-middleware install antigravity --audit-db "/absolute/path/to/security_events.db"

Run only the command for the agent you use, then enable the generated command
hooks in that workspace. The default screening assessor relies on local
Ollama. The hooks leave the agent's answering model and permissions untouched.
They record concise decisions, not raw prompt or tool-result text. See the
[hook setup and coverage guide](AGENT_HOOKS.md) for limitations and smoke tests.

## Validate a build

- Confirm **/health** on the local gateway returns the intended detector.
  Health is a process check; it does not contact the answering model.
- Send a benign message through the protected app and look for inspection
  and, when answering is enabled, forwarding/outcome events in the dashboard.
- Run the local integration smoke test and check that withheld test inputs
  produce inspection events with no forwarding event.
- Use only Windows builds from a successful Windows workflow run.

Windows acceptance verified the native dashboard against actual local Qwen
gateway events. The direct and indirect test requests were withheld and the
benign request was forwarded. The dashboard showed two withheld inspections
and one passed inspection. A separate wheel test verified generated hook
commands, their shared audit rows, and benign local Qwen checks for Codex
prompts and tool results and Antigravity prompts. Live host sessions still
need the agent's interactive trust or enablement step. The GitHub platform
matrix still needs its first run on a pushed revision.
