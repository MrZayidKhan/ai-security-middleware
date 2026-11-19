# Project Objectives and Scope

The project builds an installable security layer for AI agents. It evaluates untrusted text at the points an integration controls and withholds suspicious text before the answering model receives it. Users can install the Python package from a Git clone or wheel and enable it in a supported workspace. The local Ollama application provides a separate environment for demonstrating the inspection, review, and action controls.

## Objectives and acceptance criteria

| Objective | Acceptance evidence |
| --- | --- |
| Make the guard portable | Build a wheel from a clean checkout. Install from source and wheel on Windows, macOS, and Linux without relying on repository-specific paths. |
| Protect supported agent context | In a live Codex and Antigravity workspace, submit a benign prompt and a harmless injection fixture. Verify that the benign turn proceeds and the held prompt is never sent to the answering model. In Codex, separately verify that a held result from a supported tool is replaced before the next model call. |
| Keep content decisions separate from tool authority | Verify that passing inspection or approving an excerpt cannot grant permission to execute a disallowed action. Exercise this against the controlled local tool gateway. |
| Assess effectiveness and usability | Report false positives, missed injections, sanitization outcomes, and latency on labeled direct and indirect text cases. Record the detector configuration and keep functional tests separate from accuracy measurements. |

## Supported surfaces

| Surface | Current scope |
| --- | --- |
| Codex | Workspace hooks inspect typed prompts and tool results delivered to `PostToolUse`. The hook withholds text requiring sanitization or review. A withheld tool result is replaced with feedback. Any side effects from the tool have already occurred. |
| Google Antigravity | Workspace `PreInvocation` hook inspects the latest typed prompt and can stop the model call. The native hook contract does not provide tool result text. |
| Python integration | `PromptSecurityMiddleware` and `SecureChatClient` screen model-bound text at a boundary the application controls. Callers can forward sanitized replacements. |
| Local HTTP and demo application | Bounded text requests to Ollama, protected retrieval from approved documents, exact-excerpt review, local events, and a separate action gateway for the controlled demo tools. |
| Rust analytics dashboard | Native read-only desktop viewer for inspection decisions and audit events from a shared local SQLite database. Can open existing logs without an active model, agent, or gateway. |

The hook package includes a rules mode and defaults to the local Ollama/Qwen assessor. It needs no development dataset or trained artifact. The host agent retains its model and permission controls. The hook package, the English contextual verifier, and the local demo have different configuration and evidence. Results for one do not automatically apply to the others.

## Limits and current verification

- Coverage is opt-in and depends on the events the host runs. Attachments, internal context, and unhooked tool paths are outside coverage. Hook execution failures or timeouts can leave an input unscreened.
- Universal agent compatibility, a browser extension, managed hosting, mobile installers, and operating-system sandboxing are outside the current release. Full tool authorization for third-party agents, comprehensive audit coverage, and automatic recovery of suspended agent sessions remain open.
- The package targets Windows, macOS, and Linux where the agent can run compatible Python command hooks. On Windows, the installed wheel generated working commands for all three supported hook events. Rules-mode fixtures exercised release and block, and Ollama-backed handler checks released benign fixtures for all three events. Live in-app hook trust, invocation, and enforcement in Codex and Antigravity, and macOS/Linux execution still need verification.

The installed gateway supports an explicit audit database path. Agent hooks can
write metadata-only decisions to the same database using their optional audit
flag. See [standalone setup](STANDALONE_SETUP.md) for the Windows, macOS, and
Linux dashboard build targets and how GitHub produces downloads.

See the [agent setup guide](AGENT_HOOKS.md), [security model](SECURITY_MODEL.md), and [project tracker](PROJECT_TRACKER.md).
