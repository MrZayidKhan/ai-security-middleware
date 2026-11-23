# Project Objectives and Scope

The current release focus is experimental English text screening on Windows
x64. An installable Python middleware evaluates text before a supported agent
receives it. The standalone detector uses deterministic rules and pretrained
Horizon Small through ONNX Runtime. The agent supplies the answering model and
decides its tool permissions. See the [project README](../README.md) for setup.

## Objectives and acceptance criteria

| Objective | Acceptance evidence |
| --- | --- |
| Install on Windows | Extract one bundle and complete offline setup. ACP mode creates the runtime and audit database without requiring a workspace. Native hook mode accepts an explicit workspace. |
| Protect a persistent conversation | Submit benign, removable, and held text to one ACP session. The agent receives accepted text only. A reviewed draft must be rechecked, use the same session, and never reach the agent after cancellation or expiry. |
| Demonstrate live interoperability | Run the same flow in a signed-in Antigravity and Codex editor thread. Local verification with a simulated ACP agent is complete. Live signed-in verification remains open. |
| Keep tool authority separate | A text verdict or review release does not authorize a tool. Demonstrate bounded action enforcement in the separate controlled demo. Design and test third-party pre-execution authorization independently. |
| Measure effectiveness | Report accuracy, precision, recall, F1, false decisions, and timing with source counts and held-out policy configuration. Keep functional redaction and workflow evidence separate. |

## Supported surfaces

| Surface | Screening and release |
| --- | --- |
| ACP editor chat | Screens typed text blocks in a persistent session with Antigravity or the Codex ACP adapter. A rule-based rewrite can be delivered automatically. A held turn can accept an edited and rechecked dashboard draft within two minutes. |
| Codex native workspace hooks | Screens typed prompts and supported `PostToolUse` results. A typed turn needing sanitization is withheld and may show a cleaned preview. A withheld tool result is replaced with feedback after the tool has already run. |
| Antigravity native workspace hooks | Screens the latest typed prompt at `PreInvocation`. The hook can block and show a cleaned preview. It cannot replace the original typed turn or see native tool-result text. |
| Protected CLI launcher | One prompt is screened before a fresh agent CLI turn starts. It passes only accepted text and stops on a hold. |
| Offline HTTP sanitizer | Loopback `POST /api/sanitize` screens a bounded request and returns released messages for a caller to forward. It does not call an answering model. |
| Python embedding | `PromptSecurityMiddleware` and `SecureChatClient` enforce configured text inspection where the application owns the model boundary. |
| Rust dashboard | Shows recorded decisions and available prompt evidence from SQLite. It queues a revised draft for a pending ACP turn. It can view saved events without an agent running. |

Compatibility and trust details are in [Agent Hooks](AGENT_HOOKS.md) and the
[bundle guide](../packaging/OFFLINE_DETECTOR.md). A local answering-model demo
with a controlled action gateway remains a separate prototype.

## Limits

- ACP accepts text blocks. Attachments, tool results and tool permissions
  are outside ACP prompt screening. Native hook coverage depends on host
  version, supported events, workspace trust and invocation. A host may
  continue unscreened after a hook failure.
- Automatic cleaned-text substitution is available at the ACP, launcher,
  HTTP caller or Python boundary. Native desktop prompts use the preview and
  resubmit workflow.
- Held and sanitized typed text may be stored in the local audit database.
  Review does not recover a disconnected or expired session.
- Mobile, browser, managed deployment, and macOS or Linux packaging are out
  of current scope. The 90% overall accuracy goal is open. The [saved English
  regression report](offline_detector_evaluation.json) records the measured
  batch and source limitations.

Follow the [architecture](ARCHITECTURE.md), [security model](SECURITY_MODEL.md),
and [project tracker](PROJECT_TRACKER.md) for the current state and remaining
work.
