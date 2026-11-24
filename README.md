# Prompt Security Middleware

**Experimental · English text · Windows x64**

This middleware screens prompts before a supported agent receives them. The
standalone detector combines deterministic rules and the pretrained Horizon
Small neural network, running locally through ONNX Runtime. It uses SQLite
for audit events and a native Rust dashboard for inspection and review.
The detector works offline. The answering agent uses its own authentication,
tools, and model connection.

This README and the [dashboard README](rust-dashboard/README.md) describe
the current checkout. Linked guides provide setup and implementation details.

## What happens to a prompt

1. The inspector validates and normalizes the text and checks for recognized
   override lines, sensitive-data directives, and suspicious encoded content.
2. **PASS** releases the inspected text. **SANITIZE** removes a line identified
   by a rule and releases the remainder only if it passes reinspection,
   including the local Horizon check. **HOLD_FOR_REVIEW** withholds unresolved
   or high-risk content and can also indicate an unavailable detector.
3. Horizon supplies a document-level risk signal. Exact flagged excerpts in
   the dashboard come from rule matches. A model-only hold may have no exact
   excerpt.

Tool permissions are separate from text inspection. The repository contains
an experimental action gateway for selected operations. It is not enforced
across all connected agents.

## Ways to connect

| Integration | Current behavior |
| --- | --- |
| **Protected editor chat (ACP)** | Use an editor such as Zed with Antigravity (`agy acp`) or the Codex ACP adapter (`codex-acp`). Text prompts pass or are sanitized before reaching the agent. The same conversation stays open across turns. A held turn can receive a revised draft from the Rust dashboard. |
| **Native Codex and Antigravity hooks** | Workspace hooks enforce blocks and can show a cleaned preview for typed prompts. Submit the cleaned version in a new chat. These hooks cannot substitute text in the original turn. Codex also screens supported post-tool results. |
| **Protected CLI launcher** | `Open Protected Agent.cmd` screens one prompt and starts a fresh CLI turn with the accepted text. Enter `/send` to submit multiline input. |
| **Local HTTP sanitizer** | `Open Sanitizer.cmd` starts the loopback service. A client calls `POST /api/sanitize` and can forward the returned messages after release. The endpoint does not call an answering model. |
| **Python integration** | Applications can use `ContentInspector` or the model-facing `PromptSecurityMiddleware` at a boundary they control. |

ACP currently accepts text prompt blocks. Attachments, tool results, and
agent permissions are outside ACP prompt screening. Native hooks cover only
the events provided by each host. Hook trust and coverage are described in
the [agent hook guide](docs/AGENT_HOOKS.md).

### In-app Protected Send development

The [Windows overlay prototype](native-overlay/README.md) targets the existing
Antigravity composer. It provides a separate local draft buffer over the input
area. The experimental **Try native composer** mode uses the original input
box when the companion can verify the active chat, draft, and Send control.
The local Windows x64 GUI installer bundles the offline worker and dashboard.
All 15 [demo prompts](docs/PROMPT_SECURITY_DEMO.txt) matched their expected
inspection outcomes against the rebuilt bundled worker. Native Antigravity
interception and delivery are still unverified.

The [Antigravity connector prototype](integrations/antigravity/README.md)
adds a separate draft panel within the official app. Its local connector
service shares the Rules + Horizon policy and the dashboard review store.
Each host connector must bind a submission to the intended conversation
and verify delivery through that host's supported interface. The stock
composer remains a separate path. Antigravity live delivery and a native
Codex connector remain separate acceptance checks.
See the [connector contract and acceptance checks](docs/PROTECTED_SEND_CONNECTORS.md).

## Windows setup

Use the all-in-one Windows x64 ZIP built for the version you want to test.
GitHub Actions artifacts reflect the revision that built them. Check that
the bundled setup guide describes the features you need. The current x64
bundle expects Windows Python **3.14** and includes the Horizon files and
Python dependency wheels.

1. Extract the full ZIP into a fresh folder and run **Setup.cmd**.
2. Setup installs without a menu or workspace and registers user-level hooks
   for detected Antigravity and Codex installations. It attempts to install
   the experimental Antigravity panel when `agy` is available. Codex requires
   reviewing and trusting new hooks in the app. For the optional ACP editor
   integration, the editor supplies the workspace at runtime. Use the
   [ACP example in the bundle guide](packaging/OFFLINE_DETECTOR.md#protected-chat-in-an-acp-editor)
   to add the protected agent to your editor. The selected agent CLI or ACP
   adapter must be installed and authenticated separately.
3. **Configure Workspace Hooks.cmd** is available for explicit project-level
   setup. Existing project and user hooks can both run, so avoid installing
   the same guard at both scopes for one project.
4. Open **Open Dashboard.cmd** from the same bundle. It reads
   `runtime_data/security_events.db`.

**Uninstall.cmd** disconnects workspace hooks recorded by the installer and
removes managed bundle files while preserving the audit database. Remove any
custom ACP editor entry you added manually.

## Reviewing a held ACP turn

The dashboard distinguishes **Malicious · Blocked** (an explicit hard-block
rule, no release) from **Uncertain · Held for review** (a hold without a
hard-block match). This policy applies to the protected ACP adapter,
one-shot launcher, and offline native prompt hooks.

Open the held event in the dashboard, write a revised draft, and click
**Recheck and send** within two minutes. The adapter ties the draft to the
waiting ACP turn and rechecks it before forwarding. A canceled or expired
review cannot be sent. If the revision is still held, submit a new draft via
the editor. Native hook events offer **Copy for resubmission** instead.

Held and sanitized typed prompts can be stored in the local database along
with their rule matches and cleaned text. Treat that database as sensitive.

## Classifier evaluation

The shipped Horizon model is pretrained. Earlier local models trained on
PromptShield and deepset were experiments. See [dataset decisions](docs/DATASET_DECISIONS.md)
for the training and evaluation split.

The [saved English regression report](docs/offline_detector_evaluation.json)
contains 1,811 examples after removing 22 repeats: 240 Horizon boundary
pairs, 339 NotInject prompts, 1,054 InjecAgent base cases, and 178 BIPIA clean
contexts.

| Configuration | Accuracy | Precision | Recall | F1 |
| --- | ---: | ---: | ---: | ---: |
| Rules only | 36.33% | 81.82% | 2.30% | 4.47% |
| Rules + Horizon | 84.32% | 95.50% | 79.56% | 86.80% |

Both a hold and a sanitization count as detections. This public regression
suite measures detection and recorded decisions. It yielded zero combined
sanitizations, so use the redaction smoke tests to demonstrate cleanup.
Overall accuracy is below the 90% target. Upstream training overlap is unknown,
and the indirect benign and attack cases come from different sources.

Re-run the evaluation from the repository root once the local model, datasets,
and development dependencies are installed:

```powershell
.\.venv\Scripts\python.exe -m scripts.evaluate_offline_detector --model-dir models/pretrained/horizon-small --output offline-evaluation-demo.json
```

See [dataset import](docs/DATASET_IMPORT.md) and [Horizon setup](docs/HORIZON_SETUP.md).

## Verification and remaining work

- Local verification covered the Windows ACP stdio bridge with a real Horizon
  model and simulated agent, same-conversation reviewed release, hold
  cancellation, and rejected drafts. The focused run passed **23 Python tests**
  and **2 Rust tests**.
- The ACP installer was verified from a fresh extracted ZIP with no workspace
  registration. The tests did not exercise a live signed-in Antigravity or
  Codex session in Zed.
- Next work includes a live two-agent smoke test, broader indirect-content
  coverage, pre-execution tool-call authorization, audit retention controls,
  and independent evaluation on fresh data.

```powershell
.\.venv\Scripts\python.exe -m pytest tests/test_acp_guard.py tests/test_agent_hooks.py tests/test_protected_agent.py tests/test_bundle_uninstall.py -q
cargo test --locked --manifest-path rust-dashboard/Cargo.toml
```

## Project guides

- [Architecture](docs/ARCHITECTURE.md) and [security model](docs/SECURITY_MODEL.md) explain the active boundaries and remaining risks.
- [Scope](docs/PROJECT_SCOPE.md), [roadmap](docs/IMPLEMENTATION_ROADMAP.md), and [tracker](docs/PROJECT_TRACKER.md) distinguish implemented features, verified checkpoints, and open work.
- [Windows setup](docs/STANDALONE_SETUP.md), [native hook setup](docs/AGENT_HOOKS.md), and [manual testing](docs/MANUAL_TESTING.md) cover setup and live checks.
- [Evaluation summary](docs/PROMPT_INJECTION_EVALUATION.md) links the current offline report and earlier model experiments.

## Contribution and branch policy

Make changes on a new branch and test them before pushing for review. Merge
into main only after review and explicit approval. Keep credentials, model
weights, local datasets, and runtime databases out of commits. See
[development](docs/DEVELOPMENT.md) for the repository workflow.
