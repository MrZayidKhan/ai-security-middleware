# Windows setup and desktop analytics

The current Windows x64 bundle contains the Python middleware, offline model
and wheels, native Rust dashboard, and setup and uninstall scripts. Use the
[bundle guide](../packaging/OFFLINE_DETECTOR.md) for the full procedure.

1. Obtain an all-in-one ZIP for the revision you intend to test. CI artifacts
   reflect the revision that built them. Extract the downloaded ZIP into a new
   folder and use Windows x64 Python 3.14.
2. Run **Setup.cmd** to install without selecting a workspace.
   Run **Configure Workspace Hooks.cmd** separately to connect a specific folder.
3. For ACP, add the protected agent to your editor using the configuration
   example in the bundle guide. Install and authenticate the selected agent's
   CLI or ACP adapter separately. An installed Zed integration still needs
   the protected agent entry to use this middleware.
4. Open **Open Dashboard.cmd** in the same bundle folder. Use that bundle's
   `runtime_data/security_events.db` as the ACP configuration's audit path.

Windows installers are produced by the [GitHub Actions workflow](https://github.com/MrZayidKhan/ai-security-middleware/actions).
Versioned downloads are available after a [release build](https://github.com/MrZayidKhan/ai-security-middleware/releases)
succeeds. An archive built before an implementation change will not contain
that change. The current local ACP installer passed a fresh-extraction smoke
test. Live ACP runs with signed-in agents still need verification.

## Choose a local integration

- **Persistent editor chat:** ACP accepts typed text and forwards accepted
  text in the original session. For a hold, open the event in the dashboard,
  write a draft and choose **Recheck and send** within two minutes.
- **Native agent workspace:** See [agent hook setup and coverage](AGENT_HOOKS.md).
  The original typed turn is blocked when cleanup is required. Use the
  cleaned preview to resubmit in a new chat.
- **Local application:** Start **Open Sanitizer.cmd** and send bounded text
  to `POST /api/sanitize` on `127.0.0.1:8787`. Your application chooses
  whether to forward the released messages to its agent.
- **One-shot CLI:** Start **Open Protected Agent.cmd** and use `/send` to
  submit a single screened prompt. Each launch uses a fresh agent turn.

The standalone detector needs no answering model. The optional legacy
Ollama gateway is documented separately in [application connection](APPLICATION_CONNECTION_ENGLISH.md).

## Locate the audit database

The dashboard can view existing events without a model or gateway. It writes
a review draft when you explicitly submit one for a live ACP turn. For a
standalone dashboard binary, pass a specific file with `--db PATH`. The
`--summary` flag prints counts. See the [dashboard README](../rust-dashboard/README.md)
for discovery order and source builds.

The source launch script `python -m scripts.run_middleware` uses the
checkout's `runtime_data/security_events.db` by default. The installed
gateway defaults to `%USERPROFILE%\.ai-security-middleware\security_events.db`.
Pass `--audit-db PATH` to make tools share a database explicitly.

Counts describe recorded verdicts. A hold can mean uncertainty or detector
failure. Held and sanitized typed text can be stored in the local database.
The uninstaller preserves audit data.
