# Security Dashboard

**Status: experimental — Windows is the current primary target.**

This native Rust desktop application displays the middleware's SQLite audit
events and lets a reviewer submit edited text to a waiting ACP chat. The
dashboard uses eframe/egui for the interface and rusqlite for database access.
Existing events can be viewed independently of Python or an agent. The
middleware must be running to capture new events or recheck a review draft.

## Run on Windows

In the all-in-one x64 bundle, run **Setup.cmd** and then **Open Dashboard.cmd**.
The bundle uses `runtime_data/security_events.db`. Configure your ACP editor
to use that same path. **Setup.cmd** installs without a workspace path.
**Configure Workspace Hooks.cmd** connects a specific project to the bundle.

Open the built executable, or provide a specific database path:

```powershell
.\security-dashboard.exe --db C:\path\to\security_events.db
```

To print counts without opening a window:

```powershell
.\security-dashboard.exe --summary --db C:\path\to\security_events.db
```

The application searches for a database in this order:

1. The path passed with `--db`.
2. The `AI_SECURITY_MIDDLEWARE_AUDIT_DB` environment variable.
3. `runtime_data/security_events.db` in the current directory or beside the executable.
4. `%USERPROFILE%\.ai-security-middleware\security_events.db`.

You can paste another database path into the window or drop a database file on
the window. The view refreshes in the background. Select an outcome card for a
quick filter, or combine outcomes with a time range, event type, or recorded
verdict. Search matches case IDs, reasons, and stored details such as prompts
and rule names. The case list shows the newest 200 matching records and reports
the total matching count. Overview counts remain all-time for the open
database.

For Protected Send events, **Sanitized** records a successful text inspection
and rewrite. Check the companion notification and the Antigravity message
bubble to validate delivery. The dashboard records inspection before the
companion attempts to send.

## Prompt review

Select an event to see the original prompt, exact rule matches if available,
and the cleaned text if the inspector produced it. Horizon supplies a risk
signal for the text as a whole. An event can be held without an exact match.
Older events and integrations that log only metadata may have no prompt text.

**Malicious · Blocked** means an explicit hard-block rule matched. That
event has no release action. **Uncertain · Held for review** means the text
was withheld without a hard-block rule match. A live ACP hold can accept a
revised draft for reinspection. The dashboard keeps older withheld events
in a separate bucket because their records lack the new classification.

- **Held ACP turn:** Enter a revised draft and click **Recheck and send**
  within two minutes. The dashboard queues the draft. The adapter rechecks it
  and submits it to the same conversation if approved by inspection. An
  expired or canceled turn cannot accept a draft.
- **Native workspace hook:** Use **Copy for resubmission** for the cleaned
  text or an edited draft, then submit it in a new chat. The native hook
  cannot resume the original turn.

Prompt content and rule matches can be retained in the local database. Treat
it as sensitive and keep it out of source control. Uninstall preserves it.

The summary counts recorded audit events and inspection outcomes; it does not
claim that every withheld event is a confirmed attack. A withheld event can
represent an uncertain verdict or a detector outage.

## Build and test

From the repository root, with a Rust toolchain installed:

```powershell
cargo build --release --locked --manifest-path rust-dashboard/Cargo.toml
cargo test --locked --manifest-path rust-dashboard/Cargo.toml
```

The executable is written below `rust-dashboard\target\release\`.

## Scope

The dashboard leaves inspection, release decisions, and tool permissions to
the middleware and agent. The ACP review flow was tested against a simulated
agent. A live review in a signed-in editor session remains to be verified.
See the [project README](../README.md) for supported integrations and tests.
