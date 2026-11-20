# Security Dashboard

**Status: experimental — Windows is the current primary target.**

This native Rust desktop application is a read-only viewer for the middleware's
SQLite audit database. It can run independently of Python, a browser, or the
gateway. A gateway or an audited agent workspace must run separately to create
new events.

## Run on Windows

In the all-in-one x64 bundle, run **Setup.cmd** and then **Open Dashboard.cmd**.
Setup gives the workspace hooks and dashboard the same audit database.

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
the window. The view refreshes in the background and supports decision/type
filters plus event details.

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

The dashboard displays recorded decisions; it does not inspect prompts, grant
permissions, execute tools, or replace the middleware policy engine. Packaging
for additional operating systems is part of the next phase after the Windows
workflow is stable.
