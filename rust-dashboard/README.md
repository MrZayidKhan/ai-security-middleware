# Security Middleware Dashboard

This Rust desktop app reads the same SQLite audit database as the middleware.
It starts without Python, Ollama, Node.js, or a browser. Run the gateway or an
audited workspace hook separately to produce new events.

Open the executable, or supply a specific database:

    security-dashboard --db /path/to/security_events.db

The app looks for the database in this order:

1. The path passed with `--db`.
2. The `AI_SECURITY_MIDDLEWARE_AUDIT_DB` environment variable.
3. An existing `runtime_data/security_events.db` in the current directory or
   next to the executable.
4. `~/.ai-security-middleware/security_events.db`.

You can paste another database path in the window or drop its file onto the
window. The dashboard refreshes in the background. Filter the latest 200
matching events by type and decision, then select an event to see its stored
metadata.

The all-time cards count audit events and screening outcomes, not confirmed
attacks. A withheld event can represent an uncertain verdict or detector
outage. An inspection with sanitized text counts once, and later forwarding
and model outcome records do not inflate inspection counts.

To read counts without opening a window:

    security-dashboard --summary --db /path/to/security_events.db

Build from source with a Rust toolchain and a native build environment:

    cargo build --release --locked --manifest-path rust-dashboard/Cargo.toml
    cargo test --locked --manifest-path rust-dashboard/Cargo.toml

The platform executable is under `rust-dashboard/target/release/`.
