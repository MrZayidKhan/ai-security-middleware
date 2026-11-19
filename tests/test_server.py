import sqlite3

from fastapi.testclient import TestClient
import uvicorn

from security_middleware import server


def test_installed_gateway_uses_selected_audit_db(tmp_path, monkeypatch):
    db = tmp_path / "audit" / "security_events.db"
    monkeypatch.setattr("sys.argv", [
        "ai-security-middleware-serve", "--audit-db", str(db),
        "--detector", "english-verifier", "--port", "8793",
    ])
    launches = []
    monkeypatch.setattr(uvicorn, "run", lambda app, **options: launches.append((app, options)))

    server.main()

    [(app, options)] = launches
    assert options["host"] == "127.0.0.1"
    assert options["port"] == 8793
    with TestClient(app) as client:
        health = client.get("/health").json()
    assert health["detectors"] == "rules+english-contextual-verifier"
    assert health["answer_model"] == "qwen3.5:4b"
    with sqlite3.connect(db) as connection:
        assert connection.execute("SELECT COUNT(*) FROM security_events").fetchone() == (0,)
