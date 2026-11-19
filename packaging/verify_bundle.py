"""Verify the installed wheel and its SQLite contract with the native dashboard."""

import argparse
import json
import os
from pathlib import Path
import socket
import subprocess
from tempfile import TemporaryDirectory
from time import monotonic, sleep
from urllib.error import URLError
from urllib.request import urlopen
from venv import EnvBuilder


def run(*command, cwd, **kwargs):
    return subprocess.run(command, cwd=cwd, check=True, timeout=240, **kwargs)


def reserve_port():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind(("127.0.0.1", 0))
        return listener.getsockname()[1]


def verify_gateway(executable, database, cwd):
    port = reserve_port()
    url = f"http://127.0.0.1:{port}/health"
    log_path = cwd / "gateway.log"
    with log_path.open("w+", encoding="utf-8") as log:
        server = subprocess.Popen(
            [executable, "--port", str(port), "--audit-db", database],
            cwd=cwd,
            stdout=log,
            stderr=subprocess.STDOUT,
        )
        try:
            deadline = monotonic() + 25
            while server.poll() is None and monotonic() < deadline:
                try:
                    with urlopen(url, timeout=1) as response:
                        health = json.load(response)
                    if health.get("service") != "prompt-security-middleware" or health.get("status") != "running":
                        raise RuntimeError(f"Unexpected gateway health response: {health}")
                    if not database.is_file():
                        raise RuntimeError("The gateway did not create the configured audit database")
                    return
                except (URLError, TimeoutError):
                    sleep(0.2)
            log.seek(0)
            raise RuntimeError(f"Installed gateway did not start:\n{log.read()}")
        finally:
            if server.poll() is None:
                if os.name == "nt":
                    # A Windows wheel entry point uses a launcher process.
                    # Stop its worker too so the temporary environment can be removed.
                    subprocess.run(
                        ["taskkill", "/F", "/T", "/PID", str(server.pid)],
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL,
                        timeout=5,
                        check=False,
                    )
                else:
                    server.terminate()
                try:
                    server.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    server.kill()
                    server.wait(timeout=5)


def verify_distribution(wheel, dashboard):
    with TemporaryDirectory(prefix="security-middleware-smoke-") as temp:
        staging = Path(temp)
        env_dir = staging / "venv"
        EnvBuilder(with_pip=True).create(env_dir)
        if os.name == "nt":
            bin_dir, suffix = env_dir / "Scripts", ".exe"
        else:
            bin_dir, suffix = env_dir / "bin", ""
        python = bin_dir / f"python{suffix}"
        installer = bin_dir / f"ai-security-middleware{suffix}"
        gateway = bin_dir / f"ai-security-middleware-serve{suffix}"

        run(python, "-m", "pip", "install", f"ai-security-middleware[gateway] @ {wheel.as_uri()}", cwd=staging)
        run(python, "-m", "pip", "check", cwd=staging)
        database = staging / "logs" / "security_events.db"
        for agent, directory in (("codex", ".codex"), ("antigravity", ".agents")):
            run(installer, "install", agent, "--detector", "rules", "--audit-db", database, cwd=staging)
            if not (staging / directory / "hooks.json").is_file():
                raise RuntimeError(f"The installed CLI did not create {agent}'s configuration")

        verify_gateway(gateway, database, staging)
        print("Installed gateway started and created its configured SQLite audit database.")

        codex = run(
            installer, "hook", "codex-prompt", "--detector", "rules", "--audit-db", database,
            cwd=staging, input=json.dumps({"prompt": "Summarize the schedule."}), capture_output=True, text=True,
        )
        antigravity = run(
            installer, "hook", "antigravity-prompt", "--detector", "rules", "--audit-db", database,
            cwd=staging, input="{}", capture_output=True, text=True,
        )
        if json.loads(codex.stdout) != {} or json.loads(antigravity.stdout).get("terminationBehavior") != "terminate":
            raise RuntimeError("Installed hooks did not release a benign prompt and terminate malformed input")
        print("Installed hooks handled benign and malformed input.")
        if dashboard is None:
            return

        result = run(dashboard, "--db", database, "--summary", cwd=staging, capture_output=True, text=True)
        summary = json.loads(result.stdout)
        expected = {"event_count": 2, "inspections": 2, "passed": 1, "withheld": 1}
        if any(summary.get(key) != value for key, value in expected.items()):
            raise RuntimeError(f"Unexpected dashboard interpretation of the wheel's audit data: {summary}")
        print("Dashboard read and classified the installed hooks' decisions from the shared audit database.")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--wheel-dir", type=Path, required=True)
    parser.add_argument("--dashboard", type=Path)
    args = parser.parse_args()
    wheels = sorted(args.wheel_dir.resolve().glob("ai_security_middleware-*.whl"))
    if len(wheels) != 1:
        parser.error("the wheel directory must contain exactly one project wheel")
    dashboard = args.dashboard.resolve(strict=True) if args.dashboard is not None else None
    verify_distribution(wheels[0], dashboard)


if __name__ == "__main__":
    main()
