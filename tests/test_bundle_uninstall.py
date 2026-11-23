"""The Windows bundle uninstaller should preserve independent user hooks."""

import importlib.util
import json
from pathlib import Path

import pytest

from security_middleware.agent_hooks import configure, user_hook_directory


spec = importlib.util.spec_from_file_location(
    "uninstall_detector", Path(__file__).resolve().parents[1] / "packaging" / "uninstall_detector.py"
)
uninstaller = importlib.util.module_from_spec(spec)
spec.loader.exec_module(uninstaller)


@pytest.mark.parametrize("agent", ["codex", "antigravity"])
def test_uninstall_disconnects_owned_hook_and_retains_audit(tmp_path, monkeypatch, agent):
    tmp_path = tmp_path.resolve()
    bundle = tmp_path / "bundle"
    bundle.mkdir()
    registry = bundle / "installed-workspaces.json"
    monkeypatch.setattr(uninstaller, "ROOT", bundle)
    monkeypatch.setattr(uninstaller, "REGISTRY", registry)
    monkeypatch.setattr("builtins.input", lambda _: "UNINSTALL")
    for name in ("model", "wheels", ".venv", "runtime_data"):
        (bundle / name).mkdir()
    (bundle / "model" / "model_quantized.onnx").touch()
    (bundle / "wheels" / "example.whl").touch()
    (bundle / "security-dashboard.exe").touch()
    audit = bundle / "runtime_data" / "security_events.db"
    audit.write_bytes(b"audit history")

    workspace = tmp_path / "workspace"
    event = "UserPromptSubmit" if agent == "codex" else "PreInvocation"
    path = workspace / (".codex" if agent == "codex" else ".agents") / "hooks.json"
    path.parent.mkdir(parents=True)
    owned = {"command": "installed command"}
    unrelated = {"command": "user command"}
    if agent == "codex":
        config = {"hooks": {event: [{"hooks": [owned, unrelated]}]}}
        expected = {"hooks": {event: [{"hooks": [unrelated]}]}}
    else:
        config = {uninstaller.GROUP: {event: [owned]}, "user-hook": {event: [unrelated]}}
        expected = {"user-hook": {event: [unrelated]}}
    path.write_text(json.dumps(config), encoding="utf-8")
    registry.write_text(json.dumps([{
        "agent": agent, "workspace": str(workspace), "commands": {event: owned["command"]}
    }]), encoding="utf-8")

    uninstaller.uninstall()

    assert json.loads(path.read_text(encoding="utf-8")) == expected
    assert audit.read_bytes() == b"audit history"
    assert {item.name for item in bundle.iterdir()} == {"runtime_data"}


@pytest.mark.parametrize("agent", ["codex", "antigravity"])
def test_user_hooks_setup_is_idempotent_and_uninstall_preserves_other_hooks(tmp_path, monkeypatch, agent):
    profile = tmp_path.resolve() / "profile"
    profile.mkdir()
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: profile))
    monkeypatch.delenv("CODEX_HOME", raising=False)
    bundle = tmp_path.resolve() / "bundle"
    bundle.mkdir()
    (bundle / "model").mkdir()
    (bundle / "python-version.txt").touch()
    monkeypatch.setattr(uninstaller, "ROOT", bundle)
    monkeypatch.setattr(uninstaller, "REGISTRY", bundle / "installed-workspaces.json")
    monkeypatch.setattr("builtins.input", lambda _: "UNINSTALL")
    audit = bundle / "runtime_data" / "security_events.db"
    audit.parent.mkdir()
    audit.touch()
    path = user_hook_directory(agent) / "hooks.json"
    path.parent.mkdir(parents=True)
    original = {"other": {"enabled": False}}
    path.write_text(json.dumps(original), encoding="utf-8")

    for _ in range(2):
        uninstaller.register(agent, bundle, user_level=True)
        assert configure(agent, bundle, "offline", audit_db=audit, model_dir=bundle / "model",
                         user_level=True) == path
    assert len(uninstaller.read_json(uninstaller.REGISTRY)) == 1
    assert path.read_text(encoding="utf-8").count("hook antigravity-prompt" if agent == "antigravity"
                                                   else "hook codex-prompt") == 1

    uninstaller.uninstall()

    assert uninstaller.read_json(path)["other"] == original["other"]
    assert "security_middleware.agent_hooks" not in path.read_text(encoding="utf-8")
    assert audit.exists()
