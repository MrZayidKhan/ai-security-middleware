"""Disconnect registered workspaces and remove the extracted detector bundle."""

import argparse
import json
import shutil
from pathlib import Path
from tempfile import NamedTemporaryFile


ROOT = Path(__file__).resolve().parent
REGISTRY = ROOT / "installed-workspaces.json"
GROUP = "ai-security-middleware"
EVENTS = {"UserPromptSubmit": "codex-prompt", "PostToolUse": "codex-result"}
MODEL_FILES = (
    "advisory_profile.json", "config.json", "model_quantized.onnx", "tokenizer.json",
    "LICENSE", "NOTICE", "README.md",
)
BUNDLE_FILES = (
    "Setup.cmd", "setup_detector.ps1", "Open Dashboard.cmd", "security-dashboard.exe",
    "Open Sanitizer.cmd", "OFFLINE_DETECTOR.md", "python-version.txt",
)


def write_json(path, value):
    temporary = None
    try:
        with NamedTemporaryFile(mode="w", encoding="utf-8", dir=path.parent, delete=False) as stream:
            temporary = Path(stream.name)
            json.dump(value, stream, indent=2, ensure_ascii=False)
            stream.write("\n")
        temporary.replace(path)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def read_json(path):
    return json.loads(path.read_text(encoding="utf-8-sig"))


def owned_child(parent, name):
    path = parent / name
    if path.is_symlink() or path.resolve() != path:
        raise ValueError(f"Refusing to touch a redirected path: {path}")
    return path


def hook_path(agent, workspace):
    if agent not in {"codex", "antigravity"}:
        raise ValueError("Unknown agent in workspace registry.")
    directory = owned_child(workspace, ".codex" if agent == "codex" else ".agents")
    return owned_child(directory, "hooks.json")


def register(agent, workspace):
    from security_middleware.agent_hooks import command_for

    if not (ROOT / "python-version.txt").is_file() or not (ROOT / "model").is_dir():
        raise ValueError("Workspace registration must run from the extracted bundle.")
    workspace = Path(workspace).resolve(strict=True)
    audit = ROOT / "runtime_data" / "security_events.db"
    model = ROOT / "model"
    if agent == "codex":
        commands = {
            key: command_for(event, "offline", "powershell", audit, model)["command"]
            for key, event in EVENTS.items()
        }
    else:
        commands = {
            "PreInvocation": command_for("antigravity-prompt", "offline", "cmd", audit, model)["command"]
        }
    registry = owned_child(ROOT, REGISTRY.name)
    entries = read_json(registry) if registry.exists() else []
    entries = [entry for entry in entries if (entry["agent"], entry["workspace"]) != (agent, str(workspace))]
    entries.append({"agent": agent, "workspace": str(workspace), "commands": commands})
    write_json(registry, entries)


def disconnect(entry):
    workspace = Path(entry["workspace"]).resolve()
    path = hook_path(entry["agent"], workspace)
    if not path.exists():
        return
    config = read_json(path)
    previous = json.dumps(config)
    if entry["agent"] == "antigravity":
        group = config.get(GROUP)
        if isinstance(group, dict):
            handlers = group.get("PreInvocation", [])
            remaining = [h for h in handlers if h.get("command") != entry["commands"]["PreInvocation"]]
            if remaining != handlers:
                if remaining:
                    group["PreInvocation"] = remaining
                else:
                    del group["PreInvocation"]
                    if not (group.keys() - {"enabled"}):
                        del config[GROUP]
    else:
        hooks = config.get("hooks", {})
        for event, command in entry["commands"].items():
            groups = hooks.get(event, [])
            for group in list(groups):
                handlers = group.get("hooks", [])
                remaining = [h for h in handlers if h.get("command") != command]
                if remaining != handlers:
                    if remaining:
                        group["hooks"] = remaining
                    else:
                        groups.remove(group)
    if json.dumps(config) != previous:
        write_json(path, config)


def uninstall():
    registry = owned_child(ROOT, REGISTRY.name)
    if not registry.is_file():
        raise ValueError("Installation registry missing. Run Setup again for each connected workspace first.")
    entries = read_json(registry)
    if not isinstance(entries, list) or not entries:
        raise ValueError("Installation registry is empty or invalid.")
    # Check the bundle targets before disconnecting or removing anything.
    model = owned_child(ROOT, "model")
    wheels = owned_child(ROOT, "wheels")
    venv = owned_child(ROOT, ".venv")
    files = [owned_child(ROOT, name) for name in BUNDLE_FILES]
    files.extend(owned_child(model, name) for name in MODEL_FILES)
    files.extend(owned_child(wheels, path.name) for path in wheels.glob("*.whl"))
    print("Close the agents, dashboard, and sanitizer before continuing.")
    if input("Type UNINSTALL to disconnect the registered workspaces and remove this bundle: ") != "UNINSTALL":
        print("Uninstall cancelled.")
        return
    for entry in entries:
        disconnect(entry)
        print(f"Processed {entry['agent']} workspace: {entry['workspace']}")
    if venv.is_dir():
        shutil.rmtree(venv)
    for path in files:
        path.unlink(missing_ok=True)
    for directory in (model, wheels):
        if directory.is_dir() and not any(directory.iterdir()):
            directory.rmdir()
    registry.unlink()
    print("Detector and dashboard files removed. The audit database and uninstall launcher remain in this folder.")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--register", nargs=2, metavar=("AGENT", "WORKSPACE"))
    args = parser.parse_args()
    try:
        if args.register:
            register(*args.register)
        else:
            uninstall()
    except (OSError, ValueError, TypeError, KeyError, AttributeError) as error:
        parser.exit(1, f"Uninstall configuration failed: {error}\n")


if __name__ == "__main__":
    main()
