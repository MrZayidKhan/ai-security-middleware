"""Desktop chat for the local prompt-security middleware."""

from concurrent.futures import ThreadPoolExecutor
import argparse
import json
from pathlib import Path
import subprocess
import sys
from time import monotonic
import tkinter as tk
from tkinter import ttk
from tkinter.scrolledtext import ScrolledText
from urllib.error import URLError
from urllib.request import urlopen

from security_middleware.application_client import MiddlewareChatClient
from security_middleware.middleware import ModelContextBlockedError
from security_middleware.models import ChatMessage
from security_middleware.ollama_client import ModelConnectionError, ModelResponseError


def middleware_ready(base_url, *, demo=False):
    try:
        with urlopen(f"{base_url}/health", timeout=0.5) as response:
            health = json.load(response)
    except (URLError, OSError, ValueError):
        return False
    if (not isinstance(health, dict)
            or health.get("service") != "prompt-security-middleware"
            or health.get("status") != "running"):
        return False
    if demo:
        return (health.get("answer_model") == "qwen3.5:0.8b"
                and health.get("detectors") == "rules+english-contextual-verifier")
    return True


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--demo", action="store_true", help="Use the smaller answering model.")
    demo = parser.parse_args().demo
    port = 8789 if demo else 8787
    base_url = f"http://127.0.0.1:{port}"
    window = tk.Tk()
    window.title("Protected Qwen Chat — Demo" if demo else "Protected Qwen Chat")
    window.geometry("740x560")
    window.minsize(420, 340)
    panel = ttk.Frame(window, padding=16)
    panel.pack(fill="both", expand=True)
    transcript = ScrolledText(panel, wrap="word", state="disabled", font=("Segoe UI", 11))
    transcript.pack(fill="both", expand=True)
    prompt = tk.Text(panel, height=4, wrap="word", font=("Segoe UI", 11))
    prompt.pack(fill="x", pady=(12, 8))
    controls = ttk.Frame(panel)
    controls.pack(fill="x")
    screen_only = tk.BooleanVar(value=demo)
    if demo:
        ttk.Checkbutton(controls, text="Detector only", variable=screen_only).pack(side="left", padx=(0, 12))
    status = tk.StringVar(value="Connecting to the prompt injection detector…")
    ttk.Label(panel, textvariable=status, wraplength=390).pack(anchor="w", pady=(8, 0))
    model = "qwen3.5:0.8b" if demo else "qwen3.5:4b"
    client = MiddlewareChatClient(base_url, model=model)
    executor = ThreadPoolExecutor(max_workers=1)
    history: list[ChatMessage] = []

    def append(speaker, content):
        transcript.configure(state="normal")
        transcript.insert("end", f"{speaker}\n{content}\n\n")
        transcript.configure(state="disabled")
        transcript.see("end")

    def new_chat():
        history.clear()
        transcript.configure(state="normal")
        transcript.delete("1.0", "end")
        transcript.configure(state="disabled")
        prompt.delete("1.0", "end")
        status.set("New conversation")
        prompt.focus_set()

    def finish(future, request, screening):
        if not future.done():
            window.after(100, finish, future, request, screening)
            return
        try:
            reply = future.result()
        except ModelContextBlockedError:
            append("Middleware", "Message withheld. Qwen did not receive it for answering.")
            status.set("Withheld")
        except (ModelConnectionError, ModelResponseError) as error:
            append("Middleware", str(error))
            status.set("Request failed")
        except Exception:
            append("Chat", "Unexpected request error.")
            status.set("Request failed")
        else:
            if screening:
                append("Middleware", f"Screening result: {', '.join(reply)}. No reply requested.")
                status.set("Screening complete")
            else:
                history[:] = [*request, reply]
                append("Qwen", reply.content)
                status.set("Released by middleware")
        finally:
            prompt.configure(state="normal")
            send_button.state(["!disabled"])
            reset_button.state(["!disabled"])
            prompt.focus_set()

    def send(event=None):
        if send_button.instate(["disabled"]):
            return "break"
        content = prompt.get("1.0", "end-1c").strip()
        if not content:
            return "break"
        if len(content) > 20000:
            status.set("Shorten this message to 20,000 characters or fewer.")
            return "break"
        screening = screen_only.get()
        message = ChatMessage(role="user", content=content)
        request = [message] if screening else [*history, message]
        if len(request) > 32 or any(len(m.content) > 20000 for m in request) or sum(
            len(m.content) for m in request
        ) > 40000:
            status.set("Conversation limit reached. Start a new chat or shorten this message.")
            return "break"
        append("You", content)
        prompt.delete("1.0", "end")
        prompt.configure(state="disabled")
        send_button.state(["disabled"])
        reset_button.state(["disabled"])
        status.set("Screening prompt…" if screening else "Waiting for middleware screening and response…")
        future = executor.submit(client.screen, message) if screening else executor.submit(client.chat, request, tools=[])
        window.after(100, finish, future, request, screening)
        return "break"

    send_button = ttk.Button(controls, text="Send", command=send)
    send_button.pack(side="right")
    reset_button = ttk.Button(controls, text="New chat", command=new_chat)
    reset_button.pack(side="left")
    prompt.bind("<Return>", send)
    def insert_newline(_event):
        prompt.insert("insert", "\n")
        return "break"

    prompt.bind("<Shift-Return>", insert_newline)
    prompt.focus_set()
    send_button.state(["disabled"])
    reset_button.state(["disabled"])
    owned_middleware = None
    deadline = monotonic() + 20

    def wait_for_middleware():
        if middleware_ready(base_url, demo=demo):
            status.set("Detector connected · Enter to send")
            send_button.state(["!disabled"])
            reset_button.state(["!disabled"])
        elif monotonic() >= deadline or (
            owned_middleware is not None and owned_middleware.poll() is not None
        ):
            status.set(f"The detector could not start on port {port}. Close and reopen this window to retry.")
        else:
            window.after(250, wait_for_middleware)

    try:
        if not middleware_ready(base_url, demo=demo):
            try:
                flags = ["--detector", "english-verifier"]
                if demo:
                    flags.append("--demo")
                owned_middleware = subprocess.Popen(
                    [sys.executable, "-m", "scripts.run_middleware", "--port", str(port), *flags],
                    cwd=Path(__file__).resolve().parents[1],
                    creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
            except OSError:
                deadline = monotonic()
        window.after(0, wait_for_middleware)
        window.mainloop()
    finally:
        executor.shutdown(wait=False, cancel_futures=True)
        if owned_middleware is not None and owned_middleware.poll() is None:
            owned_middleware.terminate()


if __name__ == "__main__":
    main()
