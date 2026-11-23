"""Local stdio MCP transport for the Antigravity Protected Send panel."""

import argparse
import json
import sys
from pathlib import Path

from security_middleware.connector_service import ConnectorService
from security_middleware.content_protection import ContentInspector
from security_middleware.horizon_detector import HorizonDetector

UI_URI = "ui://protected-send/panel.html"
UI_MIME = "text/html;profile=mcp-app"
UI_EXTENSION = "io.modelcontextprotocol/ui"
ANTIGRAVITY_EXTENSION = "com.google.antigravity/ui"
PROTOCOLS = ("2025-11-25", "2025-06-18", "2025-03-26")
MAX_FRAME = 512 * 1024


def tool(name, description, fields, metadata):
    return {
        "name": name, "description": description, "_meta": metadata,
        "inputSchema": {
            "type": "object", "properties": {key: {"type": "string"} for key in fields},
            "required": list(fields), "additionalProperties": False,
        },
    }


TOOLS = [
    tool("protected_open", "Open the Protected Send panel.", [], {
        "ui": {"resourceUri": UI_URI},
        ANTIGRAVITY_EXTENSION: {"entrypoints": [{"type": "aux_pane", "title": "Protected Send"}]},
    }),
    tool("protected_check", "Screen a draft from the Protected Send panel.", ["text", "target"],
         {"ui": {"visibility": ["app"]}}),
    tool("protected_poll", "Check whether a pending local review is ready.", ["ticket", "target"],
         {"ui": {"visibility": ["app"]}}),
    tool("protected_cancel", "Cancel a pending local review.", ["ticket", "target"],
         {"ui": {"visibility": ["app"]}}),
]


class RpcError(Exception):
    def __init__(self, code, message):
        super().__init__(message)
        self.code = code


class PanelServer:
    def __init__(self, service, html):
        self.service = service
        self.html = html
        self.initialized = False
        self.desktop = False

    def dispatch(self, method, params):
        if method == "initialize":
            if self.initialized or self.desktop:
                raise RpcError(-32600, "Server already initialized.")
            capabilities = params.get("capabilities")
            extensions = capabilities.get("extensions") if isinstance(capabilities, dict) else None
            native = extensions.get(ANTIGRAVITY_EXTENSION) if isinstance(extensions, dict) else None
            if not (isinstance(native, dict) and isinstance(native.get("entrypoints"), list)
                    and "aux_pane" in native["entrypoints"] and UI_EXTENSION in extensions):
                raise RpcError(-32001, "Protected Send requires the Antigravity desktop MCP Apps host.")
            self.desktop = True
            requested = params.get("protocolVersion")
            return {
                "protocolVersion": requested if requested in PROTOCOLS else PROTOCOLS[0],
                "capabilities": {"tools": {}, "resources": {}},
                "serverInfo": {"name": "protected-send", "version": "0.1.0"},
            }
        if method == "notifications/initialized" and self.desktop:
            self.initialized = True
            return {}
        if method == "ping":
            return {}
        if not self.initialized:
            raise RpcError(-32001, "Protected Send has not been initialized.")
        if method == "tools/list":
            return {"tools": TOOLS}
        if method == "resources/list":
            return {"resources": [{"uri": UI_URI, "name": "Protected Send", "mimeType": UI_MIME}]}
        if method == "resources/read" and params.get("uri") == UI_URI:
            return {"contents": [{"uri": UI_URI, "mimeType": UI_MIME, "text": self.html,
                                  "_meta": {"ui": {"csp": {}}}}]}
        if method == "tools/call":
            return self.call(params)
        raise RpcError(-32601, "Unsupported Protected Send operation.")

    def call(self, params):
        name = params.get("name")
        args = params.get("arguments", {})
        definition = next((entry for entry in TOOLS if entry["name"] == name), None)
        if definition is None or not isinstance(args, dict):
            raise RpcError(-32602, "Invalid tool arguments.")
        expected = set(definition["inputSchema"]["required"])
        if set(args) != expected or any(not isinstance(value, str) for value in args.values()):
            raise RpcError(-32602, "Invalid tool arguments.")
        if name == "protected_open":
            return {"content": [{"type": "text", "text": "Protected Send is ready."}]}
        handler = {
            "protected_check": self.service.inspect,
            "protected_poll": self.service.poll,
            "protected_cancel": self.service.cancel,
        }[name]
        try:
            outcome = handler(**args)
        except ValueError:
            return {"isError": True, "content": [{"type": "text", "text": "Invalid draft or review."}]}
        return {"content": [], "structuredContent": outcome}

    def receive(self, request):
        if not isinstance(request, dict) or request.get("jsonrpc") != "2.0":
            return None
        method = request.get("method")
        request_id = request.get("id")
        if request_id is None:
            if method == "notifications/initialized" and self.desktop:
                self.dispatch(method, {})
            return None
        if isinstance(request_id, bool) or not isinstance(request_id, (str, int)):
            return None
        response = {"jsonrpc": "2.0", "id": request_id}
        try:
            params = request.get("params", {})
            if not isinstance(params, dict):
                raise RpcError(-32602, "Invalid parameters.")
            response["result"] = self.dispatch(method, params)
        except RpcError as exc:
            response["error"] = {"code": exc.code, "message": str(exc)}
        except Exception:
            response["error"] = {"code": -32603, "message": "Local Protected Send error."}
        return response


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--model-dir", required=True, type=Path)
    parser.add_argument("--audit-db", required=True, type=Path)
    parser.add_argument("--panel-html", required=True, type=Path)
    args = parser.parse_args()
    detector = HorizonDetector.from_advisory_profile(args.model_dir)
    inspector = ContentInspector(detector=detector, classify_sanitized_text=True)
    server = PanelServer(ConnectorService(inspector, args.audit_db), args.panel_html.read_text(encoding="utf-8"))
    while frame := sys.stdin.buffer.readline(MAX_FRAME + 1):
        if len(frame) > MAX_FRAME:
            return 1
        try:
            request = json.loads(frame)
        except (ValueError, UnicodeError, RecursionError):
            continue
        response = server.receive(request)
        if response is not None:
            print(json.dumps(response), flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
