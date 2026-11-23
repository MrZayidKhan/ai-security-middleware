# Protected Send connectors

The shared Python service, `ConnectorService`, checks a draft locally and
returns one of four policy decisions. Each connector controls the draft entry
point and uses a host-supported message operation to submit accepted text.
The service has no ability to send a message or call an answering agent.

| Operation | Result |
| --- | --- |
| `inspect(text, target)` | Returns accepted text for Pass or Sanitize. Malicious · Blocked has no release. An Uncertain hold may return a short-lived review ticket. |
| `poll(ticket, target)` | Returns a pending state or a one-time result after the dashboard draft is rechecked. A different target, expired review, canceled review, or rejected draft returns no text. |
| `cancel(ticket, target)` | Closes a pending review without releasing its text. |

The target is an opaque identifier for a connector view. It binds a draft to
its local review, and the connector is responsible for keeping the view bound
to the intended conversation. The Rust dashboard queues edits in the same
SQLite database the connector uses. Keep it local and treat it as sensitive.

## Host acceptance

- **Antigravity desktop:** The [prototype](../integrations/antigravity/README.md)
  uses the official MCP Apps side panel. It checks for desktop panel
  capabilities before making screening tools available. Live panel registration
  and delivery remain to be verified.
- **Codex desktop:** A separate connector is pending. OpenAI's
  [MCP Extensions specification](https://github.com/openai/mcp-extensions/blob/main/docs/spec.md)
  describes thread entrypoints and message submission. Verify those
  capabilities in a disposable thread before enabling delivery.
- **Other agents:** Provide a connector only when the host can offer a draft
  entry point and a reliable destination for accepted text. The policy and
  audit format are shared across connectors.

For each host, verify pass and sanitize in the same thread, zero submissions
on block, reinspection of a dashboard draft, no send after cancellation or
expiry, and no delivery to a different thread after navigation. Test with
harmless synthetic text. The protected panel covers its own submissions.
Native hooks, where enabled, remain a separate control for the stock composer.
