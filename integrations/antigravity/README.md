# Protected Send for Antigravity Desktop

This experimental plugin opens a **Protected Send** side panel beside a normal
Antigravity Desktop chat. It uses the app's MCP Apps interface and the bundle's
local Rules + Horizon detector. It has no editor dependency or external web assets.

## Prepare the plugin

In the Windows bundle, run **Setup.cmd**, then **Install Antigravity
Panel.cmd**. Setup generates the local plugin configuration with the
extracted bundle's paths. The install launcher needs `agy`, the
Antigravity CLI, in the standard Windows install folder or on PATH to
validate and install the plugin. The chat
itself runs in the official Antigravity Desktop app.

### From the source checkout

1. For this source prototype, use the repository's Python environment with
   the local Horizon dependencies installed. From the repository root, run
   `python -m pip install -e .` in that environment so the plugin can import
   the connector when Antigravity launches Python.
2. Copy this plugin directory to a local staging folder. In that copy, rename
   `mcp_config.json.example` to `mcp_config.json`. Set `command` to the
   environment's absolute Python executable, `--model-dir` to the local
   Horizon model folder, and `--audit-db` to the dashboard's SQLite path. Keep
   `${PLUGIN_ROOT}/protected-send.html` unchanged so Antigravity locates the
   panel HTML in the installed plugin.
3. With the Antigravity CLI available, validate the staged plugin with
   `agy plugin validate <plugin-folder> --strict`, then install with
   `agy plugin install <plugin-folder>`. Follow Google's
   [local plugin guide](https://antigravity.google/docs/build-plugins).
   The CLI is only used to install or validate this panel. The chat itself
   happens in Antigravity Desktop.
4. In the intended Desktop chat, use the side-panel **+** menu or
   **More actions → Plugins** to open **Protected Send**. Open
   the Rust dashboard with that audit database to view inspection results.

## Use the panel

Type or paste a draft into the panel. Press Enter to check and send.
Shift+Enter adds a line. The host receives the draft as a call to its local,
app-only inspection tool; the original draft is never submitted to the
chat by this panel.

- **Pass / Sanitize:** The panel submits only the accepted text to the
  conversation associated with the panel. If focus changed during checking,
  confirm the checked draft from the visible panel before sending.
- **Malicious · Blocked:** The panel sends nothing and offers no review release.
- **Uncertain · Held for review:** Open the newest held item in the Rust
  dashboard and use **Recheck and send** with a revised draft within two
  minutes. The connector rechecks it and returns an accepted revision to the
  originating panel only. Verify the conversation and use **Send checked
  draft** there. The final confirmation prevents unattended background sends
  when switching between a dashboard and chat.

The panel refuses a host without the expected MCP Apps version, local tool
calls and conversation messaging capability. We use the host's current-thread
routing, with no background-conversation override. Antigravity's public MCP
Apps API does not expose a stable conversation ID to this panel. Its actual
conversation routing and compatibility need a signed-in Desktop test. If a
send is rejected or its result is uncertain, check the chat before reopening
the panel and trying again. The original Antigravity composer is a separate
path and remains subject to any workspace hook you configure.

Held and sanitized prompts remain in the local audit database. Protect the
database as sensitive. To remove the panel, disable or uninstall the plugin
in Antigravity before moving or uninstalling the bundle it points to.

## Verification

Run the simulated panel-host tests with
`node --test integrations/antigravity/panel.test.cjs` from the checkout.
These test the payload and cancellation behavior without contacting an
answering model. The plugin has not yet been validated inside a live signed-in
Antigravity chat.
