const assert = require("node:assert/strict");
const { readFileSync } = require("node:fs");
const { join } = require("node:path");
const test = require("node:test");
const vm = require("node:vm");

const script = readFileSync(join(__dirname, "protected-send.html"), "utf8").match(/<script>([\s\S]+)<\/script>/)[1];

function fixture(check, options = {}) {
  const handlers = new Map();
  const timers = new Map();
  const requests = [];
  const nodes = new Map();
  const sourceOrigin = "https://antigravity.invalid";
  let timerId = 0;
  const host = {
    postMessage(packet, origin) {
      requests.push(JSON.parse(JSON.stringify(packet)));
      if (!("id" in packet) || !packet.method) return;
      const result = (() => {
        if (packet.method === "ui/initialize") {
          return {
            protocolVersion: "2026-01-26",
            hostCapabilities: options.capabilities ?? { serverTools: {}, message: { text: {} } },
          };
        }
        assert.equal(origin, sourceOrigin);
        if (packet.method === "ui/message") return options.messageResult ?? {};
        assert.equal(packet.method, "tools/call");
        if (packet.params.name === "protected_check") return { structuredContent: check };
        if (packet.params.name === "protected_poll") return { structuredContent: options.poll };
        if (packet.params.name === "protected_cancel") return { structuredContent: { decision: "UNCERTAIN" } };
        throw new Error("Unexpected request");
      })();
      queueMicrotask(() => receive({ jsonrpc: "2.0", id: packet.id, result }));
    },
  };
  function receive(packet) {
    handlers.get("message")({ source: host, origin: sourceOrigin, data: packet });
  }
  const window = { parent: host, addEventListener: (event, listener) => handlers.set(event, listener) };
  const document = {
    visibilityState: "visible",
    hasFocus: () => true,
    getElementById(id) {
      if (!nodes.has(id)) {
        nodes.set(id, {
          value: "", textContent: "", dataset: {},
          addEventListener: (event, listener) => handlers.set(id + "." + event, listener),
        });
      }
      return nodes.get(id);
    },
  };
  vm.runInNewContext(script, {
    window, document, crypto: require("node:crypto").webcrypto,
    setTimeout(callback, delay) {
      timers.set(++timerId, { callback, delay });
      return timerId;
    },
    clearTimeout: (id) => timers.delete(id),
  });
  return {
    receive, requests, nodes,
    async submit(text) {
      if (text !== undefined) nodes.get("draft").value = text;
      await handlers.get("composer.submit")({ preventDefault() {} });
    },
    async discard() {
      await handlers.get("discard.click")();
    },
    async runPoll() {
      const scheduled = [...timers.values()].find((entry) => entry.delay === 1500);
      assert.ok(scheduled);
      await scheduled.callback();
    },
    sent: () => requests.filter((packet) => packet.method === "ui/message"),
  };
}

const ready = () => new Promise((resolve) => setImmediate(resolve));
const hold = { decision: "UNCERTAIN", state: "pending", ticket: "0123456789abcdef" };

test("sends only the accepted text to the current host conversation", async () => {
  const app = fixture({ decision: "SANITIZE", text: "Describe a rainbow." });
  await ready();
  await app.submit("Draft before local inspection");
  assert.deepEqual(app.sent().map((packet) => packet.params), [{
    role: "user", content: [{ type: "text", text: "Describe a rainbow." }],
  }]);
  assert.match(app.nodes.get("status").textContent, /Sanitized/);
});

test("hard block and missing message capability send nothing", async () => {
  const blocked = fixture({ decision: "MALICIOUS_BLOCKED" });
  const unsupported = fixture({ decision: "PASS", text: "A simple draft." }, { capabilities: { serverTools: {} } });
  await ready();
  await blocked.submit("Harmless simulated blocked fixture");
  await unsupported.submit("A simple draft.");
  assert.equal(blocked.sent().length, 0);
  assert.equal(unsupported.requests.some((packet) => packet.method === "tools/call"), false);
  assert.match(blocked.nodes.get("status").textContent, /Blocked/);
});

test("dashboard-reviewed text requires final confirmation from this pane", async () => {
  const app = fixture(hold, { poll: { decision: "PASS", text: "Describe a prism." } });
  await ready();
  await app.submit("A locally held simulation.");
  await app.runPoll();
  assert.equal(app.sent().length, 0);
  assert.equal(app.nodes.get("draft").value, "Describe a prism.");
  const calls = app.requests.filter((packet) => packet.method === "tools/call");
  assert.equal(calls[0].params.arguments.target, calls[1].params.arguments.target);
  await app.submit();
  assert.equal(app.sent()[0].params.content[0].text, "Describe a prism.");
});

test("context change cancels a local review and disables this pane", async () => {
  const app = fixture(hold);
  await ready();
  await app.submit("A locally held simulation.");
  app.receive({ jsonrpc: "2.0", method: "ui/notifications/host-context-changed", params: { conversationId: "other" } });
  assert.equal(app.sent().length, 0);
  assert.ok(app.requests.some((packet) => packet.params?.name === "protected_cancel"));
  assert.equal(app.nodes.get("send").disabled, true);
});

test("host rejection is reported and is not automatically retried", async () => {
  const app = fixture({ decision: "PASS", text: "Describe a rainbow." }, { messageResult: { isError: true } });
  await ready();
  await app.submit("Describe a rainbow.");
  await app.submit("Describe a rainbow.");
  assert.equal(app.sent().length, 1);
  assert.match(app.nodes.get("status").textContent, /rejected delivery/);
});
