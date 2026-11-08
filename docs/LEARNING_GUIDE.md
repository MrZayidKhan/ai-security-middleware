# Learning Guide

## Approach

This guide grows with the application. Each milestone explains only the concepts needed for the component being built, then links them to the code and tests that use them.

## Learning order

1. **Environment and local model** — Python virtual environments, local services, and a basic request/response.
2. **Tool loop** — JSON, structured requests, parsing, and iteration limits.
3. **Controlled tools** — document IDs, SQLite functions, and a simulated outbox.
4. **Security gateway** — validation, allowlists, permissions, scopes, and audit records.
5. **Content protection** — untrusted content, provenance, sanitization, and review decisions.
6. **Interfaces and evaluation** — API endpoints, dashboard data, tests, and measured results.

## What each implementation lesson includes

When a component is approved, its lesson will cover its responsibility, inputs and outputs, key code paths, likely errors, security decisions, exact run/test commands, and the results observed. No module-specific explanation is included before its code exists.

## Milestone 2: agent loop

`ChatMessage` and `ToolCall` in `security_middleware/models.py` define the data exchanged with Ollama. Pydantic validates this data before the loop uses it.

`OllamaClient` sends a non-streaming request to the local service. If the service cannot be reached or returns malformed data, it raises a clear error instead of passing raw data onward.

`AgentLoop` sends the user task, receives a proposal, adds the fixed tool result to the conversation, and asks the model for a final response. Its three-round limit prevents accidental endless repetition.

Run the practical demonstration with `python -m scripts.run_agent_demo` from the project virtual environment. The test file uses a fake model client, so it checks loop behavior without requiring the local model.

## Milestone 3: controlled local tools

`ControlledTools` accepts fixed application paths when it starts. The caller supplies document IDs such as `project-overview`; it never supplies a raw filesystem path. The code resolves the selected file and confirms it remains under the approved document folder.

The SQLite record lookup uses a `?` placeholder with a record ID. This is a parameterized query: the value stays data instead of being treated as SQL code. The outbox inserts a local `DRAFT` row and exposes no sending capability.

Run the practical check with `python -m scripts.run_controlled_tools_demo` from the project virtual environment.

## Milestone 4: action gateway

The gateway is the decision point between a proposed action and a local operation. It validates the request and its tool-specific arguments, checks whether the tool and resource are permitted, applies limits, then either returns `BLOCK` or calls the fixed executor.

`ALLOW` means the policy permitted the attempt. `SUCCEEDED` means the local operation completed. Keeping these separate avoids presenting an execution failure as a policy block or a success.

Run `python -m scripts.run_gateway_demo` from the project virtual environment to see one allowed request and one blocked request.

## Milestone 5: content protection

`ContentEnvelope` carries text with source ID, content ID, origin trust, and sensitivity. These labels remain separate because a source can be untrusted without every sentence being malicious.

`ContentInspector` uses visible rules rather than a hidden confidence score. It sanitizes a clear override instruction, holds a directive to expose sensitive data, and passes content with no configured suspicious pattern. The test corpus includes benign discussion of prompt injection so ordinary security writing does not trigger solely on keywords.

`ReviewQueue` stores held content locally. Approval requires a specific reviewed excerpt and does not change tool permissions.
