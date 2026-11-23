"""Decision gate for an intercepted native composer submission."""

from dataclasses import dataclass
from typing import Protocol

from security_middleware.connector_service import ConnectorService


@dataclass(frozen=True)
class Draft:
    target: str
    text: str


class Composer(Protocol):
    def read(self) -> Draft | None:
        """Read the actual editable text and verified conversation identity."""
        ...

    def replace_if_current(self, expected: Draft, text: str) -> bool: ...

    def send_if_current(self, expected: Draft) -> bool: ...


def submit_intercepted(
    original: Draft, service: ConnectorService, composer: Composer,
) -> dict:
    """Call only after the original submission event has been consumed."""
    if composer.read() != original:
        return {"state": "changed"}
    decision = service.inspect(original.text, original.target)
    if decision.get("state") != "ready" or decision.get("decision") not in {"PASS", "SANITIZE"}:
        return decision
    text = decision.get("text")
    if not isinstance(text, str) or not text.strip() or composer.read() != original:
        return {"state": "changed"}
    approved = Draft(original.target, text)
    if approved != original and not composer.replace_if_current(original, text):
        return {"state": "changed"}
    if composer.read() != approved or not composer.send_if_current(approved):
        return {"state": "unconfirmed"}
    return {"state": "sent", "decision": decision["decision"]}
