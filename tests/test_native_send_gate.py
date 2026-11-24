from unittest.mock import Mock

import pytest

from security_middleware.native_send_gate import Draft, submit_intercepted


ORIGINAL = Draft("chat-one", "Original draft")
CLEAN = Draft("chat-one", "Cleaned draft")


@pytest.mark.parametrize("outcome,text", [("PASS", ORIGINAL.text), ("SANITIZE", CLEAN.text)])
def test_only_approved_draft_is_sent_once(outcome, text):
    service = Mock()
    service.inspect.return_value = {"decision": outcome, "state": "ready", "text": text}
    composer = Mock()
    composer.read.side_effect = [ORIGINAL, ORIGINAL, Draft("chat-one", text)]
    assert submit_intercepted(ORIGINAL, service, composer) == {"state": "sent", "decision": outcome}
    composer.send_if_current.assert_called_once_with(Draft("chat-one", text))


@pytest.mark.parametrize("readback", [ORIGINAL, Draft("chat-two", CLEAN.text), None])
def test_stale_or_wrong_chat_readback_prevents_send(readback):
    service = Mock()
    service.inspect.return_value = {"decision": "SANITIZE", "state": "ready", "text": CLEAN.text}
    composer = Mock()
    composer.read.side_effect = [ORIGINAL, ORIGINAL, readback]
    assert submit_intercepted(ORIGINAL, service, composer)["state"] == "unconfirmed"
    composer.send_if_current.assert_not_called()


@pytest.mark.parametrize("decision,state", [("MALICIOUS_BLOCKED", "blocked"), ("UNCERTAIN", "pending")])
def test_block_and_hold_never_edit_or_send(decision, state):
    service = Mock()
    service.inspect.return_value = {"decision": decision, "state": state}
    composer = Mock()
    composer.read.return_value = ORIGINAL
    assert submit_intercepted(ORIGINAL, service, composer)["state"] == state
    composer.replace_if_current.assert_not_called()
    composer.send_if_current.assert_not_called()
