# Protected Send Windows overlay

This prototype covers the existing Antigravity message area with a small
Windows overlay. The agent's conversation remains the only chat. The overlay
follows a verified Antigravity window and keeps the draft local until the
offline detector decides what can be submitted.

- **Allow:** pass the checked text to the original conversation.
- **Sanitize and allow:** pass only the rechecked remainder, and show a local
  popup with the rule-matched text that was removed. The popup carries the
  redaction marker detail, so the agent receives the actual cleaned draft.
- **Block:** keep the draft local and show the reason in a popup. An uncertain
  result also stays local and can be edited and retried.

The status window and tray menu offer **Start protection** and **Stop
protection**. Stop hides the overlay and prevents pending handoffs. Minimize
the status window to keep protection available. Close it or choose **Exit**
to shut down the app. The overlay covers the measured draft field and native
Send area while attached. It leaves the native model selector and neighboring
controls accessible through a region cutout. A small **Protected** label
identifies the draft field. Other agent submission paths are separate.

## Experimental native composer

Choose **Try native composer** in the status window to hide the overlay and
listen only for submission input against a fresh, verified foreground
Antigravity composer. The monitor consumes unmodified Enter when composer
focus is proven and left clicks in the verified Send region. It does not
record typing or inspect other windows. The native hook remains a separate
backup if enabled.

The status window indicates whether keyboard focus could be verified. A
captured submission snapshots the real draft, runs local rules and Horizon,
then verifies the target and text again. For sanitization it waits for the
selection to appear and tries Ctrl+A if accessibility selection fails. It
replaces only a verified full selection, checks the resulting editable text,
and invokes the native Send control once. A change in focus, draft, or
conversation can halt a handoff.
The overlay remains available through **Use overlay**.

Live coverage can vary with Antigravity versions and accessibility support.
This experiment does not guarantee interception during unavailable or stale
composer identification, or for other submission methods.

The transport verifies the destination, empty native composer, actual editable
text after insertion, and the Send control before invoking it once. It refuses
unrecognized controls, ambiguous or changed conversations, elevated or
unsupported installations, and blank conversations without an identifiable
thread. The original app's other submission paths remain separate.

The GUI installer uses a per-user application directory and ships the local
Windows x64 Python runtime, classifier, dependency wheels laid out for that
runtime, and dashboard. The Antigravity app is supplied by its vendor. The
overlay uses Windows' built-in .NET Framework, with no separately installed
Python, editor, or agent CLI required. Current packaging targets Windows
10/11 x64; Windows ARM64 and other agents are outside this prototype.

## Verification

The Windows executable builds with `build.ps1`; `--self-test` exercises
the decision classification without opening the interface. Python tests
exercise the worker and protective decision gate. A live end-to-end run
covering overlay attachment, pass, redaction, block, and changing chats
before submission is still required. Keep signed-in chat data out of tests.

The dashboard database is
`%LOCALAPPDATA%\PromptSecurityMiddleware\runtime_data\security_events.db`.
Held and sanitized content can be retained there. Remove installer artifacts
and local data separately according to your retention policy.
