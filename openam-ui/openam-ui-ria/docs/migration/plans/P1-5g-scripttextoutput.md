# P1-5g — Login parity: ScriptTextOutput execution (device-print / WebAuthn / reCAPTCHA)

**Depends on:** P1-5b · **Not required for the parity gate** · Read [`README.md`](README.md) first.

## Goal

Handle `TextOutputCallback` with `messageType` 4 (ScriptTextOutput), which legacy executed as **raw
server-provided JavaScript**. This powers device-print collectors, WebAuthn, and reCAPTCHA hooks. It was
deliberately deferred from P1-5b because arbitrary server-JS execution is security-sensitive and React-hostile.

## Legacy reference
- `RESTLoginView.callbackRender` script branch (`_ScriptTextOutput.html`): when a TextOutputCallback's
  `messageType` output is `4`, the script value is injected into the DOM and executed. P1-5b renders
  `messageType` 0/1/2 as alerts and **no-ops** `messageType` 4 (marked gap).

## Approach (new stack) — to be designed at pickup
Execution of untrusted server script needs a deliberate, reviewed mechanism. Options to weigh:
- Controlled execution of AM-issued scripts with a documented trust boundary (AM is same-origin/trusted), writing
  the expected hidden-input result back into the challenge (device print / WebAuthn assertion / reCAPTCHA token).
- Native React integrations for the common cases (WebAuthn via `navigator.credentials`, reCAPTCHA via its SDK,
  device-print via a first-party collector) instead of executing the server blob verbatim.
Requires a security review (this is the one login item flagged for it). May be re-prioritized into a dedicated
auth-module slice rather than the core login parity set.

## Files (anticipated)
- `commons-ui-next/src/auth/` — ScriptTextOutput handling in the renderer/loop; a hardened script/result adapter.
- `commons-ui-next/src/mock/` — a ScriptTextOutput scenario (e.g. device print → hidden result).
- Tests + security review notes.

## Out of scope
Everything else in P1-5b–f. This task does not affect the login route status.

## Verification
Vitest + typecheck + lint; `dev:mock` of a scripted stage; explicit security review sign-off before merge.
