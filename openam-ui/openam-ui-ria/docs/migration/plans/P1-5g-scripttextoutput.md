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

## Approach (implemented 2026-07-03)
Chose **controlled execution of AM-issued scripts** with a documented trust boundary (AM is
same-origin/cookie-authenticated), over native per-mechanism React integrations (WebAuthn/
reCAPTCHA/device-print) — the latter was rejected as speculative without concrete AM-side script
content to target (see the reference doc's module audit: none of AM's actual first-party
ScriptTextOutput producers are compatible with this app without further per-module work anyway,
regardless of which approach was picked). Full research + design write-up, including the real AM
wire format (messageType is a JSON *string*, a latent bug fixed here), the jQuery/RequireJS coupling
of every known first-party AM script producer, the write-back convention, and the jsdom testing
limitation: **[`../reference/script-text-output.md`](../reference/script-text-output.md)**.

Ships **disabled by default** (`CallbackForm`'s `allowScriptExecution` prop, `false` unless a caller
opts in; `LoginPage.tsx` passes `false` explicitly) — this operationalizes "requires a security
review sign-off before merge" as a concrete safe default: the mechanism is built and tested, but
production enablement is a separate, deliberate step gated on that review (and a manual `dev:mock`
check — see the reference doc's Testing limitation section).

## Files
- `commons-ui-next/src/auth/scriptExecution.ts` — the execution + write-back adapter.
- `commons-ui-next/src/auth/callbacks.ts` — `isScriptTextOutputCallback`, `getScript`, and a
  `getMessageType` string-coercion fix (the real AM wire-format bug above).
- `commons-ui-next/src/auth/CallbackForm.tsx` — `allowScriptExecution` prop + the execution effect.
- `commons-ui-next/src/mock/{fixtures,handlers}/authenticate.ts` — a device-print-style
  HiddenValueCallback + ScriptTextOutputCallback scenario.
- Tests: `commons-ui-next/src/auth/callbacks.test.ts` (pure logic), `openam-ui-eui/src/features/
  auth/CallbackForm.test.tsx` (`ScriptTextOutputCallback (P1-5g)` suite).

## Out of scope
Everything else in P1-5b–f. This task does not affect the login route status. Native/legacy-script
compatibility for QR/authenticator-app registration, the built-in reCAPTCHA module, and the
Scripted module's `document.forms[0]`/auto-submit convention — see the reference doc's Follow-up
section.

## Verification
Vitest + typecheck + lint — all green. Manual `dev:mock` verification of real script execution (as
opposed to the simulated write-back the Vitest suite exercises — see the reference doc's Testing
limitation section) was **not** done as part of this task; do this before flipping
`allowScriptExecution` to `true` anywhere, alongside the still-outstanding human security review
sign-off.
