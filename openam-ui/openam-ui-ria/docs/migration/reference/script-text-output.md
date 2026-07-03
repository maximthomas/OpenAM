# ScriptTextOutputCallback (P1-5g) — research + design

Written while implementing P1-5g. Captures the AM-side ground truth (found by reading the actual
Java sources, not assumed) and the resulting design, so a future session doesn't need to re-derive
it. New commons-ui-next files: `src/auth/scriptExecution.ts` (the adapter),
`src/auth/callbacks.ts` (`isScriptTextOutputCallback`, `getScript`, and a `getMessageType` fix).

## What AM actually sends (verified against source, not assumed)

- `ScriptTextOutputCallback` (`openam-core/.../callbacks/ScriptTextOutputCallback.java`) is a
  `TextOutputCallback` subclass that hardcodes `getMessageType()` to return the constant `SCRIPT = 4`.
- **The wire format is a JSON *string*, not a number.** `RestAuthTextOutputCallbackHandler
  .convertToJson` (`openam-core-rest/.../callbackhandlers/RestAuthTextOutputCallbackHandler.java:74`)
  does `createOutputField("messageType", String.valueOf(messageType))` — so real AM sends
  `{"name":"messageType","value":"4"}`, a string. **This was a real, latent bug**: commons-ui-next's
  `getMessageType()` only recognized `typeof val === 'number'`, silently falling back to `0` for a
  string — meaning ScriptTextOutput would never have been detected against real AM at all, only
  against mock fixtures that happened to model `messageType` as a JS number. Fixed to coerce both.
- `HiddenValueCallback`'s wire shape (`RestAuthHiddenValueCallbackHandler.convertToJson`): output is
  `[{name: "value", value: callback.getValue()}]`; input is `[{name: "IDToken"+index, value:
  callback.getId()}]` — i.e. **the input's initial value is the callback's own `id`**, not empty.
  Our mock fixture models this loosely (empty string) since the exact round-trip semantics don't
  matter for the write-back mechanism we built (see below).

## Every known first-party AM script producer depends on legacy XUI globals

Searched the whole OpenAM tree for `ScriptTextOutputCallback` usages. Every real, first-party
producer assumes the legacy XUI page environment (`jQuery`, `RequireJS`'s global `require`) is
present:

- **QR / Authenticator-App registration** (`QRCallbackBuilder.java` →
  `GenerationUtils.getQRCodeGenerationJavascript`, also used by `AuthenticatorOATH.java`): emits
  `require(['org/forgerock/openam/server/util/QRCodeReader'], function (QRCodeReader) {
  QRCodeReader.createCode({...}) })` — a **RequireJS module load**, hardcoded module path included.
  Will throw `require is not defined` in the new app; there is no shim and adding one would mean
  reintroducing RequireJS, which is explicitly out of scope for the migration.
- **Built-in reCAPTCHA module** (`openam-auth-recaptcha/.../ReCaptcha.java:getScriptCallback`):
  emits `if (window.$ && window.require) { $('#recaptcha-container').attr('data-sitekey', ...);
  require([jsUrl], function() {}); }` — gated on `window.$`/`window.require` being present, so on
  this app it silently no-ops (the `if` is false) rather than throwing — but the reCAPTCHA challenge
  then never loads, so this auth module would functionally break (no crash, just no captcha UI).
- **Generic "Scripted" auth module** (admin-authored client-side script,
  `openam-auth-scripted/.../ScriptedClientUtilityFunctions.java:createClientSideScriptExecutorFunction`)
  is the most interesting case — it already anticipates a non-XUI client:
  ```js
  if (window.require) { /* spinner via commons-ui Messages/SpinnerManager — skipped if absent */ }
  (function(output) {
    function submit() {
      if (!(window.jQuery)) { document.forms[0].submit(); }   // "Crude detection... XUI is not present"
      else { $('input[type=submit]').trigger('click'); }
    }
    <admin's script>
    setTimeout(submit, 0);
  })(document.forms[0].elements['clientScriptOutputData']);
  ```
  This degrades gracefully (no `require`/`jQuery` branch), but still assumes a literal
  `document.forms[0].elements[name]` — a real native `<form>` with a field addressable by that
  name/id — and, worse, calls **`document.forms[0].submit()`**, which (unlike `.requestSubmit()`)
  bypasses any JS `submit` event handler and would trigger a genuine full-page form POST/reload in
  a form without a real `action` in this app. This convention was **not** replicated (see below).

**Conclusion baked into the design below**: this task delivers the *execution mechanism* (P1-5g's
plan doc framed this as "controlled execution... writing the result back into the challenge"), not
drop-in compatibility with any specific existing AM auth module's script. QR/authenticator-app
registration and the built-in reCAPTCHA module will not function unmodified; the generic Scripted
module's `document.forms[0]`/auto-submit convention was deliberately not replicated either. Any of
these becoming a real requirement is follow-up work, not part of this task.

## Design: the hardened script adapter (`commons-ui-next/src/auth/scriptExecution.ts`)

Chosen over "native per-mechanism integrations" (WebAuthn/reCAPTCHA/device-print reimplemented in
React) because the latter is speculative without concrete AM-side script content to target, and
over a "no-op stub" because the plan doc's own framing ("controlled execution... writing the
result back") pointed at building the real mechanism.

- **Security boundary**: AM is same-origin and the session is already cookie-authenticated
  (`iPlanetDirectoryPro`) by the time any callback renders, so the script carries the same trust
  level as any other same-origin AM response — matches legacy's implicit trust model (jQuery's
  `.html()` auto-executes injected `<script>` tags; see `RESTLoginView.js` `callbackRender`'s
  script branch + `_ScriptTextOutput.html`'s `{{{messageValue}}}` triple-stash).
- **Stays off by default**: `CallbackForm`'s `allowScriptExecution` prop defaults to `false`; the
  eui `LoginPage.tsx` passes `false` explicitly with a comment. This operationalizes the plan doc's
  "requires a security review sign-off before merge" as a concrete, safe default rather than a
  vague TODO — the mechanism ships built and tested, but a human has to flip one boolean (and
  presumably review this doc) before it runs in production.
- **Mechanism**: `document.createElement('script'); scriptEl.text = wrapped; document.body.append(
  scriptEl)`. A real `<script>` element (not `dangerouslySetInnerHTML`, which does not execute
  `<script>` content — same as plain `innerHTML`) — this is the actual DOM API for synchronous
  script execution, independent of jQuery.
- **Write-back convention (new-app-specific, not legacy-compatible)**: the raw AM script is wrapped
  in `;(function (setResult) { try { <script> } catch (e) {} })(window.__scriptTextOutputResult_N);`
  — a uniquely-named `window` global (incrementing counter) bridges the closure-scoped `onResult`
  callback into the separately-executed script text (functions can't be serialized into a `<script>`
  string, so a temporary global is the only way to hand a live reference across). The AM script (if
  authored for this app) just calls `setResult(value)` as an in-scope identifier. The try/catch
  means a broken/incompatible script (e.g. one that assumes `jQuery`/`require`, per the audit above)
  fails silently rather than throwing an uncaught exception into the host page.
- **Pairing convention**: `CallbackForm` writes the reported value into the stage's callbacks array
  via the existing `setCallbackValue`/index-based state (`values[i]`) — **not** DOM-name addressing.
  The target index is the stage's **sole** `HiddenValueCallback` if there is exactly one (matches
  both real examples found: the Scripted module's 2-callback stage, and our own
  `AUTH_CHALLENGE_TEXT_OUTPUT`/`AUTH_CHALLENGE_SCRIPT_TEXT_OUTPUT` mock fixtures) — deliberately not
  index-adjacency (`i-1`/`i+1`), since the two real examples found actually disagree on ordering
  (Scripted puts `HiddenValueCallback` *before* the script callback; our pre-existing
  `AUTH_CHALLENGE_TEXT_OUTPUT` fixture put it *after*). Zero or multiple `HiddenValueCallback`s in
  the stage → the result has nowhere well-defined to go and is dropped (no crash).
- Runs once per stage: the `useEffect` in `CallbackForm.tsx` is keyed on `challenge.authId`.

## Testing limitation (jsdom) — verified empirically, not assumed

Vitest's jsdom environment (`openam-ui-eui/vite.config.ts`, `environment: 'jsdom'`) **does**
attempt to evaluate an appended `<script>` element's text (confirmed: it's not a no-op), but runs it
via `vm.runInContext` against jsdom's own internal window object, which is **not** the same
`globalThis` the test module itself sees — a `window.someGlobal = fn` assignment made in test code
is invisible to code running inside the injected `<script>`, and vice versa. (`new Function(code)()`
was tried as an alternative — it *does* share the realm and would be trivially testable — but was
rejected: it requires a `script-src 'unsafe-eval'` CSP directive, a materially broader relaxation
than allowing a same-origin inline `<script>` tag, which matters for the one item in this codebase
explicitly flagged for security review.)

Consequence for `CallbackForm.test.tsx`'s `ScriptTextOutputCallback (P1-5g)` suite: tests verify the
*setup* (a `<script>` element is/isn't created depending on `allowScriptExecution`; its `.text`
contains the expected wrapped script) via `vi.spyOn(document, 'createElement')`, and verify the
write-back *wiring* by manually invoking the exposed `window.__scriptTextOutputResult_N` hook
(simulating what the script would do in a real browser) rather than relying on jsdom to actually run
the injected code. **Real end-to-end script execution should be manually checked via `npm run
dev:mock` before `allowScriptExecution` is ever flipped to `true` in production** — this was not
done as part of this task (no route currently exercises the scenario outside `server.use()` test
overrides); it's a needed step of the eventual security review, not just a Vitest gap.

## Follow-up (not done, not currently needed)

- QR/authenticator-app registration and the built-in reCAPTCHA module remain non-functional in the
  new app (see above) — would need either a dedicated per-module React integration or AM-side
  script changes targeting the `setResult` convention.
- The Scripted module's `document.forms[0]`/auto-submit convention isn't replicated — an admin's
  existing Scripted-module script written for legacy XUI will not auto-submit in the new app.
