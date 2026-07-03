/**
 * The contents of this file are subject to the terms of the Common Development and
 * Distribution License (the License). You may not use this file except in compliance with the
 * License.
 *
 * You can obtain a copy of the License at legal/CDDLv1.0.txt. See the License for the
 * specific language governing permission and limitations under the License.
 *
 * When distributing Covered Software, include this CDDL Header Notice in each file and include
 * the License file at legal/CDDLv1.0.txt. If applicable, add the following below the CDDL
 * Header, with the fields enclosed by brackets [] replaced by your own identifying
 * information: "Portions copyright [year] [name of copyright owner]".
 *
 * Copyright 2026 3A Systems LLC.
 */

/**
 * Execution adapter for ScriptTextOutputCallback (TextOutputCallback messageType 4) — P1-5g.
 * Full writeup: docs/migration/reference/script-text-output.md (openam-ui-ria).
 *
 * SECURITY BOUNDARY: by the time any callback is rendered, this app has already reached AM
 * same-origin over the cookie-authenticated session (iPlanetDirectoryPro) — a
 * ScriptTextOutputCallback's script carries the same trust level as any other same-origin AM
 * response. This mirrors legacy XUI, where jQuery's `.html()` auto-executes the `<script>`
 * spliced into `_ScriptTextOutput.html` (RESTLoginView.js callbackRender). Executing it here is
 * still a deliberate widening of this app's script-execution surface versus the rest of the React
 * codebase, so callers must opt in explicitly (CallbackForm's `allowScriptExecution` prop,
 * default false) until this has a human security review sign-off.
 *
 * WRITE-BACK CONVENTION (new-app-specific — NOT compatible with unmodified legacy AM scripts):
 * the script is wrapped in an IIFE that receives a `setResult(value)` function, which reports a
 * computed value (device-print blob, WebAuthn assertion, reCAPTCHA token, ...) back to the
 * caller. This does not replicate legacy's DOM-name addressing
 * (`document.forms[0].elements[name]`) or its jQuery/RequireJS-coupled first-party producers
 * (QR/authenticator-app registration via org.forgerock.openam.utils.qr.GenerationUtils, the
 * built-in reCAPTCHA auth module) — those assume globals this app does not provide and will not
 * run unmodified here. Scripts targeting the new UI must call `setResult` directly.
 */

let counter = 0

export function runScriptTextOutput(script: string, onResult: (value: string) => void): () => void {
  const globalName = `__scriptTextOutputResult_${++counter}`
  const win = window as unknown as Record<string, unknown>
  win[globalName] = onResult

  // Wrapped in try/catch: a broken or incompatible AM script must not crash the host page with an
  // uncaught exception (e.g. a script written for legacy XUI calling a global — jQuery/RequireJS —
  // this app does not provide; see the reference doc).
  const scriptEl = document.createElement('script')
  scriptEl.text = `;(function (setResult) {\ntry {\n${script}\n} catch (e) {}\n})(window.${globalName});`
  document.body.appendChild(scriptEl)

  return () => {
    scriptEl.remove()
    delete win[globalName]
  }
}
