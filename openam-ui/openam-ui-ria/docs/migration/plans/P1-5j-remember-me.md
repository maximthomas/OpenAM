# P1-5j — Login parity: remember-me (persist username)

**Depends on:** P1-5b · Read [`README.md`](README.md) (shared research) first.

> **Split (2026-07-03).** Carved out of the original P1-5f (see [`P1-5f-error-logout-views.md`](P1-5f-error-logout-views.md)
> for the split rationale). Small and self-contained; touches only `CallbackForm` (a pure new prop) and `LoginPage`.
> Functionally independent of P1-5f, but recommended to land **after** it to avoid `LoginPage` merge friction. It is a
> **gate precondition** for P1-5k (full login parity includes remember-me), so P1-5k `depends_on` it.

## Goal

Remember the username across logins: pre-fill the first text (Name) input, check the box, focus the password field
on return. Persist to the same **`login` cookie** legacy XUI uses so the remembered username carries across
`/XUI` ↔ `/EUI` during coexistence.

## Legacy reference
- **RESTLoginView.formSubmit** (221–228) — on submit, if the remember-me box is checked, write the **first text
  input's** value to cookie `login`; else clear it.
- **RESTLoginView.prefillLoginData** (407–418) — on render, if cookie `login` is set: pre-fill the first text input
  with it, check the box, focus the password field.
- **`_RememberLogin.html`** — the checkbox partial; label `templates.user.LoginTemplate.loginRemember`. Rendered
  only on username/password stages (`showRememberLogin`).
- Cookie: name **`login`**, **20-day** expiry, value = the remembered username. No AM endpoint (pure client cookie).

## Locked decisions (planning, 2026-07)
- **Storage = the legacy `login` cookie**, 20-day expiry, same name — cross-app carryover during coexistence.
- Checkbox is gated to challenges that contain a `NameCallback` (i.e. real username/password stages), mirroring
  legacy `showRememberLogin`. Not shown on Choice/Confirmation-only or redirect/polling stages.

## Current state (reuse, don't duplicate)
- `commons-ui-next/auth/CallbackForm.tsx` — generic renderer; props are `{ challenge, onSubmit, submitting }`. Seeds
  controlled `values` state from the challenge; renders NameCallback as a text input, PasswordCallback as password.
  Guards available: `isNameCallback`, `isPasswordCallback`, `getPrompt`.
- eui `features/auth/LoginPage.tsx` — drives `useAuthenticationFlow`, renders `<CallbackForm>` keyed on
  `challenge.authId`.
- i18n already has `templates.user.LoginTemplate.loginRemember` ("Remember my username").

## Implementation steps (ordered, each independently testable)

1. **`rememberMe.ts`** (eui `features/auth/`) — cookie `login` helpers: `getRememberedLogin()`,
   `setRememberedLogin(username)` (20-day expiry, `path=/`), `clearRememberedLogin()`. Plain `document.cookie`;
   no dependency.
2. **`CallbackForm` remember-me prop** (`commons-ui-next/src/auth/CallbackForm.tsx`) — add optional
   `rememberMe?: { checked: boolean; onChange: (checked: boolean) => void }`. When present **and** the challenge
   contains a `NameCallback`, render the checkbox (`templates.user.LoginTemplate.loginRemember`) just before the
   submit button. Pure props, no app import → stays ADR-0002-clean (extractable).
3. **Wire in `LoginPage.tsx`** — on mount, if `getRememberedLogin()` exists: seed the `NameCallback` value + default
   the checkbox checked + `autoFocus` the password input. On submit, `setRememberedLogin(name)` when checked, else
   `clearRememberedLogin()`. Manage the checkbox state and pass it to `CallbackForm` via the new prop.
4. **Tests:** remember-me round-trip — submit with the box checked → cookie set; reload → Name input pre-filled,
   box checked, password focused; submit with the box unchecked → cookie cleared. `CallbackForm` renders the
   checkbox only when a `NameCallback` is present.
5. **Docs:** update `reference/eui-foundation.md` (`CallbackForm` `rememberMe` prop, `rememberMe.ts`); `tasks.yml`
   P1-5j → done. Does **not** touch `route-ownership.yml` (gate flip is P1-5k).

## Files
- **New (eui `openam-ui-eui/src/features/auth/`):** `rememberMe.ts` (+ test).
- **Edit:** `commons-ui-next/src/auth/CallbackForm.tsx` (+ its test `CallbackForm.test.tsx`),
  eui `features/auth/LoginPage.tsx` (+ `LoginPage.test.tsx`), `reference/eui-foundation.md`, `tasks.yml`.
- **Conventions:** CDDL header, TS strict, 2-space/single-quote, react-bootstrap 5; no app-specific imports into
  `commons-ui-next` (ADR-0002 — the `rememberMe` prop must stay a pure prop, the cookie logic lives in the eui app).

## Out of scope
Everything else in the login split (views/failure-nav → P1-5f; session-timeout + gate flip → P1-5k). Remember-me for
non-username stages (legacy only remembers the first text input).

## Verification
`npm run test:run` + `npm run lint` + typecheck for both packages; `dev:mock` walk: log in with the box checked,
reload the login page, confirm the username is pre-filled and the box is checked; uncheck + submit, reload, confirm
it is cleared.
