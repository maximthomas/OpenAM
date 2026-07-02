# P1-5b — Login parity (engine): multi-stage callback loop + generic callback renderer

**Depends on:** P1-5 · **Blocks:** P1-5c/d/e/f/g · Read [`README.md`](README.md) (shared research) first.

## Goal

Replace P1-5's static single-stage login with a **generic, multi-stage AM-callback engine**: the login form is
just the current `/json/authenticate` challenge rendered as controls, submitted, and repeated until success or
failure. This is the parity-critical core; every other P1-5x task layers onto it.

## Locked decisions (from the design interview)

1. **Placement** — the widened callback model + the generic renderer live in **commons-ui-next** (reusable AM
   primitive, extracted upstream per ADR-0002; `AppShell` already puts react-bootstrap UI there). The multi-stage
   **loop hook** (TanStack Query) + `LoginPage` live in **eui** (QueryClient is an app concern).
2. **Callback model** — open `type: string` + generic `output`/`input` arrays + small typed guards/helpers +
   a `KNOWN_CALLBACK_TYPES` union for the renderer switch. Unknown types → text input (Default).
3. **Refactor, don't fork** — single-stage username/password becomes a 1-stage instance of the general loop.
   One auth code path. `LoginPage.test.tsx` stays green (updated as needed).
4. **Failure handling** — on a `failure` step, show the AM error and **restart** (fresh `startAuthentication`,
   back to stage 1; AM invalidates `authId` on failure). 408 timeout-retry is deferred to P1-5c.
5. **Rendering** — functional parity, modernized/consistent controls. A synthetic "Log in" submit button is
   injected when a stage carries no ConfirmationCallback (username/password stages have none).
6. **Labels** — derived from each callback's `output` "prompt" (trim a trailing `:`) — the only source that
   generalizes across callback types.
7. **ScriptTextOutput** — render TextOutputCallback `messageType` 0/1/2 as Bootstrap alerts (info/warning/error);
   `messageType` 4 (ScriptTextOutput) executes nothing — deferred to P1-5g with a clearly-marked gap.

### Callback → control map (in-scope)
`NameCallback`/Default → text · `PasswordCallback` → password · `TextInputCallback` → textarea ·
`HiddenValueCallback` → hidden input · `ChoiceCallback` → labeled `<select>` (or radio group) ·
`ConfirmationCallback` → button(s), submitted value = chosen option index · `TextOutputCallback` → alert.
**Out (P1-5c):** `RedirectCallback`, `PollingWaitCallback`.

## Files to change

### commons-ui-next
- **`src/auth/types.ts`** — widen `AmCallback.type` to `string`; add `KnownCallbackType` union +
  `KNOWN_CALLBACK_TYPES` const. Leave `AmCallbackOutput`/`AmCallbackInput`/`AmAuthChallenge`/`AuthStep` intact.
- **`src/auth/callbacks.ts`** *(new — pure helpers)* — `getOutput(cb, name)`, `getPrompt(cb)` (trims trailing `:`),
  `getChoices(cb)`, `getMessageType(cb)`, type guards. Reuse `setCallbackValue`/`fillCallbacks` from `authenticate.ts`.
- **`src/auth/CallbackForm.tsx`** *(new — React/react-bootstrap)* — self-contained: seeds controlled field state
  from the challenge, renders one control per callback via the map above, injects the synthetic submit when no
  ConfirmationCallback is present, renders `challenge.header` as the title, and calls
  `onSubmit(challengeWithValues, confirmationIndex?)`. Props `{ challenge, onSubmit, submitting }`.
- **`src/auth/index.ts`** — export `CallbackForm`, the new helpers, `KNOWN_CALLBACK_TYPES`, and new types.
  (Keep the single `./auth` subpath in `package.json`; no new exports entry — react is already a peer dep.)
- **`src/mock/fixtures/authenticate.ts`** — add multi-stage fixtures: a 2-stage chain (username stage → password
  stage), a ChoiceCallback stage, a ConfirmationCallback stage, a TextOutput+HiddenValue stage. Keep `demo/changeit`.
- **`src/mock/handlers/authenticate.ts`** — extend `resolveAuthenticate` into a tiny stage state-machine keyed
  by the submitted `stage`/`authId`, returning the next fixture until success/failure. Single-stage path unchanged.
- **Tests** *(new)* — `src/auth/CallbackForm.test.tsx` (each control type; synthetic submit; ChoiceCallback
  selection) + multi-stage protocol assertions beside `src/auth/auth.test.ts`.

### eui
- **`src/features/auth/useLogin.ts`** → rework into the loop hook (rename to `useAuthenticationFlow.ts` or keep
  the name): holds current `AuthStep`, starts auth on mount, exposes `submit(filledChallenge, confirmationIndex?)`
  (TanStack Query mutation over `submitCallbacks`) and `restart()`. Keep `retry: false`.
- **`src/features/auth/LoginPage.tsx`** — render `<CallbackForm>` for `requirements` steps; on `success` →
  `setToken` + `navigate('/')`; on `failure` → show AM error + `restart()`. Same `AppShell variant="auth"` mount;
  `App.tsx` route `/login` unchanged.
- **`src/features/auth/LoginPage.test.tsx`** — update label queries to the prompt-derived labels
  (`User Name`, `Password`); keep happy-path + failure green; add a multi-stage walk-through test.
- Sweep stale `P1-5b` comment pointers in the two auth files to the correct task ids.

## Out of scope (deferred)
Redirect/polling + 408 retry (P1-5c) · goto/validateGoto (P1-5d) · existing-session/realm-change + zero-page
(P1-5e) · session dialog + error/expired/logout views + remember-me (P1-5f) · ScriptTextOutput exec (P1-5g).
Login route stays `status: in_progress`.

## Verification
1. `npm run test:run` in `openam-ui/openam-ui-eui` **and** `openam-ui/commons-ui-next` (multi-stage + per-control
   + refactored LoginPage tests green).
2. `npm run typecheck` + `npm run lint` in both packages.
3. Route-ownership drift test still passes (no ownership change).
4. Manual: `npm run dev:mock` (from `openam-ui/openam-ui-eui`) → walk the single-stage login **and** a multi-stage
   chain against the MSW mock (ADR-0010 / P0-8); confirm restart-on-failure and a ChoiceCallback stage advancing.
