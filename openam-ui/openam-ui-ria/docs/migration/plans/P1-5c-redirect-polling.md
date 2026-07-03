# P1-5c — Login parity: RedirectCallback + PollingWaitCallback + 408 timeout-retry

**Depends on:** P1-5b · Read [`README.md`](README.md) (shared research) first.

## Goal

Handle the two "special" callbacks that alter the P1-5b engine loop, plus AM request timeouts.

## Legacy reference
- **RedirectCallback** — `RESTLoginView.js` 326–341. Reads `redirectUrl`/`redirectMethod`/`redirectData` from
  callback `output`; for `POST` builds a hidden-field form and submits it, for `GET` uses `window.location.replace`.
  Federation resumption tracked via an `AuthenticationToken` cookie when a `trackingCookie` output is present.
- **PollingWaitCallback** — `RESTLoginView.js` 342–352 + empty `_PollingWait.html`. Reads `waitTime`, delays,
  then re-submits the same challenge (`suppressSpinner`) — used for push auth. Guarded so a stray poll can't loop.
- **408 timeout-retry** — `AuthNService.js`. Retries the `/json/authenticate` request on a `408` response.

## Approach (new stack)
- Extend `KNOWN_CALLBACK_TYPES` + the P1-5b `CallbackForm`/loop so `RedirectCallback` and `PollingWaitCallback`
  are **intercept** cases, not rendered controls:
  - **Redirect:** before rendering, if a stage contains a RedirectCallback, perform the navigation (build+submit a
    form for POST, or `location.replace` for GET). Preserve `trackingCookie` handling. No React form is shown.
  - **Polling:** render a "waiting" state (spinner + optional message), schedule a re-submit of the current
    challenge after `waitTime` in the eui loop hook, and stop once the step is no longer a polling stage.
- **408 retry:** add bounded retry (respecting AM's timeout semantics) in the loop hook / a transport wrapper.
  Keep it distinct from restart-on-failure (P1-5b).

## Files (anticipated)
- `commons-ui-next/src/auth/types.ts` (add the two types to the known set), `callbacks.ts` (redirect/poll accessors).
- `commons-ui-next/src/auth/CallbackForm.tsx` (polling "waiting" UI + redirect intercept), or a small sibling
  component if the loop owns the intercept.
- `openam-ui-eui/src/features/auth/useAuthenticationFlow.ts` (poll scheduling, 408 retry) — (landed as `useLogin.ts`).
- `commons-ui-next/src/mock/{fixtures,handlers}/authenticate.ts` — add a SAML/OAuth redirect scenario and a
  push-polling scenario (returns PollingWaitCallback N times, then success).
- Tests: redirect intercept, polling advance/stop, 408 retry.

> **Gap found (2026-07-02, docs review):** this task specified and implemented the **outbound** redirect
> (navigating to the external IdP) but nothing for the **return leg** — resuming the flow when the browser
> comes back from the IdP. Legacy tracks this via an `authId` cookie set before navigating away and
> consumed on return (`AuthNService.js`); the new engine stores nothing, so a federation login restarts at
> stage 1 instead of resuming. This task was nonetheless marked `done` since the outbound half is real
> parity progress. Tracked separately as task **P1-5i** (depends on this task) — see
> `docs/migration/plans/review-remediation-2026-07.md`, Stage 5. P1-5f's parity gate cannot flip
> login → `migrated` until P1-5i lands.
>
> **Resolved (2026-07-03, Stage 5).** P1-5i is done: `commons-ui-next/src/auth/trackingToken.ts` ports the
> `authId` cookie; `resumeAuthentication` (in `authenticate.ts`) resumes with `{ authId }` instead of an
> empty `begin()`; `useLogin.ts` sets the cookie when a tracked `RedirectCallback` requirements step
> appears (before navigating away) and resumes from it on mount instead of restarting. See P1-5i's
> `tasks.yml` detail for the full breakdown.

## Out of scope
Rendering of standard callbacks (P1-5b) · goto (P1-5d). ScriptTextOutput stays deferred (P1-5g).
RedirectCallback return-leg resume (authId tracking cookie) — see the gap note above; tracked as P1-5i.

## Verification
Vitest + typecheck + lint in both packages; `dev:mock` walk of a push-polling flow and a (mock) redirect flow.
