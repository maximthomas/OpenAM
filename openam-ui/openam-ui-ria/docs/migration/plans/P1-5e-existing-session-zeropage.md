# P1-5e — Login parity: existing-session/realm-change (confirmLogin) + zero-page/auto-login

**Depends on:** P1-5b (and benefits from P1-5d's param handling) · Read [`README.md`](README.md) first.

## Goal

Two entry-time behaviors: reuse/confirm an already-valid session, and auto-submit credentials supplied in the URL.

## Legacy reference
- **existing-session** — `RESTLoginView.handleExistingSession` (142–175). If the initial `/json/authenticate`
  response already carries a `tokenId`, fetch the logged-in user (`SessionManager.getLoggedUser` →
  `POST /json/users?_action=idFromSession`); if `isRealmChanged()` route to `#confirmLogin/`, else set the
  success URL and navigate (honoring goto). `arg=newsession` forces logout first.
- **confirmLogin** — `RESTConfirmLoginView.js` (47). If realm changed, log out of the previous session then show
  "logged out of previous site, log in to new site"; else navigate to the default route.
- **zero-page / auto-login** — `RESTLoginView.isZeroPageLoginAllowed` (192–205) + `autoLogin` (177–190). Maps
  `IDTokenN` URL params to `callback_N` values and submits immediately without rendering; gated by a referrer
  whitelist and an `autoLoginAttempts` counter to prevent loops.

## Approach (new stack)
- In the eui loop hook: after `startAuthentication`, if the step is `success` on the first call, treat it as an
  existing session → resolve the user via a new `idFromSession` helper in `commons-ui-next/session`, compare realm,
  and either route to a new `confirmLogin` route/component or complete the login.
- Add a `ConfirmLogin` component + `/confirmLogin` route (eui) mirroring `RESTConfirmLoginView`.
- Zero-page: read `IDTokenN` params (reuse P1-5d param parsing), pre-fill the challenge, and submit once via the
  loop hook; enforce a referrer/allow-list policy + a single-attempt guard. Keep the policy in a small, testable
  helper (the interview flagged the legacy version as fragile).

## Files (anticipated)
- `commons-ui-next/src/session/` — `idFromSession` (`POST /json/users?_action=idFromSession`), realm compare helper.
- `openam-ui-eui/src/features/auth/` — existing-session branch in the loop, `ConfirmLogin.tsx`, zero-page helper.
- `openam-ui-eui/src/App.tsx` — add the `/confirmLogin` route.
- `commons-ui-next/src/mock/handlers/` — `idFromSession` + an initial-tokenId `/authenticate` scenario.
- Tests: existing-session same-realm completes; realm-change → confirmLogin; zero-page submit + attempt guard.

## Out of scope
goto validation itself (P1-5d) · session-timeout dialog (P1-5f). Login route stays `in_progress`.

## Verification
Vitest + typecheck + lint; `dev:mock` with a pre-authenticated session and an `IDToken1`/`IDToken2` auto-login URL.
