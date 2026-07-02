# P1-5d — Login parity: goto/realm/fragment params + validateGoto

**Depends on:** P1-5b · Coordinate with **P1-10** · Read [`README.md`](README.md) (shared research) first.

## Goal

Honor the auth URL params legacy supports on entry, and the validated `goto` redirect on success — replacing
P1-5b's hardcoded "success → `/`".

## Legacy reference
- **`RESTLoginView.handleParams`** (420–448) — parses composite fragment+query params; maps legacy shorthand
  `authlevel/module/service/user/resource` → `authIndexType`/`authIndexValue` (unless `composite_advice` set);
  special-cases `/SSORedirect` / `/SSOPOST` context prefixing.
- **`RESTLoginHelper.setSuccessURL`** (130–160) — if `goto` present, validate+sanitize via server, else fall back
  to AM `successUrl` (excluding the admin console path); stores the result in `gotoUrl.jsm` state.
- **`AuthNService.validateGotoUrl`** (263–273) — `POST /json/users?_action=validateGoto`, returns sanitized
  `successURL` (open-redirect guard).
- **`RESTLoginHelper.filterUrlParams`** — whitelist for replay: `arg, authIndexType, authIndexValue, goto,
  gotoOnFail, ForceAuth, locale`.

## Approach (new stack)
- Add a small param module (eui `features/auth` or commons-ui-next if reusable): read HashRouter query/fragment
  params, normalize the shorthand → `authIndexType`/`authIndexValue`, expose a `goto` accessor + a whitelist filter.
- Thread `authIndexType`/`authIndexValue`/`realm` into `startAuthentication` (extend its signature — currently
  takes only `transport`) so the correct tree/realm is selected.
- Add `validateGoto(transport, goto)` to `commons-ui-next/session` (or `/auth`) → `POST /json/users?_action=validateGoto`;
  on success navigate to the sanitized URL instead of `/`.
- **Coordinate with P1-10:** P1-10 normalizes `#login` → `#/login` and must preserve these query params; agree on
  the entry point where params are read so validation and spelling-normalization don't fight. Validation can run
  before or after normalization — document the order chosen.

## Files (anticipated)
- `commons-ui-next/src/auth/authenticate.ts` (params on `startAuthentication`), maybe `src/http` for realm.
- `commons-ui-next/src/session/` or `src/auth/` — `validateGoto`.
- `openam-ui-eui/src/features/auth/` — param parsing/whitelist + success-redirect wiring in the loop hook.
- `commons-ui-next/src/mock/handlers/` — mock `validateGoto` + authIndex-aware `/authenticate`.
- Tests: shorthand mapping, goto validation (allowed + rejected), authIndex selection.

## Out of scope
Multi-stage engine (P1-5b) · hash-spelling normalization itself (P1-10) · existing-session realm change (P1-5e).

## Verification
Vitest + typecheck + lint; `dev:mock` login with `?goto=` (accepted + rejected) and an authIndexType/Value param.
