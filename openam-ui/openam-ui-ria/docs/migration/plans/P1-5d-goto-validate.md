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

### 1. Auth URL param parsing — `openam-ui-eui/src/features/auth/loginParams.ts`

Parse `useSearchParams()` from react-router (HashRouter exposes params after `#/path?`).  
Shorthand normalization: `authlevel/module/service/user/resource` → `authIndexType`/`authIndexValue`, skipped if
`authIndexType === 'composite_advice'` already set.  
`buildAuthQuery(params)` builds `?authIndexType=...&authIndexValue=...` query string for appending to `/authenticate`.

SSORedirect/SSOPOST context-prefixing deferred — the AM validateGoto call handles this on the server side.

### 2. Thread params into `startAuthentication`

Extend `commons-ui-next/src/auth/authenticate.ts` `startAuthentication(transport, queryString?)` — appends the
optional query string to `/authenticate`. Backward-compatible (queryString is optional).

Pass `queryString` through `useAuthenticationFlow(queryString?)` → `startAuthentication`.

### 3. `validateGoto` — `commons-ui-next/src/auth/validateGoto.ts`

`POST /users?_action=validateGoto` with `{ goto: decodedGoto }` body.  
Returns sanitized `successURL` string or `null` on failure (400 / network error).  
On success in `LoginPage`: if `goto` param present, call `validateGoto`; navigate to validated URL via
`window.location.href` (may be external); on failure fall back to `'/'`.  
If no `goto`, fall back to `'/'` (the EUI home). AM's `successUrl` not used (points to admin console for root realm).

### 4. MSW handler — `commons-ui-next/src/mock/handlers/users.ts`

Handles `POST */json/users?_action=validateGoto` and `POST */json/realms/root/users?_action=validateGoto`.  
Allowlist: relative paths (`/…`), `http://localhost:…/*`, `http://allowed.example.com`.  
Rejects `http://open-redirect.evil.com` with 400.

### 5. Coordination with P1-10

P1-10 normalizes hash spellings (`#login` → `#/login`) on app load, before any route renders. LoginPage reads URL
params via react-router `useSearchParams`, which runs after the hash normalization. Order is:

```
load → P1-10 normalization → HashRouter routes match → LoginPage useSearchParams → parseLoginParams
```

No conflict. P1-10 must preserve query params when normalizing hash spellings (document this constraint in P1-10).

## Files to create/modify

| File | Action | Notes |
|---|---|---|
| `commons-ui-next/src/auth/authenticate.ts` | modify | Add `queryString?: string` to `startAuthentication` |
| `commons-ui-next/src/auth/validateGoto.ts` | **new** | `validateGoto(transport, goto)` |
| `commons-ui-next/src/auth/index.ts` | modify | Export `validateGoto` |
| `commons-ui-next/src/mock/handlers/users.ts` | **new** | MSW handler for validateGoto |
| `commons-ui-next/src/mock/handlers/index.ts` | modify | Add `usersHandlers` |
| `openam-ui-eui/src/features/auth/loginParams.ts` | **new** | Parse + normalize URL params |
| `openam-ui-eui/src/features/auth/loginParams.test.ts` | **new** | Shorthand mapping, whitelist, composite_advice bypass |
| `openam-ui-eui/src/features/auth/useLogin.ts` | modify | Accept and thread `queryString` |
| `openam-ui-eui/src/features/auth/LoginPage.tsx` | modify | Parse params, thread query, validate goto on success |
| `openam-ui-eui/src/features/auth/LoginPage.test.tsx` | modify | Add goto-accepted, goto-rejected, authIndexType cases |

## Out of scope
Multi-stage engine (P1-5b) · RedirectCallback/PollingWaitCallback (P1-5c) · hash-spelling normalization itself (P1-10)
· existing-session realm change (P1-5e) · SSORedirect context-prefixing (rare edge case, deferred).

## Verification
Vitest + typecheck + lint in both packages; `dev:mock` login with `?goto=http://allowed.example.com` (accepted),
`?goto=http://open-redirect.evil.com` (rejected → falls back to `/`), and `?module=DataStore` (shorthand maps to
`?authIndexType=module&authIndexValue=DataStore` on the authenticate request).
