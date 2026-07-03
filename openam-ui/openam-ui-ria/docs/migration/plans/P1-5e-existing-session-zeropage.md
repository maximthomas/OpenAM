# P1-5e — Login parity: existing-session/realm-change (confirmLogin) + zero-page/auto-login

**Depends on:** P1-5b (and builds on P1-5d's param parsing) · Read [`README.md`](README.md) first.

## Goal

Two entry-time behaviors: reuse/confirm an already-valid session, and auto-submit credentials supplied in
the URL. Both run before the user sees a form — the hook detects the scenario and either bypasses the
form entirely or submits it automatically.

## Legacy reference

- **existing-session** — `RESTLoginView.handleExistingSession` (142–175). If the initial
  `/json/authenticate` already carries a `tokenId`, fetch the logged-in user
  (`POST /json/users?_action=idFromSession`); if `isRealmChanged()` route to `#confirmLogin/`, else
  resolve the success URL (honoring `goto`). `arg=newsession` URL param forces a logout first so AM
  starts a fresh session.
- **confirmLogin** — `RESTConfirmLoginView.js` (47). If the realm changed, clear the stale session and
  show "logged out of previous site, log in to new site"; otherwise navigate to the default route.
- **zero-page / auto-login** — `RESTLoginView.isZeroPageLoginAllowed` (192–205) + `autoLogin`
  (177–190). Maps `IDToken1`/`IDToken2`/… URL params to `callback_0`/`callback_1`/… and submits
  immediately without rendering the form; gated by `zeroPageLoginAllowed` from server info and an
  `autoLoginAttempts` counter to prevent loops.

## Key simplifications over legacy

- **No `idFromSession` call needed for realm detection**: `AmAuthSuccess.realm` in the
  `/authenticate` success response already carries the session realm.  `idFromSession` IS needed by
  P1-5f's error/expired views — it is deferred to that task, not added here.
- **No `refererWhitelist` sub-object**: the current `AmServerInfo` exposes a flat
  `zeroPageLoginAllowed: boolean`. Use it as the sole gate; a referrer whitelist extension is a
  future enhancement, not a parity blocker.

> **Correction (2026-07-02, docs review):** the real AM `/json/serverinfo/*` response returns
> `zeroPageLogin: { enabled, refererWhitelist, allowedWithoutReferer }`
> (`openam-core-rest/.../models/ServerInfo.java:87`, `ServerInfoResource.java:185`) — the flat
> `zeroPageLoginAllowed` above was the mock's own invention, so "the current `AmServerInfo` exposes…"
> was circular reasoning, not a grounded simplification. The referrer whitelist is required for both
> parity and security (an unlisted referrer must not auto-submit credentials). Fixed by task **P1-5h**
> (see `docs/migration/plans/review-remediation-2026-07.md`, Stage 4).
>
> **Resolved (2026-07-03, Stage 4).** `P1-5h` landed: `AmServerInfo.zeroPageLoginAllowed` is now
> `zeroPageLogin: AmZeroPageLogin`, and `commons-ui-next/src/serverinfo/zeroPageLogin.ts` implements
> the referrer-whitelist gate (`isZeroPageLoginAllowed`), wired into `LoginPage.tsx`. The "No
> `refererWhitelist` sub-object" simplification above and the "Referrer whitelist enforcement" row in
> Out of scope (below) are superseded by this fix.

---

## Implementation steps

### Step 1 — `commons-ui-next/src/serverinfo/` (NEW MODULE)

Zero-page needs to read `zeroPageLoginAllowed` from AM's server info. There is no fetch utility yet —
only a mock handler. Add a real `serverinfo` module.

**`commons-ui-next/src/serverinfo/types.ts`** — move `AmServerInfo` here from `mock/types.ts` and
re-export it there so existing mock imports keep working:
```ts
export type AmServerInfo = { /* same fields as in mock/types.ts today */ }
```

**`commons-ui-next/src/serverinfo/serverinfo.ts`** — fetch helper:
```ts
export async function fetchServerInfo(transport: Transport): Promise<AmServerInfo>
// GET /json/serverinfo/* (wildcard returns the full server info object)
```

**`commons-ui-next/src/serverinfo/index.ts`** — barrel:
```ts
export { fetchServerInfo } from './serverinfo.ts'
export type { AmServerInfo } from './types.ts'
```

**`commons-ui-next/package.json`** — add export entry:
```json
"./serverinfo": "./src/serverinfo/index.ts"
```

**`commons-ui-next/src/mock/types.ts`** — replace the inline `AmServerInfo` definition with a
re-export from the real module:
```ts
export type { AmServerInfo } from '../serverinfo/types.ts'
```

### Step 2 — `useAuthenticationFlow` — expose `isExistingSession` (MODIFY `useLogin.ts`)

Track how many callbacks have been submitted. If `step.kind === 'success'` and no submit has been
made, the initial `/authenticate` returned a tokenId — the user has a live session.

```ts
const submitCountRef = useRef(0)

// in submitMutation.onSuccess:
onSuccess: (result) => {
  submitCountRef.current += 1
  setStep(result)
}
```

Expose in the returned object:
```ts
isExistingSession: step?.kind === 'success' && submitCountRef.current === 0,
```

Reset `submitCountRef.current = 0` inside `startAuth` (alongside the existing `setStep(null)`) so
restarted flows work correctly.

### Step 3 — `arg=newsession` client-side token clear (MODIFY `LoginPage.tsx`)

`arg` is already forwarded to AM via `buildAuthQuery` (P1-5d), so AM handles the server-side logout.
Additionally clear any EUI-side stored token so it doesn't linger across sessions:

```tsx
// On mount, clear stale token if newsession is requested.
useEffect(() => {
  if (loginParams.arg === 'newsession') {
    clearToken()
  }
}, [loginParams.arg])
```

### Step 4 — Existing-session branch in `LoginPage.tsx` (MODIFY)

In the existing `useEffect` that reacts to `step` changes, handle the existing-session case:

```ts
if (step?.kind === 'success' && isExistingSession) {
  // Compare session realm (from the auth response) with URL realm param.
  const sessionRealm = step.success.realm ?? '/'
  const urlRealm = loginParams.realm ?? '/'   // realm is not yet in LoginParams — add it in Step 6
  if (normalizeRealm(sessionRealm) !== normalizeRealm(urlRealm)) {
    // Realm changed — user had a session in a different realm.
    void navigate(`/confirmLogin?previousRealm=${encodeURIComponent(sessionRealm)}`)
  } else {
    // Same realm — treat as a normal success.
    // (goto / navigate('/') logic already below; set token and fall through.)
    setToken(step.success.tokenId)
    if (loginParams.goto) {
      validateGoto(amTransport, loginParams.goto).then(...)
    } else {
      void navigate('/')
    }
  }
  return
}
```

`normalizeRealm` strips trailing slashes and lower-cases for comparison.

> Note: `realm` URL param is not yet in `LoginParams`. Add it in Step 6 below.

### Step 5 — `ConfirmLogin` component + route (NEW file + App.tsx MODIFY)

**`openam-ui-eui/src/features/auth/ConfirmLogin.tsx`**

Simple read-only view — no AM calls needed here. A `BootstrapDialog`-equivalent is P1-5f territory.
This is a full-page info + link:

```tsx
export default function ConfirmLogin() {
  const [searchParams] = useSearchParams()
  const previousRealm = searchParams.get('previousRealm') ?? '/'
  const { t } = useTranslation()

  return (
    <Alert variant="info">
      <Alert.Heading>{t('login.existingSession.title')}</Alert.Heading>
      <p>{t('login.existingSession.body', { realm: previousRealm })}</p>
      <Link to="/login">{t('common.user.login')}</Link>
    </Alert>
  )
}
```

**`openam-ui-eui/src/App.tsx`** — add inside the auth-shell `<Route>`:
```tsx
<Route path="/confirmLogin" element={<ConfirmLogin />} />
```

**i18n keys to add** to `commons-ui-next` English locale (or eui locale if there is one):
- `login.existingSession.title` — "You have been signed out"
- `login.existingSession.body` — "Your session from {{realm}} has ended. Please sign in to continue."

### Step 6 — Add `realm` to `LoginParams` and `extractIDTokens` helper (MODIFY `loginParams.ts`)

**Add `realm?: string` to `LoginParams`** and to `PARAM_WHITELIST` (but NOT to `buildAuthQuery`'s
`AUTH_KEYS`, since realm routing is handled by the transport layer's realm-path resolution, not as a
query param on `/authenticate`).

**Add `extractIDTokens(searchParams: URLSearchParams): string[]`** — returns `IDToken1`, `IDToken2`, …
values in order (stopping at the first missing index):
```ts
export function extractIDTokens(searchParams: URLSearchParams): string[] {
  const tokens: string[] = []
  for (let i = 1; ; i++) {
    const val = searchParams.get(`IDToken${i}`)
    if (val === null) break
    tokens.push(val)
  }
  return tokens
}
```

### Step 7 — Zero-page/auto-login in `LoginPage.tsx` (MODIFY)

**Fetch server info** alongside the auth flow:
```ts
const { data: serverInfo } = useQuery({
  queryKey: ['serverinfo'],
  queryFn: () => fetchServerInfo(amTransport),
  staleTime: Infinity,   // server info doesn't change during a session
})
```

**Extract IDTokens** on first render:
```ts
const idTokens = useMemo(() => extractIDTokens(searchParams), [searchParams])
```

**Auto-submit ref** to guard against retry loops:
```ts
const zeroPageAttemptedRef = useRef(false)
```

**In the `useEffect` that watches `step`**:

```ts
// Zero-page auto-login: when the first challenge arrives and conditions are met, pre-fill and submit.
if (
  step?.kind === 'requirements' &&
  !zeroPageAttemptedRef.current &&
  idTokens.length > 0 &&
  serverInfo?.zeroPageLoginAllowed
) {
  zeroPageAttemptedRef.current = true
  const filled = fillCallbacks(step.challenge, idTokens)
  submit(filled)
  return
}
```

On failure, `zeroPageAttemptedRef.current` stays `true` → the form renders normally and the user
types credentials.

**Render guard**: while `serverInfo` is loading and `idTokens.length > 0`, show a spinner (avoid
briefly flashing the form before the server-info check completes).

### Step 8 — MSW handlers (MODIFY `authenticate.ts`, `handlers/sessions.ts`)

**Mock scenario: initial `/authenticate` returns success** (existing session).

Add to `commons-ui-next/src/mock/fixtures/authenticate.ts`:
```ts
export const AUTH_EXISTING_SESSION_ID = 'mock-existing-session-token-id'

// AUTH_SUCCESS_EXISTING_SESSION is the same as AUTH_SUCCESS — it already has tokenId/realm.
// We reuse AUTH_SUCCESS for this scenario.
```

Add to `commons-ui-next/src/mock/handlers/authenticate.ts`:
```ts
/**
 * Existing-session authenticate handler — initial call (no authId) immediately returns success.
 * Use in tests via server.use() to simulate a user with a live session visiting /login.
 */
export async function existingSessionAuthenticateHandler(): Promise<Response> {
  return HttpResponse.json(AUTH_SUCCESS)
}
```

**Mock for different-realm scenario**: same as above, but the `AUTH_SUCCESS` fixture's `realm` is
`'/other-realm'`. Add:
```ts
export const AUTH_SUCCESS_OTHER_REALM: AmAuthSuccess = {
  ...AUTH_SUCCESS,
  realm: '/other-realm',
}
```

And:
```ts
export async function existingSessionOtherRealmHandler(_request: Request): Promise<Response> {
  return HttpResponse.json(AUTH_SUCCESS_OTHER_REALM)
}
```

---

## Files to create / modify

| File | Action | Notes |
|------|--------|-------|
| `commons-ui-next/src/serverinfo/types.ts` | **new** | Move `AmServerInfo` here from `mock/types.ts` |
| `commons-ui-next/src/serverinfo/serverinfo.ts` | **new** | `fetchServerInfo(transport)` |
| `commons-ui-next/src/serverinfo/index.ts` | **new** | Barrel export |
| `commons-ui-next/package.json` | modify | Add `"./serverinfo"` export |
| `commons-ui-next/src/mock/types.ts` | modify | Re-export `AmServerInfo` from `../serverinfo/types.ts` |
| `commons-ui-next/src/mock/fixtures/authenticate.ts` | modify | Add `AUTH_SUCCESS_OTHER_REALM`, `AUTH_EXISTING_SESSION_ID` |
| `commons-ui-next/src/mock/handlers/authenticate.ts` | modify | Add `existingSessionAuthenticateHandler`, `existingSessionOtherRealmHandler` |
| `openam-ui-eui/src/features/auth/useLogin.ts` | modify | `submitCountRef`, expose `isExistingSession` |
| `openam-ui-eui/src/features/auth/loginParams.ts` | modify | Add `realm` to `LoginParams`; add `extractIDTokens` |
| `openam-ui-eui/src/features/auth/ConfirmLogin.tsx` | **new** | Info page for realm-change scenario |
| `openam-ui-eui/src/features/auth/LoginPage.tsx` | modify | `arg=newsession` clear; existing-session branch; zero-page auto-submit; server-info fetch |
| `openam-ui-eui/src/App.tsx` | modify | Add `/confirmLogin` route |

## Tests

Extend `openam-ui-eui/src/features/auth/LoginPage.test.tsx`:

| Scenario | Setup | Assert |
|----------|-------|--------|
| Existing session, same realm | `server.use(http.post('*/json/authenticate', existingSessionAuthenticateHandler))` | Success path executes (navigate to `/` or goto) |
| Existing session, realm changed | `server.use(http.post('*/json/authenticate', existingSessionOtherRealmHandler))` | `navigate('/confirmLogin?previousRealm=%2Fother-realm')` called |
| `arg=newsession` clears token | Set token before mount; mount with `?arg=newsession` | `getToken()` returns null after mount |
| Zero-page allowed + IDTokens | Override server info `zeroPageLoginAllowed: true`; URL has `IDToken1=demo&IDToken2=changeit`; normal single-stage challenge | `submitCallbacks` called with pre-filled values; success path |
| Zero-page disabled | Server info `zeroPageLoginAllowed: false`; URL has `IDToken1=...` | Form renders normally; no auto-submit |
| Zero-page attempt guard | Zero-page enabled; AM returns 401 on auto-submit | Form renders; `zeroPageAttemptedRef` prevents second auto-submit |

## Out of scope

- `idFromSession` (`POST /json/users?_action=idFromSession`) — needed by P1-5f's error/expired views; defer.
- `RESTLoginDialog` session-timeout modal — P1-5f.
- `LoginFailureView` / `SessionExpiredView` / `RESTLogoutView` — P1-5f.
- Remember-me — P1-5j (split out of P1-5f, 2026-07-03).
- `ScriptTextOutput` execution — P1-5g.
- Referrer whitelist enforcement — not exposed by `AmServerInfo.zeroPageLoginAllowed` (flat boolean); future enhancement.
- Login route stays `status: in_progress` until P1-5k (the parity gate — P1-5f was split 3-way on 2026-07-03) lands.

## Verification

`npm run typecheck && npm run lint && npm run test:run` in both `commons-ui-next` and `openam-ui-eui`.

Manual smoke with `npm run dev:mock` in `openam-ui-eui`:
1. Add `existingSessionAuthenticateHandler` override to the browser worker temporarily → visiting `/login`
   should skip the form and redirect to `/`.
2. Same but with `AUTH_SUCCESS_OTHER_REALM` → should redirect to `/confirmLogin`.
3. Visit `#/login?IDToken1=demo&IDToken2=changeit` (with the mock server info temporarily set to
   `zeroPageLoginAllowed: true`) → form should auto-submit and land at `/`.
