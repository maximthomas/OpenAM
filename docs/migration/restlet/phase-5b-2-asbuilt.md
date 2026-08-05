# Phase 5b-2 — `/device/user`, `/connect/checkSession`, `/connect/endSession` → CHF: as-built

What actually landed, and **every value measured against live Restlet**. This file is the durable record: the Restlet oracle dies at 5d-1c and these numbers cannot be re-derived afterwards. Spec: [phase-5b-2.md](phase-5b-2.md).

---

<a id="as-built-5-e3--recorded-2026-07-28"></a>
## As-built — 5-E3, recorded 2026-07-28 (test-only)

Captured against a live container built from this tree: `openam-e2e:5e3` (the repo
`openam-distribution/openam-distribution-docker/Dockerfile` with its three `#COPY` lines uncommented, exactly
CI's `build-docker` sed) over `openam-server/target/OpenAM-16.2.0-SNAPSHOT.war`, plus
`openidentityplatform/opendj:latest` on the `test-openam` network, configured with CI's `conf.file`. Restlet
still serves `/oauth2`: every realm-prefixed row carries `Server: Restlet-Framework/2.4.4`, and `/oauth2/*` is
still mapped to `ForgeRockRest` in `web.xml` with no CHF `HttpRouteProvider` claiming those paths.

**Deliverables — e2e only, zero main-source lines:**

| File | Change |
|---|---|
| `e2e/common/oauth2-fixtures.mjs` | `POST_LOGOUT_REDIRECT_URI`, `POST_LOGOUT_REDIRECT_URI_WITH_QUERY`, `CLIENT_SESSION_URI`; `ensureOidcClient` additionally registers both post-logout URIs and a `clientSessionURI`; new `ensureDeviceConsentClient` and `deviceCodeForConsent` |
| `e2e/oauth2/oidc-test.spec.mjs` | new describe `OIDC session endpoints contract lock (5-E3, live Restlet)` — **9 rows** |
| `e2e/oauth2/oauth2-endpoints-test.spec.mjs` | new describe `OAuth2 device flow contract lock (5-E3, live Restlet)` — **5 rows** |

`npx playwright test oauth2` — **62 passed** (48 before), twice in a row. No existing row edited.

### The recorded rows

| # | Request | Recorded |
|---|---|---|
| 1 | `/device/user?user_code=<unknown>` | **200** `text/html;charset=UTF-8`, the code-entry form with `errorCode: "not_found"`. **Identical anonymously** — the code lookup fails before any session check, so an unknown code never reaches the 301-to-login a valid code triggers |
| 2 | `/device/user` POST `decision=allow` / `decision=deny` | **both 200**, both the **thanks** page (`done: true`). The branch only chooses update-vs-delete and then falls through to the same render; the difference is invisible on the wire |
| 3 | `/device/user` POST, `csrf` missing or wrong | **400** `text/html;charset=UTF-8`, `<title>OAuth2 Error Page</title>`, `message: "bad_request"`, **no `Location`** |
| 4 | `/device/user` consent page | **200**; model keys `clientId`, `scope` (`"openid profile"`), `state`, `nonce`, `responseType`, `locale`, `realm`, plus `userCode`/`userName`/`displayName`/`isSaveConsentEnabled`/`displayScopes`/`formTarget` |
| 5 | cache headers, all three endpoints, success **and** error | **none** — no `Cache-Control`, no `Pragma`, anywhere. [Finding 8](phase-5b-2-research.md#8--none-of-the-three-gets-cache-headers) confirmed |
| 6 | `/oauth2/connect/checkSession` vs `/oauth2/realms/root/connect/checkSession` | bare path = **JSP** (`<script src="../../js/sha256.js">`, **no** `Server` header); realm-prefixed = **Restlet FTL** (absolute `<base>/js/sha256.js`, `Server: Restlet-Framework/2.4.4`). Both **200** `text/html;charset=UTF-8` |
| 6b | checkSession `GET` vs `POST` | byte-identical |
| 6c | checkSession with a valid `id_token` in the **`Referer`** query | **200**, page carries `var clientURI = "<clientSessionURI>";` |
| 6d | checkSession, `Referer` `id_token` with **no `aud`** / **unknown `aud`** / **malformed** | all **400** `application/json` `{"error":"server_error","error_description":"Internal Server Error (500) - …"}` |
| 6e | checkSession, **signed** id_token from a client with **no** `clientSessionURI` (added 2026-07-28) | **400** `server_error` — the `NoSuchElementException` half of D7's fourth wrap, on the wire. Needs a *verifying* signature: `isJwtValid` HMACs against the client secret and a false there returns `""` early (a **200**), so a crafted-signature JWT cannot reach the throw at all |
| 7 | checkSession `?display=` | `page` → **200**; `popup`, `touch`, `wap` → **400** `server_error` `"Bad Request (400) - Server can not serve the content of authorization page"`; `bogus` → **400** `server_error` with the generic `"Internal Server Error (500) - …"` |
| 8 | endSession + registered `post_logout_redirect_uri` | no `state` → **302** to the URI **verbatim** (no trailing `?`); with `state` → `?state=st%20ate%2F1` (space `%20`, `/` `%2F`); URI that already has a query → existing query **preserved verbatim**, state **appended with `&`** |
| 9 | endSession, unregistered / relative `post_logout_redirect_uri` | **400 JSON** `redirect_uri_mismatch` / `relative_redirect_uri`, with the exact descriptions, no `Location` |
| 10 | endSession, malformed `id_token_hint` (and an unparseable redirect URI) | **400 JSON** `server_error`, generic description |
| 11 | `PUT` on all three | **405** `application/json`, **CREST** body `{"code":405,"reason":"Method Not Allowed","message":"The method specified in the request is not allowed for the resource identified by the request URI"}` — **no `error` field at all** |

### What the observation settled

1. **[D5](phase-5b-2.md#d5) confirmed — and the reasoning that nearly overturned it was wrong.** While writing the probe I
   read `OAuth2Representation.getRepresentation` and concluded `?display=popup` would be a **200**, because
   popup is special-cased and `templates/popup/authorize.ftl` *does* exist. Live Restlet answers **400**. The
   mechanism is a third one neither the plan nor that reading had: the popup branch renders
   `popup/authorize.ftl` **against the check-session model**, which has no `display_name`, so FreeMarker throws
   `InvalidReferenceException`, `popup.getText()` fails, and the `IOException` becomes the *same*
   `ResourceException` a missing template produces. Three mechanisms — missing template (`touch`/`wap`), failed
   render (`popup`), `Enum.valueOf` (`bogus`) — two distinct bodies, one status. **D5 stands as written.**
2. **[D7](phase-5b-2.md#d7) confirmed, and it needs a fourth wrap.** Rows 6d and 10 pin **400 `server_error`** on every
   client-reachable unchecked throw. But row 6c only passes because the fixture now sets `clientSessionURI`:
   `OpenAMClientRegistration.getClientSessionURI()` ends in `set.iterator().next()` with no emptiness guard
   (`:426-434`), and the admin API leaves that attribute **empty by default** — so for a default-configured
   client, a valid `id_token` in the `Referer` throws `NoSuchElementException` and check-session 400s on its
   own happy path. ⇒ **add a fourth row to D7's table**: `getClientSessionURI` must be wrapped too, and the
   separate null-guard ticket (checklist step 9) should cover the empty-set case, not just the NPE.
3. **[D8](phase-5b-2.md#d8) resolved — and the open question answered "no normalisation".** `new Reference(uri)` does **not**
   rewrite a URI that already carries a query: `http://app.invalid/logout?ui=1` + `state=s2` comes out as
   `…?ui=1&state=s2`, existing pair untouched, `state` appended. With no `state` the URI is emitted byte-for-byte
   with no trailing `?`. The encoding is `%20` for space and `%2F` for `/` — **not** `+`. `RedirectUris.compose`
   has to match all three shapes; the space encoding is the one most likely to drift.
4. **[D10](phase-5b-2.md#d10)'s justification narrowed — see the correction box in D10.** Row 11 shows all three endpoints
   emit a **CREST** 405 body, not `method_not_allowed`. D10 rests on `/authorize` + `/access_token` alone.
5. **Open question 4 answered.** A device CSRF failure really is the **HTML error page** (the 4-arg `doCatch`),
   confirming [D1](phase-5b-2.md#d1)'s split: browser base for the device handler, JSON base for the other two.
6. **Open question 5 answered.** The `errorCode=not_found` form is a **200**, and — not anticipated — it is a
   200 **anonymously** as well.

### Two guards added 2026-07-28, after review of the D10 commit

Both recorded while the container was still up, because the oracle dies at 5d-1. `npx playwright test oauth2`
**63 passed** (was 62).

1. **Row 9 gained the case that tells the two URI sets apart.** `EndSession.validateRedirect:151` checks
   `client.getPostLogoutRedirectUris()`. Row 9's original negatives were `http://evil.invalid/x` (in neither
   set) and a relative URI — neither of which can catch an `EndSessionHandler` wired to `getRedirectUris()`
   instead. `REDIRECT_URI` (`http://app.invalid/cb`) is registered as an ordinary `redirectionURI` and **not**
   as a post-logout one, so it is the single discriminating input; live Restlet answers **400
   `redirect_uri_mismatch`** for it, and that is now pinned.
2. **New row 6e — the empty-`clientSessionURI` half of D7's fourth wrap.** ⚠ The review that prompted this
   claimed the wrap was unguarded; **that was wrong**. `CheckSession.getClientSessionURI:115` has exactly one
   throwing exit, `return clientRegistration.getClientSessionURI()`, and *both* failure modes leave through it
   — so row 6d's no-`aud` case already fails if the wrap is dropped. What row 6e adds is narrower and is not
   about the port: it pins the **empty-set** behaviour so the separate null-guard ticket (checklist step 9)
   cannot repair the null-registration half and silently leave this one. Same "a test to change deliberately"
   rationale row 6d already states for the NPE.
   ⚠ It needs `ensureNoSessionUriOidcClient` — a **confidential** client with a secret and no
   `clientSessionURI` — and a **genuinely HS256-signed** id_token (`signedJwt` in the spec, `node:crypto`).
   `isJwtValid` HMAC-verifies against `getClientSecret()` and returns false for an empty secret, and a false
   there returns `""` early — a **200**. So a public client, or the crafted-signature `jwt()` helper the other
   rows use, cannot exercise this path at all. The 400 is itself proof the signature verified.

### Three environment facts the rows had to be written around

Worth knowing before writing any further device-flow or check-session e2e; all three cost a probe cycle here.

1. **check-session takes its `id_token` from the `Referer` header's query string**, not from a request
   parameter (`CheckSession.getIDToken:191-218`). Without a `Referer` the model's `client_uri` is `""` and the
   endpoint's whole purpose is untested — which is exactly the state the pre-5-E3 smoke row was in.
2. **The consent-requiring device flow cannot use `response_type=device_code`.** `/device/code` stores the
   value **verbatim** and `/device/user` replays it through `authorizationService.authorize`, which validates
   against `providerSettings.getAllowedResponseTypes()` — and there is no `device_code` **response-type**
   handler (only `code`/`token`/`id_token`/`none`; `device_code` is a *grant* type). So the conventional call
   yields `unsupported_response_type`. Because this provider also pins `codeVerifierEnforced:true`, the working
   combination is `response_type=code` **plus** `code_challenge`/`code_challenge_method`, which `/device/code`
   accepts and stores (`DeviceCodeResource:119-120`). A consent-*implied* client sidesteps both, which is why
   the pre-existing device rows never hit this. Captured as `deviceCodeForConsent()`.
3. **`test_client_consent` cannot serve these rows** — it has no `device_code` grant and is a file-local const
   in `oauth2-test.spec.mjs`, not an export. The plan's "reuse it" instruction is superseded by
   `ensureDeviceConsentClient`.

### Two pre-existing quirks the CHF port must reproduce

- **`CodeThanks.ftl` renders `realm : "${realm?js_string}/XUI"`** — the realm arrives with `/XUI` appended
  (`realm : "\//XUI"` on the wire). Pinned by row 2 so the golden keeps it.
- **The JSP and the FTL check-session pages differ behaviourally, not just cosmetically.** The JSP emits
  `var validSession = "false"` — a **quoted string**, so `!validSession` is always false and `getBrowserState()`
  reads the cookie even for an invalid session. The FTL's `?js_string` escapes without adding quotes, so it
  emits a bare boolean literal and the guard works. The CHF handler inherits the **FTL**, i.e. the correct
  behaviour; the bare path keeps the JSP. Row 6 records both so the 5d-1 diff on the bare path is not misread
  as a regression.

⇒ **5-E3 done. R-5b2.4's unrecoverable-oracle risk is retired for
all three endpoints.** Next: **5b-2a**, starting with D10 on its own (checklist step 5).

---

<a id="as-built-5b-2a--landed-2026-07-28"></a>
## As-built — 5b-2a, landed 2026-07-28 (checklist steps 5–10)

Two commits, kept separable exactly as checklist step 5 asked:

| Commit | Scope |
|---|---|
| `f1ffda5d28` | **[D10](phase-5b-2.md#d10) alone** — `case 405 → method_not_allowed` in `OAuth2ErrorFilter.errorFor`, plus the javadoc that had argued the other way and the four IT rows it moves |
| `67c71eb41e` | **The handler pair** — `EndSessionHandler`, `CheckSessionHandler`, their tests, the D5 pointer resolutions and the T1 ticket (steps 6–10) |

⚠ `67c71eb41e`'s message cites the D10 commit as `db70b6490b`. **That hash does not exist on this branch** — the
commit was rebased before it landed, and the message was not re-written. D10 is **`f1ffda5d28`**; anyone
following the stale hash will find nothing.

**Deliverables:**

| File | Change |
|---|---|
| `openidconnect/http/EndSessionHandler.java` | **new**, 172 L — `@Get` only, on `AbstractOAuth2HttpJsonEndpoint` |
| `openidconnect/http/CheckSessionHandler.java` | **new**, 143 L — `@Get` + `@Post`, same base, both verbs one body |
| `oauth2/http/OAuth2ErrorFilter.java` | D10: one `case`, 405 dropped from the `default` comment, +14 javadoc lines recording the route-scope caveat |
| `oauth2/http/FreemarkerTemplateRenderer.java` | step 8 — the deferred `renderForDisplay` question answered in place (and the per-endpoint IAE mapping corrected) |
| `EndSessionHandlerTest` / `CheckSessionHandlerTest` | **new**, 339 L / 301 L — **12 + 11** `@Test`, no data providers |
| `RestletErrorParityTest` | +1 row, `aSlashInsideAValueIsEncodedByRestletAndNotByChf` (divergence row 9, below) |
| `AuthorizeRouteCompositionIT`, `OAuth2ErrorRouteCompositionIT`, `OAuth2ErrorFilterTest`, `AuthorizeHandlerTest` | D10's blast radius — 4 IT rows + 1 renamed filter test + 1 javadoc |
| `e2e/oauth2/oidc-test.spec.mjs`, `e2e/common/oauth2-fixtures.mjs`, `e2e/oauth2/oauth2-endpoints-test.spec.mjs` | the two 5-E3 guards added post-review (rows 9 and 6e) + six `toBe`→`toContain` `Content-Type` fixes |

**Gates.** `openam-oauth2` **1157 surefire + 18 failsafe** green — 1132 after 5b-1, 1133 after D10, and the
delta is exactly the 23 new `@Test` plus the parity row, so nothing was quietly disabled. `e2e/oauth2`
**63 passed**. Grep gate on the two new handlers: `org.restlet|getCurrent()` → **0** (re-verified against the
tree while writing this section). Javadoc/doclint clean, whole-reactor `install -DskipTests` green.
**Nothing is routed until 5d-1.**

### What the plan got wrong, and what each miss cost

1. ⚠ **[D7](phase-5b-2.md#d7)'s wrap list was short by one, and the gap was wire-visible.** D7 tables a single unchecked
   throw for endSession — `reconstructJwt` inside `validateRedirect` — but `OpenIDConnectEndSession.endSession:68`
   reconstructs the id_token **itself**, before `validateRedirect` is reached, and on the
   no-`post_logout_redirect_uri` path `validateRedirect` never runs at all. A malformed `id_token_hint`
   therefore escaped unchecked and became the framework's **500** where live Restlet answers 400 `server_error`
   ([5-E3 row 10](#as-built-5-e3--recorded-2026-07-28), both halves).
   ⚠ **The first unit test for it was a false green**: `OpenIDConnectEndSession` is a mock, so the unstubbed
   call was a silent no-op and control fell through to the *second*, already-wrapped reconstruction. Stubbing
   the throw turned it red at 500. Found in review, not by the suite — the same lesson as 5b-1's oracle-found
   defects, one layer down: **a mock cannot fail on the path the plan forgot to name**.
   ⇒ two tests now pin it: `aMalformedIdTokenHintIs400ServerErrorNot500` and
   `aMalformedIdTokenHintIs400EvenWithNoRedirectUri`.
2. **Statement order inside `validateRedirect` is load-bearing.** The port had hoisted `URI.create` above
   `clientRegistrationStore.get`; Restlet resolves the client first (`EndSession:142-146`). With **both** inputs
   bad — an `azp` naming an unregistered client *and* an unparseable target — that silently swapped
   `invalid_client` for `server_error`. Restored, with a comment saying why.
3. **The golden claim was wrong in our favour** — struck in place above rather than deleted, because
   regenerating a golden after 5d is forbidden and acting on the stale text would do exactly that.
4. **Gate 6's blast-radius prediction** was 1 test row; the truth was 4 across 2 ITs — recorded in the
   [D10 as-built box](phase-5b-2.md#d10). The gate passed on substance: every moved row is a 405 assertion.
5. **`OAuth2ErrorFilter` is bound to no route yet**, contra gate 6 and R-5b2.9,
   which both call it "a live-bound path". Build-ahead holds — and so no test here proves D10 on a real wire;
   only the 5d-1 e2e re-run will.

### The wraps as built — typed, not blanket

[D7](phase-5b-2.md#d7) says "narrow", and the first `CheckSessionHandler` draft did not honour it: a single
`catch (Exception)` spanning four collaborator calls *and* the render — precisely the blanket mapper
[decisions.md D3](decisions.md) forbids, and a contradiction of the justification written into its sibling two
files away. As landed:

| Handler | Wrapped call | Caught |
|---|---|---|
| `EndSessionHandler` | `openIDConnectEndSession.endSession` | `JwtRuntimeException` |
| `EndSessionHandler` | `URI.create` on the redirect target | `IllegalArgumentException` |
| `CheckSessionHandler` | `getClientSessionURI`/`getValidSession` | `NullPointerException`, `NoSuchElementException` |
| `CheckSessionHandler` | `renderForDisplay` | `IOException`, `TemplateException`, `IllegalArgumentException` |

A fault in `baseURLProviderFactory` therefore stays a **500** instead of being masked as a 400 — which is the
whole point of D3, and what the blanket draft would have lost.

### Two divergences found here, recorded rather than fixed

Both landed in [plan.md's expected-divergences table](plan.md#expected-divergences-at-the-flip) as **rows 9 and
10**, and both were settled against the real thing rather than reasoned about:

- **Row 9 — the `/` encoding.** [D8](phase-5b-2.md#d8) claims percent-encoding parity was "proven and closed at 3c-2". It was
  proven for the characters *that test's fixture happened to contain* (`a b&c=d+e`). Feeding the handler 5-E3's
  recorded live value `st ate/1` produced `state=st%20ate/1` against Restlet's `st%20ate%2F1`:
  `Form.toQueryString` does not encode `/` inside a value. Confirmed on **both legs** by the new
  `RestletErrorParityTest` row while Restlet is still on the classpath. Not fixed, on D8's own instruction —
  `RedirectUris` is shared with `/authorize`, so bending the encoder changes bytes on a committed endpoint to
  buy nothing a client can observe (RFC 3986 §3.4 puts `/` in the `query` production). ⇒ **it applies to
  `/authorize` too; 5b-2a only found it.** e2e row 8 now accepts either encoding so the spec stays re-runnable
  across the flip.
- **Row 10 — the `state` echo.** `AbstractOAuth2HttpJsonEndpoint.onError` adds `state` to **every** JSON error
  body; Restlet's two resources passed `null` (`EndSession:106`) and never emitted it. Settled by probing the
  live container: `GET /connect/endSession?state=abc123` returns a byte-identical body to the same request
  without it. Not fixable per-endpoint — an override drops the `@ExceptionHandler` annotation ([D1](phase-5b-2.md#d1)) — and
  **not specific to this step**: the base has behaved this way since 5a-2, so it applies to every CHF JSON
  endpoint and deserves one deliberate look across all of them at 5d-1.

### Decisions and pointers closed

- **[D5](phase-5b-2.md#d5) confirmed and both deferred pointers resolved** (step 8): it errors, no `page/` fallback.
  `FreemarkerTemplateRenderer`'s javadoc had framed a fallback as parity-preserving; it would have been a
  **widening** of a live 400 into a 200. Also corrected there: the IAE mapping is **per endpoint**
  (`AuthorizeHandler` → `invalid_request`, `CheckSessionHandler` → `server_error`), not one rule.
- **[D7](phase-5b-2.md#d7)'s fourth wrap implemented**, and the two "a test to change deliberately" rows exist:
  `anNpeFromGetClientSessionUriIs400ServerErrorNot500` and
  `aNoSuchElementFromAnEmptyClientSessionUriIs400ServerErrorNot500`.
- **Step 9 filed as post-migration ticket
  [T1](plan.md#post-migration-tickets--raised-by-the-port-deliberately-not-fixed-in-it)** (tabled in full in
  [phase-5-oauth2.md](phase-5-oauth2.md), summarised in plan.md's post-migration table next to T2–T4). It must cover **both** throws — the
  `NoSuchElementException` from an empty attribute, which is the admin API's default and therefore the common
  case, and the `NullPointerException` from a null registration.
- **The renderer-parity seam closed by test, not by golden**: `theModelCarriesTheFourKeysWithTheRestletsTypes`
  asserts the handler builds the same four keys with the same **types** as `RendererFixtures.checkSession()` —
  `valid_session` a `String`, because the template emits it unquoted into JavaScript.

### One e2e-hygiene fix worth carrying forward

Six assertions moved from `toBe` to `toContain` on `Content-Type`. The oidc spec's own header declares those
bytes out of scope (CHF emits `application/json; charset=UTF-8` where Restlet emits it bare) — but five of its
rows pinned them exactly, and the device spec's row 11 did too. All six would have gone red at the flip for a
reason the file had already declared out of scope, destroying the *"re-run unchanged; red is a regression"*
contract that makes the whole §E apparatus worth anything. ⚠ **The 5-E rows in `oauth2-test.spec.mjs` keep
their exact assertions** — there, the charset *is* the oracle, not an oversight.

⇒ **5b-2a done.** Next: **5b-2b**, starting with the [D2](phase-5b-2.md#d2) `ConsentPageRenderer` correction on its own
(checklist step 11) — still realm-only in the tree, so the device consent page cannot render correctly until it
lands.

---

<a id="as-built-5b-2b--landed-2026-07-28"></a>
## As-built — 5b-2b, landed 2026-07-28 (checklist steps 11–16)

One commit, `06f9251ce6` — the [D2](phase-5b-2.md#d2) correction, the handler, and both test classes. Unlike 5b-2a there was
nothing worth splitting off: D2 is a three-line change that only the device consent page can exercise, so
landing it alone would have committed a change no test could fail without.

**Deliverables:**

| File | Change |
|---|---|
| `oauth2/http/DeviceCodeVerificationHandler.java` | **new**, 306 L — `@Get` + `@Post`, on `AbstractOAuth2HttpBrowserEndpoint` ([D1](phase-5b-2.md#d1)) |
| `oauth2/http/ConsentPageRenderer.java` | [D2](phase-5b-2.md#d2) — phase 1 copies all nine keys from the attributes (was: `realm` alone); `QUERY_KEYS` → `MODEL_KEYS`, since both phases now read the same list and a name saying *query* misstates which of Restlet's two bulk copies phase 1 reproduces |
| `DeviceCodeVerificationHandlerTest` | **new**, 21 `@Test` (one data provider, 3 rows) |
| `DeviceCodeRouteCompositionIT` | **new**, 7 `@Test` — checklist step 14, including the mandated real-factory row |
| `ConsentPageRendererTest` | +2 rows: the whole model from seeded attributes, and a phase-order guard (vacuous before D2, meaningful after) |

**Gates.** `openam-oauth2` **1180 surefire + 25 failsafe** green — 1157 + 18 after 5b-2a, and the delta is
exactly the 21 + 2 new surefire rows and the 7 new failsafe ones, so nothing was quietly disabled. Grep gate on
every new and changed file: `org.restlet|getCurrent()` → **0**. Whole-reactor `install -DskipTests` green
(doclint). **Nothing is routed until 5d-1.**

### The plan held; three details it is worth restating in code

Unlike 5b-2a, this step found no gap in its own plan. [D2](phase-5b-2.md#d2), [D3](phase-5b-2.md#d3) and [D4](phase-5b-2.md#d4) went in as written,
and [finding 7](phase-5b-2-research.md#7-the-device-verify-control-flow-branch-by-branch) called both of the traps below correctly —
they are recorded here because the *code* has to keep them true, and neither is visible from the ported method.

1. **The `InvalidGrantException` catch must stay wrapped around `readDeviceCode` alone** (`:138`, and finding 7's
   closing note). `updateDeviceCode` and `deleteDeviceCode` throw the **same type**; if the catch widened to the
   method, a store failure at the end of an *authorised* consent would render as "that code is not valid" — a
   user-visible lie that also hides the fault. As built the catch spans three lines, and every later
   `InvalidGrantException` reaches the base mapper as an error.

2. **Two of Restlet's guards are constant inside the branch they live in.** `:164-165` computes
   `!requireConsent || "allow".equals(decision)` and `requireConsent && "on".equals(save_consent)` at a point
   only reachable when `requireConsent` is true and `decision` is non-empty. Ported as the literals, with a
   comment saying why: copying the dead disjuncts preserves the *appearance* of a branch that cannot be taken.

3. **Only two of Restlet's five catch clauses survive as code.** The one above, and
   `ResourceOwnerConsentRequired` — which is not an `OAuth2Exception` and so can never reach an
   `@ExceptionHandler`. The other three are what the browser base already does.

**Checklist step 13 was already done and is not repeated** — `RestletRendererParityTest` has carried the
`CodeVerificationForm` / `CodeThanks` goldens since 3c-1 (the correction recorded above the checklist).
Regenerating them would have been forbidden anyway.

### ⚠ The false green recurred, in a new disguise

Three of the "unusable user code" rows — unknown code, `null`, already issued — were green **for the wrong
reason** on first write. `readDeviceCode` was stubbed with `anyString()`, `user_code` was never stubbed on the
mock request, and `anyString()` does **not** match `null`: so `readDeviceCode(null, o2)` ran, matched no stub,
returned Mockito's default `null`, and all three rows collapsed onto the `deviceCode == null` branch. The
`InvalidGrantException` and `isIssued()` paths were never executed by anything.

Fixed by stubbing `user_code` to a real value, stubbing `readDeviceCode` by exact value, and adding
`verify(tokenStore).readDeviceCode(USER_CODE, o2)` so the three rows cannot silently re-collapse. **This is the
same failure shape as 5b-2a's unstubbed `OpenIDConnectEndSession`**, and it was again caught by reviewing the
tests rather than by running them: a mock's default return is a *plausible* value, so a row asserting an
outcome that default also produces is green and mute. Standing lesson for the rest of phase 5: when a row
asserts a branch, assert the **call that selects it** too.

### The IT was widened past the checklist, and mutation-checked

Step 14 requires the real `OAuth2RequestFactory` in **one** row (finding 14 / R-5b2.3). As built the whole IT
uses it: once the factory is real, every row also exercises real parameter resolution — query on `GET`, form
body on `POST`, request attribute ahead of both — instead of a stubbed `getParameter`, and that precedence *is*
the device flow's behaviour. The only context requirement is an `AttributesContext` in the chain.

The R-5b2.3 row puts `state=wire-state` on the query and `af0ifjsldkj` in the device code, then throws after
seeding; the 302's query must carry the device code's value. It has to be observed on a **redirect**, because
`page/error.ftl` never prints `state` — and the `redirect_uri` has to come off the wire, because a `DeviceCode`
stores none.

**Mutation-checked rather than trusted.** Commenting out the single `seedAttributesFromDeviceCode` call turns
**5 of the 7** rows red, R-5b2.3 among them (`to contain: state=af0ifjsldkj`). The 405 row and the CSRF-page row
survive, correctly: neither depends on seeding. Recorded because the suite went green on its first run, which
after the defect above is not evidence of anything by itself.

Three of its rows are subtler than they read:

- **`aFormPostSurvivesAnAuditShapedBufferedRead`.** The status assertion alone would be a false green: if the
  entity were consumed by the auditor's read, `decision` would come back absent, the handler would take the
  *no-decision* branch, and that branch also renders a 200 thanks page. The discriminator is
  `verify(tokenStore).updateDeviceCode(...)`.
- **`aNonAsciiConsentPageReachesTheWireAsUtf8`.** Decoding the wire bytes as UTF-8 is what discriminates: an
  ISO-8859-1 encode substitutes one `'?'` per unmappable character, and those bytes cannot decode back into the
  name. `AuthorizeRouteCompositionIT`'s UTF-8 row covers the *error* page; this is the consent page.
- **`theDeviceConsentPageIsBuiltFromTheSeededDeviceCode`** — added after reviewing the class, and **not in the
  checklist**. [D2](phase-5b-2.md#d2) is the reason 5b-2b touches `ConsentPageRenderer` at all, and until this row it was
  asserted only against the model *map*. On the device flow there is no query for that model to come from, so
  `client_id`/`scope`/`state`/`nonce`/`response_type`/`realm`/`ui_locales` reach the page **only** through
  seeding → phase 1 — and a key missing from `MODEL_KEYS` does not fail, it turns the template's
  `<#if x??>` false and drops the field silently (finding 2 / R-5b1.2). The row asserts all seven in the
  rendered HTML, through the real seeding, the real renderer and the real template.

### Research worth not repeating

- **`Custom.REALM` vs `Params.REALM`.** Five nested classes in `OAuth2Constants` declare a `REALM` whose value
  is `"realm"`, and the Restlet layer mixes them. The tie-break is not style:
  **`ChfOAuth2Request.attributes()` writes the realm under `Custom.REALM`**, so a reader spelling it any other
  way reads a different map entry with the same string value. Every CHF-layer read is `Custom.REALM` — 8/8
  before this step, 10/10 after.
- **FreeMarker's `?js_string` escapes `/` as `\/`.** Every template in this migration emits its model through
  it, so a page assertion written against the model value fails on any value containing a slash — a realm, a
  `redirect_uri`, a form target. `realm: "/alpha"` in the model is `realm: "\/alpha"` on the wire. (It is also
  why the goldens carry `\/`; nothing is wrong with them.)
- **`OAuth2Utils.joinStatic(Collection, String)`** already exists, and the instance `join` is a one-line
  delegate to it — so the scope set and the accepted-language list join without injecting `OAuth2Utils`.
- **`DeviceCode.setStringProperty` skips nulls**, so every entry of the record's map is a non-empty list. That
  is what makes the port's `values.iterator().next()` safe, and why `getObject()` can be walked at all.
  `scope` is the one entry that is a genuine multi-value list; `clientID` is the one key that is renamed on the
  way out (`client_id`).
- **A render failure builds a non-redirecting 400 page here**, duplicating ~3 lines of
  `AuthorizeHandler.serverErrorPage` rather than hoisting them to the committed shared base. Deliberate: this
  endpoint's `redirect_uri` can only have arrived on the wire unvalidated, so the page must not be able to
  become a redirect — and moving the method onto the base would change a committed endpoint to save three
  lines.

### Divergences: none new, one broadened

[Row 1](plan.md#expected-divergences-at-the-flip) now names `/device/user` as well as `/authorize`. This is what
finding 7 predicted — *"record it as the same divergence row, not a new one"* — and the code confirms the shape
is identical: `DeviceCodeVerificationResource:186-193` catches `IllegalArgumentException` and **redirects** to
the raw `redirect_uri` unless the message names `client_id`, while an IAE from `?display=` is raised inside the
sibling `catch (ResourceOwnerConsentRequired)` and so reaches `doCatch` as a 400 `server_error` page instead.
[D7](phase-5b-1.md#d7) answers all three with one non-redirecting 400 `invalid_request` page, closing the same
open redirect. The generalisation is structural, not per-endpoint: D7 lives on the browser base, so it applies
to every browser endpoint this migration ports.

⇒ **5b-2b done, and 5b-2 with it.** Next: **5c** (`resource_set`).
