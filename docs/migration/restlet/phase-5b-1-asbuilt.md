# Phase 5b-1 — OAuth2 `/authorize` → CHF: as-built

What actually landed, and **every value measured against live Restlet**. This file is the durable record: the Restlet oracle dies at 5d-1c and these numbers cannot be re-derived afterwards. Spec: [phase-5b-1.md](phase-5b-1.md).

---

## As-built

<a id="as-built-5-e2--recorded-2026-07-26"></a>
### 5-E2 — recorded 2026-07-26 (S1 + S2, test-only)

Captured against a live container built from this tree: `openam-e2e:5e2` (the repo `Dockerfile` with its
`COPY` lines enabled over `openam-server/target/OpenAM-16.2.0-SNAPSHOT.war`) + `openidentityplatform/opendj`
on the `test-openam` network, configured exactly as CI's `build-docker` leg configures the IDP. Restlet still
serves `/oauth2` (`Server: Restlet-Framework/2.4.4` on every row); the only main-source deltas between the WAR
and HEAD are unrouted CHF classes plus two additive edits (`LoginHintHook`'s CHF method, `OAuth2GuiceModule`'s
Multibinder), so the Restlet `/authorize` path is byte-identical to HEAD's.

**Deliverables** — `e2e/oauth2/oauth2-test.spec.mjs` only, no main code:

- `ensureConsentClientExists` → `test_client_consent` (`isConsentImplied:false`, `clientType:Public`,
  `responseTypes:[code, token]`, `grantTypes:[authorization_code, implicit]`, same `redirect_uri`/`scope`),
  wired into the existing `beforeAll`. Additive — no existing row changed behaviour.
- `describe("OAuth2 /authorize contract lock (5-E2, live Restlet)")`, **10 tests**: the 9 planned rows plus
  **row 9b** (see the D6 correction below). Suite: **23 green** (13 existing + 10 new), re-runnable.

**Two environment facts the rows had to be written around** (both discovered by observation, both worth
knowing before writing any further `/authorize` e2e):

1. **The provider enforces PKCE.** A `response_type=code` request without `code_challenge` fails validation
   with `400 invalid_request` "Missing parameter, 'code_challenge'" **before** the session, consent or scope
   logic runs — the first probe of rows 1/2/5 recorded that error instead of the intended one. Every row that
   must get past validation carries a real fixed S256 challenge.
2. **On `/authorize` the `iPlanetDirectoryPro` *header* does not authenticate — only the *cookie* does.** A
   header-only request gets the 301 to `/UI/Login`. This is the mirror image of
   [../../test-infrastructure.md](../../test-infrastructure.md)'s cookie gotcha (the existing "Should receive
   an auth code" test passes only because `getAuthToken` left a session cookie in the shared context, not
   because of the header it sets). Each row therefore runs in a disposable context whose jar is seeded
   explicitly — via `apiRequest.newContext({storageState:{cookies:[…]}})` — with exactly the identity, and the
   extra cookies, that row needs.

#### The recorded rows

| # | Request | Recorded |
|---|---|---|
| 1 | valid GET, no session | **301**; `Location` = `<base>/UI/Login?realm=%2F&goto=<the whole request URL, singly percent-encoded>` — `realm` first, `%2F` not `/`, and the already-encoded `redirect_uri` therefore appears double-encoded; `no-store`+`no-cache` |
| 2 | authenticated GET, consent client | **200** `text/html;charset=UTF-8` (**no space** after the `;`); `no-store`+`no-cache`; `Set-Cookie: oauth2_csrf=…;Path=/;HttpOnly;SameSite=Lax`; model on the wire: `csrf`, `clientId`/`displayName` = `test_client_consent`, `userName` = `Demo Demo`, `responseType`, `redirectUri`, `scope`, `state`, `isSaveConsentEnabled: true`, `displayScopes: [ { "name": "profile" … } ]`, `locale: "*"`, and **`formTarget` = `\/openam/oauth2/authorize?<full query>`** — context path included, confirming [finding 4](phase-5b-1-research.md#4--the-consent-data-model-is-already-pinned-by-a-golden--reproduce-it-key-for-key) |
| 3 | unknown `client_id` | **400** `text/html;charset=UTF-8`, **no `Location`**; page carries `message: "invalid_client"` / `description: "Client authentication failed"` |
| 4 | registered client, unregistered `redirect_uri` | **400** `text/html;charset=UTF-8`, **no `Location`** (the no-auto-redirect policy holds); `redirect_uri_mismatch` / "The redirection URI provided does not match a pre-registered value." |
| 5 | unknown scope, `response_type=code` | **302** to `http://app.invalid/cb?…` — parameters in the **query**, no `#`; `error=invalid_scope`, `error_description=Unknown/invalid scope(s): [no_such_scope]`, `state` echoed |
| 6 | the same, `response_type=token` | **302** to `http://app.invalid/cb#…` — parameters in the **fragment**, query empty. R-5b1.3's oracle |
| 7 | `PUT` | **405** `application/json` `{"error_description":"Required Method: GET or POST found: PUT","error":"method_not_allowed"}` + `no-store`/`no-cache` |
| 8 | `POST` `Content-Type: application/json` | **400** `application/json` `{"error_description":"Invalid Content Type","error":"invalid_request"}` + `no-store`/`no-cache` |
| 9 | consent `POST` `decision=allow` + the page's `csrf` | **302**; parameters **appended to the query**: `code`, `scope`, `iss=<base>/oauth2`, `state`, `client_id`; `no-store`/`no-cache`; **no `Set-Cookie` at all** |
| 9b | the `oidcLoginHint` contract (3 cases) | see [D6](phase-5b-1.md#d6) — consent page emits `oidcLoginHint=demo; Path=/; HttpOnly`; success with **no prior cookie** emits **nothing**; success with a prior cookie emits exactly one `oidcLoginHint=; Expires=<past>` carrying **neither `Path` nor `HttpOnly`** |

#### What the observation changed

1. **[D8](phase-5b-1.md#d8) resolved — both filter errors survive the CONTINUE fall-through.** Rows 7 and 8 recorded a
   **405** and a **400** that stand on the wire, exactly as `GET /access_token` did in 5-E. ⇒ `AuthorizeHandler`
   gets **no verb check** (the framework 405 matches on status; the body code diverged to `invalid_request` —
   `method_not_allowed` since [D10](phase-5b-2.md#d10), leaving only `error_description` as the 5d-1 body diff)
   and **must reproduce the content-type check** and return. This is the answer S8 was
   waiting on; 5b-1b is now unblocked on that axis.
2. **[D6](phase-5b-1.md#d6)'s premise corrected.** Restlet does **not** emit a `Set-Cookie` on a first authorize success
   carrying `login_hint`; it emits one only when the *request* already carried the cookie. The CHF port's
   delete must therefore be unconditional-when-set rather than guarded on the incoming cookie, or the first
   authorize would leave the cookie set in the browser. Recorded as row 9b and folded into D6's table.
3. **Row 9b exists at all.** The plan folded the D6 baseline into row 9; the correction above needs three
   distinct cookie states, which do not fit one request. Row 9 keeps the redirect-composition contract, 9b owns
   the cookie contract.
4. **A free `Accept-Language` data point for [D3](phase-5b-1.md#d3)**: with no `Accept-Language` on the request, Restlet's
   `ClientInfo.getAcceptedLanguages()` yields the single tag `*`, and the consent page renders `locale: "*"`.
   That is the "absent header" row of the S4 parity table, already answered — and note it is **not** the empty
   string, so a CHF `getAcceptedLanguages()` returning an empty list would render `locale: ""` and diverge.
   S4 must A/B this case explicitly.
5. **`formTarget` confirmed against the live wire**, not just against the fixture: `\/openam/oauth2/authorize?…`
   includes the context path and the full query, so [finding 4](phase-5b-1-research.md#4--the-consent-data-model-is-already-pinned-by-a-golden--reproduce-it-key-for-key)'s
   `request.getUri().getPath()` translation is right and R-5b1.8's guard is aimed at the right value.

#### Verification

- `npx playwright test oauth2` — **23 passed**, twice in a row (creation path and already-exists path both
  exercised); no existing row edited.
- `mvn -o -pl openam-oauth2 test -Dtest=RestletRendererParityTest,RestletErrorParityTest` — **27 green**
  (criterion 3: the 3c goldens are proven-legacy before any 5b main code lands).

⇒ **S1 and S2 done; the R-5b1.1 unrecoverable-oracle risk is
retired.** Next: **S3** (the D1 extract).

### S3 — the D1 extract (2026-07-26)

`AbstractOAuth2HttpEndpoint` created with the two `@Inject` fields, `withErrorHeaders` and `noCache`;
`AbstractOAuth2HttpJsonEndpoint` reduced to its `@ExceptionHandler` and made to extend it. **Surefire baseline
is 983, not the 979 the plan predicted** — the 5-E2 commit added 4 Java regression tests alongside the e2e
rows. 983 before, 983 after, **no test file edited**, which is the gate: a pure refactor is one where no
assertion had to change. The existing handler tests' reflection scaffolding already walked the full hierarchy
(`for (Class<?> c = target.getClass(); c != null; c = c.getSuperclass())`), so [finding
11](phase-5b-1-research.md#11--the-three-level-base-hierarchy-is-safe--and-the-obvious-alternative-is-not)'s three-level warning cost
nothing.

<a id="as-built-s4"></a>
### S4 — `getAcceptedLanguages()` (2026-07-26): D3's premise was wrong twice

The A/B oracle (`RestletAcceptLanguageParityTest`, 12 rows) overturned two things the plan asserted, and
both changed the code:

1. **⚠ CHF destroys the raw header before our code runs.** D3 says "implement it on `ChfOAuth2Request` by
   parsing the raw `Accept-Language` header" — but `Headers.put`/`add` re-parse any header with a registered
   factory and store the *parsed object*, so `getFirst("Accept-Language")` returns
   `AcceptLanguageHeader`'s canonical rendering: re-sorted by quality, `q` values synthesised by position, the
   client's own `q` discarded, case normalised. `HttpFrameworkServlet` populates the request through that same
   path, so this is production behaviour, not a test artefact. The full measurement is in
   [chf-patterns §6](chf-patterns.md#-headers-re-parses-known-headers-on-the-way-in--the-raw-value-is-unrecoverable-phase-5b-1a);
   it applies to **every** typed header, so it is filed there rather than here.
   ⇒ **the accessor reads `getHttpServletRequest().getHeader("Accept-Language")`** — the same bytes Restlet's
   own servlet adapter read — and falls back to the CHF header only when the chain carries no servlet request.
   *This is a correction to D3, not a divergence:* it is what makes byte parity achievable at all. The commons
   gap the plan filed is real but is now understood to be larger than "the accessor is lossy" — the raw value
   cannot be recovered from a CHF `Headers` at all.
2. **Restlet does not sort by `q`.** D3 predicted "the tokens in descending-q order, ties broken by header
   order". The oracle says plain **header order**: `en-GB,en;q=0.8,fr;q=0.9` → `["en-GB", "en", "fr"]`, and
   `en;foo=bar;q=0.3,de` → `["en", "de"]`. So the implementation parses no `q` at all — it splits on `,`,
   drops everything after the first `;`, trims, and skips empties. ~12 lines, and the sort/`quality()`
   machinery the first cut had was deleted.

Also recorded, each now a test row:

- **absent header → `["*"]`** (`PreferenceReader.addLanguages(null, …)` adds `Language.ALL`), confirming the
  5-E2 `locale: "*"` observation, while a **present-but-empty header → `[]`**. The two are different, and only
  the absent case gets the wildcard.
- **case is preserved verbatim** — `EN-gb` stays `EN-gb`.
- **one deliberate divergence:** Restlet **throws** `IllegalArgumentException("Invalid quality value detected")`
  on `en;q=bogus`, i.e. a 500 for a header the client controls. CHF ignores the parameter and returns `["en"]`.
  Not reproduced — the `q` only ever fed an ordering Restlet does not apply. Asserted as a divergence row in
  the parity test rather than hidden; belongs in 5d-1's smoke matrix.

`RestletOAuth2Request` untouched, per D3. Suite **1001** (983 + 12 parity + 6 `ChfOAuth2RequestTest` rows).

<a id="as-built-s5-s6-s6a"></a>
### S5, S6, S6a — the browser substrate (2026-07-26)

**S5 — `AbstractOAuth2HttpBrowserEndpoint`.** D2 as written, including both of its corrections to the
umbrella's pseudocode (two-argument `redirectingTo`, one `toResponse` exit). 8 lines of mapper, 13 test rows.
Two notes from writing the suite:

- The **adversarial row passes for two independent reasons**, which is the point:
  `ResourceOwnerAuthenticationRequired` is in `NEVER_REDIRECT` *and* its target is pinned by
  [D13](decisions.md), so `redirect_uri=https://evil.example/` cannot retarget the 301 even if a future
  subclass gets the guard wrong.
- One planned row was **wrong in the plan's own collapse table**: `OAuth2ProviderNotFoundException` renders
  **404 `not_found`**, inherited from `NotFoundException` — not `server_error`. The table in
  [finding 3](phase-5b-1-research.md#3--the-two-catch-lists-and-what-collapsing-them-actually-changes) says only "inherits
  `NotFoundException`", so nothing there was contradicted, but 5b-1b's collapse-table rows should use
  `not_found`.
- An **empty** `redirect_uri` is treated as no target (it would otherwise produce a `Location`-less 302,
  the `Headers.put(name, null)`-removes-the-header trap `OAuth2ErrorResponseFactory` already documents).

**S6 — the hook seam.** `ChfAuthorizeRequestHook` + `LoginHintHook`'s fourth impl + the fourth Multibinder.
The [D6](phase-5b-1.md#d6) correction is implemented **without per-request state**: `afterAuthorizeSuccess` recomputes the
before-hook's own condition (`setsCookie`, a function of the two values it reads) rather than remembering what
it did. One instance serves every request, so a field would be cross-request state — and note `LoginHintHook`
carries no `@Singleton` and none of its four `addBinding().to(...)` calls scopes it, so Guice actually builds a
**separate instance per Multibinder**; the stateless design is required either way, but not for the
"one shared singleton" reason first written here. The delete therefore
fires on `beforeWouldSet || requestCarriedCookie` — the union that makes all three of row 9b's cookie states
end with the cookie gone. Refactor taken while there: the private `hasLoginHintCookie` became
`loginHintCookieValue` (the before-hook needs the value, not just presence) and the delete-cookie construction
was pulled into one `removeCookie(OAuth2Request)`; `afterTokenHandling` keeps its incoming-cookie guard, which
is correct for the token path.

**S6a — `AuthorizeRouteCompositionIT`**, 6 rows, all four planned claims plus a POST row: 301 and 302 pass
`OAuth2ErrorFilter` untouched (it keys on `>= 400`), the HTML page is not rewritten into a JSON body, a
non-ASCII page reaches the wire as UTF-8 **bytes** (asserted on `getEntity().getBytes()`, since an ISO-8859-1
encode is invisible to `getString()`), and `PUT` on a `@Get`/`@Post`-only handler is the framework 405
rewritten to `invalid_request` — [D8](phase-5b-1.md#d8)'s body divergence, now pinned in process.

**Verification.** `mvn -o -pl openam-oauth2 verify` — **1021 surefire + 14 failsafe**, green.
`javadoc -Ddoclint=all,-missing -DfailOnWarnings=true` clean over the new classes.
`grep -rn "org.restlet\|getCurrent()"` over the three new main files → 0 (`LoginHintHook` and
`RestletAcceptLanguageParityTest` are exempt, as in 5a-1). `install -DskipTests` done, so 5b-1b compiles
against the new base.

#### What the code review changed (2026-07-26)

Seven of thirteen findings were acted on; the rest are recorded below as rejected-with-reason.

1. **⚠ The oracle was reading the wrong jar, and the accessor dropped repeated header lines.** This reactor
   resolves `org.openidentityplatform.openam.jakarta:org.restlet`, **not** upstream `org.restlet.jee:2.4.4` —
   the parity *test* always ran against the right one (Maven resolved it), but the bytecode check behind
   [S4](#as-built-s4)'s claim did not. In the real jar, `HttpRequest.getClientInfo()` reads
   `getRequestHeaders().getValues(name)`, and **`Series.getValues` joins repeated header lines with a comma**.
   `HttpServletRequest.getHeader` returns only the first, so `Accept-Language: de` + `Accept-Language: fr` on
   two lines gave Restlet `[de, fr]` and CHF `[de]` — the consent page silently losing a language. Fixed:
   the accessor folds `getHeaders(name)` with `String.join(",", …)`. The data provider now feeds **lists of
   header lines** to both legs (a single-String provider cannot express the case at all), with three new rows;
   15 parity rows green.
2. **A vacuous test deleted.** `acceptedLanguagesDoNotAffectGetLocale` never put an `Accept-Language` on the
   CHF request — the only source `getLocale()` reads — so it passed for an unrelated reason and would have
   passed with the accessor deleted entirely. Rewritten to populate **both** sources with **different** values,
   so it fails if either accessor starts reading the other's.
3. **The delegating wrappers were silently holed.** `ValidateIdTokenRequest` (both the CHF and Restlet twins)
   forwards all 17 accessors; because the new method is *concrete*, the compiler did not force an 18th, so a
   wrapped request would answer `[]`. Forwarders added.
4. **Uniform mutability** — `Collections.unmodifiableList` on both branches, so the result's mutability no
   longer depends on whether the client sent a header.
5. **A narrowing in the refactor undone** — `hasLoginHintCookie` → `loginHintCookieValue` changed the token
   path's guard from cookie *presence* to *non-null value*. The accessor now normalises a null-valued cookie to
   `""`, so non-null still means "present".
6. **The [D6](phase-5b-1.md#d6) recompute has a caller contract, now stated.** `afterAuthorizeSuccess` recomputing the
   before-hook's decision is only equal to what happened if the **same** `OAuth2Request` instance reaches both
   hooks and `login_hint` is unperturbed between them. [D9](phase-5b-1.md#d9) already specifies one cached instance per
   request; `ChfAuthorizeRequestHook`'s javadoc now makes it a documented precondition rather than an
   assumption **S8 must honour**.
7. **⚠ [D8](phase-5b-1.md#d8) is one row wider than written — the 405 also loses its cache headers.** The framework's 405 is
   not a thrown `OAuth2Exception`, so it never reaches `onError`, the only caller of `withErrorHeaders`; live
   Restlet stamped `no-store`/`no-cache` on that exact response (5-E2 row 7) because `OAuth2Filter` *wrapped*
   the resource rather than being invoked by it. The composition IT now asserts their **absence**, so 5d-1's
   smoke matrix inherits the row instead of discovering it. The same gap applies to any
   non-`OAuth2Exception` reaching the framework's 500.

**Rejected, with reason:** a null-guard on `getHttpServletResponse()` in the two new hooks (the shipped 5a-1
`afterTokenHandling` dereferences it the same way, and `HttpFrameworkServlet` always installs it — guarding
would hide a misconfiguration rather than fix one); overriding the accessor on `RestletOAuth2Request` so the
Restlet leg answers `["*"]` (D3 excludes it because nothing on that leg calls it — `ConsentRequiredResource`
keeps its own loop until 5d-2 — and `ConsentPageRenderer` is CHF-only); fixing `getLocale()` to read the
servlet header too (D3 explicitly leaves it alone: its own contract, its own tests, and it is out of 5b-1's
scope); a Guice test for the new Multibinder (build-ahead by design — S8 is its consumer, and the module has no
`OAuth2GuiceModuleTest` to extend); and extracting the duplicated test scaffolding (`inject` is duplicated
verbatim across ~10 existing handler suites — matching house style beats a local abstraction).

#### Second review round (2026-07-26)

Ten of fourteen acted on. Three found real defects in code the first round had already passed over:

1. **⚠ A client-triggerable 500 on `/authorize`** (user-confirmed fix). `beforeAuthorizeHandling` put the raw,
   client-supplied `login_hint` into a servlet `Cookie`. Tomcat's default `Rfc6265CookieProcessor` rejects any
   value outside RFC 6265's `cookie-octet` — space, `,`, `;`, `"`, `\`, non-ASCII — by throwing
   `IllegalArgumentException` **while generating the header**, outside any handler's reach, so
   `?login_hint=John%20Doe` would have reached the browser as a CREST 500. Restlet never hit this because it
   wrote the `Set-Cookie` itself, unvalidated, emitting a malformed header instead. **The cookie is now skipped
   when the value is not a valid `cookie-octet` string** — byte-identical for every value Restlet could legally
   send (usernames, email addresses), and no container-dependent failure for the rest. The check lives inside
   `setsCookie`, so the after-hook's "did the before-hook set it?" answer stays exact. 6 new rows. A 5d-1
   divergence row.
2. **⚠ A naive `split(",")` fabricated a language tag.** `Accept-Language: en;x="a,b",de` → Restlet
   `["en", "de"]`, ours `["en", "b\"", "de"]` — and per the accessor's own contract those tags are interpolated
   **raw into the consent page's JavaScript**, so a fabricated quote-bearing tag is what S7 would have emitted.
   Malformed input (the grammar allows only `q`), but Restlet's tokenising reader handles it and ours did not.
   Split is now quote-aware; the parity row is in the table, and it **failed before the fix** — the only kind of
   regression row worth having.
3. **The UTF-8 wire assertion was half vacuous.** `new String(wire, ISO_8859_1)` maps every byte into
   U+0000..U+00FF, so `doesNotContain(NON_ASCII)` can never fail whatever the encoding. Replaced with a byte
   subsequence search for the UTF-8 encoding, plus the absence of the `'?'` run an ISO-8859-1 encoder leaves.
   Risk #21 is only covered now.

Also: `getAcceptedLanguages()` is **memoised** like the class's four other derived values (the header cannot
change within a request, the consent path reads it per render, and `getHeaders()` returns a one-shot
`Enumeration` — which had armed a trap for the next test to call it twice); a `WWW-Authenticate` row added for
`InvalidClientAuthZHeaderException`, the only `NEVER_REDIRECT` type carrying a challenge and previously
unexercised through the browser mapper; `isEmpty` switched to `oauth2.core.Utils` to match `OAuth2Error`, whose
predicate it mirrors; `Params.STATE` instead of a bare literal; the hook's double reads of the cookie array and
the `login_hint` parameter collapsed to one each; and the browser base's javadoc now states that
`IllegalArgumentException` is **deliberately not mapped** and must be caught by each subclass per [D7](phase-5b-1.md#d7) —
the thing S8 would otherwise ship as a CREST 500.

⚠ **A factual correction to the S6 note above:** `LoginHintHook` carries **no `@Singleton`** and none of its
four `addBinding().to(...)` calls scopes it, so Guice builds a separate instance per Multibinder — not the
"shared singleton" first written here. The stateless design is required either way (one instance serves every
request), but for the ordinary reason, not that one.

**Rejected, with reason:** overriding the accessor on `RestletOAuth2Request` (raised twice; D3 excludes it
because nothing on that leg calls it, and `ConsentPageRenderer` is CHF-only — the class dies at 5d-2, so the
override would be dead code); making `getLocale()` share the servlet source (D3 explicitly leaves it alone —
its own contract, its own tests, out of 5b-1's scope); forwarding the six *stateful* members on the
`ValidateIdTokenRequest` wrappers (pre-existing, unrelated to this change — flagged, not fixed); and dropping
the `!isEmpty(redirectUri)` guard and the `error.getParameterLocation()` argument as redundant ([D2](phase-5b-1.md#d2)
specifies both, and the guard is what keeps a `Location`-less 302 unreachable regardless of downstream
contracts).

⇒ **5b-1a complete.** Next: **S7** (`ConsentPageRenderer`), which consumes `getAcceptedLanguages()` for the
model's `locale` key.

<a id="as-built-s7"></a>
### S7 — `ConsentPageRenderer` (2026-07-26): the port was uneventful, the fixture was not

[D5](phase-5b-1.md#d5) as written — a `@Singleton` collaborator, not a base class, with the model built in the producer's
three phases in order. ~90 lines of main code, 16 test rows. The port itself raised nothing; **what it found in
the test fixture did**.

Producing the model from real code, and asserting it key-for-key against `RendererFixtures.authorize()`, exposed
**two defects in the fixture** — the artifact the goldens were rendered from, and the thing
[finding 4](phase-5b-1-research.md#4--the-consent-data-model-is-already-pinned-by-a-golden--reproduce-it-key-for-key) called "already
de-risked":

1. **`display_scope` was missing entirely.** The key was added to the producer on **2026-07-20** by the
   **CVE-2026-62280** fix (reflected XSS on the WAP consent page) and the fixture, derived before that, never
   caught up. `wap/authorize.ftl` is its only reader, so the `wap` golden carried an **empty region** where
   production renders the scope list.
2. **Claim *values* were not ESAPI-encoded.** `ConsentRequiredResource:135-137` pushes claim descriptions
   **and values** through `encodeForHTML`, so production emits `demo&#x40;example.com`; the fixture hand-wrote
   the raw `@` — despite its own javadoc claiming the values "are produced by running the same `JsonValue` calls
   the producer runs".

⚠ **Both were invisible to `RestletRendererParityTest` by construction** — it feeds the *same* model to both
legs, so a fictional model still passes `Restlet == CHF`. That is the blind spot the fixture's class javadoc
warns about, and it is exactly why **R-5b1.2**'s guard is stated as
"key-for-key against the producer-derived model" rather than against a hand-written expectation. The guard
earned its place on its first run.

Fixed in `RendererFixtures`, and the **five** affected goldens regenerated through the sanctioned
`-Dgolden.regenerate=true` path. That is legitimate only because this is pre-5d: the regenerated files are
re-derived from the **live Restlet renderer**, and `Restlet == golden == CHF` re-verifies without the flag. The
diffs are minimal and exactly what the two fixes predict — two `<b>` lines in `wap/authorize.html`, and
`@` → `&#x40;` in the four `displayScopes` interpolations.

Three smaller notes from writing the class:

- **`acr` is a query key, not the request's `acr_values`.** The templates read `${acr}`, and the producer only
  ever had whatever the query literally carried; `OAuth2Constants.JWTTokenParams.ACR` is the constant, not
  `Params.ACR_VALUES`.
- **`target` has no `?` when the query is empty**, matching the producer's `StringUtils.isBlank` guard — and it
  follows a `setQueryParameter` mutation, which a servlet-request reconstruction would not (R-5b1.8, asserted).
- **`locale` is `"*"` when no `Accept-Language` was sent**, which is [S4](#as-built-s4)'s wire-parity answer
  arriving in the consent page. Worth knowing before reading a `locale : "*"` on a rendered page as a bug.

**Verification.** `mvn -o -pl openam-oauth2 verify` — **1052 surefire + 14 failsafe**, green, with
`RestletRendererParityTest` (11) still green against the regenerated goldens. Grep gate over the new main file
→ 0. Doclint clean.

<a id="as-built-s8"></a>
### S8 — `AuthorizeHandler` (2026-07-26): fourteen catch clauses, one mapper

[D9](phase-5b-1.md#d9) as written, with [D7](phase-5b-1.md#d7)'s catch and [D8](phase-5b-1.md#d8)'s content-type check. ~120 lines of main code, 45 test
rows plus 3 new composition rows. Three implementation notes:

- **The `IllegalArgumentException` catch sits one level out**, in a two-method split (`authorize(ctx, request)`
  wrapping a private `authorize(o2, request)`) rather than beside the consent catch. That placement *is*
  [finding 9](phase-5b-1-research.md#9--display-and-the-two-illegalargumentexception-sources)'s fix: `?display=bogus` raises its IAE
  from **inside** the consent branch, and a sibling `catch` does not protect a `catch` body — which is precisely
  how Restlet leaked it to `doCatch` as a `server_error`. A single flat `try` would have reproduced the bug.
- **One `Render` functional interface** wraps the two render call sites (consent page, form-post page) so the
  `IOException`/`TemplateException` → `ServerException` conversion is written once. A render fault stays a
  contractual **400** error page rather than the framework's 500: a missing template is a deployment fault, not
  one of the bug paths [D3](decisions.md) sends to the framework.
- **The form-post target is composed before the branch**, reproducing `OAuth2Representation:164-165` — so the
  form posts to a URI that *already* carries the parameters and repeats them as hidden inputs. Asserted rather
  than tidied.

**Two facts the test suite discovered, both of which corrected the plan rather than the code:**

1. **⚠ `CsrfException` cannot be raised on `GET` — structurally, not by convention.** Mockito refused to stub it
   on the 1-arg `authorize`, because it is absent from that method's `throws` clause (the CSRF check lives in
   the 3-arg overload). [Finding 3](phase-5b-1-research.md#3--the-two-catch-lists-and-what-collapsing-them-actually-changes) says
   "*not caught — unreachable on GET*"; this makes it a compiler-enforced fact. The shared collapse table
   therefore **cannot** carry the row — it is a POST-only test.
2. **⚠ The HTML error page does not carry `state`.** `page/error.ftl` interpolates only `error` and
   `error_description`; the `state` the producer has always put in the model reaches **no template**
   (`RendererFixtures.error()`'s javadoc already recorded this for the model, but the plan's test bullet asked
   for "`state` echoed in every error body"). It is echoed on the **redirect** branch only, where it rides in
   `asMap()` as a query parameter. Legacy behaviour, reproduced; pinned by a dedicated row so that a future
   change which starts rendering it registers as the wire change it would be. `OAuth2Error.withState` is still
   set on the D7 path — Restlet passed `state` there too, and it is not dead: the error-page fallback branch
   emits `asMap()` as JSON.

**Collapse table, as asserted** (one row per Restlet catch clause, values read off `AuthorizeResource` and each
exception's own definition — run against **both** verbs unless noted):

| Exception | Status / error | Redirects? |
|---|---|---|
| `RedirectUriMismatchException` | 400 `redirect_uri_mismatch` | no |
| `DuplicateRequestParameterException` | 400 `invalid_request` | no |
| `OAuth2ProviderNotFoundException` | 404 `not_found` | no — **[D6](decisions.md) change on POST** |
| `CsrfException` *(POST only)* | 400 `bad_request` | no |
| `InvalidScopeException`, `AccessDeniedException` | own | **yes**, per the exception's `parameterLocation` |
| `ResourceOwnerAuthenticationRequired` | 301 login URI | pinned target; an attacker's `redirect_uri` cannot retarget it |
| `InvalidClientAuthZHeaderException` | 401 `invalid_client` + `WWW-Authenticate` | no |
| `IllegalArgumentException` ×3 sources | 400 `invalid_request` page | no — **[D7](phase-5b-1.md#d7) change** |

**Composition IT extended** (14 → 17 failsafe) with three rows that drive the **real** handler rather than the
stand-in, for claims a fixture cannot make: that `/authorize` genuinely is a two-verb endpoint (so the
[D8](phase-5b-1.md#d8) 405 divergence is about the real thing), and that a 400 HTML page and a 302 the handler **returns** —
rather than ones the framework builds from a thrown exception — survive `OAuth2ErrorFilter` untouched.
[D7](phase-5b-1.md#d7)'s page is the only response on this endpoint that takes the returned-not-thrown path.

**No Guice module change.** `AuthorizeHandler` is concrete with field `@Inject`s, so Guice JIT-binds it; the
`Set<ChfAuthorizeRequestHook>` it needs comes from [S6](#as-built-s5-s6-s6a)'s Multibinder. It is bound and
routed nowhere until 5d-1, as planned.

**Verification.** `mvn -o -pl openam-oauth2 verify` — **1102 surefire + 17 failsafe**, green. Grep gate over the
two new main files → 0. Doclint clean.

⚠ **Whole-reactor `install -DskipTests` is green except for one pre-existing offline hole.** 139 modules
SUCCESS, **`OpenAM Server` (the WAR) included** — so criterion 10's real question, that the new wiring
assembles, is answered. The single FAILURE is `openam-doc-source`, which dies at its *first* goal in 0.058 s:
`doc-maven-plugin:3.1.2` needs `json-fluent:3.1.2`, and `~/.m2` holds only `3.1.1` plus snapshots, so `-o`
cannot resolve it. A docs module containing no Java, failing on a missing artifact; the 16 SKIPPED modules are
its downstream packaging. **Needs one online run to seed the artifact before the 5b-1b commit** if the gate is
to be reported as unconditionally green.

#### What the code review changed — S7/S8 (2026-07-26)

Five of thirteen findings were real; two of those were **open redirects this step introduced**, and the same
root cause produced both.

1. **⚠⚠ The content-type check redirected the error.** The natural port —
   `throw new InvalidRequestException("Invalid Content Type")` — reaches the new browser mapper, and
   `InvalidRequestException` is **not** in `NEVER_REDIRECT`, so a JSON-bodied request carrying
   `redirect_uri=https://evil/` got a **302 to that URI**. The request had failed before the client was ever
   resolved, so nothing had validated it. Restlet built this error with the 4-argument
   `OAuth2RestletException` (last parameter `state`, redirect left null) and always rendered the page
   (`OAuth2Filter:66-70`). **This is the exact trap [D7](phase-5b-1.md#d7) exists to describe, walked into one method
   over.**
2. **⚠⚠ A template fault redirected too**, for the same reason: `ServerException` is redirectable, so a missing
   `authorize.ftl` sent `error=server_error&error_description=<template path>` to the client's callback instead
   of showing an operator the failure. Restlet's `ExceptionHandler.handle(Throwable, …):86-89` also used the
   null-redirect form.
   ⇒ **Both fixed by making every error this handler builds itself a *built* response, not a thrown one**, via
   one `errorPage(o2, error, description)` helper on `OAuth2Error.of(int, String, String)` — which has no
   redirect target by construction, so `toResponse` cannot take a redirect branch. The class javadoc now states
   the rule. Corollary taken while there: a failed form-post render no longer runs the after-hooks, since
   [D9](phase-5b-1.md#d9) puts them after the representation is built and one that failed to build was not.
   **Root cause worth carrying forward:** on the *JSON* base (5a) throwing was always safe, because that base
   has no redirect branch. On the browser base it is not. Any 5b/5c handler that builds its own error must use
   the built form.
3. **⚠ `target` was percent-decoded.** `ConsentPageRenderer.target` read `MutableUri.getPath()/getQuery()` —
   the **decoded** accessors; `getRawPath()/getRawQuery()` are the raw ones — where Restlet's
   `Reference.getQuery()` returns the raw string (its decoding form is the `getQuery(boolean)` overload). So
   `redirect_uri=https%3A%2F%2Frp%2Fcb%3Fa%3D1%26b%3D2` became a form action whose `&` and `=` the consent
   POST re-parses as extra top-level parameters → `RedirectUriMismatchException` on post-back. **Settled
   against a recorded oracle, not by reading code:** 5-E2 row 9 asserts live Restlet's `target` equals the
   percent-encoded query and then posts back to it successfully. No existing row could see it — the key-for-key
   assertion deliberately skips `target`'s value, and all three dedicated `target` rows used a query that is
   byte-identical encoded and decoded. New row asserts the escapes survive.
4. **⚠ `display` was read query-only.** `OAuth2Representation:72` uses `getParameter`, and `display` was never
   one of the keys the `getQuery().getValuesMap()` copy supplied — so R-5b1.9's
   query-only rule does not reach it. Harmless on `/authorize` (GET), wrong for the POST reuse this class was
   built for: a device-flow consent form carrying `display=touch` in its body would have silently fallen back
   to `page/`. Now `getParameter`; new row drives it from a form body.
5. **⚠ The `Accept-Language` splitter still fabricated a tag, one escape level deeper.**
   `en;x="a\",b",de` → Restlet `[en, de]`, ours `[en, b",de]`: the quote-toggle ignored RFC 9110's `\"`
   escape and closed the string early. Same defect class as the previous round's finding. **Recorded the way
   that one was — a parity row added first, which failed against the real parser, then the fix.** 17 parity
   rows.

**Rejected, with reason:** that `onError` builds a second `OAuth2Request` and loses attributes (**false** —
`OAuth2RequestFactory.create(Context, Request)` caches on the `AttributesContext`, so the mapper gets the
handler's own instance; no re-parse, and the instance-identity contract holds); reverting the `login_hint`
cookie-octet skip in favour of percent-encoding (user-confirmed 2026-07-26 — and encoding would change the
value the auth chain reads, trading one regression for another); replacing the servlet-response cookie with a
retractable CHF `SetCookieHeader` to undo the [D6](phase-5b-1.md#d6) double `Set-Cookie` (the buffering alternative was
user-rejected 2026-07-25, and 5a-1's cookie spike settled the servlet-response mechanism); and de-duplicating
`validateContentType` against `TokenEndpointHandler`'s copy onto the shared base (after fix 1 the two are no
longer the same method — this one must *return* a page, that one *throws* to a JSON base; only the predicate is
common, and hoisting it would touch shipped 5a code for two call sites).

#### Third review round — staged files (2026-07-26)

Nine findings; **seven held, one was wrong, one was weak**. Three acted on by decision. Verification after:
**1129 surefire + 18 failsafe**, doclint clean.

##### 1. ⚠ The content-type check accepted a body with no `Content-Type`, where Restlet 400'd it

The severest defect this phase has produced, and it was **in two endpoints**, one of them already committed.

Restlet's whole check is `!MediaType.APPLICATION_WWW_FORM.equals(entity.getMediaType())`. `equals(null)` is
false, so the negation fires and a header-less body is a 400. Both CHF ports read a null type as "no opinion"
and passed it through. On `/authorize` that is not a wrong status but a **wrong decision**:
`ChfOAuth2Request.getParameter:104-110` reads a POST body only when the type *is* form, so the consent form's
`decision=allow` arrives as `null`, `consentGiven` becomes `false`, and `authorizationService.authorize` is
told the resource owner **refused** — the client gets `access_denied` for an approval the user gave, and
nothing anywhere reports an error.

**Settled by an oracle rather than by argument**, per this phase's method. `RestletContentTypeParityTest`
drives *both real filters* and the CHF predicate over one table, and it disagreed with three of my predictions:

| row | Restlet | CHF (before) | outcome |
|---|---|---|---|
| no `Content-Type`, non-empty body | **reject** | accept | CHF fixed |
| `APPLICATION/X-WWW-FORM-URLENCODED` | **reject** | accept | recorded divergence, kept |
| empty body (both filters) | accept | accept | fixture bug, fixed |

The second row is a **new discovery**: `MediaType.equals` compares names case-sensitively, so Restlet 400'd a
header RFC 7231 §3.1.1.1 calls legal. Two places in the codebase asserted the opposite in prose — the
`TokenEndpointHandler` javadoc and `mixedCaseFormContentTypeIsAccepted`'s comment, both claiming "Restlet's
`MediaType.equals` accepted mixed case, so we must too". The *behaviour* stays (a widening can only turn a
Restlet 400 into a success, never the reverse); the false justification is gone, and the row is now labelled a
divergence. The third row was my fixture's fault — `new StringRepresentation("")` is not an
`EmptyRepresentation`, which is how `TokenEndpointFilter` tests emptiness, so the fixture now models what the
adapter yields.

⚠ **Honest limit of the oracle**: it drives the filters, not the servlet adapter that produced the entity in
production. That gap does not reach the row it was built for — the filter accepts *exactly one* media type, so
whatever an adapter defaults a header-less body to (null, `application/octet-stream`, `*/*`), the answer is a
400 unless it defaults to form-urlencoded itself, which no HTTP stack does.

⇒ The rule now lives once, in **`OAuth2ContentTypes.isFormUrlEncoded`**, because two independent ports of one
contract had drifted into the same defect and fixing either alone would have left the other wrong. The callers
still differ in what they do with the answer — the token endpoint throws, `/authorize` must *build* its refusal
([§20](chf-patterns.md#20-on-the-browser-base-build-your-errors--never-throw-them-phase-5b-1)) — which is why
it returns a boolean. One existing test, `noContentTypeIsAccepted`, **was the defect written down as an
assertion**; it is now `noContentTypeIsRejected`. The motivating case has its own row,
`aConsentPostWithNoContentTypeIsRejectedRatherThanReadAsARefusal`, whose decisive assertion is that the service
is never told anything about a decision it cannot have. Same fix let `/access_token` validate **before**
`requestFactory.create`, closing there the client-lookup-per-malformed-post cost that round 2 closed here.

##### 2. The framework 405's missing cache headers — closed, not just recorded

`OAuth2Filter:72-77` added `no-store`/`Pragma` after its try/catch, unconditionally, so they landed on
responses that never reached the resource. The CHF ports moved stamping into the handler methods, which covers
everything a handler *returns* and nothing the framework produces alone — the 405 for an unannotated verb, the
404, the CREST 500. No care inside a handler closes that, because the handler is not on the path.

⇒ **`OAuth2NoCacheFilter`**, which restores the wrapping Restlet had, composed on `/authorize` and
`/access_token` **only** — applying it application-wide would be a widening, for the same reason `noCache` is
opt-in per handler. The IT row that recorded the gap by asserting the two headers *absent* now asserts them
present, on the stand-in and on the real handler.

(The reviewer's claim that "nothing asserts the cache headers" was inaccurate — the IT row did, deliberately,
as a pinned divergence. What was true is that recording it was a choice, and it has now been reversed.)

##### 3. Two comments of mine that were wrong

- The `HeaderUtil.split` comment claimed `en;x="a,b",de` *and* the backslash case "both fabricated a tag". The
  deleted quote-toggle handled the first correctly; only `en;x="a\",b",de` broke it, and only that row is new.
- `AbstractOAuth2HttpBrowserEndpoint`'s "⚠ subclasses must not override" warning named only `onError`, leaving
  `onIllegalArgument` — added by the D7 move, and the easier of the two to want to override — unguarded against
  the identical annotation-loss trap.

##### Rejected, with the reason

- **"The CSRF token is minted before `?display=` is validated."** Real behaviour, *faithful* behaviour:
  `AuthorizeResource:131-132` passes `getDataModel(e, request)` as an **argument** to
  `representation.getRepresentation(...)`, and Java evaluates arguments first — so Restlet also minted the token
  before `OAuth2Representation:73-75` ran `Enum.valueOf`. Changing it is a deliberate product change needing its
  own decision, not a review fix.
- **"`onIllegalArgument` destroys the stack trace."** The mechanism is real (`OAuth2ErrorResponseFactory:378-386`
  logs at DEBUG with a null cause), but the framing — that the D7 move caused it — is not: the pre-move code
  built the same 400. Deferred out of the review as its own decision, then **✅ resolved 2026-07-26
  (user-approved): thread the cause, leave severity alone.** New `OAuth2Error.of(int, String, String, Throwable)`
  — a fourth factory rather than a `withCause` wither, because `cause` is `final` and the withers copy-then-assign
  — and `onIllegalArgument` passes the exception. The severity branch is deliberately untouched: **most
  exceptions arriving here are client-caused** (a bad parameter, an unknown `?display=`), so escalating any
  caused error to WARN would both mislabel the common case and hand unauthenticated input a log-flooding lever.
  DEBUG stays the default and now carries a stack when someone turns it on. Two rows pin it — that the cause
  reaches the error handed to the factory but *not* `asMap` (the client is told the message, never the type or
  the frames), and that the four-argument factory still carries **no redirect target**, which is the property
  D7 depends on.
- **"A hook throwing discards an issued authorization."** Structurally true; deferred out of the review, then
  **✅ decided 2026-07-26 (user-approved): record it, change nothing.** <a id="div-hook-throw"></a>

  **The divergence, for the 5d-1 matrix.** `AuthorizeHandler.succeed` runs the after-hooks *after* the
  representation is built and outside the `try` that guards it (deliberately — [D9](phase-5b-1.md#d9) puts them after the
  representation, and one that failed to build was not a success). By then
  `authorizationService.authorize` has already minted and stored the code or token. A hook's
  `RuntimeException` is neither an `OAuth2Exception` nor an `IllegalArgumentException`, so it passes **both**
  base mappers and becomes `AnnotatedMethod`'s CREST-JSON 500 — rendered to a browser, where Restlet's
  `doCatch` produced the contractual HTML `server_error` page. The user agent never receives its redirect
  either way; only the error's shape differs.

  **Why nothing changes.** Each remedy trades one wrong answer for another: mapping `RuntimeException` on the
  browser base would restore Restlet's shape but reverse [D3](phase-5b-1.md#d3)'s deliberate boundary that the framework
  shape is for bug paths, and swallowing the hook failure to return the redirect anyway has the best semantics
  — the authorization *was* granted — but diverges from Restlet in the opposite direction and makes a hook
  failure that genuinely matters silent. On a path with no proven trigger, recording beats guessing.

  ⚠ **The one concrete reachability, left as is:** `LoginHintHook.afterAuthorizeSuccess` → `removeCookie` calls
  `o2request.getHttpServletResponse().addCookie(...)` unguarded, while the sibling read path *is* guarded
  (`request == null ? null : request.getCookies()`). That asymmetry is real; whether a live chain can present a
  null servlet response is **not proven either way**, and an earlier review round already rejected adding the
  guard. If 5d-1's soak ever produces a CREST-JSON body from `/authorize`, this is the first place to look.
- **"Three spellings of no-store."** Accurate, mild; the proposed remedy touches the token endpoint too.

#### Second review round — S7/S8 (2026-07-26)

Five of fourteen acted on. One of them **corrected a divergence the first round had not looked for**:

1. **⚠ The content-type refusal rendered the HTML error page where live Restlet sent JSON — and paid a store
   lookup to do it.** 5-E2 **row 8** recorded `400 application/json`
   `{"error_description":"Invalid Content Type","error":"invalid_request"}`; the filter wrote a Jackson
   representation and never a page. Fixed to `errorResponseFactory.toJsonResponse(...)`, which matches the
   recorded bytes — and, because that entry point needs no `OAuth2Request` at all, the check now runs
   **before** `requestFactory.create`. That matters beyond tidiness: `create` performs an unconditional
   `ClientRegistrationStore.get(client_id, …)`, so the previous ordering let an unauthenticated flood of
   malformed posts cost one client-registration lookup each, where `OAuth2Filter.beforeHandle` rejected them
   without ever reaching the resource. Asserted with `verify(requestFactory, never()).create(...)`.
2. **⚠ The render-fault page discarded the cause.** `serverErrorPage` built
   `new ServerException(e)` only to read `getMessage()`, so `OAuth2Error` carried `cause == null` and the
   provider log recorded a broken template with no stack — naming neither the template nor the frame that read
   it. `ServerException(Throwable)` calls `initCause` *specifically* so that survives. Now
   `OAuth2Error.of(new ServerException(e))`: identical wire shape, cause threaded through, still
   non-redirecting because nothing calls `redirectingTo` on it.
3. **The hand-rolled `Accept-Language` splitter was already in the library.**
   `org.forgerock.http.header.HeaderUtil.split(value, ',')` is quoted-string aware **including** the RFC 2616
   §2.2 backslash escape, trims, and drops empties — exactly the 18-line loop plus its `isEmpty` filter, and
   already imported elsewhere in this migration. Replaced; ~30 lines of code and justifying javadoc deleted.
   **The 17 parity rows are what make this safe** — the swap is proven equivalent against the real Restlet
   parser rather than by reading both implementations.
4. **A skipped `login_hint` cookie is now logged** (`debug`, naming the rejected value *class*, never the value
   — it is a claimed identity). The skip was previously invisible to operators: the user saw a login form that
   was not pre-filled and the log said nothing.
5. **An overstated comment corrected.** `redirectingTo(uri, error.getParameterLocation())` was described as
   load-bearing against "dropping this argument"; there is no one-argument overload, so it is a no-op today.
   The comment now says what is true — the parameter is not optional, and both alternatives a future edit
   reaches for (`null`, or a hardcoded `QUERY`) default every implicit-flow error to the query string.

**⚠ A pre-existing product bug surfaced, deliberately not fixed here.**
`templates/touch/authorize.ftl:56` emits **`isplayName:`** where `page/` and `popup/` both emit
`displayName:`. `openam-ui-ria/.../user/AuthorizeTemplate.html:19` renders `{{{oauth2Data.displayName}}}` as the
consent page's `<h1>`, so **`?display=touch` shows a blank client name** and asks the user to authorize an
unnamed client. Untouched by this migration and older than it; the regenerated `golden/touch/authorize.html`
records it because a golden's job is to record what legacy emits. Fixing it changes the wire and belongs in its
own change, not inside a port whose contract is byte-parity — but it should not be lost, so it is written down
here.

**Rejected, with reason:** that `ConsentPageRenderer` should reuse `OAuth2ErrorResponseFactory`'s
`normalised()`/`baseUrlOf()` (the producer at `ConsentRequiredResource:94-95` passes the **raw**
`getParameter("realm")` to an unguarded `getRootURL` — the port is verbatim, and the provider-cache growth is
pre-existing legacy behaviour that the *error* path chose to fix as its own decision); null-guarding
`getHttpServletResponse()` in the hooks (raised and rejected in the first round for the same still-true reason
— the shipped 5a-1 `afterTokenHandling` dereferences it identically and `HttpFrameworkServlet` always installs
it); folding repeated header lines in the CHF-header **fallback** branch of `parseAcceptedLanguages` (that
branch reads the already-canonicalised CHF value and is documented as best-effort, not byte-parity — no
servlet deployment reaches it); the duplicated `ValidateIdTokenRequest` decorators and the duplicated test
scaffolding (both pre-existing, both rejected in round one, both unchanged in kind); and that no test drives a
real `ChfAuthorizeRequestHook` through a composed route (true, and it is exactly R-5b1.7 build-ahead risk — the
CHF cookie path has no live guard until 5d-1 wires the route, which is why 5-E2 recorded the Restlet baseline
rather than trying to assert the CHF one early).

**Three findings raised as design questions rather than acted on**, since each would change a locked decision:

- **[D7](phase-5b-1.md#d7) could live on the base as a second `@ExceptionHandler`.** `AnnotatedMethod` indexes handlers by
  exception type and dispatches most-specific-first, so
  `@ExceptionHandler public Response onIllegalArgument(IllegalArgumentException e, …)` on
  `AbstractOAuth2HttpBrowserEndpoint` is legal — and, building `OAuth2Error.of(int, String, String)`, it has no
  redirect target by construction, satisfying "never redirect" without any `mayRedirect` rule. D7's stated
  reason ("its type is redirectable") is about `OAuth2Error.of(OAuth2Exception)`, which an IAE never reaches.
  That would delete both `try`/`catch` blocks from `AuthorizeHandler` and hand the policy to 5b-2 and every
  later browser endpoint for free, removing the footgun the base's own javadoc admits to ("a subclass that
  forgets leaks the framework's CREST 500 to a browser"). The wire behaviour is unchanged; only D7's
  *"Scope: one `try`/`catch` around the whole handler-method body"* implementation note would go.
  **✅ Done 2026-07-26 (user-approved).** `AbstractOAuth2HttpBrowserEndpoint.onIllegalArgument` now carries the
  policy; `AuthorizeHandler` lost both `try`/`catch` blocks, the private two-method split that existed only to
  place one of them, and its `errorPage` helper. **The whole suite passed unchanged** — every D7 row (three IAE
  sources, both verbs, cache headers, absent `Location`) still green with the catches deleted, which is the
  behaviour-preservation evidence. Coverage added where the policy now lives: 3 rows on
  `AbstractOAuth2HttpBrowserEndpointTest` (including that the two mappers coexist and dispatch on type) and a
  composition row proving the page still reaches the browser as markup through `OAuth2ErrorFilter`.
  Two framework facts verified before the move, both worth carrying: `AnnotatedMethod.invoke:99-107` routes an
  endpoint method's throw — checked or unchecked — to `handleException`, so a `RuntimeException` is fully
  mappable; and a failure of the framework's *own* plumbing takes the sibling `catch (Throwable)` branch
  instead, so a reflective `IllegalArgumentException` still becomes the framework's 500 rather than being
  disguised as a client error.

- **`QUERY_KEYS` enumerates nine names where Restlet bulk-copied the whole query map** *and* the whole
  attributes map. Shipping templates read only these nine, so nothing is broken today — but a deployment with
  a customised `authorize.ftl` reading, say, `${prompt}` loses the field silently, and the key-for-key fixture
  assertion proves the nine are *present*, never that nine is *enough*. A bulk copy is available
  (`new Form().fromQueryString(request.getUri().getRawQuery())`) and would be both simpler and strictly more
  faithful. [D5](phase-5b-1.md#d5) and [finding 4](phase-5b-1-research.md#4--the-consent-data-model-is-already-pinned-by-a-golden--reproduce-it-key-for-key)
  locked the enumeration on the premise that "CHF has no equivalent bulk copy", which is not quite true.

  **✅ Resolved 2026-07-26 (user-approved): keep the enumeration, add a drift guard.** First, the measurement
  that decides it — extracting every variable the four shipped `authorize.ftl` templates read and subtracting
  the keys phase 1/3 write and the `<#list … as r>` loop variable leaves exactly
  `acr client_id nonce realm redirect_uri response_type scope state ui_locales`: **the nine, precisely.** The
  enumeration is complete, so this was never a correctness gap; every extra key a bulk copy would carry is
  inert, because no template reads it and every name templates *do* read beyond the nine is written by phase 3,
  which runs last. That left only drift as an argument for the bulk copy — and a test kills drift more cheaply
  than a rewrite that would have obliged us to reproduce Restlet `Series.getValuesMap()`'s duplicate-name
  semantics exactly (the precise class of subtle mismatch this phase kept turning up) and would have let a
  client put arbitrary keys into the model, harmless only because phase 3 happens to overwrite collisions.

  `ConsentPageRendererTest.everyTemplateVariableIsSuppliedByTheModel` asserts the real invariant —
  **every variable a template reads is a key the renderer supplies** — iterating `DisplayType.values()` so a
  fifth display cannot be missed. Nothing is written down twice: the supplied set comes from a live
  `dataModel()` call, so phases 1 and 3 subtract themselves and only the query enumeration is stated, as a
  query string. That makes it strictly stronger than a `QUERY_KEYS` equality check — it catches a dropped
  phase-3 key too — and it needs no access to the private field. The extractor deliberately
  **over**-approximates on FreeMarker it does not model (`<#assign>`, an unknown operator): a false positive
  fails the build and someone looks; an under-approximation would let the drift through, which is the one
  outcome that must not happen. **Mutation-tested both ways**: adding `${prompt}` to `page/authorize.ftl`
  fails it naming file and variable, and deleting `NONCE` from `QUERY_KEYS` fails it too (alongside the
  fixture row — two independent guards). ⚠ Known limit, unchanged by this: it guards the **shipped** templates,
  so a deployment that customises `authorize.ftl` to read a tenth parameter still loses the field silently.
  That case is a bulk copy's only remaining advantage, and it is not one this repo's tests can ever see.
- **`OAuth2Request.getAcceptedLanguages()` defaults to an empty list** and `RestletOAuth2Request` does not
  override it, so a Restlet-backed request reaching a shared collaborator would get `locale=null` rather than
  the `"*"` [S4](#as-built-s4) established. Unreachable today ([D3](phase-5b-1.md#d3) rejected the override twice, correctly:
  nothing on that leg calls it), but a default of `["*"]` would make the gap harmless if that ever changes.

  **✅ Resolved 2026-07-26 (user-approved): the base default is now `List.of("*")`.** One line, plus the
  javadoc that explains it and a pinning row. The reasoning: the tags exist to be *joined into a page*
  (`ConsentPageRenderer:157` → the `locale` key), and `joinStatic` of an empty list is `""` — a value no live
  request has ever produced, because a client that sends no `Accept-Language` yields `*`. So the honest
  default for "this transport cannot tell you" is the same answer as "the client did not ask": both mean *no
  stated preference*, and every consumer already handles the wildcard. The alternative considered and
  rejected was making the method **abstract** — compiler-enforced and exact, but it would have obliged
  `RestletOAuth2Request` and both `IdTokenInfo*` decorators to implement it, i.e. **new Restlet code written
  during the phase whose purpose is deleting Restlet**, to cover a call that never happens.

  ⚠ The precondition D3 relied on is unchanged and still correct: the Restlet resources
  (`ConsentRequiredResource:102`, `DeviceCodeVerificationResource:230`) read
  `getRequest().getClientInfo().getAcceptedLanguages()` **directly**, never through `OAuth2Request`, so
  overriding it on the Restlet leg would still be dead code. This change does not make the leg answer
  correctly — it makes it answer *harmlessly*. Pinned by
  `RestletOAuth2RequestTest.theInheritedAcceptedLanguagesAreTheWildcardNotAnEmptyList`, which asserts what the
  one non-overriding subclass inherits. Orphaned the `java.util.Collections` import in `OAuth2Request`, removed.

---

## ⇒ 5b-1 complete (2026-07-26)

`77c37284cf` (5-E2 + 5b-1a + 5b-1b) plus the close-out. **1132 surefire + 18 failsafe**, doclint clean, import
gate 0, wired to **no route** until 5d-1.

**What this phase produced beyond the plan.** Three things were not on the map and are worth carrying into 5b-2:

1. **Two oracles now exist that did not.** `RestletAcceptLanguageParityTest` and `RestletContentTypeParityTest`
   drive the *real* Restlet code from a unit test. Both were written because reading the source gave the wrong
   answer, and both then disagreed with a prediction — the second one on three of eight rows. When a port turns
   on a library call whose behaviour is not obvious (`MediaType.equals`, `ClientInfo`'s parser), **execute it
   rather than read it**; the cost is one data-provider table.
2. **A whole class of defect has a name and a rule** —
   [chf-patterns §20](chf-patterns.md#20-on-the-browser-base-build-your-errors--never-throw-them-phase-5b-1):
   on the browser base, errors a handler detects itself must be **built**, not thrown, because the two natural
   exception types are redirectable and `mayRedirect` keys on type. Two open redirects came from breaking it.
   The test rule that catches it: **every row asserting a self-built error must stub a `redirect_uri`**, or it
   passes either way.
3. **`OAuth2NoCacheFilter` restores something a handler cannot do for itself.** Per-method header stamping
   cannot reach a response the framework produces without entering a handler. Any later phase that moves a
   Restlet `Filter`'s behaviour into a handler should ask which responses the filter saw that the handler will
   not.

**Two review findings were rejected on evidence**, and the evidence is the reusable part: the port builds the
consent model before validating `?display=` (faithful — `AuthorizeResource:131-132` passes `getDataModel(...)`
as an *argument*, and Java evaluates arguments first), and `onError` does not build a second `OAuth2Request`
(`OAuth2RequestFactory.create` caches on the `AttributesContext`).

**Next: 5b-2** — device/user, checkSession, endSession. It consumes `AbstractOAuth2HttpBrowserEndpoint` (both
mappers, including D7's, inherited without doing anything) and `ConsentPageRenderer` unchanged; the renderer's
query-only reads were written for exactly that reuse, since 5b-2 renders the same model from inside a `@Post`
(R-5b1.9).
