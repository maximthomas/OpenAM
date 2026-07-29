# Restlet → CHF Migration: Decision Record

Restlet removal from OpenAM, planned 2026-07-08 on branch `features/restlet-migration`.
This is the durable summary of the locked decisions; the executable detail lives in
[plan.md](plan.md) and the research backing it in [inventory.md](inventory.md).

## Locked decisions

- **Target**: CHF Handlers (`org.forgerock.http`) — `HttpRouteProvider` SPI +
  `Endpoints.from` annotated POJOs.
- **Strategy**: incremental strangler, one endpoint area per shippable green commit, in
  order: XACML → core `OAuth2Request` re-plumb → UMA → OAuth2/OIDC (flip in the last
  sub-phase) → WebFinger/stragglers → outbound scripting client (`java.net.http`) →
  delete `openam-restlet` + `transform-jakarta/restlet-parent-jakarta`.
- **Scope**: full Restlet removal, including outbound clients and the vendored
  jakarta-transformed fork.
- **New-class conventions** (locked 2026-07-16, during 3b): every class *authored* by this
  migration goes under **`org.openidentityplatform.openam.<area>`**, mirroring the legacy
  structure it replaces (`org.forgerock.oauth2.core` → `org.openidentityplatform.openam.oauth2.core`;
  3c's response layer → `…openam.oauth2.http`; Phase 4 → `…openam.uma`). New files carry the CDDL
  header with **`Copyright 2026 3A Systems LLC.`** and **no `@since` tag**. Do not copy the header or
  `@since` from the class being ported — that is the failure mode.
  - *Applies to new classes only.* Classes **modified** in place keep their existing package and
    header; add a `Portions copyright … 3A Systems LLC.` line as the surrounding files do.
  - *Exception — tests needing package-private access.* A test stays in the package of its subject
    when it calls package-private members: `OAuth2GuiceModuleTest` lives in
    `org.forgerock.openam.oauth2.guice` because it invokes the module's package-private `@Provides`
    methods directly.
  - *Applied retroactively to 3a (done in 3b).* `ChfOAuth2Request`, `BasicAuthHeader` and
    `ChfOAuth2RequestTest` shipped into `org.forgerock.oauth2.core` before this rule existed; 3b
    relocated all three to `org.openidentityplatform.openam.oauth2.core` and dropped their
    `@since 15.2.0` tags. Six files took import-only updates (`OAuth2Request`, `OAuth2RequestFactory`,
    `RestletOAuth2Request`, `ClientCredentialsReader`, `IdTokenInfo`, plus two tests).
  - *The Restlet shims stay put.* `RestletOAuth2Request`/`RestletOAuth2RequestTest` were also authored
    by 3a, but are deliberately **not** moved: the new package is for target-state code, and these exist
    only to hold Restlet-coupled logic until Phase 5d deletes them. Same reasoning for any future
    `Restlet*` shim.

## Phase 3c — behaviour changes that land at the Phase 5d flip (locked 2026-07-17)

3c is **build-ahead**: its classes are wired to no route until Phase 5, so these decisions are invisible
when they land and become `/oauth2` behaviour months later, at the flip. They are recorded here so they
are not re-litigated — and deliberately **excluded from the e2e contract lock**, which asserts only
behaviour 3c reproduces. Full rationale: [phase-3c-1-renderer.md](phase-3c-1-renderer.md),
[phase-3c-2-error-layer.md](phase-3c-2-error-layer.md).

- **D3 — the uncaught-*bug* path keeps CHF's 500; Restlet's 400 is not reproduced.**
  `ServerException` hardcodes **400** + `server_error` (`ServerException.java:39`), so today every
  unmapped `Throwable` reaching `ExceptionHandler` exits **400**. CHF's framework gives **500**.
  We keep 500: that path is by definition a bug with no legitimate client contract, handlers are
  required to catch everything anyway ([chf-patterns.md](chf-patterns.md) §2), and reproducing 400
  would mean a filter that *downgrades* a 500 — permanently masking server bugs from monitoring.
  **The contractual 400 is preserved exactly** (see D2 below). This is the only status divergence.
  - *Not a migration concern (D2):* fixing `ServerException` = 400 itself is a one-line edit to a class
    **both transports share**, so it changes Restlet and CHF identically. Do it separately, with its own
    test and release note. Bundling a status change into a migration is how migrations get blamed for
    regressions.
- **D5 — the popup renderer stops ignoring `templateName`.** `OAuth2Representation:80` hardcodes
  `"authorize.ftl"`, so `display=popup` renders the consent page whatever template was asked for.
  Reachable via exactly one caller (`OpenIDConnectCheckSessionEndpoint:95`). Fixed, because the live
  authorize flow is byte-identical (the only shipping popup pair is `authorize.ftl` + `popup.ftl`) and
  nobody can depend on receiving a consent page when they asked for a check-session iframe.
  ⚠ **Consequence:** `checkSession?display=popup` then resolves a non-existent
  `templates/popup/checkSession.ftl`. ~~Whether that should error or fall back to `page/` is **Phase 5b's
  call** when it ports `CheckSessionHandler`.~~ **Settled 2026-07-28 — it errors**
  ([phase-5b-2 D5](phase-5b-2.md#d5), landed in 5b-2a): `CheckSessionHandler` collapses it to a 400
  `server_error`, which is what live Restlet answers for every non-`page` display (5-E3 row 7 — observed, not
  inferred). A `page/` fallback would have been a **widening of a live 400 into a 200**, and the legacy
  "200 with the wrong page" was never actually reachable: rendering `popup/authorize.ftl` against the
  check-session model hits an unguarded `${display_name}` and throws anyway.
- **D6 — the no-redirect policy becomes an explicit table, unified to the safe union.** Today it is
  emergent from catch ordering + which `OAuth2RestletException` constructor each catch picks — no flag,
  no predicate. `AuthorizeResource`'s GET (`:120-149`) and POST (`:187-206`) lists have **drifted**:
  `OAuth2ProviderNotFoundException` does **not** redirect on GET but **does** on POST, via the generic
  catch that passes the **unvalidated** `request.getParameter("redirect_uri")`. With no provider the
  redirect URI was never validated — an **open redirect**. `OAuth2Error.mayRedirect(OAuth2Exception)`
  encodes the union of both sets as data, and the test enumerates every `OAuth2Exception` subclass so
  adding one without a verdict fails the build. (Named `isRedirectable` in earlier drafts; split into
  `mayRedirect` — the policy — and `hasRedirectUri()` — the state — because one name for both invites
  writing the state check where the policy check belongs.)
  ⚠ **Changes POST behaviour** at the flip: `POST /oauth2/authorize` against a realm with no OAuth2
  provider renders the error page instead of redirecting. Include in 5d's smoke matrix.
- **D1 — the OAuth2 error map gets a canonical field order.** `OAuth2RestletException.asMap()` uses a
  bare `HashMap`, so today's order is deterministic-but-arbitrary. There is no *designed* order to
  preserve; RFC 6749 does not order error params and clients parse by name. `OAuth2Error.asMap()` uses a
  `LinkedHashMap`: `error, error_description, error_uri, state`.
- **D11 — the `Location` header is set verbatim.** Restlet's `Redirector` runs the redirect URI through
  a Restlet `Template`, so `{...}` sequences are variable-substituted — on a URI that the generic catch
  supplies **unvalidated**. Reproducing that would reproduce a URI-injection vector.
  ⚠ **Corrected 2026-07-22 by observation** (`RestletErrorParityTest`): what the `Template` actually does
  to an *unbound* variable is **delete** it, so today `redirect_uri=https://app/cb/{rid}` redirects to
  `https://app/cb/` — a silently mangled target rather than an injected one. The decision is unchanged;
  the harm it avoids is more mundane than the phrase "injection vector" suggests. It also forces the
  implementation: `RedirectUris` must not parse the URI, because `java.net.URI` (and therefore CHF's
  `MutableUri`) rejects braces outright where Restlet's lenient `Reference` accepted them.
- **D13 — `ResourceOwnerAuthenticationRequired` keeps its own redirect URI.** RoAR is the sole producer
  of the 307 → **301** branch and the only `OAuth2Exception` whose redirect target comes from the
  *exception* (the login page) rather than from the request. Under D6's data-driven policy it would
  default to redirectable, and a generic mapper would then overwrite the login URI with the client's
  `redirect_uri` — emitting **301 → an unvalidated client URI** on unauthenticated `GET /oauth2/authorize`,
  while still *looking* correct (a 301 with a `Location`). Two deliberately redundant mechanisms:
  `OAuth2Error.of` populates the URI from the exception and pins it, and RoAR is in `NEVER_REDIRECT` so
  `mayRedirect` is false. Both are asserted, including the adversarial
  `of(roar).redirectingTo("https://evil/", …)` case. This is **reproduction**, not a change.
- **D14 — the `WWW-Authenticate` challenge rides on `OAuth2Error`.** Today the header is set by the
  *resources* (`TokenEndpointResource`, `RefreshTokenResource`, `TokenRevocationResource`) on the Restlet
  `Response` **before** they throw; `ExceptionHandler` never touches it. In CHF there is no `getResponse()`
  to decorate before throwing — the factory builds the whole `Response` — so the challenge is carried on
  the error and emitted by the factory on **every** branch. Spelling confirmed by observation rather than
  belief (`RestletErrorParityTest`, via `AuthenticatorUtils.formatRequest`): `Basic realm="<realm>"`.
  Phase 5a's ported handlers must route the exception through `OAuth2Error.of` rather than re-deriving
  the header.
  ⚠ **The realm is escaped, and Restlet did not escape it — a wire divergence.** `HttpBasicHelper`
  interpolated the realm raw. It is **client-controlled**: `ClientAuthenticationFailureFactory` builds the
  challenge from `getRealm(request)`, and `OpenAMClientAuthenticationFailureFactory` reads the `realm`
  request parameter and, when `RealmNormaliser.normalise` throws, deliberately falls back to the
  **un-normalised** value. So `?realm=x"` broke out of the quoted-string, and CR/LF left header framing to
  whatever the container happened to reject — CHF's `GenericHeader` validates neither. The port applies
  RFC 7235 quoting (`HeaderUtil.quote`) after dropping control characters. Deliberate, and the one row of
  5d's `WWW-Authenticate` smoke check where pre- and post-flip bytes may legitimately differ: only for a
  realm containing `"`, `\` or a control character, which no valid realm does.

### Considered and explicitly *not* changed (so it is not re-litigated)

- **`wap/authorize.ftl` keeps `Content-Type: text/html`** (decided 2026-07-17, during 3c-1 review). The
  template is WML (`<?xml?>` + `<!DOCTYPE wml>`), yet Restlet serves it as `text/html; charset=UTF-8` like every
  other page, because the media type is fixed at `TemplateRepresentation(template, MediaType.TEXT_HTML)` and
  never varies by display. 3c-1 **reproduces** this: `toHtmlResponse` is the single HTML exit and gives WAP the
  same header. Serving it as `text/vnd.wap.wml` would be a behaviour change with no caller asking for it, and
  3c-1's charter is reproduction. **Revisit in Phase 5b** when `AuthorizeHandler` is ported and the display
  types are on the table anyway. (An earlier 3c-1 draft's parity checklist said WAP must "not [be] given
  `text/html` blindly", contradicting its own finding 5 — that row is corrected.)

- **Framework defects in code we own get fixed, not patterned around** (locked 2026-07-21; **done
  2026-07-22**). `openam-http` (`org.forgerock.openam.http.annotations`) is a module of **this** repo, so its
  four endpoint-framework defects were fixed as a prerequisite to 3c-2 rather than worked around:
  [openam-http-framework.md](openam-http-framework.md) — **F1** a handler-thrown exception gets a response
  body, **F2** `@ExceptionHandler` becomes real (`@Retention(RUNTIME)` + discovery + dispatch), **F3** the
  `Promise` return type is implemented, **F4** the module's own unread `@Produces` is honoured so a `String`
  return stops being silently ISO-8859-1. **Landed 2026-07-22, with the package's first 64 tests** ([as-built](openam-http-framework.md#as-built)). Consequences for 3c-2: `OAuth2ErrorFilter` loses its synthesize rule,
  R-3c.9/R-3c.14 are retired, and 5b's handlers may `throw` the existing `OAuth2Exception` hierarchy into one
  `@ExceptionHandler` per endpoint class instead of hand-returning `Response`s per verb. `OAuth2Error` stays a
  value type — it is what that method *builds*.
  The general rule, including the tier map and the cases where working around **is** correct (commons
  artifacts cost a release cycle), is [docs/framework-ownership.md](../../framework-ownership.md).

<a id="chf-cleanup-backlog"></a>
## CHF cleanup backlog (tracked, not blocking)

Commons/CHF (`org.forgerock.http`, `../commons`) sharp edges found during the migration that we **own** and could
fix at source, but that no in-flight phase strictly needs. Per
[docs/framework-ownership.md](../../framework-ownership.md) a commons fix costs a release cycle, so these are
routed around in-phase and fixed here only when a phase actually requires the corrected behaviour.

- **`Form.fromRequestEntity` exact-matches the whole `Content-Type` header** (`Form.java:231-239`:
  `"application/x-www-form-urlencoded".equalsIgnoreCase(header)`), so a legitimate
  `application/x-www-form-urlencoded;charset=UTF-8` body is silently parsed as **empty**; `Request.getForm()`
  (`Request.java:79-88`) inherits this. Found 2026-07-23 during Phase 3d review
  ([phase-3d-audit.md](phase-3d-audit.md) finding 8); it is also why the audit query-param leak is
  self-inconsistent (a bare form POST leaks its body into `queryParameters`, a `;charset=…` one does not).
  **Proposed fix:** parse media type/subtype and ignore parameters (a proper `Content-Type` parse), matched
  case-insensitively. **Blast radius:** every `getForm()` / `fromRequestEntity` consumer across the ecosystem —
  its own commit + tests, never bundled into a migration phase. **Status: deferred** — Phase 3d routes around it
  (`Form.fromRequestQuery` for query-only detail, `new Form().fromFormString(...)` for the body auditors), so
  nothing in 3d/4/5 needs it yet. Do it when a phase must read a charset-suffixed form body via `getForm()`.

- **`AcceptLanguageHeader` exposes only parsed `Locale`s, never the raw language tags** (commons,
  `org.forgerock.http.header.AcceptLanguageHeader` → `getLocales(): PreferredLocales`). Round-tripping through
  `java.util.Locale` drops a `*`, normalises non-canonical case, and re-derives the q-ordering rather than
  reporting it — so a consumer that needs the tags *as the client sent them* cannot use it. Found 2026-07-25
  planning Phase 5b-1: the OAuth2 consent page interpolates the accepted-language tags into JavaScript
  (`${locale?js_string}`, from `ConsentRequiredResource:101-105`), and Restlet handed over the raw
  `Preference<Language>` names. **Proposed fix:** a purely additive accessor returning the raw tokens in
  preference order beside `getLocales()`. **Blast radius:** none (new method). **Status: deferred** — 5b-1a
  hand-parses the header in `ChfOAuth2Request.getAcceptedLanguages()` (~15 lines, one class we own, A/B'd
  against Restlet's parser), so nothing blocks on a commons release. Do it when a second consumer appears.

- **`AMAccessAuditEventBuilder.forRequest` builds `http/request/path` with `uri.getPort()`**
  (`AMAccessAuditEventBuilder.java:122`), which is **-1** when the request URI carries no explicit port (default
  80/443, e.g. behind a TLS-terminating load balancer), yielding audited paths like
  `http://host:-1/oauth2/access_token`. Found 2026-07-23 during Phase 3d-1 review. **In-tree (openam-audit-core,
  ours) — not commons**, so unlike the item above it costs no release cycle. **Pre-existing** and identical on
  `/json` audit today, so left out of the 3d-1 live-path commit to keep its blast radius minimal. **Proposed
  fix:** omit the `:port` segment when `getPort() < 0` (or emit the scheme default). **Status: deferred** — record
  in 5d's audit smoke (the pre/post-flip `http/request/path` diff surfaces it); fix in its own openam-audit-core
  commit with a test.

- **`openam-http`'s `@Consumes`, `@Payload` and `@PayloadTranslator` are dead API.** All three are declared
  under `org.forgerock.openam.http.annotations`, retained at runtime and documented as if they worked —
  `@Consumes` as *"the content type that is consumed by the method"* — but
  `grep -rn "Consumes\|Payload\|PayloadTranslator" openam-http/src/main/java` outside their own declarations
  returns **nothing**. `AnnotatedMethod` binds only `@Contextual` parameters and the `Request`; `Endpoints.from`
  dispatches on verb alone. ⇒ **no media-type validation and no payload binding anywhere in the CHF endpoint
  framework**, and a future port that writes `@Consumes("application/json")` gets silence rather than a 415.
  Found 2026-07-29 planning Phase 5c ([finding 9](phase-5c.md#9--openam-https-consumespayload-annotations-are-dead-api)).
  **In-tree (ours), no release cycle. Proposed fix:** either implement `@Consumes` (~20 lines in
  `AnnotatedMethod`: compare the parsed request media type, 415 on mismatch) or delete all three. **Status:
  gate answered 2026-07-29 → delete.** [5-E4 row 12](phase-5c.md#as-built-5-e4--recorded-2026-07-29) measured
  the incumbent: live Restlet enforces **nothing** on `/oauth2/resource_set` — `text/plain` and
  `application/xml` both answer **201**, as does an **absent** `Content-Type`. All three are **asserted** by
  row 12 — the absent case through `node:http` rather than Playwright, which always supplies a
  `Content-Type` and would have made a row claiming to test absence pass for the wrong reason. The row
  asserts that no `Content-Type` actually went out, so the evidence this deletion rests on survives the
  flip. Only an unparseable *body* fails. So there is no
  behaviour to preserve, implementing `@Consumes` would be a **new** restriction rather than parity, and
  deleting the three annotations costs no oracle. Still its own commit, never bundled into a port.

- **`Endpoints.from` has no conditional-request (`If-Match` / `If-None-Match` / ETag) support.** Restlet's
  `ServerResource` evaluated preconditions for its resources ([chf-patterns §21](chf-patterns.md#21-restlets-conditional-request-machinery-phase-5c)),
  so a resource whose own Java only checks *"was `If-Match` sent"* nonetheless had full match enforcement. CHF
  offers nothing equivalent. Found 2026-07-29 planning Phase 5c. **Proposed fix (if ever needed):** an optional
  ETag-producing method discovered the way `@ExceptionHandler` already is. **Status: deferred** — `/oauth2/resource_set`
  is the codebase's **only** consumer, so [5c D6](phase-5c.md#d6) implements a ~60-line tested helper in the
  OAuth2 package rather than designing a framework hook for one caller. Revisit if a second endpoint needs ETags.

- **`Endpoints.from` does not map `HEAD` to the `GET` method.** Its verb map is built from
  `{DELETE, GET, POST, PUT}` (`Endpoints.java:60-63`), so `HEAD` takes the unmapped-verb branch and answers
  **405** — where Restlet's `ServerResource.doHandle(Method, Form, Representation)` rewrites `HEAD` → `GET`
  before annotation lookup and answers **200 with no body**. Found 2026-07-29 reviewing Phase 5c
  ([finding 13](phase-5c.md#13--head-is-served-by-restlet-and-405d-by-chf--and-it-is-not-a-5c-problem)).
  **In-tree (ours), no release cycle. Proposed fix:** `methods.put("HEAD", methods.get("GET"))` — body
  suppression is already the servlet container's job. **Blast radius:** additive; endpoints that 405 today
  start answering. **Status: open, owner 5d-1** — this is a **Phase-5-wide** divergence affecting every ported
  endpoint with a `@Get`, so it is fixed (or written into the divergence table) once, for all 15 endpoints,
  not per step. **Incumbent recorded 2026-07-29** —
  [5-E4 row 15](phase-5c.md#as-built-5-e4--recorded-2026-07-29): `HEAD` on `/oauth2/resource_set/{rsid}` and on
  both collection forms answers **200**, `application/json`, no `Content-Length`, with headers identical to the
  same URL's `GET` — the item form carrying the `ETag` — and it honours `If-None-Match` (→ 304). *Body*
  emptiness is not part of the oracle: an HTTP client discards a HEAD entity regardless, so it cannot be
  observed and no row asserts it. The oracle now exists in the suite; the decision does not.

- **`Endpoints.from` does not map `PATCH` at all — and Restlet routes it to `@Put`.** Same shape as the `HEAD`
  item above and found the same way, but **measured rather than disassembled**: on live Restlet a `PATCH` to
  `/oauth2/resource_set/{rsid}` reaches `updateResourceSet` and performs a **full replace**, answering 200
  ([5-E4 row 11](phase-5c.md#as-built-5-e4--recorded-2026-07-29)). CHF's verb map has no `PATCH` entry, so the
  port answers 405. **In-tree (ours). Proposed fix:** none obviously right — aliasing `PATCH` to `PUT` would
  bake in a Restlet quirk that is wrong by RFC 5789 (a `PATCH` is not a replace), while dropping it changes a
  working call into an error. **Status: open, owner 5d-1.** Unlike `HEAD` this is **not** Phase-5-wide: it bites
  wherever a `@Put` exists, which on the ported surface is `/oauth2/resource_set` alone. Most likely outcome is
  a divergence row rather than a framework change.

- **Commons `UriRouteMatcher` cannot express a trailing-slash route.** `createRegex` strips the template's
  trailing slash while `Paths.getPathElements` preserves the request's, so `EQUALS "foo/"` matches nothing
  ([chf-patterns §22](chf-patterns.md#22-chf-uri-template-matching--trailing-slashes-variables-and-head-phase-5c-review)).
  Found 2026-07-29 reviewing Phase 5c, where `/oauth2/resource_set/` is a live URL. **Commons — costs a release
  cycle, and changing trailing-slash semantics would move every CHF route in the ecosystem. Status: routed
  around, permanently** — the nested-router shape of [5c D9](phase-5c.md#d9) expresses the same family
  correctly and is the pattern any later phase should copy.

## Cutover lever

The `OpenAM` `HttpFrameworkServlet` in
`openam-server-only/src/main/webapp/WEB-INF/web.xml` uses
`routing-base=context_path`, so each area moves by adding an `HttpRouteProvider` for
its leading path segment (+ `META-INF/services` registration) and moving its
`<servlet-mapping>` from `ForgeRockRest` to `OpenAM`.

## Status tracking

Update the phase-status table in [plan.md](plan.md) as phases land.
