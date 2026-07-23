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
  `templates/popup/checkSession.ftl`. Whether that should error or fall back to `page/` is **Phase 5b's
  call** when it ports `CheckSessionHandler`.
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

- **`AMAccessAuditEventBuilder.forRequest` builds `http/request/path` with `uri.getPort()`**
  (`AMAccessAuditEventBuilder.java:122`), which is **-1** when the request URI carries no explicit port (default
  80/443, e.g. behind a TLS-terminating load balancer), yielding audited paths like
  `http://host:-1/oauth2/access_token`. Found 2026-07-23 during Phase 3d-1 review. **In-tree (openam-audit-core,
  ours) — not commons**, so unlike the item above it costs no release cycle. **Pre-existing** and identical on
  `/json` audit today, so left out of the 3d-1 live-path commit to keep its blast radius minimal. **Proposed
  fix:** omit the `:port` segment when `getPort() < 0` (or emit the scheme default). **Status: deferred** — record
  in 5d's audit smoke (the pre/post-flip `http/request/path` diff surfaces it); fix in its own openam-audit-core
  commit with a test.

## Cutover lever

The `OpenAM` `HttpFrameworkServlet` in
`openam-server-only/src/main/webapp/WEB-INF/web.xml` uses
`routing-base=context_path`, so each area moves by adding an `HttpRouteProvider` for
its leading path segment (+ `META-INF/services` registration) and moving its
`<servlet-mapping>` from `ForgeRockRest` to `OpenAM`.

## Status tracking

Update the phase-status table in [plan.md](plan.md) as phases land.
