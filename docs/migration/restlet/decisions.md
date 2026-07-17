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
  redirect URI was never validated — an **open redirect**. `OAuth2Error.isRedirectable` encodes the
  union of both sets as data, and the test enumerates every `OAuth2Exception` subclass so adding one
  without a verdict fails the build.
  ⚠ **Changes POST behaviour** at the flip: `POST /oauth2/authorize` against a realm with no OAuth2
  provider renders the error page instead of redirecting. Include in 5d's smoke matrix.
- **D1 — the OAuth2 error map gets a canonical field order.** `OAuth2RestletException.asMap()` uses a
  bare `HashMap`, so today's order is deterministic-but-arbitrary. There is no *designed* order to
  preserve; RFC 6749 does not order error params and clients parse by name. `OAuth2Error.asMap()` uses a
  `LinkedHashMap`: `error, error_description, error_uri, state`.
- **D11 — the `Location` header is set verbatim.** Restlet's `Redirector` runs the redirect URI through
  a Restlet `Template`, so `{...}` sequences are variable-substituted — on a URI that the generic catch
  supplies **unvalidated**. Reproducing that would reproduce a URI-injection vector.

### Considered and explicitly *not* changed (so it is not re-litigated)

- **`wap/authorize.ftl` keeps `Content-Type: text/html`** (decided 2026-07-17, during 3c-1 review). The
  template is WML (`<?xml?>` + `<!DOCTYPE wml>`), yet Restlet serves it as `text/html; charset=UTF-8` like every
  other page, because the media type is fixed at `TemplateRepresentation(template, MediaType.TEXT_HTML)` and
  never varies by display. 3c-1 **reproduces** this: `toHtmlResponse` is the single HTML exit and gives WAP the
  same header. Serving it as `text/vnd.wap.wml` would be a behaviour change with no caller asking for it, and
  3c-1's charter is reproduction. **Revisit in Phase 5b** when `AuthorizeHandler` is ported and the display
  types are on the table anyway. (An earlier 3c-1 draft's parity checklist said WAP must "not [be] given
  `text/html` blindly", contradicting its own finding 5 — that row is corrected.)

## Cutover lever

The `OpenAM` `HttpFrameworkServlet` in
`openam-server-only/src/main/webapp/WEB-INF/web.xml` uses
`routing-base=context_path`, so each area moves by adding an `HttpRouteProvider` for
its leading path segment (+ `META-INF/services` registration) and moving its
`<servlet-mapping>` from `ForgeRockRest` to `OpenAM`.

## Status tracking

Update the phase-status table in [plan.md](plan.md) as phases land.
