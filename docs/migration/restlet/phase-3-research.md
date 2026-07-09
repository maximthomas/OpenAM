# Phase 3 — Research & Sizing (`OAuth2Request` dual-transport re-plumb)

Research backing Phase 3 of the Restlet → CHF migration. Parent tracker:
[plan.md](plan.md); inventory: [inventory.md](inventory.md); reusable CHF patterns:
[chf-patterns.md](chf-patterns.md). Captured 2026-07-09 on branch
`features/restlet-migration`.

**Purpose:** Phase 3 makes the OAuth2 core transport-neutral while both transports
coexist (no route flips). This document records the coupling map, verified CHF facts, and
the sizing that drives the **recommended split into four shippable sub-phases (3a–3d)**.
Each sub-phase gets its own detailed plan doc (like [phase-2-xacml.md](phase-2-xacml.md))
when it is scheduled — this doc is the shared substrate for all four.

---

## 1. Verified CHF facts (de-risks 3a)

- **The servlet request/response are on the `AttributesContext`.**
  `org.forgerock.http.servlet.HttpFrameworkServlet.service(...)` (servlet 3.1.1, lines
  246–247) does:
  ```java
  attributesContext.getAttributes().put(HttpServletRequest.class.getName(), req);
  attributesContext.getAttributes().put(HttpServletResponse.class.getName(), resp);
  ```
  So `ChfOAuth2Request.getHttpServletRequest()` /`getHttpServletResponse()` read
  `context.asContext(AttributesContext.class).getAttributes().get(HttpServletRequest.class.getName())`.
  This is the CHF equivalent of the Restlet `ServletUtils.getRequest(restletRequest)`
  bridge and removes the single biggest unknown in the re-plumb: **the servlet request the
  session validator / token store / baseURL code needs is available in the CHF transport.**
- **Realm** is read from `context.asContext(RealmContext.class).getRealm().asPath()`
  (confirmed in Phase 2). This replaces `RestletRealmRouter.REALM_URL` attribute reads
  (used today by `OAuth2Request.getEndpointType()`).
- **Query/form parsing**: `org.forgerock.http.protocol.Form.fromRequestQuery(request)`
  (query) and `new Form().fromString(entity.getString())` / `request.getEntity().getForm()`
  (POST form). Body JSON via `request.getEntity().getJson()` (buffered, re-readable — CHF
  buffers the entity, unlike Restlet's single-shot stream that the current code works around
  with `setEntity(form.getWebRepresentation())`).

## 2. The coupling surface — exact inventory

### 2a. `getRequest()` consumers that must move to neutral accessors (13 main-src files)

These are invoked by grant handlers / stores shared by **both** transports, so they cannot
keep grubbing the Restlet `Request`. Each must switch to a transport-neutral `OAuth2Request`
accessor that both `RestletOAuth2Request` and `ChfOAuth2Request` implement.

| File | Module | What it pulls off the request today |
|---|---|---|
| `oauth2.core.ResourceOwnerSessionValidator` | openam-oauth2 | `getHttpServletRequest()` (SSO token, auth URL, goto), `getResourceRef().toString()`, removeLoginPrompt |
| `oauth2.core.ResourceOwnerAuthenticator` | openam-oauth2 | `getHttpServletRequest()` **+ `getHttpServletResponse()` via `Response.getCurrent()`** for `lc.login(req,resp)` |
| `oauth2.core.ClientAuthenticator` | openam-oauth2 | `getHttpServletRequest()`/`getHttpServletResponse()` via `Request.getCurrent()`/`Response.getCurrent()`; writes `AM_CTX_ID` attribute |
| `oauth2.core.CsrfProtection` | openam-oauth2 | `getHttpServletRequest()` + `getHttpServletResponse()` via `Response.getCurrent()` |
| `oauth2.core.TokenInfoService` | openam-oauth2 | writes `OAuth2Constants.Custom.REALM` request attribute |
| `openam.oauth2.StatefulTokenStore` | openam-oauth2 | `getHttpServletRequest()` (cookie extraction, SSO token); reads `ACR` request attribute |
| `openam.oauth2.OpenAMScopeValidator` | openam-oauth2 | `getHttpServletRequest()`; reads a request attribute |
| `openam.oauth2.OAuth2UrisFactory` | openam-oauth2 | request for base URL |
| `openam.oauth2.ClientCredentialsReader` | openam-oauth2 | `getBasicAuthCredentials()` (ChallengeResponse), `getEndpointType()==TOKEN` (last-segment check) |
| `openidconnect.IdTokenResponseTypeHandler` | openam-oauth2 | request access |
| `uma.UmaTokenIntrospectionHandler` | openam-uma | request access |
| `uma.UmaUrisFactory` | openam-uma | request for base URL |
| `uma.AuthorizationRequestEndpoint` | openam-uma | request access (Restlet endpoint — but shares the factory) |

Plus `OpenAMClientRegistrationStore`/`OpenAMClientRegistration` (baseURL / servlet request).

### 2b. Required neutral accessors on `OAuth2Request` (superset of the plan's list)

The plan (3a) lists `getHttpServletRequest`, `getBasicAuthCredentials`,
`getAuthorizationBearerToken`, `getAcceptedLanguages`. Research adds two more that the
consumer scan proves are needed:

- **`getHttpServletResponse()`** — `CsrfProtection`, `ResourceOwnerAuthenticator`,
  `ClientAuthenticator` all need the servlet **response** (today via `Response.getCurrent()`
  + `ServletUtils.getResponse`). CHF supplies it from the same `AttributesContext` key.
- A neutral way to write/read **request attributes** (`OAuth2Constants.Custom.REALM`,
  `ACR`, `AM_CTX_ID`) — today `request.getRequest().getAttributes().put(...)`. Keep the
  existing `OAuth2Request` internal attribute map as the neutral home (it already exists for
  parameter precedence); expose `setAttribute`/`getAttribute` if not already public.

### 2c. Restlet `getCurrent()` thread-local leaks (NOT in the plan — must be handled)

`org.restlet.Request.getCurrent()` / `Response.getCurrent()` are Restlet thread-locals with
**no CHF equivalent**. Beyond the auth collaborators above, they appear in error
construction paths:

- `openam.oauth2.OpenAMClientRegistration` (5×), `openam.oauth2.Utils` (1×),
  `openidconnect.OpenIdConnectToken` (1×) — all
  `OAuthProblemException.OAuthError.SERVER_ERROR.handle(Request.getCurrent(), ...)`.

These compile fine while Restlet is on the classpath, but they will **NPE / return null**
when reached via the CHF transport (no current Restlet request on the thread). Options for
the sub-phase that owns them: (a) thread the `OAuth2Request` through to these call sites and
drop the `Request.getCurrent()` argument; (b) set a request/response ThreadLocal at the CHF
route boundary as a bridge. **Decision deferred to the 3a/3b detailed plan**; flagged here so
it is not missed. (Restlet-package endpoint classes that still call `getCurrent()` and are
not migrated until Phase 5 can keep it.)

## 3. Sub-component sizing

| Sub-phase | Core work | New | Modified | Deleted | Risk |
|---|---|---|---|---|---|
| **3a** `OAuth2Request` abstraction | make `OAuth2Request` abstract; `RestletOAuth2Request` (verbatim impl); `ChfOAuth2Request` (4-tier precedence, body re-read, param-count, locale, endpoint-type, servlet req/resp from `AttributesContext`); `OAuth2RequestFactory.create(Context,Request)` + cache on `AttributesContext`; migrate the 13 §2a consumers to neutral accessors | 2 | ~16 | 0 | **High** — live Restlet path runs through this; exact parameter precedence + body re-read parity |
| **3b** neutral collaborators | 3× `Header/FormBody/QueryParameter AccessTokenVerifier` + rebind in `OAuth2GuiceModule`; `ClientCredentialsReader` (basic-auth + endpoint-type); `OAuth2Utils` split (delete Restlet half) | 3 | ~4 | 3 | **Med** — live path; basic-auth ISO-8859-1 charset |
| **3c** response/HTML/exception | new pkg `org.forgerock.oauth2.http`: `FreemarkerTemplateRenderer`, `OAuth2ErrorResponseFactory`, `OAuth2ErrorFilter` | 3 | 0 | 0 | **Med** — build-ahead (not wired until Phase 5b); 301/302 semantics, fragment vs query, `asMap()` order, golden renders |
| **3d** audit | `OAuth2HttpAccessAuditFilter`, `UMAHttpAccessAuditFilter`, `HttpBodyAuditor` (CHF `AbstractHttpAccessAuditFilter` subclasses) | 3 | 0 | 0 | **Med** — build-ahead (wired in Phase 4/5); userId/trackingIds/body-detail parity |

**Total: ~11 new + ~20 modified classes + tests.** That is 3–4 normal PRs, not one.

**Live-vs-additive split (important):** 3a and 3b **modify code the running Restlet
endpoints execute** (OAuth2Request, verifiers, ClientCredentialsReader, OAuth2Utils) — every
change must keep the Restlet path green, verified by the existing Restlet-path unit tests.
3c and 3d are **purely additive build-ahead** — new classes wired to no route until Phase
4/5 — so they carry integration risk only when their consumers land, and are independently
mergeable in any order after 3a.

## 4. Recommended split

Four shippable green commits, each its own detailed plan doc, in order:

1. **3a — `OAuth2Request` abstraction + consumer re-plumb.** The keystone; everything else
   depends on the neutral API. Ship with the full Restlet-path test suite green +
   `ChfOAuth2RequestTest` (precedence matrix, body re-read, param-count, locale, endpoint
   type, ISO-8859-1 basic auth).
2. **3b — neutral collaborators** (verifiers, `ClientCredentialsReader`, `OAuth2Utils`).
   Depends on 3a's accessors.
3. **3c — response/HTML/exception layer** (`org.forgerock.oauth2.http`). Depends on 3a
   (`ChfOAuth2Request`) for context; independent of 3b/3d.
4. **3d — audit filters.** Depends on 3a; independent of 3b/3c.

3c and 3d can be reordered or parallelised after 3a lands. 3b should follow 3a directly
because it touches the same live token-endpoint path.

## 5. Phase-3-specific risks (extends the plan's risk register)

- **R-3.1 Parameter precedence exactness (3a).** Restlet order: attributes → query → POST
  form → POST JSON; `getParameterCount` = query duplicates only. CHF `Form`/entity parsing
  must reproduce this bit-for-bit. Guard: `ChfOAuth2RequestTest` precedence matrix + keep
  `RestletOAuth2Request` tests green.
- **R-3.2 Body re-readability (3a).** Restlet re-`setEntity` after `new Form(entity)`; CHF
  buffers the entity so form + JSON + audit + auth can all read it. Guard: re-read stability
  test; confirm CHF entity is buffered (it is — `ByteArrayBranchingStream`).
- **R-3.3 `getCurrent()` thread-locals (3a/3b).** See §2c — the one place the plan's bullets
  are incomplete. Must be explicitly resolved, not inherited.
- **R-3.4 Build-ahead classes are untested against a live route until Phase 4/5 (3c/3d).**
  Mitigate by recording pre-flip curl/golden captures of the current Restlet error/HTML/audit
  output *now* (while Restlet still serves `/oauth2`+`/uma`) so 3c/3d output can be diffed
  when it goes live. Consider a `phase-3-golden/` capture step.
- **R-3.5 Servlet-attribute cache mirroring (3a).** Plan says mirror the per-request
  `OAuth2Request` cache to the servlet attribute "so mixed stacks agree." Since web.xml maps
  each path to exactly one servlet (no path served by both transports simultaneously),
  evaluate whether mirroring is actually needed or is dead complexity — decide in the 3a plan.

## 6. Reuse pointers

- Servlet req/resp bridge, realm read, query/form parsing: §1 above.
- CHF handler/filter test scaffolding, `Endpoints.from` semantics, realm-routing wiring,
  `Handlers.chainOf` ordering: [chf-patterns.md](chf-patterns.md).
- CHF audit base to extend: `AbstractHttpAccessAuditFilter` +
  `HttpAccessAuditFilterFactory` (openam-audit-core); port userId/trackingIds/body detail
  from `OAuth2AbstractAccessAuditFilter` + `RestletBodyAuditor` (openam-rest).
