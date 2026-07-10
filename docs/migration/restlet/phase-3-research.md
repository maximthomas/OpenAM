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
- **Query parsing**: `org.forgerock.http.protocol.Form.fromRequestQuery(request)`.
- **Body JSON** via `request.getEntity().getJson()` (buffered, re-readable — `Entity` caches
  its `json` and `string` fields, unlike Restlet's single-shot stream that the current code
  works around with `setEntity(form.getWebRepresentation())`).
- **POST form parsing — two traps** (verified against http-framework 3.1.1 bytecode; an
  earlier draft of this section named a method that does not exist):
  - `Entity` has **no `getForm()`** method. Its full surface is
    `getBytes/getJson/getString/newDecodedContent*/push/pop/set*`.
  - `Request.getForm()` is `fromRequestQuery(this)` **then** `fromRequestEntity(this)` into
    one `Form` — it **merges query and body**, collapsing the query/form precedence tiers.
    Unusable for `getParameter`.
  - `Form.fromRequestEntity(request)` guards on
    `ContentTypeHeader.getFirst(...).equalsIgnoreCase("application/x-www-form-urlencoded")`
    — an exact compare against the **whole header value**, so
    `application/x-www-form-urlencoded;charset=UTF-8` yields an **empty form, silently**.
    Restlet compares the parsed `MediaType` and ignores parameters.

  Correct recipe: parse the media type with `ContentTypeHeader.valueOf(request).getType()`,
  compare that, then `new Form().fromFormString(entity.getString())`. Same for the JSON tier.
- **The request URL is mutable**: `Request.getUri()` returns a `MutableUri` with
  `setQuery(String)` / `setRawQuery(String)`. Needed because
  `ResourceOwnerSessionValidator.alterMaxAge`/`removeLoginPrompt` rewrite the request URL's
  query and the result is read back as the login redirect's `goto` — see
  [phase-3a-oauth2request.md](phase-3a-oauth2request.md).

## 2. The coupling surface — exact inventory

### 2a. `getRequest()` consumers that must move to neutral accessors (12 main-src files)

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

Plus `OpenAMClientRegistrationStore`/`OpenAMClientRegistration` (baseURL / servlet request).

**Correction to an earlier draft of this table:** `uma.AuthorizationRequestEndpoint:123`'s
`this.getRequest()` is Restlet `ServerResource.getRequest()`, **not**
`OAuth2Request.getRequest()` — a false positive. It needs no accessor change; it is ported
wholesale in Phase 4.

### 2a-bis. Compile breaks from making `OAuth2Request` abstract (missed by the first pass)

Not accessor migrations — these simply stop compiling:

- **Direct constructor calls outside the factory** (both openam-uma; both become
  `new RestletOAuth2Request(...)`, so `RestletOAuth2Request` must be `public` and openam-uma
  keeps its Restlet compile dep until Phase 4):
  `UmaUrisFactory:79`, `UmaProviderSettingsFactory:75`.
- **Two subclasses already exist** beyond the two new transport ones:
  - `OAuth2Request.RealmOnlyOAuth2Request` — throws from most wire accessors, but does **not**
    override `getEndpointType()` today.
  - `openidconnect.restlet.IdTokenInfo.ValidateIdTokenRequest` — a **delegating wrapper**
    (`super(null, null)` + forwards to a delegate). Its new accessors must **delegate, not
    throw**: `/oauth2/idtokeninfo` executes it.
- The `@Inject`/`@Assisted` annotations on today's constructor are vestigial — no
  `FactoryModuleBuilder` binding for `OAuth2Request` exists in the repo.

### 2b. Required neutral accessors on `OAuth2Request` (superset of the plan's list)

The plan (3a) lists `getHttpServletRequest`, `getBasicAuthCredentials`,
`getAuthorizationBearerToken`, `getAcceptedLanguages`. Research adds two more that the
consumer scan proves are needed:

- **`getHttpServletResponse()`** — `CsrfProtection`, `ResourceOwnerAuthenticator`,
  `ClientAuthenticator` all need the servlet **response** (today via `Response.getCurrent()`
  + `ServletUtils.getResponse`). CHF supplies it from the same `AttributesContext` key.
- A neutral way to write/read **request attributes** (`OAuth2Constants.Custom.REALM`,
  `ACR`, `AM_CTX_ID`) — today `request.getRequest().getAttributes().put(...)`, i.e. the
  **Restlet request's** attribute map. (Correction: `OAuth2Request` has **no** internal
  attribute map today — `getParameter`'s attribute tier reads
  `request.getAttributes()` straight off the Restlet request. `ChfOAuth2Request` introduces
  the map.) Expose `setAttribute`/`getAttribute`.
  - These are **not** servlet attributes. `ClientAuthenticator` writes
    `NO_SESSION_REQUEST_ATTR` on the servlet request (`:155`) and `AM_CTX_ID` on the Restlet
    request (`:183`) — different spaces, different accessors.
  - `AM_CTX_ID` appears to have **no reader** off request attributes anywhere in the repo.
    Confirm before preserving it.
- **`setQueryParameter()` / `removeQueryParameterValue()`** — `alterMaxAge` and
  `removeLoginPrompt` mutate the request URL's query, and `authenticationRequired` reads the
  mutated URL back as the login redirect's `goto`. An attribute cannot substitute: it never
  reaches the browser, so the re-auth loop guard breaks. See §5 R-3.7.
- **`getEndpointType()` on CHF is not simply the remaining URI.** `EndpointType.get(path)`
  matches paths **with a leading slash** and returns **`null`** on a miss.
  `UriRouterContext.getRemainingUri()` has no leading slash, and once the endpoint router has
  matched, the innermost `UriRouterContext`'s remaining URI is empty. Derive the path by
  stripping the **realm router's** matched URI from `Request.getUri()`, mirroring the Restlet
  `REALM_URL` logic, and prepend `/`.

### 2c. Restlet `getCurrent()` thread-local leaks (NOT in the plan — must be handled)

`org.restlet.Request.getCurrent()` / `Response.getCurrent()` are Restlet thread-locals with
**no CHF equivalent**. There are **12** uses outside `openam-oauth2`'s restlet packages:

- **Error construction (7):** `openam.oauth2.OpenAMClientRegistration` (5×),
  `openam.oauth2.Utils` (1×), `openidconnect.OpenIdConnectToken` (1×) — all
  `OAuthProblemException.OAuthError.SERVER_ERROR.handle(Request.getCurrent(), ...)`.
- **Auth collaborators (5), already in §2a:** `CsrfProtection:207`,
  `ResourceOwnerAuthenticator:105,107`, `ClientAuthenticator:154,157`.

Note that `RestletOAuth2Request.getHttpServletResponse()` will itself be
`ServletUtils.getResponse(Response.getCurrent())` and lives in `org.forgerock.oauth2.core`,
so any `getCurrent()` grep gate must exclude that file (or the class must live in a
`/restlet/` package).

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
| **3a** `OAuth2Request` abstraction | make `OAuth2Request` abstract; `RestletOAuth2Request` (verbatim impl); `ChfOAuth2Request` (4-tier precedence, body re-read, param-count, locale, endpoint-type, servlet req/resp from `AttributesContext`); `BasicAuthHeader`; `OAuth2RequestFactory.create(Context,Request)` + cache on `AttributesContext`; migrate the §2a consumers to neutral accessors; fix the §2a-bis compile breaks | 3 | ~18 | 0 | **High** — live Restlet path runs through this; parameter precedence, body re-read, **and the `alterMaxAge`/`removeLoginPrompt` goto-URL contract** |
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
  *(Settled: do not mirror.)*
- **R-3.6 `Content-Type` parameters (3a).** CHF's `Form.fromRequestEntity` string-compares the
  whole `Content-Type` header; Restlet compares the parsed `MediaType`. A `;charset=UTF-8`
  suffix silently empties the form. Guard: parse via `ContentTypeHeader.valueOf`; test both
  media types with a charset parameter. See §1.
- **R-3.7 goto-URL query mutation (3a) — highest severity.** `alterMaxAge` and
  `removeLoginPrompt` rewrite the request URL's query string, which
  `authenticationRequired` then reads back as the login redirect's `goto`. Replacing either
  with a request-attribute write leaves the original `max_age` / `prompt=login` in the goto
  URL and produces an **infinite `/authorize` ↔ login redirect loop** — on the live Restlet
  path, not just CHF. Guard: neutral `setQueryParameter`/`removeQueryParameterValue`;
  `getRequestUrl()` assertions; browser smoke of `max_age` re-auth and `prompt=login`.
- **R-3.8 Factory client-registration resolution (3a).** `create(Request)` today resolves the
  client via `httpRequest.getParameter(CLIENT_ID)` (servlet semantics: query + form body).
  The neutral `getParameter` adds an attribute tier and a JSON-body tier, so a JSON `POST`
  carrying `client_id` would newly pre-resolve a registration. Guard: leave `create(Request)`
  as-is; use the neutral accessor only in `create(Context, Request)`.

## 6. Reuse pointers

- Servlet req/resp bridge, realm read, query/form parsing: §1 above.
- CHF handler/filter test scaffolding, `Endpoints.from` semantics, realm-routing wiring,
  `Handlers.chainOf` ordering: [chf-patterns.md](chf-patterns.md).
- CHF audit base to extend: `AbstractHttpAccessAuditFilter` +
  `HttpAccessAuditFilterFactory` (openam-audit-core); port userId/trackingIds/body detail
  from `OAuth2AbstractAccessAuditFilter` + `RestletBodyAuditor` (openam-rest).
