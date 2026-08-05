# Phase 5d-1 — the flip: `/oauth2` → CHF: key research findings

Background for [phase-5d-1.md](phase-5d-1.md) — the findings that drove its design. Read once; the spec is what you re-read while implementing.

---

## Key research findings

The reusable half of this research — when `Endpoints.from` builds its endpoints, what a CHF router answers
for a no-match, how `RealmContextFilter` actually resolves, the two 405 producers, servlet-mapping precedence
— is written up as [chf-patterns §23](chf-patterns.md#23-route-provider-mechanics--when-handlers-are-built-and-what-a-no-match-answers-phase-5d-1)
so a later phase does not have to read the framework again. The findings below are the 5d-1-specific
consequences.

<a id="1--the-hook-re-sign-is-already-done"></a>
### 1. The hook re-sign is **already done** — plan.md's 5d-1 row is stale on this point

[plan.md](plan.md)'s 5d-1 row lists *"hook re-sign"* as flip work, and
[phase-5-oauth2 D5-2](phase-5-oauth2.md) describes it as a coordination problem for this step. It was
discharged in 5a-1/5b-1:

- `ChfTokenRequestHook` and `ChfAuthorizeRequestHook` exist (`…/oauth2/http/`), neutral-signature
  (`OAuth2Request` only);
- `LoginHintHook` (`org/forgerock/openidconnect/restlet/LoginHintHook.java:42-43`) implements **all four**
  interfaces — the two Restlet ones and the two CHF ones;
- `OAuth2GuiceModule:236-242` already binds both CHF Multibinders to `LoginHintHook`;
- `TokenEndpointHandler:64` and `AuthorizeHandler:84` already inject the CHF sets.

⇒ **5d-1 does no hook work.** The Restlet interfaces + their `LoginHintHook` methods are deleted at **5d-2**,
as designed. The stale line is corrected in [plan.md](plan.md) as part of this step.

<a id="2--the-route-table-is-18-attachments-and-7-distinct-auditor-pairs-lift-both-verbatim"></a>
### 2. The route table is 18 attachments and 7 distinct auditor pairs — lift both verbatim

Source of truth: `openam-oauth2/src/main/java/org/forgerock/openam/oauth2/rest/OAuth2RouterProvider.java:94-147`.
Per [finding #4 of the umbrella](phase-5-oauth2.md), the auditor pairs are **wire contract** and must be copied,
not re-derived. The complete table, with the line each row comes from:

| # | Restlet attach (line) | CHF route (`EQUALS` unless noted) | Handler | req auditor | resp auditor |
|---|---|---|---|---|---|
| 1 | `:96` `/realms/{realmId}` | `STARTS_WITH REALM_ROUTE` (realm router) | — | — | — |
| 2 | `:100` `/authorize` | `authorize` | `AuthorizeHandler` | `noBodyAuditor()` | `noBodyAuditor()` |
| 3 | `:102` `/access_token` | `access_token` | `TokenEndpointHandler` | `formAuditor(RESPONSE_TYPE, GRANT_TYPE, CLIENT_ID, USERNAME, SCOPE, REDIRECT_URI)` | `jsonAuditor(SCOPE, TOKEN_TYPE)` |
| 4 | `:106` `/tokeninfo` | `tokeninfo` | `TokenInfoHandler` | `noBodyAuditor()` | `jsonAuditor(SCOPE, TOKEN_TYPE)` |
| 5 | `:111` `/introspect` | `introspect` | `TokenIntrospectionHandler` | `formAuditor(TOKEN_TYPE_HINT)` | `jsonAuditor(SCOPE, TOKEN_TYPE, CLIENT_ID, USERNAME, ACTIVE)` |
| 6 | `:117` `/connect/register` | `connect/register` | `ConnectClientRegistrationHandler` | `jsonAuditor(CLIENT_NAME, APPLICATION_TYPE, REDIRECT_URIS)` | `jsonAuditor(CLIENT_ID, CLIENT_NAME, APPLICATION_TYPE, REDIRECT_URIS)` |
| 7 | `:120` `/userinfo` | `userinfo` | `UserInfoHandler` | `noBodyAuditor()` | `noBodyAuditor()` |
| 8 | `:121` `/idtokeninfo` | `idtokeninfo` | `IdTokenInfoHandler` | `noBodyAuditor()` | `noBodyAuditor()` |
| 9 | `:122` `/connect/checkSession` | `connect/checkSession` | `CheckSessionHandler` | `noBodyAuditor()` | `noBodyAuditor()` |
| 10 | `:123` `/connect/endSession` | `connect/endSession` | `EndSessionHandler` | `noBodyAuditor()` | `noBodyAuditor()` |
| 11 | `:124` `/connect/jwk_uri` | `connect/jwk_uri` | `JwkUriHandler` | `noBodyAuditor()` | `noBodyAuditor()` |
| 12–14 | `:131-133` `/resource_set/{rsid}`, `/resource_set`, `/resource_set/` | `STARTS_WITH resource_set` + child `EQUALS ""` / `EQUALS "{rsid}"` ([D2](phase-5d-1.md#d2)) | `ResourceSetRegistrationHandler` | `jsonAuditor(NAME, SCOPES)` | `jsonAuditor("_id")` |
| 15 | `:137` `/.well-known/openid-configuration` | `.well-known/openid-configuration` | `OpenIDConnectConfigurationHandler` | `noBodyAuditor()` | `noBodyAuditor()` |
| 16 | `:141` `/device/user` | `device/user` | `DeviceCodeVerificationHandler` | `noBodyAuditor()` | `noBodyAuditor()` |
| 17 | `:142` `/device/code` | `device/code` | `DeviceCodeHandler` | `formAuditor(RESPONSE_TYPE, GRANT_TYPE, CLIENT_ID, SCOPE)` | `noBodyAuditor()` |
| 18 | `:146` `/token/revoke` | `token/revoke` | `TokenRevocationHandler` | `noBodyAuditor()` | `noBodyAuditor()` |

Two mechanical conversions, both already established
([chf-patterns §15](chf-patterns.md#15-chf-access-audit-base-abstracthttpaccessauditfilter--shape--traps-phase-3d)):
Restlet's `jacksonAuditor(...)` **and** `jsonAuditor(...)` both become CHF `jsonAuditor(...)`, and
`noBodyAuditor()` is `null` on the CHF side — the constant is kept for readability, exactly as
`UmaHttpRouteProvider` uses it. The constants themselves come from the same static imports
`OAuth2RouterProvider:20-27` uses, including `ShortClientAttributeNames.CLIENT_NAME.getType()` for row 6.

<a id="3--the-provider-instantiates-all-15-handlers-when-the-router-is-built-and-that-router-is-the-whole-chf-servlets"></a>
### 3. ⚠ The provider instantiates all 15 handlers when the router is built — and that router is the **whole** CHF servlet's

`Endpoints.from(Class)` resolves the instance immediately: `Endpoints.java:97-109` →
`InjectorHolder.getInstance(key)`, called from `from(Class)` at **route-construction** time, not per request.
`HttpRouterProvider.get()` (`openam-http/.../HttpRouterProvider.java:46-56`) iterates **every**
`HttpRouteProvider` on the classpath and adds all their routes to **one** `Router`, which backs the single
`OpenAM` `HttpFrameworkServlet`.

⇒ two consequences that decide the commit split:

1. once `OAuth2HttpRouteProvider` is in `META-INF/services`, a Guice failure while constructing **any** of the
   15 handlers (or any collaborator of theirs) aborts the construction of the router that also serves `/json`,
   `/xacml`, `/uma` and `/rest-sts`. The failure mode is *"the admin console stops working"*, not
   *"`/oauth2` 500s"*, and it happens **whether or not the web.xml line has moved**;
2. therefore the services registration must **not** ride along with the mapping move. 5d-1b lands the provider
   **and** the services line with `/oauth2` still on Restlet, so that this exact failure mode is exercised by
   the 5d-1b soak (`mvn install` + Cargo boot + the full e2e suite, whose very first action is a `/json`
   login) while `/oauth2` behaviour is still Restlet's. 5d-1c is then one line.

**Contingency, deliberately not the default.** `HttpRoute.newHttpRoute(mode, template, Provider<Handler>)`
exists and would defer construction — but `HttpRoute.getHandler():213-216` calls `handler.get()` **per
request**, so it would rebuild the entire 18-route tree on every `/oauth2` hit. Use it only if boot ordering
forces it, and never without measuring. XACML and UMA both build eagerly today and boot fine, which is the
evidence that eager is right.

<a id="4--checksession-needs-no-route-surgery--the-servlet-mapping-does-it"></a>
### 4. `connect/checkSession` needs **no** route surgery — the servlet mapping already does it

[D5-5](phase-5-oauth2.md) locks *"keep the JSP; `CheckSessionHandler` serves realm-prefixed paths only"*, which
reads like the route table needs a carve-out. It does not. `web.xml:1085-1088` maps
`/oauth2/connect/checkSession` **exactly** to the `OAuth2ConnectCheckSession` JSP servlet, and an exact mapping
out-ranks the `/oauth2/*` path mapping regardless of which servlet owns the prefix (Servlet spec §12.2). So the
bare path never reaches CHF, before or after the flip, and registering `connect/checkSession` once in the
endpoint router yields exactly the Restlet arrangement: JSP on the bare path, handler on
`/oauth2/realms/{realm}/connect/checkSession`.

The same precedence protects `/oauth2/registerClient.jsp` (`web.xml:1080-1083`). `/oauth2/checkSession.jsp`
(the file exists at `openam-server-only/src/main/webapp/oauth2/checkSession.jsp`) is *not* protected — an
extension mapping loses to a path mapping — but it is already 404 today under `ForgeRockRest`, so nothing
changes.

<a id="5--openam-http-has-two-405-producers-and-the-allow-fix-belongs-where-the-verb-map-is"></a>
### 5. `openam-http` has **two** 405 producers, and the `Allow` fix belongs where the verb map is

- `Endpoints.java:67-77` — the request's verb is not a key in the map at all (`PATCH`, `HEAD`, `OPTIONS`,
  `PROPFIND`): builds `new Response(Status.METHOD_NOT_ALLOWED)` with a CREST entity;
- `AnnotatedMethod.java:93-98` — the verb **is** mapped but the endpoint declares no such annotated method
  (`findMethod` returns a sentinel whose `method == null`): the same 405, the same CREST body.

Only `Endpoints.from` knows the set of verbs the endpoint actually supports, and only `AnnotatedMethod` knows
whether a given entry is a sentinel. So the fix is: compute the supported-verb list once in `from()` (needs a
package-private `isSupported()` on `AnnotatedMethod`) and stamp `Allow` on **any** 405 leaving the handler —
which covers both producers in one place and is idempotent if a handler ever sets its own.

⚠ **"Supported" cannot be computed from the annotations.** `findMethod` (`AnnotatedMethod.java:204-224`) has a
**second** pass that matches by *method name* (`methodName.equals(annotation.getSimpleName().toLowerCase())`,
i.e. a method literally called `get`), and only if that also fails does it return the sentinel
(`:224`). So the `Allow` list must be derived from the returned `AnnotatedMethod`, never from a
`getAnnotation(Get.class) != null` scan — the two disagree for any endpoint using the name convention.

⚠ **`HEAD` must not appear in `Allow`.** Restlet answered `HEAD` and still advertised
`Allow: POST, PUT, GET, DELETE` ([5-E4 row 11](phase-5c-asbuilt.md#as-built-5-e4--recorded-2026-07-29)); the e2e row
asserts the **set** `["DELETE","GET","POST","PUT"]`, so adding `HEAD` would turn a recorded row red for no
behaviour gain. List the four mapped verbs only.

<a id="6--head-after-the-fix-lands-on-code-paths-that-are-already-correct"></a>
### 6. `HEAD` after the fix lands on code paths that are already correct — verified, not assumed

⚠ **One row of this finding is wrong, and 5-E5 measured it.** `HEAD /oauth2/authorize` is a **405** on
Restlet, not a run of the authorization flow — the endpoint's method filter sits *above* the `HEAD` → `GET`
rewrite. See [correction 2](phase-5d-1-asbuilt.md#5-e5-correction-2); the `AuthorizeHandler` bullet below is retained for its
description of the CHF side, which is exactly why the guard is needed. `EndSessionHandler` and the eight
lookup endpoints are unaffected — they have no method filter, and 5-E5 row 5 confirms `HEAD` serves them.

Mapping `HEAD` → the `@Get` method activates handler code that has never run under CHF. Checked, endpoint by
endpoint:

- `ResourceSetRegistrationHandler.readOrList:141-159` passes `conditions.noneMatches(model.etag, true)` —
  and Restlet's `checkWeakness` argument is literally `GET.equals(method) || HEAD.equals(method)`
  ([5-E4 row 21](phase-5c-asbuilt.md#as-built-5-e4--recorded-2026-07-29), `HttpConditions:127-139`). So a `HEAD` gets
  the same weak comparison a `GET` gets, which is what Restlet did. **No handler change needed.**
- `AuthorizeHandler.authorize:100-101` runs the real authorization flow on `HEAD` — including consent-page
  rendering and, on success, a 302 with an issued code. Restlet did precisely the same (it rewrote the verb
  *before* annotation lookup), so this is parity, not a new hazard.
- `EndSessionHandler.endSession:91-99` is a `@Get` that calls `openIDConnectEndSession.endSession(o2, idToken)`
  — it **ends the session** — so `HEAD /oauth2/connect/endSession` logs the user out. Again exactly what
  Restlet does today, and again worth naming rather than filing under "read-only".
- `TokenEndpointHandler` has no `@Get`; `HEAD` therefore hits the `AnnotatedMethod` sentinel → 405, as under
  Restlet's `TokenEndpointFilter.validateMethod`.
- the remaining eight `/oauth2` `@Get` methods (`tokeninfo`, `introspect`, `userinfo`, `connect/register`'s
  read, `.well-known/openid-configuration`, `connect/jwk_uri`, `connect/checkSession`, `device/user`'s form)
  are lookups or renders: a `HEAD` is their `GET` with the body dropped.

⚠ **The fix also reaches three endpoints that are already live on CHF**, and the `openam-http` commit owns
that, not the flip. Enumerated (every `Endpoints.from` consumer, checked for a `@Get`):

| Live CHF endpoint | `@Get`? | `HEAD` after 5d-1a |
|---|---|---|
| `/json/authenticate` (`AuthenticationServiceV1/V2`) | **no** — `@Post` only (`AuthenticationServiceV1:114`) | still 405. ⚠ The one that would have mattered: authentication is **not** reachable by `HEAD` |
| `/json/api` (`ApiService:83`) | yes | 200, API descriptor computed and discarded |
| `/xacml/policies` (`XacmlServiceHandler:126`) | yes — the policy **export** | 200, and it does real work: the whole realm's policies are serialised, then dropped by the connector |
| `/uma/.well-known/uma-configuration` (`:71`) | yes | 200, trivial |
| UMA `permission_request` / `authz_request` | no — `@Post` | still 405 |

⇒ the widening is real but bounded: one cheap descriptor, one trivial document, and one *expensive but
authenticated and permission-checked* export. That is the RFC-conformant behaviour (`GET` and `HEAD` are the
two methods a general-purpose server must support), and it is exactly what Restlet gave every one of these
endpoints before they were ported. Recorded rather than glossed, because "additive, nothing moves" is not
true for `/xacml/policies`.

<a id="7--content-length-on-a-head-is-tomcats-decision"></a>
### 7. `Content-Length` on a `HEAD` is the container's decision, not ours — measure it

`HttpFrameworkServlet` never sets it: `writeResponse` (`commons/.../HttpFrameworkServlet.java:355-390`) only
copies headers and streams `copyRawContentTo(servletResponse.getOutputStream())`. Tomcat suppresses the body
for `HEAD` at the connector, but whether it emits `Content-Length: 0`, the `GET` length, or nothing is its
call. [5-E4 row 15](phase-5c-asbuilt.md#as-built-5-e4--recorded-2026-07-29) asserts **no** `Content-Length` (Restlet
sent none), so this row is a genuine unknown that only a live container answers. **Measure at 5d-1c; if it
differs, it is a header-level divergence row, not a bug to chase into commons.**

<a id="8--an-unrouted-oauth2-path-is-a-bodiless-404-on-chf"></a>
### 8. An unrouted `/oauth2` path is a **bodiless** 404 on CHF

Commons `Router.handle` (`http-framework/core/.../routing/Router.java:96-104`) answers `newNotFound()` — a
`Response` with status 404 and **no entity**. `OAuth2ErrorFilter` cannot rewrite what has no body: it guards on
`Content-Type: application/json` before parsing (`OAuth2ErrorFilter:56-63`), so an empty 404 passes through
untouched.

**On the default (non-`realms/`) branch the realm layer produces no error at all**:
`RealmContextFilter.evaluate:239-248` **breaks out of its loop** when a path element fails to resolve as a
realm (the `InternalServerErrorException ignored` catch at `:245-247`), leaving the element in the remaining
URI for the router. (The `realms/{realmId}` branch is different and *does* have its own 404 — see
[finding 15](#15--the-realm-layer-has-its-own-404-and-400-and-they-are-crest-shaped).) So Restlet's
`{"code":404,…,"message":"No mapping organization found for organization identifier: /resource_set"}`
([5-E4 row 17](phase-5c-asbuilt.md#as-built-5-e4--recorded-2026-07-29)) has **no CHF counterpart at all** — neither the
message nor the shape. See [D5](phase-5d-1.md#d5).

**Why Restlet answers with a realm message, read this session:** the whole `/oauth2` router *is* a realm
router. `OAuth2RouterProvider:95` constructs `new RestletRealmRouter()`
(`openam-restlet/.../rest/service/RestletRealmRouter.java`), whose constructor `:53-57` sets the router's
**default route** to the template `/{subrealm}` in `Template.MODE_STARTS_WITH`, delegating back to itself. So
every path element that matches no attached endpoint is consumed as a **sub-realm** and looked up
(`doHandle:80-85` → `getRealmFromURI:107-118` → `Realm.of(realm, subrealm)`), and the lookup's failure message
is what the client sees. Two consequences worth having in writing:

- **which 404 you get depends on the segment count** — measured, and the mechanism is
  [5-E5's](phase-5d-1-asbuilt.md#5-e5-the-one-mechanism). With exactly **one** element below `/oauth2` the element is consumed
  by `/{subrealm}`, the recursion re-enters with an *empty* remaining URI, nothing matches, and `doHandle`
  never runs — so no realm is looked up and Restlet's own **router** 404 surfaces. With **two or more** the
  recursion re-enters non-empty and the **realm** 404 above is produced, naming the first element;
- **`/oauth2/tokeninfo/` is therefore the router 404**, not the realm one — and either way it is a 404, which
  is what [D1](phase-5d-1.md#d1)'s flat `EQUALS` table needed to know.

<a id="9--realm-resolution-is-a-different-implementation-and-its-oauth2-behaviour-is-unrecorded"></a>
### 9. ⚠ Realm resolution is a **different implementation**, and its `/oauth2` behaviour is unrecorded

`RestletRealmRouter` is replaced by `RealmRoutingFactory` + `RealmContextFilter`, which is battle-tested on
`/json` but has never been observed side-by-side with Restlet on `/oauth2`. What it does
(`RealmContextFilter.java:208-278`, read this session): DNS-alias realm from the hostname; then greedily
consume leading path elements that resolve as realms or realm aliases (**this is the legacy
`/oauth2/<subrealm>/authorize` style**); then apply a `?realm=` override, which **replaces** rather than
appends; a bad override is a `BadRequestException` (**400**), a bad resolved realm likewise.

The Restlet side reaches the same three styles by different machinery, and the differences are not cosmetic:
the legacy style is a **default route** (`/{subrealm}`, `MODE_STARTS_WITH`) rather than a loop
([finding 8](#8--an-unrouted-oauth2-path-is-a-bodiless-404-on-chf)); the `?realm=` override is applied
**only when a real endpoint route matched** (`RestletRealmRouter:86`, `next != delegateRoute`) and a bad one
is a **404**, not a 400 ([finding 15](#15--the-realm-layer-has-its-own-404-and-400-and-they-are-crest-shaped)
row d); and the hostname is resolved on the non-`realms/` branch only, with no FQDN-map test
([finding 16](#16--the-flip-adds-host-validation-to-oauth2-that-restlet-never-did)).

Coverage today, measured: `e2e/oauth2` exercises `/oauth2/realms/root/...` on exactly **two** endpoints
(`oidc-test.spec.mjs:105` and the checkSession block) and **never** uses `?realm=` or a legacy path realm on
`/oauth2`. [Risk #9](plan.md#risk-register-behavioral-compatibility) is therefore live and unmeasured, and the
oracle expires at 5d-1c. ⇒ [5-E5](phase-5d-1-asbuilt.md#as-built-5-e5--recorded-2026-08-04) rows 1–4.

<a id="10--the-global-chf-chain-adds-two-filters-oauth2-has-never-had"></a>
### 10. The global CHF chain adds two filters `/oauth2` has never had

`OpenAMHttpApplication.start():68-80` wraps the whole router in a runtime-exception logger, an
`ApiDescriptorFilter` and an `OpenApiRequestFilter`. The last two react to `?_api` / `?_crestapi` query
parameters. After the flip they apply to `/oauth2` — a small new surface on endpoints where those parameter
names are otherwise meaningless. Restlet's answer to the same query today is unrecorded ⇒ [5-E5](phase-5d-1-asbuilt.md#as-built-5-e5--recorded-2026-08-04)
row 8. Not expected to matter; recorded so a post-flip surprise has a baseline.

<a id="11--what-e2e-already-covers-and-what-it-does-not"></a>
### 11. What e2e already covers, and what it does not

All **15** endpoints appear in `e2e/oauth2`. Measured with
`grep -ohE "oauth2/[A-Za-z0-9_.{}$/-]*" e2e/oauth2/*.mjs | sort | uniq -c | sort -rn` (URL literals, so the
count is reproducible rather than grep-dependent): `authorize` 20, `device/user` 15,
`connect/checkSession` 15 (**10 of them realm-prefixed**), `connect/endSession` 10, `resource_set` 14
(8 collection + 6 `{rsid}`), `tokeninfo` 6, `idtokeninfo` 6, `device/code` 6, `access_token` 6, `userinfo` 5,
`token/revoke` 4, `connect/register` 4, `.well-known/openid-configuration` 3 (1 realm-prefixed),
`connect/jwk_uri` 3, `introspect` 1. Current totals: **oauth2 88** rows
(`oauth2-endpoints` 43 + `oauth2` 23 + `oidc` 20 + `webfinger` 2) + **uma 11** = **99 passed**, the number
5c-2 recorded on `openam-e2e:5c2`.

⇒ the flip's regression net is genuinely end-to-end; what it lacks is the *routing-edge* coverage in
[finding 9](#9--realm-resolution-is-a-different-implementation-and-its-oauth2-behaviour-is-unrecorded) and
[finding 10](#10--the-global-chf-chain-adds-two-filters-oauth2-has-never-had), which is exactly 5-E5's brief.

<a id="12--the-webxml-change-is-one-line-and-oauth2-is-forgerockrests-last-mapping"></a>
### 12. The web.xml change is one line, and `/oauth2/*` is `ForgeRockRest`'s **last** mapping

`web.xml:1138-1146`: the `ForgeRockRest` servlet is declared once and mapped once — to `/oauth2/*`. The
`OpenAM` servlet's mappings end at `:1136` (`/uma/*`). The flip moves `/oauth2/*` into that block and leaves
`ForgeRockRest` **declared but unmapped**, which is the one-line revert lever.

Unaffected, verified: `FQDNValidationFilter` on `/oauth2/device/user` + `/oauth2/authorize` (`:185-192`) and
`CORSFilter` on `/oauth2/*` (`:224-227`) are `url-pattern`-based and servlet-agnostic; the two JSP mappings
([finding 4](#4--checksession-needs-no-route-surgery--the-servlet-mapping-does-it)); `/frrest/oauth2/*`
(`:1114-1117`), which is already on `OpenAM` and belongs to the unrelated `OAuth2RestHttpRouteProvider`
(`STARTS_WITH "frrest/oauth2"` — no collision with `STARTS_WITH "oauth2"`, since routes are matched on the
full remaining URI).

<a id="13--invalidrealmnames-is-a-realm-creation-guard-not-a-router-input"></a>
### 13. `InvalidRealmNames` is a realm-**creation** guard, not a router input

The set is consumed by `OrganizationConfigManager:522` (refusing to create a realm with that name) and by the
`/json` route builders in `RestGuiceModule`. `RealmContextFilter` never reads it. So registering the `/oauth2`
endpoint segments protects against an administrator creating a realm named `authorize` (which would then
shadow the endpoint via [finding 9](#9--realm-resolution-is-a-different-implementation-and-its-oauth2-behaviour-is-unrecorded)'s
greedy consumption) — it does not affect routing directly. XACML registers `policies`; UMA registers
`permission_request` and `authz_request` (`UmaHttpRouteProvider:121-122`). ⇒ [D7](phase-5d-1.md#d7).

<a id="14--oauth2-has-no-authentication-filter--and-xacmls-chain-does"></a>
### 14. ⚠ `/oauth2` has **no** authentication filter — and the XACML provider it would be copied from does

`RestEndpointServlet.service:67-70` is the whole of the Restlet dispatch: if the servlet path is `/oauth2` it
hands the request to `RestletServiceServlet(OAuth2ServiceEndpointApplication)`, and that application's
`createInboundRoot` (`ServiceEndpointApplication:56-61`) returns the router with **nothing** wrapped around it
except the `JSONRestStatusService` passed to `super(...)` in the constructor
(`OAuth2ServiceEndpointApplication:35-38`). No CAF authentication filter, no CSRF filter, no decoder.

That matters because the nearest CHF provider to crib from —
[`XacmlHttpRouteProvider`](../../../openam-entitlements/src/main/java/org/forgerock/openam/entitlement/rest/XacmlHttpRouteProvider.java)
— **does** authenticate: it injects `@Named("RequiredAuthenticationFilter")` (`:68`, the token-requiring
variant, deliberately not the plain `AuthenticationFilter` — its javadoc at `:58` says why) and chains it
inside the realm filter, `Handlers.chainOf(endpointRouter, authenticationFilter)` (`:106`). Copying that shape
onto `/oauth2` would demand an OpenAM session on `/access_token`, i.e. break every OAuth2 client at once.
`UmaHttpRouteProvider` is the correct template: per-route protection filters, no global authentication.
[D1](phase-5d-1.md#d1)'s chain has none, deliberately.

Also verified while checking this: **no `<filter-mapping>` in `web.xml` binds by `<servlet-name>`** — every
one is `url-pattern`-based, so no servlet filter follows the servlet rather than the path
([finding 12](#12--the-webxml-change-is-one-line-and-oauth2-is-forgerockrests-last-mapping)).

<a id="15--the-realm-layer-has-its-own-404-and-400-and-they-are-crest-shaped"></a>
### 15. The realm layer has **five** error producers, and they do not agree on a status

⚠ **The "Restlet today" column's *messages* are wrong, measured 2026-08-04** — the statuses are right. Restlet
renders the **cause's** message, not the `ResourceException` description quoted below, so rows a and d both
read `No mapping organization found for organization identifier: X` on the wire
([5-E5 correction 3](phase-5d-1-asbuilt.md#5-e5-correction-3)). Row b is also refuted: the `realms/` branch **does** resolve the
host, and a bad one is a **500** ([correction 6](phase-5d-1-asbuilt.md#5-e5-correction-6)).

Read from `RealmRoutingFactory` and `RealmContextFilter` this session. Routing failures under `/oauth2` will
have **five** producers after the flip, not one — and they do not all speak the same status, let alone the same
shape:

| # | Producer | When | CHF status + body | Restlet today |
|---|---|---|---|---|
| a | `ChfRealmRouter.handle:146-154` | `/oauth2/realms/<bogus>/…` — `Realm.of` throws | **404** CREST `{"code":404,…,"message":"Realm \"bogus\" not found"}` | **404**, *byte-identical message* — `RealmRoutingFactory`'s own inner `RestletRealmRouter:254-257` throws `ResourceException(CLIENT_ERROR_NOT_FOUND, "Realm \"" + … + "\" not found")` |
| b | `HostnameFilter.filter:123-131` | on the `realms/` branch, `Realm.of(<request host>)` throws | **400** CREST `{"code":400,…,"message":"Realm \"host\" not found"}` | **no equivalent** — the outer router short-circuits when `realmId` is set (`RestletRealmRouter:75-78`), so the `realms/` branch never resolves the host at all ([finding 16](#16--the-flip-adds-host-validation-to-oauth2-that-restlet-never-did)) |
| c | `RealmContextFilter.evaluate:229-231` | non-`realms/` branch, the request host is not in the FQDN map | **400** CREST `{"code":400,…,"message":"FQDN \"h\" is not valid."}` | **no equivalent** ([finding 16](#16--the-flip-adds-host-validation-to-oauth2-that-restlet-never-did)) |
| d | `RealmContextFilter.evaluate:255-257`/`:263-276` | a bad `?realm=` override, or a resolved realm that will not look up | **400** CREST `{"code":400,…,"message":"Invalid realm, bogus"}` | **404** `"Realm \"bogus\" not found"` — `RestletRealmRouter:86-90` calls `Realm.of(override)` and `:102-104` maps the failure to `CLIENT_ERROR_NOT_FOUND`. ⚠ **a status divergence**, see 5-E5 row 2 |
| e | the endpoint router / [D5](phase-5d-1.md#d5)'s default route | no route matches the remaining URI | bodiless 404 → the OAuth2-shaped 404 [D5](phase-5d-1.md#d5) mounts | **404** realm-lookup CREST ([finding 8](#8--an-unrouted-oauth2-path-is-a-bodiless-404-on-chf)) |

Everything in that column is then rewritten by the root `OAuth2ErrorFilter`: 400 → `invalid_request`, 404 →
`not_found` ([D5](phase-5d-1.md#d5)), 500 → `server_error`. `RealmContextFilter.filter:85-93` is where a/c/d become
responses at all — `BadRequestException` → 400, any other `ResourceException` → **500**.

`ChfRealmRouter` also builds its **own** internal router (`:138-143`: recursion on `REALM_ROUTE`,
`setDefaultRoute(next)` where `next` is the handler passed to `createRouter`) — which is why
[D1](phase-5d-1.md#d1)'s root passes `root` itself and why the recursion terminates on `root`'s default route. The
`RealmContextFilter` on that default route is a no-op the second time round: `evaluate` returns the context
unchanged when a `RealmContext` is already present (`RealmContextFilter:225-227`), so a realm is never
resolved twice — and, note, so the FQDN check in row c **never runs on the `realms/` branch**.

⚠ **Two `RestletRealmRouter` classes exist and they are different.** `org.forgerock.openam.rest.service.RestletRealmRouter`
(openam-restlet, `@Deprecated`) is the *outer* `/oauth2` router (`OAuth2RouterProvider:95`); `RealmRoutingFactory`
has a private inner class of the same simple name (`:232-290`) that serves the `/realms/{realmId}` recursion
(`:96`). Only the first is 5d-2's to delete — the inner one is `RealmRoutingFactory`'s Restlet overload and
outlives this migration until every Restlet consumer is gone.

⇒ two consequences: [D5](phase-5d-1.md#d5)'s `case 404 → not_found` is what keeps producers a and e speaking one
vocabulary, and 5-E5 rows 2, 4, 11 and 14 must record the Restlet answers for the bad-override, unknown-realm,
unknown-path and unknown-host cases separately, since they are four different code paths on both stacks.

<a id="16--the-flip-adds-host-validation-to-oauth2-that-restlet-never-did"></a>
### 16. ⚠ The flip adds **host validation** to `/oauth2` that Restlet never did

⚠ **Half-refuted 2026-08-04 by [5-E5 row 14](phase-5d-1-asbuilt.md#the-recorded-rows).** The FQDN-map test really is new, but the
table below is wrong about `/oauth2/realms/root/…`: it does **not** work today under an unrecognised `Host`.
The `realmId` short-circuit cannot fire on the first pass ([the mechanism](phase-5d-1-asbuilt.md#5-e5-the-one-mechanism)), so both
styles resolve the host and both answer **500**. The flip therefore changes 500 → 400 on both, rather than
breaking a working integration ([correction 6](phase-5d-1-asbuilt.md#5-e5-correction-6)).

Found while checking finding 15's producers, and the only finding in this document that can break a *working*
deployment rather than change an error's shape. What each stack does with the request's `Host`:

| Path | Restlet today | CHF after the flip |
|---|---|---|
| `/oauth2/tokeninfo` (non-`realms/`) | `RestletRealmRouter.getRealmFromServerName:128-135` — `Realm.of(host)`; on failure **500** (`SERVER_ERROR_INTERNAL`). No FQDN-map test | `RealmContextFilter:229-231` — `coreWrapper.isValidFQDN(host)` first, i.e. `FqdnValidator.isHostnameValid`, which is a **literal membership test on the configured FQDN map** (`FqdnValidator:99-101`: `fqdnMap.values().contains(host.toLowerCase())`). Not in the map ⇒ **400** before any realm work |
| `/oauth2/realms/root/tokeninfo` | **no host resolution at all** — `realmId` is already an attribute, so `doHandle:75-78` returns early into `super.doHandle` | `HostnameFilter:123-131` — `Realm.of(host)`; not a realm or alias ⇒ **400** |

So a deployment whose clients reach `/oauth2` under a `Host` that OpenAM does not know — a proxy or ingress
that does not rewrite `Host`, an IP literal, an extra CNAME never added to the FQDN map — gets:

- `/oauth2/realms/root/authorize`: **works today, 400 after the flip**. This is the one that can break a live
  integration, and no e2e row can see it because the suite always uses the container's own hostname;
- `/oauth2/tokeninfo` and the other bare-path endpoints: **500 today, 400 after**. A better answer, but still
  a changed one.

⚠ **The two endpoints a browser actually reaches are already protected, and that narrows the blast radius —
but not where it matters.** `web.xml:185-192` maps `FQDNValidationFilter` to the **exact** patterns
`/oauth2/authorize` and `/oauth2/device/user`, and that filter **redirects** to the mapped FQDN rather than
erroring (`FQDNValidationFilter:44-61` → `AuthUtils.getValidFQDNResource`, same `FqdnValidator` underneath).
Being `url-pattern`-based it survives the flip untouched
([finding 12](#12--the-webxml-change-is-one-line-and-oauth2-is-forgerockrests-last-mapping)). But an exact
pattern does **not** cover `/oauth2/realms/root/authorize`, so the realm-prefixed spelling of the same
endpoint — the *modern* one, the one this migration is meant to keep working — is precisely the path with no
redirect in front of it.

**Not a defect to fix in CHF, and deliberately not "fixed" here.** `/json` has behaved exactly this way since
14.0 (`RestGuiceModule:213-214` builds the same pair), the FQDN map is the product's documented host-validation
mechanism, and rejecting an unrecognised `Host` on the endpoint that issues redirects to `redirect_uri` is the
defensible behaviour, not the accidental one. What this step owes it is **visibility**: [5-E5](phase-5d-1-asbuilt.md#as-built-5-e5--recorded-2026-08-04)
row 14 records both stacks' answers, [R-5d1.9](phase-5d-1.md#risk-register-extends-phase-5-oauth2s) carries it, and the
release note must say that `/oauth2` now requires the request host to be a valid FQDN or realm alias. It is
also a genuine reason the [cutover lever](decisions.md#cutover-lever) exists: it is exactly the class of
breakage that shows up in someone else's deployment and not in ours.

---

