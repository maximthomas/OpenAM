# Phase 5d-1 — the flip: `/oauth2` → CHF (Restlet left dormant)

Execution plan for **step 5d-1** of [Phase 5](phase-5-oauth2.md) of the Restlet → CHF migration — the commit
sequence that moves the live `/oauth2` surface onto the CHF handlers built in 5a–5c. Parent tracker:
[plan.md](plan.md); umbrella: [phase-5-oauth2.md](phase-5-oauth2.md); the routing template this copies:
[phase-4-uma.md](phase-4-uma.md) + [`UmaHttpRouteProvider`](../../../openam-uma/src/main/java/org/openidentityplatform/openam/uma/UmaHttpRouteProvider.java);
the steps whose output it wires: [phase-5a-1.md](phase-5a-1.md), [phase-5a-2.md](phase-5a-2.md),
[phase-5b-1.md](phase-5b-1.md), [phase-5b-2.md](phase-5b-2.md), [phase-5c.md](phase-5c.md); decisions:
[decisions.md](decisions.md); reusable CHF patterns: [chf-patterns.md](chf-patterns.md); framework fixes we own:
[openam-http-framework.md](openam-http-framework.md); test layers:
[../../test-infrastructure.md](../../test-infrastructure.md). Written 2026-07-30; branch
`features/restlet-migration`. **All facts below were verified against the tree on 2026-07-30** — file and line
references are to that state.

> **Naming.** [plan.md](plan.md)'s phase table calls this step **5d-1**. This doc splits it into **5-E5** (a
> final test-only live-oracle gate), **5d-1a** (the `openam-http` verb fixes), **5d-1b** (the route provider +
> `OAuth2RouterIT`, still unflipped) and **5d-1c** (the web.xml line, the soak and the byte-diff) — the same
> gate-first / framework-separate / build-ahead / flip rhythm every earlier step used.

## Context

Everything `/oauth2` needs already exists. All **15 handlers** are committed and unit-green
(`org.openidentityplatform.openam.oauth2.http` ×13 + `org.openidentityplatform.openam.openidconnect.http` ×2),
as are the two abstract bases, the two CHF hook interfaces, `OAuth2ErrorFilter`, `OAuth2NoCacheFilter`,
`ResourceSetErrorFilter`, `ChfAccessTokenProtectionFilter`, `OAuth2HttpAccessAuditFilter`, `HttpBodyAuditor`,
`FreemarkerTemplateRenderer`, `ConsentPageRenderer` and `HttpConditions`. **Nothing on the wire uses any of
them.** 5d-1 is the step that connects them, and it is the first time any of it is observable in production.

That makes 5d-1 unusual among the Phase 5 steps: it writes **two new main classes** (the route provider and a
~15-line not-found handler), **two** further lines of existing main code, and **one line** of deployment
descriptor, and almost all of its work is *verification* — the composition IT, the
final live-oracle gate, the e2e re-run and the byte-diff. Its risk profile is the inverse of 5b-1's: little
code, maximum blast radius.

Three properties shape the split below:

- **the live Restlet oracle dies here** ([risk #20](plan.md#risk-register-behavioral-compatibility)). Anything
  not recorded before the web.xml line moves is unrecoverable — this is the last gate opportunity in the whole
  migration (§ [5-E5](#5-e5--the-last-gate));
- **two of the handed-down defects are `openam-http`'s, not the migration's** — `HEAD` and the missing `Allow`
  header ([5c *Handed to 5d-1*](phase-5c.md#handed-to-5d-1)). The F1–F4 precedent says framework defects get
  their own commit with their own tests, never bundled into a migration commit
  ([openam-http-framework.md](openam-http-framework.md));
- **registering the route provider is itself a production change even before the flip** — see
  [finding 3](#3--the-provider-instantiates-all-15-handlers-when-the-router-is-built-and-that-router-is-the-whole-chf-servlets).
  So it gets a commit of its own, ahead of the mapping move.

> **Convention.** New classes: `org.openidentityplatform.openam.*`, CDDL header,
> `Copyright 2026 3A Systems LLC.`, **no `@since`** ([decisions.md](decisions.md)). Classes modified in place
> keep their header and gain a `Portions copyright 2026 3A Systems LLC.` line — except our own 2026 classes,
> which carry no `Portions` line.

## Scope & sizing — split four ways

| Step | Scope | New / changed | Risk |
|---|---|---|---|
| **5-E5** ✅ **done 2026-08-04** ([as-built](#as-built-5-e5--recorded-2026-08-04)) | **The last live-Restlet gate.** 14 items: realm styles (`?realm=`, legacy path realm, bogus realm), an unknown `Host`, `HEAD` and `Allow` on non-`resource_set` endpoints, unrouted-path shapes, `X-HTTP-Method-Override`, `?_api`/`?_crestapi`, `OPTIONS`, path-form edge cases. Test-only. Gates D4, D5 and D11 — and its **row 13 can redesign [D1](#d1)'s route table** | e2e spec only (0 main) | **High** — unrecoverable after 5d-1c |
| **5d-1a** | **`openam-http` verb fixes.** `HEAD` → the `@Get` method; `Allow` on both 405 producers. Own commit, own tests, no migration code. Closes two [decisions.md backlog](decisions.md#chf-cleanup-backlog) items | 2 modified + tests | **Med** — reaches every `Endpoints.from` consumer; three already-live endpoints start answering `HEAD` ([finding 6](#6--head-after-the-fix-lands-on-code-paths-that-are-already-correct)) |
| **5d-1b** | **`OAuth2HttpRouteProvider` + `META-INF/services` + `OAuth2RouterIT`.** The full 18-attachment table, the audit matrix, the nested `resource_set` router, the root error filter, the two-route no-cache filter, the synthesized 404 (+ one line in `OAuth2ErrorFilter` and two deliberate pin edits). **`/oauth2` still served by Restlet** | 2 new main + 1 line + 1 services line + 1 IT + 2 edited pins | **High** — a broken Guice graph here breaks the *whole* CHF router, `/json` included ([finding 3](#3--the-provider-instantiates-all-15-handlers-when-the-router-is-built-and-that-router-is-the-whole-chf-servlets)) |
| **5d-1c** | **The flip.** One `<servlet-mapping>` line; then Cargo boot, the e2e re-run + byte-diff, the audit smoke, the soak record. Revert = revert this commit | 1 line + docs | **High** — the wire change |

**Total new main classes: 2.** Order: **5-E5 → 5d-1a → 5d-1b → 5d-1c**. 5-E5 first because three of its rows
decide later work — rows 5 and 6 (`HEAD` and `Allow` beyond `resource_set`) are what 5d-1a is measured
against, and row 13 (trailing slash) can force every route into [D2](#d2)'s nested shape — and because
every row of it is worthless after 5d-1c. 5d-1a before 5d-1b so the IT can assert the fixed behaviour rather
than the divergence. 5d-1b before 5d-1c so the only difference between "the graph builds" and "the graph
serves" is one line.

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
| 12–14 | `:131-133` `/resource_set/{rsid}`, `/resource_set`, `/resource_set/` | `STARTS_WITH resource_set` + child `EQUALS ""` / `EQUALS "{rsid}"` ([D2](#d2)) | `ResourceSetRegistrationHandler` | `jsonAuditor(NAME, SCOPES)` | `jsonAuditor("_id")` |
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
`Allow: POST, PUT, GET, DELETE` ([5-E4 row 11](phase-5c.md#as-built-5-e4--recorded-2026-07-29)); the e2e row
asserts the **set** `["DELETE","GET","POST","PUT"]`, so adding `HEAD` would turn a recorded row red for no
behaviour gain. List the four mapped verbs only.

<a id="6--head-after-the-fix-lands-on-code-paths-that-are-already-correct"></a>
### 6. `HEAD` after the fix lands on code paths that are already correct — verified, not assumed

⚠ **One row of this finding is wrong, and 5-E5 measured it.** `HEAD /oauth2/authorize` is a **405** on
Restlet, not a run of the authorization flow — the endpoint's method filter sits *above* the `HEAD` → `GET`
rewrite. See [correction 2](#5-e5-correction-2); the `AuthorizeHandler` bullet below is retained for its
description of the CHF side, which is exactly why the guard is needed. `EndSessionHandler` and the eight
lookup endpoints are unaffected — they have no method filter, and 5-E5 row 5 confirms `HEAD` serves them.

Mapping `HEAD` → the `@Get` method activates handler code that has never run under CHF. Checked, endpoint by
endpoint:

- `ResourceSetRegistrationHandler.readOrList:141-159` passes `conditions.noneMatches(model.etag, true)` —
  and Restlet's `checkWeakness` argument is literally `GET.equals(method) || HEAD.equals(method)`
  ([5-E4 row 21](phase-5c.md#as-built-5-e4--recorded-2026-07-29), `HttpConditions:127-139`). So a `HEAD` gets
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
call. [5-E4 row 15](phase-5c.md#as-built-5-e4--recorded-2026-07-29) asserts **no** `Content-Length` (Restlet
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
([5-E4 row 17](phase-5c.md#as-built-5-e4--recorded-2026-07-29)) has **no CHF counterpart at all** — neither the
message nor the shape. See [D5](#d5).

**Why Restlet answers with a realm message, read this session:** the whole `/oauth2` router *is* a realm
router. `OAuth2RouterProvider:95` constructs `new RestletRealmRouter()`
(`openam-restlet/.../rest/service/RestletRealmRouter.java`), whose constructor `:53-57` sets the router's
**default route** to the template `/{subrealm}` in `Template.MODE_STARTS_WITH`, delegating back to itself. So
every path element that matches no attached endpoint is consumed as a **sub-realm** and looked up
(`doHandle:80-85` → `getRealmFromURI:107-118` → `Realm.of(realm, subrealm)`), and the lookup's failure message
is what the client sees. Two consequences worth having in writing:

- ~~Restlet's `/oauth2` essentially never emits a plain routing 404~~ ⚠ **corrected 2026-08-04 by
  [5-E5](#5-e5-the-one-mechanism):** it emits one whenever exactly **one** element sits below `/oauth2`. The
  element is consumed by `/{subrealm}`, the recursion re-enters with an *empty* remaining URI, nothing
  matches, and `doHandle` never runs — so no realm is looked up. Two or more elements do produce the realm
  404 this finding describes, naming the **first**;
- ~~it independently predicts row 13~~ — the prediction (`404s on Realm.of(root, "tokeninfo")`) was right about
  the status and wrong about the producer: `/oauth2/tokeninfo/` is the **router** 404. [D1](#d1)'s flat table
  stands, which is what the row existed to decide.

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
oracle expires at 5d-1c. ⇒ [5-E5](#5-e5--the-last-gate) rows 1–4.

<a id="10--the-global-chf-chain-adds-two-filters-oauth2-has-never-had"></a>
### 10. The global CHF chain adds two filters `/oauth2` has never had

`OpenAMHttpApplication.start():68-80` wraps the whole router in a runtime-exception logger, an
`ApiDescriptorFilter` and an `OpenApiRequestFilter`. The last two react to `?_api` / `?_crestapi` query
parameters. After the flip they apply to `/oauth2` — a small new surface on endpoints where those parameter
names are otherwise meaningless. Restlet's answer to the same query today is unrecorded ⇒ [5-E5](#5-e5--the-last-gate)
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
`permission_request` and `authz_request` (`UmaHttpRouteProvider:121-122`). ⇒ [D7](#d7).

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
[D1](#d1)'s chain has none, deliberately.

Also verified while checking this: **no `<filter-mapping>` in `web.xml` binds by `<servlet-name>`** — every
one is `url-pattern`-based, so no servlet filter follows the servlet rather than the path
([finding 12](#12--the-webxml-change-is-one-line-and-oauth2-is-forgerockrests-last-mapping)).

<a id="15--the-realm-layer-has-its-own-404-and-400-and-they-are-crest-shaped"></a>
### 15. The realm layer has **five** error producers, and they do not agree on a status

⚠ **The "Restlet today" column's *messages* are wrong, measured 2026-08-04** — the statuses are right. Restlet
renders the **cause's** message, not the `ResourceException` description quoted below, so rows a and d both
read `No mapping organization found for organization identifier: X` on the wire
([5-E5 correction 3](#5-e5-correction-3)). Row b is also refuted: the `realms/` branch **does** resolve the
host, and a bad one is a **500** ([correction 6](#5-e5-correction-6)).

Read from `RealmRoutingFactory` and `RealmContextFilter` this session. Routing failures under `/oauth2` will
have **five** producers after the flip, not one — and they do not all speak the same status, let alone the same
shape:

| # | Producer | When | CHF status + body | Restlet today |
|---|---|---|---|---|
| a | `ChfRealmRouter.handle:146-154` | `/oauth2/realms/<bogus>/…` — `Realm.of` throws | **404** CREST `{"code":404,…,"message":"Realm \"bogus\" not found"}` | **404**, *byte-identical message* — `RealmRoutingFactory`'s own inner `RestletRealmRouter:254-257` throws `ResourceException(CLIENT_ERROR_NOT_FOUND, "Realm \"" + … + "\" not found")` |
| b | `HostnameFilter.filter:123-131` | on the `realms/` branch, `Realm.of(<request host>)` throws | **400** CREST `{"code":400,…,"message":"Realm \"host\" not found"}` | **no equivalent** — the outer router short-circuits when `realmId` is set (`RestletRealmRouter:75-78`), so the `realms/` branch never resolves the host at all ([finding 16](#16--the-flip-adds-host-validation-to-oauth2-that-restlet-never-did)) |
| c | `RealmContextFilter.evaluate:229-231` | non-`realms/` branch, the request host is not in the FQDN map | **400** CREST `{"code":400,…,"message":"FQDN \"h\" is not valid."}` | **no equivalent** ([finding 16](#16--the-flip-adds-host-validation-to-oauth2-that-restlet-never-did)) |
| d | `RealmContextFilter.evaluate:255-257`/`:263-276` | a bad `?realm=` override, or a resolved realm that will not look up | **400** CREST `{"code":400,…,"message":"Invalid realm, bogus"}` | **404** `"Realm \"bogus\" not found"` — `RestletRealmRouter:86-90` calls `Realm.of(override)` and `:102-104` maps the failure to `CLIENT_ERROR_NOT_FOUND`. ⚠ **a status divergence**, see 5-E5 row 2 |
| e | the endpoint router / [D5](#d5)'s default route | no route matches the remaining URI | bodiless 404 → the OAuth2-shaped 404 [D5](#d5) mounts | **404** realm-lookup CREST ([finding 8](#8--an-unrouted-oauth2-path-is-a-bodiless-404-on-chf)) |

Everything in that column is then rewritten by the root `OAuth2ErrorFilter`: 400 → `invalid_request`, 404 →
`not_found` ([D5](#d5)), 500 → `server_error`. `RealmContextFilter.filter:85-93` is where a/c/d become
responses at all — `BadRequestException` → 400, any other `ResourceException` → **500**.

`ChfRealmRouter` also builds its **own** internal router (`:138-143`: recursion on `REALM_ROUTE`,
`setDefaultRoute(next)` where `next` is the handler passed to `createRouter`) — which is why
[D1](#d1)'s root passes `root` itself and why the recursion terminates on `root`'s default route. The
`RealmContextFilter` on that default route is a no-op the second time round: `evaluate` returns the context
unchanged when a `RealmContext` is already present (`RealmContextFilter:225-227`), so a realm is never
resolved twice — and, note, so the FQDN check in row c **never runs on the `realms/` branch**.

⚠ **Two `RestletRealmRouter` classes exist and they are different.** `org.forgerock.openam.rest.service.RestletRealmRouter`
(openam-restlet, `@Deprecated`) is the *outer* `/oauth2` router (`OAuth2RouterProvider:95`); `RealmRoutingFactory`
has a private inner class of the same simple name (`:232-290`) that serves the `/realms/{realmId}` recursion
(`:96`). Only the first is 5d-2's to delete — the inner one is `RealmRoutingFactory`'s Restlet overload and
outlives this migration until every Restlet consumer is gone.

⇒ two consequences: [D5](#d5)'s `case 404 → not_found` is what keeps producers a and e speaking one
vocabulary, and 5-E5 rows 2, 4, 11 and 14 must record the Restlet answers for the bad-override, unknown-realm,
unknown-path and unknown-host cases separately, since they are four different code paths on both stacks.

<a id="16--the-flip-adds-host-validation-to-oauth2-that-restlet-never-did"></a>
### 16. ⚠ The flip adds **host validation** to `/oauth2` that Restlet never did

⚠ **Half-refuted 2026-08-04 by [5-E5 row 14](#the-recorded-rows).** The FQDN-map test really is new, but the
table below is wrong about `/oauth2/realms/root/…`: it does **not** work today under an unrecognised `Host`.
The `realmId` short-circuit cannot fire on the first pass ([the mechanism](#5-e5-the-one-mechanism)), so both
styles resolve the host and both answer **500**. The flip therefore changes 500 → 400 on both, rather than
breaking a working integration ([correction 6](#5-e5-correction-6)).

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
defensible behaviour, not the accidental one. What this step owes it is **visibility**: [5-E5](#5-e5--the-last-gate)
row 14 records both stacks' answers, [R-5d1.9](#risk-register-extends-phase-5-oauth2s) carries it, and the
release note must say that `/oauth2` now requires the request host to be a valid FQDN or realm alias. It is
also a genuine reason the [cutover lever](decisions.md#cutover-lever) exists: it is exactly the class of
breakage that shows up in someone else's deployment and not in ours.

---

## Design decisions

<a id="d1"></a>
### D1 — `OAuth2HttpRouteProvider`: package, shape, and the two wrappers

**Package: `org.openidentityplatform.openam.oauth2.http`**, beside the filters it composes — **not**
`org.forgerock.openam.oauth2.rest` as [phase-5-oauth2](phase-5-oauth2.md#oauth2httprouteprovider-new-orgforgerockopenamoauth2rest--5d-1)
proposed. That proposal predates the [new-class convention](decisions.md) (`org.openidentityplatform.openam.*`,
which 4b followed for `UmaHttpRouteProvider`), and putting the CHF provider in the same package as the Restlet
`OAuth2RouterProvider` it replaces would make the 5d-2 deletion diff harder to read, not easier.

Shape, mirroring `UmaHttpRouteProvider` exactly (setter injection so the provider is `injectMembers`-friendly
— `HttpRouterProvider:49` injects members on each provider before calling `get()`):

```java
Router endpointRouter = new Router();
endpointRouter.addRoute(requestUriMatcher(EQUALS, "authorize"),
        audited(chainOf(Endpoints.from(AuthorizeHandler.class), new OAuth2NoCacheFilter()),
                noBodyAuditor(), noBodyAuditor()));
endpointRouter.addRoute(requestUriMatcher(EQUALS, "access_token"),
        audited(chainOf(Endpoints.from(TokenEndpointHandler.class), new OAuth2NoCacheFilter()),
                formAuditor(RESPONSE_TYPE, GRANT_TYPE, CLIENT_ID, USERNAME, SCOPE, REDIRECT_URI),
                jsonAuditor(SCOPE, TOKEN_TYPE)));
…                                                        // rows 4-11, 15-18 of finding 2, no extra filters
endpointRouter.addRoute(requestUriMatcher(STARTS_WITH, "resource_set"), resourceSetRouter());   // D2
endpointRouter.setDefaultRoute(new OAuth2NotFoundHandler());                                    // D5

Router root = new Router();
root.addRoute(requestUriMatcher(STARTS_WITH, REALM_ROUTE),
        chainOf(realmRoutingFactory.createRouter(root), realmRoutingFactory.createHostnameFilter()));
root.setDefaultRoute(chainOf(endpointRouter, realmContextFilter));

return singleton(newHttpRoute(STARTS_WITH, "oauth2", chainOf(root, new OAuth2ErrorFilter())));
```

- **`audited(handler, req, resp)`** = `chainOf(handler, new OAuth2HttpAccessAuditFilter(publisher, factory,
  requestFactory, req, resp))` — audit **outermost** on every route, which is where
  `OAuth2AccessAuditFilter` sits today: `auditWithOAuthFilter` (`OAuth2RouterProvider:155-163`) wraps **each
  attached restlet individually**, outside that endpoint's own `OAuth2Filter`, and the result is what
  `attach(...)` receives. So the CHF ordering is not a choice — it is the Restlet ordering, per route.
- **`OAuth2NoCacheFilter` on exactly two routes** — `authorize` and `access_token`, and nowhere else. That is
  the class's own documented scope, and the reason is not stylistic: those two are the routes the Restlet
  `OAuth2Filter` wrapped (`:72-77`), so they are the only ones whose *framework-produced* responses (405, 404,
  a non-OAuth2 500) carried `no-store`/`Pragma`. Every other endpoint sets its own headers or none. The
  handlers keep their own `noCache()` calls; stamping twice is free.
- **The root `OAuth2ErrorFilter`** wraps everything, per [D5-1](phase-5-oauth2.md) — `/oauth2`'s contract is
  the OAuth2 error shape end to end. It is idempotent (`:77` returns any body already carrying `error`),
  which is what lets `ResourceSetErrorFilter` keep its own vocabulary inside it.
- **Ordering is not a guess:** `Handlers.chainOf(H, A, B, C)` builds `A(B(C(H)))` — commons
  `Handlers.java:112-124`, *"Given [A, B, C, D] filters and a H handler, build a (A . (B . (C . (D . H))))
  chain"*. So the **first** filter argument is the outermost, which is what makes `audited(...)` the outer
  wrap and `OAuth2NoCacheFilter` sit between it and the handler.

⚠ **`OAuth2RouterIT` must assert the negative half of the no-cache scoping** (a `/tokeninfo` response carries
no `Pragma`), or a later "tidy-up" that hoists the filter to the root passes every other row. [5-E5 row
2](#the-recorded-rows) adds a second, live half of the same guard: a realm failure on `/access_token` carries
**no** cache headers today, because the stamping filter sits inside the realm layer — which the shape above
preserves.

✅ **The flat `EQUALS` table is measured-correct.** [5-E5 row 13](#the-recorded-rows) sent a trailing slash, a
case change and an empty segment at every shape of endpoint: all 404. Only `resource_set` needs [D2](#d2)'s
nested router (R-5d1.8 discharged).

<a id="d2"></a>
### D2 — `resource_set` is a nested router, and the chain wraps the **handler**

Verbatim from [5c D9](phase-5c.md#d9), which exists because
[5c finding 12](phase-5c.md#12--the-trailing-slash-route-cannot-be-expressed-with-equals-in-chf) proved three
sibling `EQUALS` routes cannot express the trailing-slash family:

```java
Handler chain = chainOf(Endpoints.from(ResourceSetRegistrationHandler.class),
        new OAuth2HttpAccessAuditFilter(publisher, factory, requestFactory,     // outermost
                jsonAuditor(NAME, SCOPES), jsonAuditor("_id")),
        new ResourceSetErrorFilter(),
        new ChfAccessTokenProtectionFilter(null, tokenStore, requestFactory, ErrorShape.OAUTH2));

Router resourceSetRouter = new Router();
resourceSetRouter.addRoute(requestUriMatcher(EQUALS, ""), chain);          // resource_set, resource_set/
resourceSetRouter.addRoute(requestUriMatcher(EQUALS, "{rsid}"), chain);    // resource_set/{rsid}
```

Two things that are **not** transcription details:

1. the chain wraps the **handler**, not `resourceSetRouter`. Wrapping the router would put
   `ResourceSetErrorFilter` outside the child's no-match 404, and its catch-all row ([D3](phase-5c.md#d3))
   would then turn that **bodiless** 404 into a **500**. ⚠ [D5](#d5) partly *hides* this: once the nested
   router has a not-found default route, the same mistake answers 404 rather than 500, because the filter
   returns a body already carrying `error` untouched. The placement is still right — a router 404 must not
   become a server error — but the demonstration has to be kept alive deliberately
   ([D5](#d5)'s pin table);
2. the protection filter is the **`ErrorShape.OAUTH2`** overload (`ChfAccessTokenProtectionFilter:88`). The
   3-arg constructor defaults to `CREST`, which is what `/uma` needs and what `resource_set` must not have
   ([5c finding 1](phase-5c.md#1--the-resource_set-401-is-oauth2-shaped-not-crest--the-4a-filter-cannot-be-reused-unchanged));
   passing the wrong one is a silent 401-shape regression that only
   `e2e/oauth2/oauth2-endpoints-test.spec.mjs:130-149` and `OAuth2RouterIT` catch.

`ResourceSetRouteCompositionIT` already proves this shape **works** in process; it cannot prove the provider
**uses** it (its router is wired inline). That is R-5c.12 and it is discharged by `OAuth2RouterIT` driving the
real provider over all three URL forms ([D9](#d9)).

<a id="d3"></a>
### D3 — the audit matrix is copied, and the copy is checked mechanically

[Finding 2](#2--the-route-table-is-18-attachments-and-7-distinct-auditor-pairs-lift-both-verbatim)'s table is
the deliverable. To make a transcription slip visible rather than silent, `OAuth2RouterIT` asserts the audited
**field lists** for the three routes that have them (`access_token` request + response, `introspect` response,
`resource_set` request), not merely that an event was emitted. A dropped field is otherwise invisible until an
auditor notices a missing column months later.

<a id="d4"></a>
### D4 — `HEAD` and `Allow` are fixed in `openam-http`; `PATCH` is recorded as a divergence

Decided 2026-07-30. Three separate questions, three different answers:

| | Restlet | CHF today | 5d-1 |
|---|---|---|---|
| `HEAD` on a `@Get` endpoint | 200, body stripped by the connector | **405** | **fix** — `Endpoints.from` maps `HEAD` to the `@Get` entry |
| `HEAD` on `/authorize` | ⚠ **405** — measured, [5-E5 correction 2](#5-e5-correction-2) | 405 | **keep the 405** — `AuthorizeHandler` refuses `HEAD` explicitly, or the fix above turns it into a flow that **issues codes** |
| `Allow` on any 405 | `Allow: POST, PUT, GET, DELETE` on `resource_set`; **`Allow: GET`** on the single-`@Get` endpoints, **absent** on the two filter-produced 405s — measured, [5-E5 row 6](#the-recorded-rows) | **absent** | **fix** — stamped on both 405 producers, **excluding `HEAD`** ([finding 5](#5--openam-http-has-two-405-producers-and-the-allow-fix-belongs-where-the-verb-map-is)) |
| `PATCH` on `resource_set` | routed to `@Put`: a working **full replace**, 200 | **405** | **record** — divergence row 14 |
| `PATCH` elsewhere | ⚠ runs the `@Get` **first**, then 405s — so the `@Get`'s errors and side effects are on the wire ([5-E5 correction 4](#5-e5-correction-4)) | 405, nothing run | **record** — row 14, widened |

`HEAD` and `Allow` are fixed because both are *specification* obligations (`Allow` is mandatory on a 405, RFC
7231 §6.5.5; `GET` and `HEAD` are the two methods every general-purpose server must support, §4.1, and §4.3.2
defines `HEAD` as `GET` without the body) and both are two-line, purely additive changes
to code we own. `PATCH` is **not** fixed at source: aliasing `PATCH` → `PUT` in `Endpoints.from` would give
every CHF endpoint with a `@Put` full-replace `PATCH` semantics, which RFC 5789 §2 explicitly forbids — trading
one wire regression on one endpoint for a wrong framework-wide default. Nor is it worth a route-scoped rewrite
filter: `PATCH` on `resource_set` is unused by the UMA UI and by every e2e row except the one that discovered
it. The `HEAD` fix's blast radius beyond `/oauth2` — three already-live CHF endpoints, one of them expensive —
is enumerated in [finding 6](#6--head-after-the-fix-lands-on-code-paths-that-are-already-correct) and is
5d-1a's to verify, not the flip's.

⚠ **Revised 2026-08-04 by [5-E5](#as-built-5-e5--recorded-2026-08-04).** The `HEAD` fix is unchanged in
principle and now carries one exception: `/authorize` answers **405** today, so mapping `HEAD` → `@Get` without
a guard would make a `HEAD` run the authorization flow and hand out a code — a capability *addition* on the
endpoint that issues credentials, and precisely the direction [risk #20](plan.md#risk-register-behavioral-compatibility)
says not to take silently. The guard belongs in `AuthorizeHandler` (which owns an explicit verb contract
already, [5b-1 D8](phase-5b-1.md)) rather than in `Endpoints.from`, which must stay generic — `/json` endpoints
gain `HEAD` correctly. `TokenEndpointHandler` needs nothing: it is `@Post`-only, so `HEAD` hits the sentinel
405 either way.

⚠ **A body byte-diff at the flip shows nothing for any of these three.** `HEAD`'s change is a status; `Allow`
is a header; `PATCH`'s 405 body is identical to the shape [D3](phase-5c.md#d3) already produces. The rows that
catch them are 5-E4 row 11, 5-E4 row 15 and [5-E5](#5-e5--the-last-gate) rows 5–6 — all header/status
assertions, which is why the gate matters more here than the diff.

Both fixed items close their [decisions.md backlog](decisions.md#chf-cleanup-backlog) entries; `PATCH`'s entry
is updated to *"resolved: divergence row 14"*. `Allow` has no backlog entry today — 5d-1a adds one, already
closed, so the reasoning survives.

<a id="d5"></a>
### D5 — an unrouted `/oauth2` path gets a synthesized body

Decided 2026-07-30. A tiny `OAuth2NotFoundHandler` is mounted as the default route of the endpoint router
**and** of the nested `resource_set` router, answering **404** with
`{"error":"not_found","error_description":"Not Found"}` and `Content-Type: application/json`. Five
sub-decisions, all deliberate:

- **both routers get the default route, not just the outer one.** A nested `Router` with no default answers
  its **own** bodiless 404 — it does not fall through to the parent's default — and
  `/oauth2/resource_set/a/b` is exactly the path [5-E4 row 17](phase-5c.md#as-built-5-e4--recorded-2026-07-29)
  recorded. Mounting on the endpoint router alone would leave the one 404 the migration has an oracle for as
  the only bodiless one on the surface.
- **the body is produced by a default route, not invented by a filter.** A filter rule that synthesized bodies
  for empty error responses existed in 3c-2's first draft and was deleted once F1 made the framework emit one;
  re-adding it would re-introduce a rule whose blast radius is every empty `≥400` on the application. A default
  route is scoped to exactly the case that has no body.
- **the handler writes the OAuth2 shape directly rather than a CREST body for the filter to rewrite.** The
  filter's `containsKey("error")` guard (`:77`) returns it unchanged, so handler and filter compose
  idempotently and the 404 body does not depend on the filter being mounted.
- **`errorFor` *does* gain `case 404 → not_found`** — one line, revised during this plan's own review.
  Without it the *other* routing 404s come out as `invalid_request`
  ([finding 15](#15--the-realm-layer-has-its-own-404-and-400-and-they-are-crest-shaped)), which would leave
  `/oauth2` saying `not_found` for a missing resource set and `invalid_request` for a missing realm. Three
  facts make the change safe and consistent: `OAuth2ErrorFilter` is mounted on **`/oauth2` only** (verified by
  grep; `UmaRouterIT` case 8 exists precisely to prove `/uma` has none); `not_found` is **already** this
  surface's word for a 404 — `NotFoundException` is `super(404, "not_found", …)`
  (`NotFoundException.java:34`), which is what `ChfAccessTokenProtectionFilter` propagates on `resource_set`,
  and `DeviceCodeVerificationHandler:75` uses the same literal; and [D10](phase-5b-2.md#d10) already set the
  precedent that a non-RFC-6749 code wins when it is the surface's incumbent. Cost: one line in `errorFor`,
  the **javadoc** that goes with it (`OAuth2ErrorFilter:129-132`'s `default:` comment reads *"400, 404 and the
  rest of 4xx"* — it must stop naming 404), plus the **edited** data-provider row in the table below — the
  test row exists already and says `invalid_request` today.
- ~~**On one of the 404 producers this buys near-parity, not just consistency.**~~ ⚠ **Struck 2026-08-04 by
  [5-E5 correction 3](#5-e5-correction-3).** The claim was that CHF's `Realm "bogus" not found` would be
  byte-identical to Restlet's message. It is not: Restlet renders the *cause's* message
  (`No mapping organization found for organization identifier: /bogus`), because
  `RestStatusService.toRepresentation:42-52` prefers `status.getThrowable().getMessage()` over the description
  the router wrote. `case 404 → not_found` stands on its remaining, sufficient ground — it keeps `/oauth2`
  saying one word for a 404 — but the *body* diverges in message as well as shape, and divergence row 15 says
  so.

⚠ **Two committed pins change with this decision, and both must be edited deliberately, not "made green".**
Found while reviewing this plan, by grepping for existing 404 assertions rather than assuming there were none:

| Pin | Today | After [D5](#d5) | Instruction |
|---|---|---|---|
| `OAuth2ErrorFilterTest:114` — the `statusToError` data provider row `{Status.NOT_FOUND, "invalid_request"}` | 404 → `invalid_request` | 404 → `not_found` | **edit the row**, with the reason in the same comment style the `method_not_allowed` row already carries |
| `ResourceSetRouteCompositionIT` row 9 (`aNoMatchBelowTheEndpointIsA404TheResourceSetFilterNeverSees:371-382`) | asserts the nested router's 404 has an **empty** entity, then demonstrates the counterfactual: wrap the *router* in `ResourceSetErrorFilter` and the same 404 becomes a **500** | the first half is now `{"error":"not_found"}`; ⚠ **and the counterfactual dies with it** — a body already carrying `error` is returned untouched by `ResourceSetErrorFilter`, so wrapping the router would answer 404, not 500 | assert the new body in the first half, and **re-express the counterfactual against a router with no default route** so the "wrapping the router turns a bodiless 404 into a 500" lesson survives. Deleting it would silently retire [D2](#d2)'s only executable guard |

⚠ The second row is the more important one: [D5](#d5) *reduces* the observable consequence of getting
[D2](#d2)'s filter placement wrong, which is precisely why the guard has to be kept deliberately rather than
allowed to lapse into a green test.

⚠ Parity is **impossible** here either way, and that is the honest framing: Restlet's message names a realm
lookup (`"No mapping organization found for organization identifier: /resource_set"`) that CHF never performs
([finding 8](#8--an-unrouted-oauth2-path-is-a-bodiless-404-on-chf)). The choice is between *a 404 with a
parseable OAuth2 body* and *a 404 with no body at all*. Divergence row 15 records it, and 5-E4 row 17 —
deliberately unasserted on the CHF side until now — is updated to assert the CHF answer as part of 5d-1c.

<a id="d6"></a>
### D6 — the flip is its own commit, and the revert is that commit

5d-1c contains the `<servlet-mapping>` move and documentation, and **nothing else**. Not the provider, not the
services file, not a test. `git revert` of that single commit restores Restlet on `/oauth2` with the CHF stack
still built and still dormant — the [cutover lever](decisions.md#cutover-lever) as designed. Any fix the soak
demands lands as a *new* commit on top, never as an amendment to 5d-1c, so the revert stays a one-liner.

<a id="d7"></a>
### D7 — `InvalidRealmNames` registration list

Register the **first path segment** of every route, since that is the element realm resolution would otherwise
consume ([finding 13](#13--invalidrealmnames-is-a-realm-creation-guard-not-a-router-input)):
`authorize`, `access_token`, `tokeninfo`, `introspect`, `userinfo`, `idtokeninfo`, `resource_set`,
`device`, `connect`, `token`, `.well-known`. Eleven names, added in `get()` exactly as
`UmaHttpRouteProvider:121-122` does — the same rule `Routers.java:94/170` applies automatically to every
`/json` route via its `firstPathSegment(uriTemplate)` helper. ⚠ Note `device`/`connect`/`token`/`.well-known`
rather than the full two-segment paths — a realm named `connect` would shadow four endpoints at once.

⚠ **This is a (small) live change at 5d-1b, before the flip.** Nothing registers any `/oauth2` segment today —
the Restlet stack never touched `InvalidRealmNameManager` — so from 5d-1b onwards `OrganizationConfigManager`
refuses to *create* a realm with one of these eleven names. Deliberate, and the same thing XACML and UMA did at
their own flips. Existing realms are unaffected: the set is consulted on creation only, and a deployment that
already has a realm called `connect` was already shadowed by Restlet's own realm router.

<a id="d8"></a>
### D8 — the audit smoke is a manual pre/post capture, recorded in the as-built

Decided 2026-07-30. [Risk #13](plan.md#risk-register-behavioral-compatibility)'s residual (the FAILED-path
`reason` string, the `queryParameters` fix, the `:-1` port) is discharged by capturing real audit records
either side of the flip rather than by new e2e machinery:

1. before 5d-1c, on the soak container: enable the file-based access-audit handler for the OAuth topic;
2. drive a fixed 8-request sequence (client_credentials token, a bad-secret token, an authorize 301, an
   authorize success, tokeninfo, introspect, a resource_set create, a 405);
3. `docker exec cat` the access log, save it as the pre-flip artefact;
4. flip, repeat, diff field by field: `eventName`, `component`, `userId`, `trackingIds`,
   `http.request.method/path/queryParameters/detail`, `http.response.detail`, `response.status`,
   `response.statusCode`, `response.detail.reason`.

Expected differences: the `reason` string on failures (`getReasonPhrase()` vs Restlet `getDescription()` — the
accepted residual), and possibly `http.request.path`'s `:-1` port
([backlog](decisions.md#chf-cleanup-backlog), pre-existing on `/json` too). Anything else is a regression.
Record the diff verbatim in the as-built — it is the only record that survives 5d-2.

<a id="d9"></a>
### D9 — `OAuth2RouterIT`: probe rows for the table, deep rows for the seams

The IT drives the **real** `OAuth2HttpRouteProvider` through `HttpRouteAccessor`, modelled on `UmaRouterIT`
(minimal injector, empty `GuiceModuleLoader`, `RealmTestHelper` over a mocked `CoreWrapper`/`RestRealmValidator`,
real `OAuth2RequestFactory`; `UmaRouterIT:379-381` is the model for the legacy-realm row). Two row
families, because proving 18 attachments exist and proving the seams work are different problems with very
different costs:

- **Probe rows (one per attachment, data-driven).** Dispatch `PROPFIND` at each route and assert
  **405 + the expected error vocabulary + `Allow` present**. A missing or misspelled route answers **404**, so
  the probe discriminates. It needs **no collaborator stubbing at all** — the framework answers before any
  endpoint method runs — and it simultaneously proves `Endpoints.from` is behind the route, that the root
  `OAuth2ErrorFilter` rewrote the CREST body (`method_not_allowed`), and — on `resource_set` alone —
  that `ResourceSetErrorFilter` won inside it (`unsupported_method_type`).
- **Deep rows (the seams).** `/access_token` GET → 405 with `no-store` (the verb is not checked by the
  handler); `/access_token` bad client secret → 401 + `WWW-Authenticate: Basic realm="/"`; `/authorize`
  unauthenticated → **301** with the asserted `Location`; `/authorize` error → 302 fragment **vs** query;
  the three error shapes coexisting in one run; `/tokeninfo` carrying **no** `Pragma` (D1's negative);
  realm styles (`?realm=`, `/realms/root/`, legacy `/oauth2/<sub>/tokeninfo`); `resource_set` over all three
  URL forms with `rsid` bound (R-5c.12); one `/access_token` request whose audit event carries the form-body
  detail (risk #1 — audit and handler reading one buffered body); the D5 404; `HEAD /oauth2/tokeninfo` → 200
  with the `GET`'s headers.

**Feasibility notes, checked so the implementer does not have to rediscover them.** The IT drives the real
filters, which raises three "will this even run in process" questions; all three are answered:

- `OAuth2HttpAccessAuditFilter.getSSOToken:175-181` wraps `SSOTokenManager.getInstance()` in
  `catch (Exception) → null`, so no session infrastructure is needed. (`ResourceSetRouteCompositionIT`
  overrides the method anyway; `OAuth2RouterIT` **cannot**, since it uses the provider's own filter instance —
  and it does not need to.)
- every audit code path is behind `auditEventPublisher.isAuditing(...)`
  (`AbstractHttpAccessAuditFilter:97/123/156`), so a mock returning `false` makes the probe rows audit-free.
- the audit **deep** row must therefore stub `isAuditing → true`, and then the context chain needs a
  `RequestAuditContext` (`:100`, `:126` read it unconditionally) with `AuditRequestContext.clear()` around the
  row — the shape `ResourceSetRouteCompositionIT` already uses.

Cost note: `Endpoints.from(Class)` resolves through Guice, so the IT's module must bind **~35** collaborator
types (mocks; the list is the union of the handlers' `@Inject` fields, all concrete-mockable). That is
mechanical, and it is also the *point* — it is the closest a test gets to proving
[finding 3](#3--the-provider-instantiates-all-15-handlers-when-the-router-is-built-and-that-router-is-the-whole-chf-servlets)'s
graph builds. It does **not** prove the *production* bindings resolve; only Cargo boot + e2e do that.

<a id="d10"></a>
### D10 — five 5c hand-downs, each with an owner in this step

| Handed-down item | Answer |
|---|---|
| Nested `resource_set` router + provider-driven IT (R-5c.12) | [D2](#d2) + [D9](#d9) |
| `HEAD` — fix or record | **fix**, 5d-1a ([D4](#d4)) |
| 5-E4 rows 15 / 17 unasserted CHF-side | asserted in 5d-1c's re-run ([D4](#d4), [D5](#d5)) |
| `PATCH` | **record**, divergence row 14 ([D4](#d4)) |
| `Allow` vanishing | **fix**, 5d-1a ([D4](#d4)) |

<a id="d11"></a>
### D11 — `X-HTTP-Method-Override`: decided when 5-E5 row 10 lands

⚠ **Settled 2026-08-04 by [5-E5 row 10](#the-recorded-rows): Restlet honours it, so the POST case is parity and
nothing is done to `Endpoints.from`.** The measurement also found the two shapes the decision did not
anticipate — the header on a *non*-POST, and Restlet's `?method=` query tunnel — both recorded as divergences
rather than fixed ([correction 5](#5-e5-correction-5)). The original framing follows.

`Endpoints.getMethod:119-126` rewrites the verb of a **POST** that carries `X-HTTP-Method-Override`, before
any route or annotation lookup. Restlet's equivalent is `TunnelService`, which is configured per application
and whose state on `/oauth2` is unrecorded. Two outcomes, and 5-E5 row 10 picks between them:

- **Restlet honours it too** → no divergence, nothing to do;
- **Restlet ignores it** → `POST /oauth2/access_token` + `X-HTTP-Method-Override: GET` changes from *a token*
  to *a 405* at the flip. That is the safe direction (capability removed, not added), but it is a wire change
  on the busiest endpoint in the product, so it is either a divergence row or a two-line gate in
  `Endpoints.from` — **decide with the measurement, not before it.**

⚠ Do not "fix" this pre-emptively: the header is honoured on `/json` today via the same code, so gating it
off in `Endpoints.from` would move CREST behaviour that has nothing to do with this migration.

---

<a id="5-e5--the-last-gate"></a>
## 5-E5 — the last gate (test-only)

✅ **Done 2026-08-04 — [as-built](#as-built-5-e5--recorded-2026-08-04)** (14 rows, `oauth2 uma` = **113
passed**, six corrections to this plan). The brief below is left as written so the corrections can be read
against what was predicted.

The final live-Restlet recording. Written **by observation**, against a container built from this tree with
`/oauth2` still on `ForgeRockRest`, in its own describe
(`/oauth2 routing contract lock (5-E5, live Restlet)`) so `-g "5-E5"` selects it at the re-run — the 5-E2/5-E3/5-E4
precedent. Target file: `e2e/oauth2/oauth2-test.spec.mjs` (it already hosts the 5-E and 5-E2 describes).

| # | Request | What it pins |
|---|---|---|
| 1 | `GET /oauth2/tokeninfo?realm=/` and `…?realm=%2F` with a valid token | the `?realm=` override is honoured and the endpoint still answers. ⚠ Restlet applies the override **only on a matched endpoint route** — `RestletRealmRouter:86` guards on `next != delegateRoute` — so add `GET /oauth2/nosuchendpoint?realm=/` to this row: on Restlet the override is skipped entirely, on CHF `RealmContextFilter` applies it before the router ever runs |
| 2 | `…?realm=bogus` on `/tokeninfo` **and** `/access_token` | status + body of a bad override. ⚠ **A status divergence is expected here.** Source says Restlet answers **404** (`RestletRealmRouter:86-90` → `:102-104`) and CHF answers **400** (`RealmContextFilter:255-257`, → `invalid_request`) — [finding 15](#15--the-realm-layer-has-its-own-404-and-400-and-they-are-crest-shaped) row d. Measure it; if confirmed it becomes divergence row 16 |
| 3 | a legacy path realm — `/oauth2/<subrealm>/tokeninfo`, sub-realm created by the fixture via `/json/realms` | that the legacy style resolves at all, and to which realm |
| 4 | `/oauth2/realms/root/tokeninfo`, `/oauth2/realms/bogus/tokeninfo`, **`/oauth2/realms/<the row-3 sub-realm>/tokeninfo`** and `/oauth2/realms/root/realms/<sub>/tokeninfo` | the modern style's success and failure answers. ⚠ The third URL is the interesting one: source says Restlet **404s** a flat `realms/<non-root>` — its inner router throws `NoRealmFoundException` unless the element is `root` or a `REALM_OBJECT` is already set (`RealmRoutingFactory:246-253`), and the outer router skips host resolution once `realmId` is present — while CHF **serves** it, because `HostnameFilter` supplies a `viaDns` `RealmContext` and `getRealm:299-301` then resolves the element as a realm alias (`RealmRoutingFactory:292-309`). A capability *gain*, i.e. the safe direction, but it must be recorded or the byte-diff reads as a regression in reverse. The fourth URL is the nested spelling both stacks accept |
| 5 | `HEAD` on `/tokeninfo`, `/.well-known/openid-configuration`, `/connect/jwk_uri`, `/authorize`, `/access_token` | the incumbent for [D4](#d4) beyond `resource_set`: status, `Content-Type`, `Content-Length`, and whether `/authorize`'s `HEAD` really runs the flow |
| 6 | `PROPFIND` / `PUT` on `/tokeninfo` and `/connect/jwk_uri` | whether live Restlet sends `Allow` on 405s **outside** `resource_set`, and its value |
| 7 | `PATCH /oauth2/tokeninfo` (no `@Put` anywhere) | bounds the `PATCH` divergence to `resource_set` — or shows it is wider |
| 8 | `GET /oauth2/tokeninfo?_api` and `?_crestapi` | baseline for [finding 10](#10--the-global-chf-chain-adds-two-filters-oauth2-has-never-had) |
| 9 | `OPTIONS /oauth2/authorize` (with and without an `Origin`) | the CORS filter's interaction, which survives the flip unchanged and must be seen to |
| 10 | `POST /oauth2/access_token` + `X-HTTP-Method-Override: GET` | ⚠ `Endpoints.getMethod:119-126` honours this header; Restlet's `TunnelService` may not. A silent verb change on the *token* endpoint is the worst place to discover one. **This row decides [D11](#d11)** |
| 11 | `/oauth2/nosuchendpoint`, `/oauth2/authorize/extra`, `/oauth2/realms/root/nosuch` | the unrouted-path answers [D5](#d5) is measured against |
| 12 | `GET /oauth2/` and `GET /oauth2` | the bare-prefix answer, which no row has ever recorded |
| 13 | path-form edge cases on an ordinary endpoint: `/oauth2/tokeninfo/` (**trailing slash**), `/oauth2/Tokeninfo` (case), `/oauth2//tokeninfo` (empty segment) | ⚠ The trailing slash is the one that matters. `resource_set` needed a **nested router** because CHF `EQUALS` cannot match a path ending in `/` ([5c finding 12](phase-5c.md#12--the-trailing-slash-route-cannot-be-expressed-with-equals-in-chf)) — and `resource_set` is the only endpoint Restlet attached twice. **Nobody had measured what Restlet answers for `/oauth2/<other-endpoint>/`** — and the answer decides whether [D1](#d1)'s flat `EQUALS` table is right or whether all 15 endpoints need [D2](#d2)'s nested shape. Disassembling the fork settles the *expectation*, though not as simply as the first reading claimed: `Router.attach(String, Restlet)` does **not** use the router's `defaultMatchingMode`, it calls `getMatchingMode(target)`, which upgrades a `Router`/`Directory` target to `MODE_STARTS_WITH` and **recurses through `Filter.getNext()`**. Every `/oauth2` endpoint row bottoms out at `RestletUtils.wrap(...)`, a **`Finder`**, so those rows really are `MODE_EQUALS` (whole-string `Matcher.matches()`) — while `/realms/{realmId}`, whose target is a `RestletRealmRouter`, is `STARTS_WITH`, which is why the realm-prefixed URLs work at all. So the endpoints have no trailing-slash tolerance, and that is also *why* `resource_set` needed three attachments. Expect a 404; **measure it anyway**, because this is the last chance and a 200 would redesign the provider. Also discharges [risk #11](plan.md#risk-register-behavioral-compatibility) (case sensitivity), which asks for exactly this spot-check pre and post |
| 14 | a `Host:` header OpenAM does not know (e.g. `Host: not-a-real-host.invalid`), on **both** `/oauth2/tokeninfo` and `/oauth2/realms/root/tokeninfo` | ⚠ [Finding 16](#16--the-flip-adds-host-validation-to-oauth2-that-restlet-never-did): the realm-prefixed form is expected to **work today and 400 after the flip**, and this is the only row whose subject can break a deployment that is working now. Record status + body for both forms. If the realm-prefixed form really does answer 200 today, it is divergence row 17 **and** a release-note line |

⚠ **Write every row by observation.** The 5b-1 lesson stands: two of 5-E2's rows overturned predictions the
plan had already built a design on. Where a row's answer changes [D4](#d4) or [D5](#d5), say so in the row's
comment and update the decision rather than the row.

⚠ **Run the whole suite in one pass against a freshly built container** — the resource-set leak documented in
[5c's gate notes](phase-5c.md#run-this-gate-against-a-fresh-container)
makes a sequential second run untrustworthy.

---

## New / modified / tests

### 5-E5 — test-only

| File | Change |
|---|---|
| `e2e/oauth2/oauth2-test.spec.mjs` | new describe, 14 rows; fixture helper to create + delete a sub-realm for row 3; row 14 needs a request with an explicit `Host` header, so it uses `request.get(url, {headers:{Host: …}})` rather than `page.goto` |

### 5d-1a — `openam-http` (own commit)

| File | Change |
|---|---|
| `openam-http/.../annotations/Endpoints.java` | `methods.put("HEAD", methods.get("GET"))`; compute the supported-verb list; stamp `Allow` on any 405 leaving the handler |
| `openam-http/.../annotations/AnnotatedMethod.java` | package-private `isSupported()` (whether the entry is the null-method sentinel) |
| `openam-http/.../annotations/EndpointsTest.java` | `HEAD` → the `@Get` method; `HEAD` → 405 when no `@Get`; `Allow` on the unmapped-verb 405; `Allow` on the sentinel 405; `Allow` excludes `HEAD`; no `Allow` on a 2xx |
| `docs/migration/restlet/decisions.md` | close the `HEAD` backlog entry; close `PATCH` as "divergence row 14"; add the (already closed) `Allow` entry |
| `docs/migration/restlet/openam-http-framework.md` | an **F5** section, in the F1–F4 house style |

### 5d-1b — the provider (own commit)

| File | Change |
|---|---|
| `…/openam/oauth2/http/OAuth2HttpRouteProvider.java` | **new** — [D1](#d1), [D2](#d2), [D3](#d3), [D7](#d7) |
| `…/openam/oauth2/http/OAuth2NotFoundHandler.java` | **new**, ~15 lines — [D5](#d5) |
| `…/openam/oauth2/http/OAuth2ErrorFilter.java` | one line — `case 404: return "not_found";` in `errorFor` — **and** the `default:` javadoc/comment at `:129-132`, which currently names 404 ([D5](#d5)) |
| `…/test/…/oauth2/http/OAuth2ErrorFilterTest.java` | **edit** the `statusToError` row at `:114` — 404 is now `not_found` ([D5](#d5)) |
| `…/test/…/oauth2/http/ResourceSetRouteCompositionIT.java` | **edit** row 9: the new 404 body, and the counterfactual re-expressed against a default-route-less router ([D5](#d5)) |
| `openam-oauth2/src/main/resources/META-INF/services/org.forgerock.openam.http.HttpRouteProvider` | append the provider. ⚠ The file already lists `OAuth2RestHttpRouteProvider` and **ends without a trailing newline** — appending naively concatenates the two class names into one unloadable line |
| `…/test/…/oauth2/http/OAuth2RouterIT.java` | **new** — [D9](#d9) |
| `…/test/…/oauth2/http/OAuth2NotFoundHandlerTest.java` | **new** |

### 5d-1c — the flip (own commit)

| File | Change |
|---|---|
| `openam-server-only/src/main/webapp/WEB-INF/web.xml` | move `/oauth2/*` from `ForgeRockRest` (`:1143-1146`) into the `OpenAM` block (after `:1136`) |
| `e2e/oauth2/*.spec.mjs`, `e2e/uma/*.spec.mjs` | **only** the rows the divergence table licenses — each edit citing its row |
| `docs/migration/restlet/phase-5d-1.md`, `plan.md` | as-built, the byte-diff record, the audit-smoke diff, new divergence rows |

---

## Verification criteria

**5-E5:** ✅ **done 2026-08-04** — [as-built](#as-built-5-e5--recorded-2026-08-04).
1. ~~`npx playwright test oauth2 uma` in **one pass** on a freshly built container ⇒ **99 + new rows**, all
   green, against unmodified Restlet. Zero main-source lines changed.~~ **113 passed** (99 + 14), one pass on
   a freshly recreated `openam-e2e:5e5`; zero main-source lines.
2. ~~Every new row's recorded value pasted into this doc's as-built (the values, not "green").~~ done —
   [the recorded rows](#the-recorded-rows) plus [six corrections](#six-corrections-to-this-plan) to this plan.

**5d-1a:**
3. `mvn -o -pl openam-http test` — baseline **73** surefire (measured green 2026-07-30); must only grow.
4. `mvn -o -pl openam-http install -DskipTests`, then
   `mvn -o -pl openam-rest,openam-oauth2,openam-uma,openam-entitlements,openam-core-rest test` — every other
   `Endpoints.from` consumer, unchanged. ⚠ Plus a **live** `HEAD` smoke on the three endpoints
   [finding 6](#6--head-after-the-fix-lands-on-code-paths-that-are-already-correct) says start answering
   (`/json/api`, `/xacml/policies`, `/uma/.well-known/uma-configuration`): each must return the same status
   and headers as its `GET`, and `/json/authenticate` must still 405.
5. `mvn -o install -DskipTests` whole reactor (**doclint is fatal**).

**5d-1b:**
6. `mvn -o -pl openam-oauth2 test` — **1281** surefire baseline, must only grow. ⚠ Not 1274: that was 5c-2's
   number *before* its own review added seven `resource_set` rows
   ([5c as-built](phase-5c.md#as-built-5-e4--recorded-2026-07-29): *"**1281** surefire (was 1274), 38
   failsafe"*). Baselining on 1274 would let those seven vanish unnoticed.
7. `mvn -o -pl openam-oauth2 verify` — `OAuth2RouterIT` green; failsafe baseline **38**.
8. `grep -rn "org.restlet\|getCurrent()"` over the new main files → **0**.
9. **Whole build with `-am`:** `mvn -o install -pl openam-oauth2,openam-oauth2-saml2,openam-uma,openam-rest -am -DskipTests`
   (the `-am` avoids the [stale-SNAPSHOT trap](chf-patterns.md#11-build--test-notes-for-the-oauth2-request-re-plumb-phase-3a)).
10. **Cargo boot** (`mvn -pl openam-server verify -P integration-test`) — the only test that proves the
    production Guice graph builds ([finding 3](#3--the-provider-instantiates-all-15-handlers-when-the-router-is-built-and-that-router-is-the-whole-chf-servlets)).
11. **The full e2e suite** on a container built from this commit — `npx playwright test` (not just `oauth2 uma`):
    `/oauth2` must still behave exactly as Restlet (nothing has flipped), **and `/json`, `/xui`, `/xacml`,
    `/uma`, `/saml` must all still work** — that is the assertion that
    [finding 3](#3--the-provider-instantiates-all-15-handlers-when-the-router-is-built-and-that-router-is-the-whole-chf-servlets)
    demands and the reason this commit exists separately.

**5d-1c (the flip):**
12. Container rebuilt from this commit; `npx playwright test oauth2 uma` in one pass, then the full suite.
13. **The byte-diff.** Re-run every `(5-E*, live Restlet)` describe and compare to the pre-flip capture. The
    **only** rows allowed to differ are the ones in
    [expected divergences](plan.md#expected-divergences-at-the-flip) — including the new rows 14/15 this step
    adds. Every unmatched difference is a regression until proven otherwise; record the complete diff in the
    as-built.
14. **The audit smoke** — [D8](#d8)'s pre/post capture and field-by-field diff.
15. Cargo boot again (the WAR now maps `/oauth2` to `OpenAM`).
16. CI green on the `features/**` push — **9 legs**, exactly (`.github/workflows/build.yml:27-34`):
    ubuntu × JDK 11/17/21/25/26, plus macOS and Windows on 11 and 26. All nine run `mvn verify`, so
    `OAuth2RouterIT` runs on all nine; **only the five ubuntu legs add `-P integration-test`** (`:52-57`), so
    the Cargo boot of criterion 10 is an ubuntu-only signal.
17. **Soak green before 5d-2 is even planned.** 5d-2 deletes ~40 classes; it must not start until 13–16 are
    recorded.

⚠ **What "green" is not.** A green e2e run proves the rows that exist. The rows that do **not** exist —
non-root realms in production deployments, `?display=` variants beyond those recorded, load — are what the
one-line revert is for.

---

## Integration testing

Three layers, per [test-infrastructure.md](../../test-infrastructure.md)'s cost model:

1. **Layer 2 — `OAuth2RouterIT`** ([D9](#d9)): the real provider, real filters, real routing, mocked
   collaborators. Runs on all 9 CI legs (`verify`). It is the only guard that can fail *before* a container is
   built, and the only one that pins the route **table** as a table.
2. **Layer 3 — Cargo boot**: proves the production Guice graph constructs. Asserts no behaviour.
3. **Layer 4 — e2e**: the 99 existing rows + 5-E5's, run pre-flip (as oracle) and post-flip (as regression
   net). This is the step's primary evidence.

The five existing composition ITs (`OAuth2ErrorRouteCompositionIT`, `OAuth2AuditRouteCompositionIT`,
`AuthorizeRouteCompositionIT`, `DeviceCodeRouteCompositionIT`, `ResourceSetRouteCompositionIT`) stay as they
are: they pin *handler-plus-chain* behaviour, and `OAuth2RouterIT` pins the *provider*. Neither subsumes the
other — 5c's own IT says so in its class javadoc.

---

## Risk register (extends [phase-5-oauth2](phase-5-oauth2.md#risk-register-extends-planmds--phase-4s)'s)

- **R-5d1.1 — the route provider breaks `/json`.** [Finding 3](#3--the-provider-instantiates-all-15-handlers-when-the-router-is-built-and-that-router-is-the-whole-chf-servlets):
  one bad binding aborts the whole CHF router. **Guard:** 5d-1b is its own commit; criteria 10 + 11 run the
  full e2e with `/oauth2` still on Restlet, so the failure surfaces with the wire unchanged.
- **R-5d1.2 — the oracle expires mid-step.** 5-E5 must land before 5d-1c, and any question raised during
  5d-1b's review that only live Restlet can answer must be asked **before** the flip commit, not after.
  **Guard:** the step order, and checklist step 13, which re-reads the open questions immediately before the
  flip commit.
- **R-5d1.3 — a transcription slip in the 18-row table.** A missing route is a 404 in production; a wrong
  auditor is a silently missing audit field. **Guard:** probe rows per attachment + [D3](#d3)'s field-list
  assertions.
- **R-5d1.4 — the no-cache filter drifts to the root.** It would widen `no-store` onto endpoints that never
  had it, invisibly. **Guard:** [D1](#d1)'s negative row.
- **R-5d1.5 — `HEAD` activates untested handler paths, on `/oauth2` *and* beyond it.** Mitigated by
  [finding 6](#6--head-after-the-fix-lands-on-code-paths-that-are-already-correct)'s per-endpoint check, but
  `/authorize`'s `HEAD` genuinely issues authorizations and `/xacml/policies`' `HEAD` serialises every policy
  in the realm. **Guard:** 5-E5 row 5 records what Restlet does *first* (if it 405s, the fix must too — it
  does not, per the disassembly, but the row decides), and criterion 4's live `HEAD` smoke covers the three
  non-OAuth2 endpoints.
- **R-5d1.6 — realm-style parity.** [Finding 9](#9--realm-resolution-is-a-different-implementation-and-its-oauth2-behaviour-is-unrecorded):
  two different implementations, one of which dies at the flip. **Guard:** 5-E5 rows 1–4 + `OAuth2RouterIT`'s
  realm rows.
- **R-5d1.7 — the revert is not actually one line.** If 5d-1c accretes a "small fix", the lever breaks.
  **Guard:** [D6](#d6), enforced by review of the commit's file list.
- ✅ **R-5d1.8 — DISCHARGED 2026-08-04.** [5-E5 row 13](#the-recorded-rows) measured it: a trailing slash is a
  404 on every endpoint, in both spellings of the 404, so [D1](#d1)'s flat `EQUALS` table is right and only
  `resource_set` needs [D2](#d2)'s nested shape. The original entry follows.
- **R-5d1.8 — the trailing-slash shape could be wrong for 14 endpoints.** CHF `EQUALS` cannot match a URI
  ending in `/`. Disassembly says Restlet cannot either — **for these rows**: `attach` derives the mode from
  the target (`getMatchingMode`), and each endpoint's target chain ends in a `Finder`, so it stays
  `MODE_EQUALS` (whole-string `Matcher.matches()`) even though `/realms/{realmId}`, a `Router` target, is
  `STARTS_WITH`. Reading the source adds a second, independent reason to expect a 404:
  the miss falls to `/{subrealm}` and fails a realm lookup
  ([finding 8](#8--an-unrouted-oauth2-path-is-a-bodiless-404-on-chf)). So [D1](#d1)'s flat table should be
  right — but both are inferences about a URL no test has ever sent. **Guard:** 5-E5 row 13, written
  **first**, because it is the only gate row whose answer can change the provider's design rather than a
  divergence table.
- ⚠ **R-5d1.9 — DOWNGRADED 2026-08-04.** [5-E5 row 14](#the-recorded-rows) found that `/oauth2/realms/root/…`
  does **not** work today under an unrecognised `Host` — it is a 500, like every other `/oauth2` URL — so the
  flip changes 500 → 400 rather than breaking a working integration. The release-note line stays (the status
  changes, and the FQDN-map test is genuinely new); "most likely to surface in someone else's deployment" no
  longer holds. Original entry:
- **R-5d1.9 — an unknown `Host` starts failing.** [Finding 16](#16--the-flip-adds-host-validation-to-oauth2-that-restlet-never-did):
  `/oauth2/realms/root/…` under a `Host` that is not a realm alias works today and 400s after the flip, and
  `/oauth2/…` gains a strict FQDN-map test it never had. **No e2e row can catch this** — the suite always uses
  the container's own hostname — so the guard is 5-E5 row 14 (record both stacks), a release-note line, and
  the [cutover lever](decisions.md#cutover-lever). ⚠ This is the risk most likely to surface in someone
  else's deployment rather than in CI, which is exactly why it is written down rather than tested.

---

## Checklist

**5-E5** — ✅ **all four done 2026-08-04**, [as-built](#as-built-5-e5--recorded-2026-08-04)

1. ~~Build the container from this tree (`openam-e2e:5e5`)~~ — built; deployed `openam-oauth2` jar
   md5-matched against the working tree's (`d03a404db1a56057c4eb1a12529717d3`), banner ignored.
2. ~~Write the 14 rows by observation; fixture for the row-3 sub-realm, with teardown.~~ — 14 rows, sub-realm
   created and deleted per run.
3. ~~`npx playwright test oauth2 uma` in one pass~~ — **113 passed**.
4. ~~If a row overturns [D4](#d4) or [D5](#d5), update the decision…~~ — **five did**: [D4](#d4) gains the
   `/authorize` `HEAD` guard and the widened `PATCH` row, [D5](#d5) loses its parity claim, [D11](#d11) is
   settled and split in three, [D1](#d1)'s flat table is **confirmed** by row 13 (run first, as instructed —
   a trailing slash is a 404 on every endpoint), and findings 6, 8, 15 and 16 carry ⚠ corrections.

**5d-1a**

5. `Endpoints.from`: `HEAD` mapping + `Allow` stamping; `AnnotatedMethod.isSupported()`.
6. Six `EndpointsTest` rows (criterion 3's list). Mutation-check: revert the `HEAD` line, the `HEAD` rows must
   go red; revert the `Allow` line, the `Allow` rows must go red.
7. Criteria 3–5 green; decisions.md + openam-http-framework.md updated; commit.

**5d-1b**

8. `OAuth2NotFoundHandler` + test; `errorFor`'s `case 404`; then the **two deliberate pin edits**
   ([D5](#d5)'s table) — `OAuth2ErrorFilterTest:114` and `ResourceSetRouteCompositionIT` row 9, the latter
   keeping its counterfactual.
9. `OAuth2HttpRouteProvider` — the 18 attachments, the audit matrix copied from
   [finding 2](#2--the-route-table-is-18-attachments-and-7-distinct-auditor-pairs-lift-both-verbatim) with the
   `file:line` citation in a comment, [D2](#d2)'s nested router, [D7](#d7)'s eleven invalid realm names.
10. `META-INF/services` append.
11. `OAuth2RouterIT` — probe rows first (they need no stubbing and immediately verify the table), then the
    deep rows.
12. Criteria 6–11 green; commit.

**5d-1c**

13. Re-read every open question in this doc; anything still needing live Restlet stops the flip.
14. Enable audit + capture the pre-flip audit artefact ([D8](#d8) steps 1–3).
15. Move the one web.xml line. Nothing else in the commit.
16. Rebuild the container; criteria 12–16.
17. Write the as-built: the byte-diff, the audit diff, the new divergence rows, the answers to 5-E4 rows 15/17,
    and the `HEAD` `Content-Length` measurement ([finding 7](#7--content-length-on-a-head-is-tomcats-decision)).
18. Update [plan.md](plan.md): 5d-1 row → done, the stale "hook re-sign" text
    ([finding 1](#1--the-hook-re-sign-is-already-done)) removed, divergence rows 14/15 added.

---

## Divergence rows this step adds to [plan.md](plan.md)

Drafted here so the flip's operator has them before the diff, not after. The first two are *decided*, not
discovered — they follow from [D4](#d4) and [D5](#d5) and no measurement can change them:

| # | What differs | Restlet | CHF | Why |
|---|---|---|---|---|
| 14 | `PATCH /oauth2/resource_set/{rsid}` | routed to the `@Put` method: a working **full replace**, 200 + new `ETag` ([5-E4 row 11](phase-5c.md#as-built-5-e4--recorded-2026-07-29)) | **405** `{"error":"unsupported_method_type"}` + `Allow: …` | [D4](#d4) — aliasing `PATCH` to `PUT` in `Endpoints.from` would impose RFC 5789-wrong full-replace `PATCH` on every CHF endpoint with a `@Put`. Scoped to `resource_set`: it is the only ported endpoint with a `@Put`. ⚠ **The body byte-diff shows nothing** — the 405 shape is identical to the one [D3](phase-5c.md#d3) already produces for `OPTIONS`/`PROPFIND`. Only the *verb's* outcome changed |
| 15 | The two routing-layer failures that stay **404** on both stacks — an unrouted path, and `/oauth2/realms/<bogus>/…` | unrouted path: 404 **CREST** naming a realm lookup — `{"code":404,"reason":"Not Found","message":"No mapping organization found for organization identifier: /resource_set"}` ([5-E4 row 17](phase-5c.md#as-built-5-e4--recorded-2026-07-29)), because Restlet's `/oauth2` router consumes any unmatched element as a sub-realm ([finding 8](#8--an-unrouted-oauth2-path-is-a-bodiless-404-on-chf)). Unknown realm: 404 CREST `{"code":404,…,"message":"Realm \"bogus\" not found"}` (`RealmRoutingFactory`'s inner `RestletRealmRouter:254-257`; **confirmed by 5-E5 row 4**) | `{"error":"not_found","error_description":…}` for both — the endpoint router's default route for the path case ([D5](#d5)), `ChfRealmRouter`'s CREST 404 rewritten by `errorFor`'s new `case 404` for the realm case | [D5](#d5). **Status is preserved; only the shape moves.** For the realm case even the `error_description` is byte-identical to Restlet's `message`. For the path case parity is unavailable — CHF's realm filter breaks out rather than looking the element up, so Restlet's message has no counterpart, and commons' `Router` would otherwise answer a **bodiless** 404 |

Two further rows are **provisional**: the source says they will be needed, but each is licensed only by its
5-E5 measurement, and if the measurement contradicts the source the *measurement* wins.

| # | What differs | Restlet (predicted from source) | CHF | Why |
|---|---|---|---|---|
| 16 ⚠ *provisional, confirmed or dropped by [5-E5](#5-e5--the-last-gate) row 2* | `?realm=<bogus>` on any `/oauth2` endpoint | **404** `{"code":404,…,"message":"Realm \"bogus\" not found"}` — `RestletRealmRouter:86-90` → `:102-104` | **400** `{"error":"invalid_request","error_description":"Invalid realm, bogus"}` — `RealmContextFilter:255-257` | The two realm layers classify the same failure differently: Restlet as *not found*, CHF as *bad request*. Not worth "fixing" in `RealmContextFilter`, which `/json` has depended on since 14.0 — but a client that branches on 404 sees a 400 |
| 17 ⚠ *provisional, confirmed or dropped by [5-E5](#5-e5--the-last-gate) row 14* | A request whose `Host` OpenAM does not know | `/oauth2/realms/root/…` **works**; `/oauth2/…` **500** | **400** for both — `HostnameFilter:123-131` and `RealmContextFilter:229-231` | [Finding 16](#16--the-flip-adds-host-validation-to-oauth2-that-restlet-never-did). The only row here that can break a deployment that works today, and therefore the one that needs a release-note line rather than just a table entry |

All four rows are added to the table **in 5d-1c's commit**, with the measured bytes rather than these drafts.
⚠ Rows 16 and 17 have since been **measured** — see the [5-E5 as-built](#as-built-5-e5--recorded-2026-08-04),
which confirms 16's status while correcting its body, **rewrites 17**, and adds four more.

---

<a id="as-built-5-e5--recorded-2026-08-04"></a>
## As-built — 5-E5, recorded 2026-08-04 (test-only)

Captured against a live container built from this tree: `openam-e2e:5e5` (the repo
`openam-distribution/openam-distribution-docker/Dockerfile` with its three `#COPY` lines uncommented, exactly
CI's `build-docker` sed) over a full `mvn install -DskipTests` of the working tree, plus
`openidentityplatform/opendj:latest` on the `test-openam` network, configured with CI's `conf.file`. Restlet
still serves `/oauth2`: `web.xml:1143-1146` is unchanged and no CHF `HttpRouteProvider` claims those paths.

Provenance was checked by **md5 of the deployed jar**, not the banner (5-E4's lesson):
`WEB-INF/lib/openam-oauth2-16.2.0-SNAPSHOT.jar` = `d03a404db1a56057c4eb1a12529717d3` = this working tree's
`openam-oauth2/target/openam-oauth2-16.2.0-SNAPSHOT.jar`. (`openam-restlet` likewise.)

**Deliverables — e2e only, zero main-source lines:**

| File | Change |
|---|---|
| `e2e/oauth2/oauth2-test.spec.mjs` | new describe `/oauth2 routing contract lock (5-E5, live Restlet)` — **14 rows**, plus a `node:http` raw client for the three things Playwright cannot express (a `Host` that does not match the connection, path bytes a normalising client would rewrite, and `PROPFIND`/`PATCH`), and a sub-realm fixture created through `/json/global-config/realms` and deleted in `afterAll`. ⚠ The realm's resource id is **base64url of the realm PATH** (`/e2e5e5realm` → `L2UyZTVlNXJlYWxt`), not its name — a `DELETE …/realms/%2Fe2e5e5realm` answers 400 |

`npx playwright test oauth2 uma`, **one pass on a freshly recreated container**: **113 passed** (1.4 min) —
99 + 14, with `oauth2-test` going **23 → 37** and `oauth2-endpoints` 43, `oidc` 20, `webfinger` 2, `uma` 11 all
unchanged. No existing row edited, no fixture changed.

### The recorded rows

| # | Request | Recorded |
|---|---|---|
| 13 | `/oauth2/tokeninfo/`, `/oauth2/Tokeninfo`, `/oauth2/TOKENINFO`, `/oauth2//tokeninfo` | **404**, and the **router** 404 — `{"code":404,"reason":"Not Found","message":"The server has not found anything matching the request URI"}`. Two-segment endpoints answer the **realm** 404 instead: `/oauth2/connect/jwk_uri/` → `…"message":"No mapping organization found for organization identifier: /connect"`, `/oauth2/.well-known/openid-configuration/` → `…: /.well-known`, `/oauth2/Connect/jwk_uri` → `…: /Connect`. Routing is **case-sensitive**. `/oauth2/resource_set/` still answers (401 `invalid_token`) — it is the one endpoint attached three times. ⇒ **[D1](#d1)'s flat `EQUALS` table stands**; no endpoint needs [D2](#d2)'s nested shape |
| 1 | `?realm=/`, `?realm=%2F` on `/tokeninfo`; `?realm=<sub>` on `/.well-known/openid-configuration`; `?realm=bogus` on an unrouted path | **200** for both spellings of root. The override really **switches** realm: `?realm=e2e5e5realm` → **404** `{"error":"not_found","error_description":"No OpenID Connect provider for realm /e2e5e5realm"}`, and `?realm=/e2e5e5realm` is identical (the leading slash is optional). ⚠ On a path that matched **no** endpoint the override is **not applied at all** — `/oauth2/nosuchendpoint?realm=bogus` is the plain router 404, not a realm error, which is `RestletRealmRouter:86`'s `next != delegateRoute` guard on the wire |
| 2 | `?realm=bogus` on `/tokeninfo` and on `POST /access_token` | **404** `{"code":404,"reason":"Not Found","message":"No mapping organization found for organization identifier: bogus"}`, identical for both, and with **no `Cache-Control`/`Pragma`** even on `/access_token` — the realm layer answers above the `OAuth2Filter`. ⇒ divergence row 16's **status** is confirmed (404 here, 400 on CHF); its **body** is corrected, see [correction 3](#5-e5-correction-3) |
| 3 | `/oauth2/<sub>/tokeninfo`, `/oauth2/<sub>/.well-known/openid-configuration`, and the same with `?realm=/` | The legacy style **resolves, and resolves to the sub-realm**: the discovery document answers **404** `No OpenID Connect provider for realm /e2e5e5realm`, while `/tokeninfo` under the same prefix answers **200**. `?realm=/` on top of a legacy prefix **replaces** it — 200, `issuer` = the root issuer |
| 4 | `/oauth2/realms/root/tokeninfo`, `/realms/bogus/tokeninfo`, **flat `/realms/<sub>/…`**, nested `/realms/root/realms/<sub>/…` | root → **200**; bogus → **404** `…"message":"No mapping organization found for organization identifier: /bogus"` (note the **leading slash**, where row 2's is bare); ⚠ **flat `/realms/<sub>/…` is SERVED, in the sub-realm** — 404 `No OpenID Connect provider for realm /e2e5e5realm`, the endpoint's own answer — and the nested spelling is identical. ⇒ [correction 1](#5-e5-correction-1) |
| 5 | `HEAD` on `/tokeninfo`, `/.well-known/openid-configuration`, `/connect/jwk_uri`, `/authorize`, `/access_token` | The first three: **200**, the `GET`'s exact `Content-Type` (`application/json` on `/tokeninfo`, `application/json;charset=UTF-8` on the other two), `/tokeninfo`'s `no-cache, no-store` intact, and **no `Content-Length`** on any of them (as 5-E4 row 15 recorded for `resource_set` — so [finding 7](#7--content-length-on-a-head-is-tomcats-decision)'s Restlet half is answered; what *Tomcat* does behind CHF is still 5d-1c's to measure). ⚠ `/authorize` and `/access_token`: **405**. A `HEAD` carrying a complete, authenticated, valid authorization request is a 405 while the byte-identical `GET` is a **302 with an issued code**. ⇒ [correction 2](#5-e5-correction-2). ⚠ Also: a `HEAD` that ends in an **error** status sends `text/html;charset=utf-8` **with** a `Content-Length` (401 → 721 B, 404 → 714 B, 405 → 726 B, 400 → 796 B) instead of the `application/json` body its `GET` sends |
| 6 | `PROPFIND` / `PUT` on `/tokeninfo` and `/connect/jwk_uri`; `PROPFIND` on `/access_token` and `/authorize` | Two producers, two shapes. The **resource**: 405 + **`Allow: GET`** + the CREST body `{"code":405,"reason":"Method Not Allowed","message":"The method specified in the request is not allowed for the resource identified by the request URI"}`, no cache headers. The **endpoint filter**: 405 + `{"error":"method_not_allowed","error_description":"Required Method: POST found: PROPFIND"}` (`/authorize`: `"Required Method: GET or POST found: PROPFIND"`) + `no-store`/`no-cache` and **no `Allow` at all**. ⇒ [D4](#d4)'s `Allow` list is **per endpoint** — `GET` here, not `resource_set`'s four |
| 7 | `PATCH` on `/tokeninfo` (with and without a token), `/connect/jwk_uri`, `/access_token` | ⚠ **`PATCH` runs the resource's `@Get` first and only then 405s.** With a valid token: 405 + `Allow: GET` + the CREST body — **carrying `Cache-Control: no-cache, no-store`, which only `ValidationServerResource.validate()` sets**. Without a token: **401 `invalid_token`** — the `@Get`'s own error, no 405 at all. A `PUT` on the same URL is a 405 with **no** cache headers, i.e. it does not run the `@Get`. On the method-filtered endpoints the filter refuses first: `{"error":"method_not_allowed","error_description":"Required Method: POST found: PATCH"}`. ⇒ [correction 4](#5-e5-correction-4) |
| 8 | `?_api`, `?_crestapi` | **Ignored**. `/connect/jwk_uri?_api` and `?_crestapi` are **byte-identical** to the plain `GET` (asserted as a body comparison, not a status); `/tokeninfo?_api` with a token is a normal 200 |
| 9 | `OPTIONS /oauth2/authorize` with and without an `Origin`; `OPTIONS /tokeninfo` | **405** `{"error":"method_not_allowed","error_description":"Required Method: GET or POST found: OPTIONS"}`, and **not one `Access-Control-*` header** in either case — the `web.xml` `CORSFilter` is unconfigured on this deployment and contributes nothing. On an endpoint with no method filter, `OPTIONS` is the same CREST 405 + `Allow: GET` as any other unmapped verb: Restlet does **not** answer `OPTIONS` automatically |
| 10 | `X-HTTP-Method-Override` and `?method=` | ⚠ Three answers, not two. **(a)** the header on a **POST** is **honoured** — `POST /access_token` + `X-HTTP-Method-Override: GET` → 405 `Required Method: POST found: GET` (the same request without it → 200 + a token), and `POST /tokeninfo` + override `GET` → **200**. **(b)** the header on a **non-POST** is *also* honoured — `GET /tokeninfo` + override `PUT` → **405**. **(c)** Restlet's own `?method=` query tunnel is live, **POST-only** — `POST /access_token?method=GET` → 405 `…found: GET`, while `GET /tokeninfo?method=PUT` → **200**. ⇒ [D11](#d11) settles, [correction 5](#5-e5-correction-5) |
| 11 | `/oauth2/nosuchendpoint`, `/oauth2/authorize/extra`, `/oauth2/connect/nosuch`, `/oauth2/realms/root/nosuch` | All **404 `application/json`**, from **two** producers by segment count: one element below `/oauth2` → the **router** 404; two → the **realm** 404 naming the first (`/authorize`, `/connect`). `/realms/root/nosuch` is a router 404 — the realm route consumed both leading elements |
| 12 | `GET /oauth2/`, `GET /oauth2`, `/oauth2/realms`, `/oauth2/realms/root` | **404**, the router's, for all four. The bare prefix is where `/{subrealm}` has nothing to bind |
| 14 | An unknown `Host` on `/oauth2/tokeninfo`, `/oauth2/realms/root/tokeninfo` and `/oauth2/.well-known/openid-configuration` | ⚠ **500** for **all three** — `{"code":500,"reason":"Internal Server Error","message":"No mapping organization found for organization identifier: not-a-real-host.invalid"}`. The realm-prefixed form does **not** work today. An IP-literal `Host` behaves the same; `Host:` without a port works. ⇒ [correction 6](#5-e5-correction-6), and divergence row 17 is rewritten |

<a id="5-e5-the-one-mechanism"></a>
### One mechanism explains rows 4, 13 and 14

`Router.doHandle` runs **before** the matched route's template is parsed, so `RestletRealmRouter.doHandle`
never sees the attributes the *current* route will set — only what an earlier pass left behind. Everything
surprising above follows from that:

- **row 13 / row 11.** One unmatched element is consumed by `/{subrealm}` (`MODE_STARTS_WITH`), leaving an
  **empty** remaining URI that matches no route at all on the recursive pass — so `doHandle` never runs again
  and Restlet's own router 404 surfaces. With **two** elements the recursion re-enters with a non-empty URI,
  `subrealm` is set from the first pass, and the realm lookup fails instead. ⇒
  [finding 8](#8--an-unrouted-oauth2-path-is-a-bodiless-404-on-chf) is right about the mechanism and wrong
  about the reach: it predicted a realm 404 for `/oauth2/tokeninfo/`, which is a **router** 404.
- **row 4.** `realmId` is set by the `/realms/{realmId}` template, i.e. after the outer `doHandle` has already
  resolved the host and stored `REALM_OBJECT` — so the inner router's "root or an existing `REALM_OBJECT`"
  guard is *always* satisfied and a flat `realms/<non-root>` resolves.
- **row 14.** The same ordering means `doHandle:75-78`'s `realmId` short-circuit **cannot fire on the first
  pass**, so `getRealmFromServerName` runs on every request, whatever the URL style.

And the wire message of every realm failure is the **cause's**, not the router's:
`RestStatusService.toRepresentation:42-52` renders `status.getThrowable().getMessage()` whenever a throwable is
present, so `RestletRealmRouter:102-104`'s `"Realm \"" + x + "\" not found"` — which
[finding 15](#15--the-realm-layer-has-its-own-404-and-400-and-they-are-crest-shaped) quotes for rows a and d —
is a `Status` *description* that never reaches a client.

### Six corrections to this plan

<a id="5-e5-correction-1"></a>
**1. A flat `/oauth2/realms/<non-root>/…` works on Restlet too.** [The 5-E5 brief](#5-e5--the-last-gate)'s row 4
predicted a Restlet 404 and a CHF **capability gain** worth recording. There is no gain and no divergence —
both stacks serve it, in the sub-realm. Had it gone unmeasured, the byte diff would have read as a regression
in reverse.

<a id="5-e5-correction-2"></a>
**2. ⚠ `HEAD /oauth2/authorize` does *not* run the authorization flow.**
[Finding 6](#6--head-after-the-fix-lands-on-code-paths-that-are-already-correct) states that it "runs the real
authorization flow — including … on success, a 302 with an issued code. Restlet did precisely the same". It
does not: `AuthorizeEndpointFilter.validateMethod` accepts `GET` and `POST` only, and Restlet's `HEAD` → `GET`
rewrite happens at **annotation lookup**, *inside* the resource and *below* that filter — so the filter sees a
`HEAD` and answers 405. Measured with a complete, authenticated, valid request: `HEAD` → **405**, the
byte-identical `GET` → **302 with a code**. `/access_token` is a 405 on both verbs, so only `/authorize` moves.
⇒ [D4](#d4) is updated: `Endpoints.from` still maps `HEAD` → `@Get`, and `AuthorizeHandler` must refuse `HEAD`
explicitly so the incumbent 405 survives.

<a id="5-e5-correction-3"></a>
**3. The realm 404's message is `No mapping organization found for organization identifier: X`.**
[Finding 15](#15--the-realm-layer-has-its-own-404-and-400-and-they-are-crest-shaped) rows a and d quote
`Realm "bogus" not found` for the Restlet side, and [D5](#d5) builds a near-byte-parity argument for divergence
row 15 on it (*"even the `error_description` is byte-identical to Restlet's `message`"*). It is not: see
[the mechanism above](#5-e5-the-one-mechanism). The identifier is spelled **`bogus`** for a `?realm=` override
and **`/bogus`** for `realms/<bogus>`. `case 404 → not_found` is still right — it keeps `/oauth2`'s 404
vocabulary consistent — but it buys **consistency only**, not parity, and D5's parity sentence is struck.

<a id="5-e5-correction-4"></a>
**4. `PATCH` is wider than `resource_set`, and it has a side effect.** [D4](#d4) scopes divergence row 14 to
`resource_set` because it is the only ported endpoint with a `@Put`. That is true of the *200*, but Restlet
runs the resource's `@Get` for **every** `PATCH` before looking for a handler — so on a `@Get`-only endpoint
the `@Get`'s errors are what reach the wire (`PATCH /oauth2/tokeninfo` without a token is a **401**, not a
405) and its side effects happen (the 405 carries `/tokeninfo`'s own cache directives). On CHF, `PATCH` is an
unmapped verb everywhere: a flat 405 that runs nothing. Divergence row 14 is widened rather than re-scoped.

<a id="5-e5-correction-5"></a>
**5. [D11](#d11) settles — and splits.** Restlet **honours** `X-HTTP-Method-Override`, so its first branch
applies and there is nothing to do for the POST case. But `Endpoints.getMethod:119-126` gates the rewrite on
`"POST".equals(method)`, and Restlet does not, and Restlet additionally honours the `?method=` **query** tunnel
on a POST, which CHF has no equivalent for. Two new divergences, both changing a **405 into a 200**:
`GET …?…` + `X-HTTP-Method-Override: PUT`, and `POST /oauth2/access_token?method=GET` — the second of which
starts **issuing tokens** for a request that is refused today. Neither is a reason to change `Endpoints`
(the header is shared with `/json`, and the query tunnel is a Restlet service nothing else implements), so both
are recorded.

<a id="5-e5-correction-6"></a>
**6. ⚠ An unknown `Host` does not work on either URL style today.**
[Finding 16](#16--the-flip-adds-host-validation-to-oauth2-that-restlet-never-did) predicted
`/oauth2/realms/root/…` **works** under an unrecognised `Host` and would start 400ing — *"the only row here
that can break a deployment that works today"*. Measured, it is a **500**, exactly like the bare-path form.
⇒ divergence row 17 becomes **500 → 400 on both styles**: a better answer to a request that already fails, not
a working integration breaking. [R-5d1.9](#risk-register-extends-phase-5-oauth2s) keeps its release-note line
(the *status* still changes, and the FQDN-map test is genuinely new) but is no longer the step's most dangerous
row. The `FQDNValidationFilter` redirect on `/oauth2/authorize` is unaffected either way.

### Divergence rows this gate hands to 5d-1c

Added to [plan.md](plan.md#expected-divergences-at-the-flip) with measured bytes **in 5d-1c's commit**, not now:

| # | What differs | Restlet (measured 2026-08-04) | CHF (expected) |
|---|---|---|---|
| 16 | `?realm=<bogus>` | **404** `{"code":404,…,"message":"No mapping organization found for organization identifier: bogus"}`, no cache headers | **400** `{"error":"invalid_request","error_description":"Invalid realm, bogus"}` |
| 17 *(rewritten)* | an unknown request `Host`, **both** URL styles | **500** `{"code":500,…,"message":"No mapping organization found for organization identifier: <host>"}` | **400** — `HostnameFilter:123-131` / `RealmContextFilter:229-231` |
| 18 | `HEAD` on an endpoint whose answer is an **error** | the JSON body and `Content-Type` are replaced by `text/html;charset=utf-8` **plus** a `Content-Length` (401 → 721 B, 404 → 714 B, 405 → 726 B, 400 → 796 B) | the `GET`'s `Content-Type`, no `Content-Length`. Not a prediction: the same probe against a CHF path (`HEAD /openam/json/nosuchthing`) answers **501 `application/json;charset=UTF-8`**, no length, no HTML — so the substitution is the Restlet stack's, and it goes away with it |
| 19 | `HEAD /oauth2/authorize` | **405** | **405**, *provided* [correction 2](#5-e5-correction-2)'s guard lands in 5d-1a; without it, a 302 **issuing an authorization code** |
| 20 | the method tunnel beyond `POST` + header | `GET …` + `X-HTTP-Method-Override: PUT` → **405**; `POST /access_token?method=GET` → **405** | **200** for both — the override is ignored on a non-POST, and `?method=` is not implemented |
| 14 *(widened)* | `PATCH` on a `@Get`-only endpoint | the `@Get` runs first: **401** `invalid_token` on `/tokeninfo` with no token; 405 + `Allow: GET` + `Cache-Control: no-cache, no-store` with one | **405**, nothing run |

---

## Handed to 5d-2

Recorded here so the deletion step reads one list:

1. **The Restlet hook interfaces** — `TokenRequestHook`, `AuthorizeRequestHook`, and `LoginHintHook`'s two
   Restlet methods ([finding 1](#1--the-hook-re-sign-is-already-done)); the CHF halves stay.
2. **`ForgeRockRest`** — after 5d-1c it is a declared servlet with **no mapping**
   ([finding 12](#12--the-webxml-change-is-one-line-and-oauth2-is-forgerockrests-last-mapping)); delete the
   declaration with the stack.
3. **`OAuth2RouterProvider` + `OAuth2RestGuiceModule`'s `@Named("OAuth2Router")` + `OAuth2GuiceModule`'s
   `@Named(RSR_ENDPOINT)` `Restlet` provider** — the last references to the Restlet OAuth2 chain
   ([5c finding 15](phase-5c.md#15-5d-2-must-also-delete-the-guice-provider-not-just-the-classes)).
4. **`org.forgerock.oauth2.restlet.resources` is not wholly deletable** — two of its three classes are
   Restlet-free and used by openam-uma
   ([5c finding 8](phase-5c.md#8--the-restlet-resources-package-is-not-deletable-at-5d-2)).
5. ⚠ **Two classes are called `RestletRealmRouter`.** The deprecated
   `org.forgerock.openam.rest.service.RestletRealmRouter` (openam-restlet) is the outer `/oauth2` router
   (`OAuth2RouterProvider:95`) and goes with the stack; `RealmRoutingFactory`'s private inner class of the
   same name (`openam-rest`, `:232-290`) backs `createRouter(org.restlet.routing.Router)` and must **survive**
   5d-2 — it is `RealmRoutingFactory`'s Restlet overload, and other Restlet consumers still call it. Deleting
   by simple name would take the wrong one
   ([finding 15](#15--the-realm-layer-has-its-own-404-and-400-and-they-are-crest-shaped)).
6. **The golden/parity tests degrade to `golden == CHF`** when the Restlet leg goes
   ([risk #19](plan.md#risk-register-behavioral-compatibility)) — expected, and the reason 5d-2 waits for a
   green soak.
