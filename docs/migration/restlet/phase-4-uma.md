# Phase 4 — UMA `/uma` → CHF: Detailed Implementation Plan

Detailed execution plan for **Phase 4** of the Restlet → CHF migration. Parent tracker:
[plan.md](plan.md); research: [inventory.md](inventory.md); decisions: [decisions.md](decisions.md);
reusable CHF patterns: [chf-patterns.md](chf-patterns.md); the pattern this phase copies:
[phase-2-xacml.md](phase-2-xacml.md) + [phase-2-integration-tests.md](phase-2-integration-tests.md);
predecessors this phase consumes: [phase-3a-oauth2request.md](phase-3a-oauth2request.md) (the neutral
`OAuth2Request`), [phase-3d-audit.md](phase-3d-audit.md) (the CHF UMA audit filter + body auditors),
[phase-3c-2-error-layer.md](phase-3c-2-error-layer.md) (`OAuth2ErrorFilter`, deliberately **not** reused
here — finding 1); test layers: [../../test-infrastructure.md](../../test-infrastructure.md). Written
2026-07-23; branch `features/restlet-migration`. All facts below verified against the tree on 2026-07-23.

## Context

Phase 4 moves the `/uma/*` protocol endpoints off Restlet onto CHF. UMA is the second-smallest area
(after XACML) and the **first that couples to `OAuth2Request`** — which Phase 3 already made
transport-neutral, so the coupling is now a solved problem. The three protocol endpoints are all
JSON-in/JSON-out with **no HTML, no redirect, no 3xx** — the entire hard surface of OAuth2 (consent
pages, `redirect_uri` composition, form-post) is absent here. That makes `/uma` a **single atomic flip**
like XACML (Phase 2), not a build-ahead-then-flip like OAuth2 (Phase 5).

The `/uma` route table (from [inventory.md](inventory.md) §5), each route wrapped by
`UMAAccessAuditFilter` and — for the two protected endpoints — an `AccessTokenProtectionFilter`:

| Route | Endpoint | Auth | Verb |
|---|---|---|---|
| `/permission_request` | `PermissionRequestEndpoint` | PAT scope (`uma_protection`) | `@Post` → 201 `{ticket}` |
| `/authz_request` | `AuthorizationRequestEndpoint` | AAT scope (`uma_authorization`) | `@Post` → 200 `{rpt}` / 403 |
| `/.well-known/uma-configuration` | `UmaWellKnownConfigurationEndpoint` | **none (public)** | `@Get` → 200 JSON |

(UMA *policy management* is already CREST under `/json` — 21 files, `UmaRestRouteProvider` — and is **out
of scope**. Only these three Restlet protocol endpoints move.)

**Outcome:** `/uma/*` served natively by the `OpenAM` `HttpFrameworkServlet` via a new
`UmaHttpRouteProvider`; the three endpoints re-based from Restlet `ServerResource` onto `Endpoints.from`;
a shared CHF `ChfAccessTokenProtectionFilter` replacing the Restlet `AccessTokenProtectionFilter`; the
Restlet UMA router/application/exception-handler deleted; status codes, both error-body shapes, headers,
scope enforcement, and audit preserved.

## Scope & sizing — two sub-phases

Phase 4 splits into **4a** and **4b**, driven by *module boundary + risk profile* (the same rationale as
[3c-1/3c-2](phase-3c-2-error-layer.md) and [3d-1/3d-2](phase-3d-audit.md)):

- **4a — `ChfAccessTokenProtectionFilter` (openam-oauth2), build-ahead.** The shared bearer-token guard.
  It lives in openam-**oauth2** (not openam-uma) because **Phase 5c reuses it** for `resource_set`
  (the Restlet `AccessTokenProtectionFilter` is bound by *both* `UmaGuiceModule` and `OAuth2GuiceModule`
  — [inventory.md](inventory.md) §9). Wired to no route until 4b, so it is build-ahead: no live guard, its
  parity oracle is the Restlet `AccessTokenProtectionFilter` it copies. openam-uma resolves openam-oauth2
  from `~/.m2`, not the reactor ([chf-patterns.md](chf-patterns.md) §11), so 4a **must `install` before 4b
  compiles** — the two-commit rhythm is forced by the build, not just tidiness. 4a also seeds `"realmObject"`
  in `ChfOAuth2Request` (finding 6) — a second small build-ahead openam-oauth2 change carried on the same
  `install`, so Phase 4b's `authz_request` and all of Phase 5's OAuth2 uris resolution work under CHF.
- **4b — UMA endpoints + the flip (openam-uma, openam-rest, web.xml).** Re-base the three endpoints, add
  the exception mapper + route provider, retype the Guice bindings, move the `<servlet-mapping>`, delete
  the Restlet UMA classes, port the tests. This is the **live flip**; its guard is the new `UmaRouterIT`
  + the e2e smoke + the ported unit tests.

Sizing: ~6 new files (1 in 4a, 5 in 4b), ~7 modified (incl. `ChfOAuth2Request` in 4a), ~3–4 deleted,
~5 test files reworked + 1 new IT (+ the `ChfOAuth2RequestTest` seed assertion).
Comparable to Phase 2 XACML plus a protection filter and two extra endpoints — a normal two-PR unit. Land
as two commits (4a then 4b); keep them conceptually separate even if a reviewer folds them.

> **Deviation from [plan.md](plan.md)'s Phase 4 sketch, recorded here.** plan.md predates the F1–F4
> framework fixes and the 3c/3d as-builts. Two of its bullets are superseded:
> 1. *"`UmaExceptionHandler` → `UmaExceptionFilter` (CHF)"* — **a filter cannot do this** (finding 2). The
>    framework turns a thrown exception into a CREST **500** *before any filter sees it*, erasing the
>    exception's real status (400/403) and its UMA error code. A response-rewriting filter cannot recover
>    them. The port uses a per-endpoint **`@ExceptionHandler`** (real since F2), not a filter.
> 2. *"401 with `WWW-Authenticate: Bearer`"* — the Restlet filter sets **no** such header and emits a
>    **CREST** `{code,reason,message}` body, not `{error:"invalid_token"}` (finding 1). Reproduce that;
>    adding the header would be a behaviour change (D5).

## Key research findings (drove this design)

### 1. ⚠ `/uma` has **two** error-body shapes today, and they are on different paths

This is the load-bearing finding, confirmed end-to-end (including disassembling the in-repo Restlet
`StatusFilter`):

- **Endpoint business exceptions → UMA shape.** A `@Post`/`@Get` method throws `UmaException` /
  `OAuth2Exception` / anything; Restlet's `ServerResource.doCatch` calls `UmaExceptionHandler.handleException`,
  which **sets an entity** `{error, error_description, [detail…]}` and the exception's status. Because the
  entity is now non-null, the outer `StatusFilter` leaves it alone.
- **Protection-filter / framework errors → CREST shape.** `AccessTokenProtectionFilter.beforeHandle`
  rejects with `response.setStatus(new Status(401, new InvalidTokenException()))` and returns `STOP`,
  **never setting an entity**. The application's outer `StatusFilter.afterHandle` then sees an error
  status with a null entity and renders one via `JSONRestStatusService.toRepresentation` →
  `ResourceException.getException(code, throwable.getMessage()).toJsonValue()` =
  **`{code, reason, message}`** (`application/json`). The same path serves a wrong-verb 405 and any
  uncaught framework error. Crucially, because `OAuth2Exception` is **not** a CREST `ResourceException`,
  the OAuth2 `error` field (`"invalid_token"`, `"insufficient_scope"`) is **discarded** — today's UMA
  client sees `{"code":401,"reason":"Unauthorized","message":"The access token provided is expired,
  revoked, malformed, or invalid for other reasons."}`, **not** `{"error":"invalid_token"}`.

⇒ **Consequence for the design:** the two shapes map cleanly onto CHF *without any error filter*:

| Today (Restlet) | CHF reproduction |
|---|---|
| endpoint exception → UMA `{error,error_description,[detail]}` | endpoint `@ExceptionHandler` → same (finding 2) |
| protection-filter reject → CREST `{code,reason,message}` | `ChfAccessTokenProtectionFilter` builds the same CREST map (finding 3) |
| 405 / uncaught → CREST `{code,reason,message}` (StatusFilter) | `Endpoints.from`'s native 405/500 CREST body ([chf-patterns.md](chf-patterns.md) §2) — *identical shape* (the unmapped-verb 405 body made self-consistent by the finding 8 fix) |

⇒ **Do NOT put [`OAuth2ErrorFilter`](phase-3c-2-error-layer.md) (3c-2) on the `/uma` route.** It rewrites
any `≥400` CREST body (`{code,…}`) into OAuth2 `{error,…}` — which would corrupt UMA's CREST-shaped
protection-filter/framework errors into a shape they have never had. `/oauth2` wants that filter; `/uma`
does not. (This is why 3c-2 scoped `OAuth2ErrorFilter` to "the whole `/oauth2` application… **Not** for
`/json`" — `/uma` is in the same "leave CREST alone" bucket as `/json` for the framework-error path.)

### 2. `@ExceptionHandler` replaces `UmaExceptionHandler` — and dispatches on the *actual* thrown exception

The F2 fix made `@ExceptionHandler` real. `AnnotatedMethod.invoke` catches the method's
`InvocationTargetException` and passes **`e.getCause()`** — the exception the method actually threw —
to the handler (`AnnotatedMethod.java:101-103`). This is the key divergence from Restlet: today
`UmaExceptionHandler.handleException` reads **`throwable.getCause()`** because Restlet *wraps* the thrown
exception (proven by `UmaExceptionHandlerTest`, which stubs `throwable.getCause()`). On CHF **there is no
wrapper** — the handler receives the `UmaException`/`OAuth2Exception` directly. So the ported dispatch
runs on `t` itself, never `t.getCause()`.

`findExceptionHandlers` scans `requestHandler.getClass().getMethods()` (`AnnotatedMethod.java:233`), which
**includes inherited public methods**, so a single `@ExceptionHandler` declared on a shared base class is
discovered on every subclass that does not override it. That lets all three endpoints share **one** mapper
(⚠ they must **not** override it — Java does not carry an annotation onto an override,
[chf-patterns.md](chf-patterns.md) §2).

### 3. `ChfAccessTokenProtectionFilter` — a CHF `Filter`, reproducing the Restlet filter byte-for-byte

The Restlet `AccessTokenProtectionFilter` (`openam-oauth2/.../oauth2/AccessTokenProtectionFilter.java`)
does: read the bearer token → `tokenStore.readAccessToken` → null/expired → **401** `InvalidTokenException`;
scope missing → **403** `InsufficientScopeException`; `NotFoundException` → **404**; `ServerException` →
**500**; success → stash `oAuth2Request.setToken(AccessToken.class, token)` and continue. On failure it sets
a bare status and stops.

The CHF port (`ChfAccessTokenProtectionFilter implements org.forgerock.http.Filter`):

- Bearer token via `oAuth2Request.getAuthorizationBearerToken()` (3a) — replaces
  `request.getChallengeResponse().getRawValue()`. A `null` token (no/again-non-Bearer header) reproduces
  the Restlet `challengeResponse == null` → 401 branch.
- The `OAuth2Request` from `requestFactory.create(context, request)` — the **same cached instance** the
  audit filter and the endpoint see ([phase-3d-audit.md](phase-3d-audit.md) as-built: `create(context,
  request)` caches one `ChfOAuth2Request` on `AttributesContext`), so `setToken(...)` is visible to the
  endpoint downstream (finding 4).
- On failure, **return a `Response` that reproduces the StatusFilter CREST body** (finding 1): build the
  entity with `ResourceException.getException(statusCode, exception.getMessage()).toJsonValue().getObject()`
  and `setEntity(map)` — which yields exactly `{code, reason, message}` at `application/json; charset=UTF-8`.
  Do **not** set `WWW-Authenticate`; do **not** emit the OAuth2 `error` field (D5).
- On success, `return next.handle(context, request)`.

Message parity table (the four Restlet exit statuses → CREST body the port must produce):

| Trigger | Status | `message` source |
|---|---|---|
| no bearer / null-or-expired token / `InvalidGrantException` | 401 | `new InvalidTokenException().getMessage()` |
| scope not held | 403 | `new InsufficientScopeException(requiredScope).getMessage()` |
| `NotFoundException` | 404 | the caught `e.getMessage()` |
| `ServerException` | 500 | the caught `e.getMessage()` |

### 4. Token sharing — the protection filter stashes, the endpoint reads, one request instance

`OAuth2RequestFactory.create(context, request)` returns the **same** `ChfOAuth2Request` for the whole
chain. So `ChfAccessTokenProtectionFilter` calling `setToken(AccessToken.class, token)` makes that token
visible to `PermissionRequestEndpoint.getClientId(request)` (`request.getToken(AccessToken.class)`) exactly
as the Restlet filter's `oAuth2Request.setToken` is visible to the endpoint today. No token needs threading
through manually — rely on the cache, as [phase-3d-audit.md](phase-3d-audit.md) established. (⚠ this must be
the `create(context, request)` overload, not `create(request)`; the endpoints and both filters must all use
it so they land on the one cached instance — verified by the composition IT, finding 8.)

### 5. The audit filter and body auditors already exist (3d-2) — this phase only *wires* them

`UMAHttpAccessAuditFilter` + `HttpBodyAuditor` (`org.openidentityplatform.openam.oauth2.audit`) shipped in
3d-2, tested against the real `RestletBodyAuditor` by the parity oracle. Phase 4 constructs them per-route
with the exact auditor pairs from the [3d matrix](phase-3d-audit.md#2--audit-is-wired-per-route-with-per-endpoint-body-auditors--not-one-filter-per-component)
— reproducing `UmaRouterProvider.auditWithUmaFilter`:

| Route | request auditor | response auditor |
|---|---|---|
| `/permission_request` | `jsonAuditor(RESOURCE_SET_ID, SCOPES)` | `noBodyAuditor()` |
| `/authz_request` | `noBodyAuditor()` | `noBodyAuditor()` |
| `/.well-known/uma-configuration` | `noBodyAuditor()` | `noBodyAuditor()` |

Wiring position ([phase-3d-audit.md](phase-3d-audit.md) work item 3): audit **outermost of the per-route
chain, inside the realm router** — so it sees the final status and does not audit realm-resolution
failures. Order relative to the protection filter: audit outermost, then protection, then endpoint (mirrors
the Restlet `UMAAccessAuditFilter` → `AccessTokenProtectionFilter` → endpoint nesting). UMA emits no 3xx,
so 3d-1's 3xx→SUCCESSFUL fix is inert here (but correct).

### 6. The provider/uris factories are already transport-neutral — but `realmObject` needed seeding (framework fix, 4a)

`UmaProviderSettingsFactory` and `UmaUrisFactory` both expose public `get(OAuth2Request)` and, for uris,
`get(Context, Realm)` / `get(OAuth2Request, Realm)` overloads (the package-private `get(Request)` Restlet
shims wrap `RestletOAuth2Request` and become **dead** once the endpoints stop calling them — deletable in
4b or deferred to Phase 8). Two seams matter:

- `UmaProviderSettingsFactory.get(OAuth2Request)` reads the realm via `getParameter(RestletRealmRouter.REALM)`
  (`"realm"`). `ChfOAuth2Request` **seeds** `"realm"` from `RealmContext.getRealm().asPath()`
  (`ChfOAuth2Request.java:324`), so `get(oAuth2Request)` **works on CHF**.
- **The `*UrisFactory.get(OAuth2Request)` overloads read `"realmObject"` directly and were the one real CHF
  break.** Both `UmaUrisFactory.get(OAuth2Request)` (`UmaUrisFactory.java:83`) and
  `OAuth2UrisFactory.get(OAuth2Request)` (`OAuth2UrisFactory.java:68`) do
  `Realm realm = request.getParameter(REALM_OBJECT)` with **no** token/`"realm"` fallback — unlike the
  provider-settings factories, which resolve through `OAuth2RealmResolver` (stashed-token realm, else seeded
  `"realm"`), so *their* `get(OAuth2Request)` is safe under CHF (permission_request:105, authz_request:125).
  Originally `ChfOAuth2Request` seeded `"realm"` but **not** `"realmObject"`, so both uris readers returned
  `null` → NPE. **Fix chosen — framework-side, in 4a: `ChfOAuth2Request` now seeds `"realmObject"` too**, from
  `RealmContext.getRealm(context)` (a `Realm` object — exactly the type both factories cast the parameter to),
  next to the existing `"realm"` seed (`ChfOAuth2Request.attributes()`, line ~324). That makes
  `get(OAuth2Request)` correct for uris resolution everywhere, so **neither Phase-4 uris call site needs a
  per-call rewrite**: the well-known endpoint still uses the explicit `urisFactory.get(context, realm)` (it
  already resolves realm from `RealmContext` — work item 3), and `AuthorizationRequestEndpoint` keeps its
  **verbatim** `oAuth2UrisFactory.get(oauth2Request)` at line 126 (finding 8). Provider settings resolve via
  `providerSettingsFactory.get(realm.asPath())` where a Restlet-`Request` shim was used (note
  `UmaProviderSettingsFactory` has `get(OAuth2Request)` / `get(String)` but **no** `get(Context, Realm)` —
  that overload is uris-only).

  > **⚠ This was nearly a silent Phase-4 bug, not merely a Phase-5 note.** `AuthorizationRequestEndpoint`
  > calls `oAuth2UrisFactory.get(oauth2Request)` **unconditionally** at line 126 on every `authz_request`, and
  > — unlike every other coupling point — it **still compiles** after the `extends ServerResource` shell
  > change (the neutral `oauth2Request` is a valid `OAuth2Request`). With `"realmObject"` unseeded it would
  > NPE at runtime on the happy path, invisible to the ported unit test **and** `UmaRouterIT` (both **mock**
  > `OAuth2UrisFactory`, so the NPE inside the real factory never fires) — surfacing only in the deferred
  > e2e. The 4a seed removes it here **and** for Phase 5's many `OAuth2UrisFactory.get(OAuth2Request)` call
  > sites: a de-risking bonus, so Phase 5 neither seeds it again nor rewrites each call.

### 7. `UmaAuditLogger` is Restlet-coupled and must be re-based (a modified-in-place class)

Distinct from the CHF access-audit filter, `UmaAuditLogger` (openam-uma,
`org.forgerock.openam.uma.audit`) is a UMA-specific audit-entry writer that `AuthorizationRequestEndpoint`
calls. It takes a Restlet `Request` in `log(...)`, `getResourceName(...)` and the private `getClientId(...)`,
only ever to build an `OAuth2Request` (`requestFactory.create(request)` → provider settings) or read the
bearer token. Re-base those signatures **`Request` → `OAuth2Request`** (the endpoint already has the
`OAuth2Request` to hand). `getClientId` → `oAuth2Request.getAuthorizationBearerToken()`. Modified in place
(keep package + header, add a `Portions copyright … 3A Systems LLC.` line). Its only production caller is
`AuthorizationRequestEndpoint`; confirm no other before changing the signature.

### 8. Two small CHF fixes (the unmapped-verb 405 body; the `realmObject` seed); nothing else needed

Phase 4 otherwise rides on already-fixed machinery: `@ExceptionHandler` is real (F2), a `String`/`Response`
return is safe (F4), the audit base carries body detail and classifies 3xx correctly (3d-1), and the entity
is buffered so the audit filter reading the body leaves it for the handler
([chf-patterns.md](chf-patterns.md) §7, finding 4).

**One framework fix was made (done + verified this phase, not deferred).** `Endpoints.from`'s unmapped-verb
fallback (`Endpoints.java`, the `method == null` branch) returned an HTTP **405** whose CREST body carried
`code: 501` (from `new NotSupportedException()`) — a self-contradictory status/body that also diverged from
Restlet, which renders a coherent 405. It now emits a **405-coded** body
(`ResourceException.getException(405, "Method Not Allowed")`), matching `AnnotatedMethod`'s
mapped-verb-with-no-method sentinel so both "method not allowed" paths render one shape. This matters for
`/uma` specifically: unlike `/oauth2` — where `OAuth2ErrorFilter` normalises every `≥400` body off the wire
status (D4) — `/uma` has **no** such filter, so the raw framework body is what a UMA client sees.
`OAuth2ErrorFilter` keys off the wire status, so its behaviour is unchanged; three stale 3c-2 comments that
cited the old `501` body were corrected. Guards: `EndpointsTest.unmappedVerbGives405WithA405Body`
(openam-http) + the existing `OAuth2ErrorRouteCompositionIT` HEAD case. ([chf-patterns.md](chf-patterns.md)
§2 updated to match.)

**A second framework fix is folded into 4a: `ChfOAuth2Request` seeds `"realmObject"`** (finding 6).
`OAuth2UrisFactory.get(OAuth2Request)` and `UmaUrisFactory.get(OAuth2Request)` read `getParameter(REALM_OBJECT)`
directly; with it unseeded, `AuthorizationRequestEndpoint`'s verbatim `oAuth2UrisFactory.get(oauth2Request)`
(line 126) NPEs on every `authz_request` under CHF — a break that **compiles clean and slips past mocked
tests**. Chosen over per-call `(Context, Realm)` rewrites because one seed fixes both Phase-4 uris sites and
all of Phase 5's OAuth2 uris calls (fix-the-framework, not work-around-per-call). Note there is **no**
`OAuth2Constants.Custom.REALM_OBJECT` constant today (only `Custom.REALM`), so the seed adds one
(`REALM_OBJECT = "realmObject"`) or references `RestletRealmRouter.REALM_OBJECT` (already imported by
`OAuth2UrisFactory` in openam-oauth2). Guard: `ChfOAuth2RequestTest` realmObject assertion + `UmaRouterIT`
case 5 driven through the **real** `OAuth2UrisFactory`.

The remaining framework sharp edge — `Form.fromRequestEntity`'s charset trap — is not on any `/uma` path
(the endpoints read the JSON body via `getBody()`, and the form body auditor uses `fromFormString`), and
stays in the [CHF cleanup backlog](decisions.md#chf-cleanup-backlog).

## Design decisions

<a id="d1"></a>
### D1 — Re-base the three endpoints **in place**, don't author new classes

The endpoints carry substantial business logic (`AuthorizationRequestEndpoint` alone is ~457 lines of
entitlement/pending-request logic that must survive **verbatim**). Re-basing the transport shell — drop
`extends ServerResource`, swap Restlet `@Post`/`Representation`/`getRequest()` for CHF
`@Post`/`Response`/`@Contextual` + `getBody()` — is a **modification in place**, not an authoring event:
the class keeps its name and package (`org.forgerock.openam.uma.*`), keeps its co-located test, and gains
a `Portions copyright 2026 3A Systems LLC.` line ([decisions.md](decisions.md) "modified in place" rule).
This is lower-risk than copying 457 lines into a new `org.openidentityplatform.openam.uma.*` class and is
what plan.md meant by "convert in place (names kept)". The genuinely-**new** classes
(`ChfAccessTokenProtectionFilter`, `UmaHttpRouteProvider`, the exception mapper) follow the new-package
convention. *(Reviewer's call: strict-convention adherents may prefer new classes in `…openam.uma`; the
trade is churn + a test package move vs. convention purity. Recommendation: in place.)*

<a id="d2"></a>
### D2 — Handler methods return `Response`, throw for errors

Each endpoint method returns a built `Response` (201 `{ticket}`, 200 `{rpt}` / config JSON) and **throws**
its existing checked exceptions (`UmaException`, `ServerException`, …) to the shared `@ExceptionHandler`.
Returning `Response` (not `JsonValue`) keeps the exact status codes explicit (201 for permission_request)
and is house style ([chf-patterns.md](chf-patterns.md) §2). Build JSON bodies with `setEntity(Map)` —
`setJson` supplies `application/json; charset=UTF-8` for free, no `JacksonRepresentationFactory` (dropped
from the constructors).

<a id="d3"></a>
### D3 — One shared exception mapper, dispatching on the thrown exception directly

Port `UmaExceptionHandler.handleException` into a pure static `UmaErrorResponseFactory.from(Throwable) →
Response` (no `JacksonRepresentationFactory` dependency on CHF), preserving the exact if/else chain but on
`t` **directly**, not `t.getCause()` (finding 2):

- `t instanceof UmaException` → status `getStatusCode()`, body `{error=getError(), error_description=getMessage()}` + `getDetail()` flattened.
- `t instanceof OAuth2Exception` → status `getStatusCode()`, body `{error=getError(), error_description=getMessage()}`.
- else → **500**, body `{error="server_error", error_description=getMessage()}`.

(The Restlet else-branch is actually *status-agnostic* — it keeps whatever status the response already
carries (`UmaExceptionHandlerTest.shouldSet500ExceptionResponse` pre-seeds **444** and asserts it *stays*
444); it reads as 500 only because Restlet pre-sets 500 for an uncaught throwable. On CHF the
`@ExceptionHandler` builds a fresh response, so the port emits a flat **500** — a deliberate, faithful
simplification for the uncaught case, and the only case that reaches this branch: `ServerException` and
`NotFoundException` are `OAuth2Exception` subclasses that hit the *earlier* branch, never this one.
Consistent with [decisions.md D3](decisions.md) "keep CHF's 500 on the bug path". Do not "restore" a
dynamic status here.) A single `AbstractUmaHttpEndpoint` base declares
`@ExceptionHandler public Response onError(Throwable t) { return UmaErrorResponseFactory.from(t); }`; the
three endpoints extend it and **must not override** `onError` (finding 2). Body order via `LinkedHashMap`
(RFC-irrelevant, benign vs. today's `HashMap`).

<a id="d4"></a>
### D4 — No `OAuth2ErrorFilter` on `/uma`

Finding 1: the filter would rewrite UMA's CREST-shaped protection-filter/framework errors into OAuth2
`{error,…}`, a shape they have never had. UMA's error contract is UMA-shape (endpoint exceptions, via
`@ExceptionHandler`) + CREST-shape (everything else, native). The IT asserts both are unchanged.

This also covers **realm-resolution failures** (bad realm in path): `RealmContextFilter` renders them as
CREST natively (`RealmContextFilter.java:88-91` — `BadRequestException` → `Response(400).setEntity(toJsonValue)`,
other `ResourceException` → 500), so `/uma` needs **no** error filter over the realm layer. This is exactly
why XACML's `XacmlXmlErrorFilter` — which exists only to convert those CREST errors into XML — has **no**
UMA analogue: for UMA, CREST *is* the target shape. Pinned by IT case 11.

<a id="d5"></a>
### D5 — Reproduce the protection filter exactly: CREST body, no `error` field, no `WWW-Authenticate`

Parity-first. The Restlet filter emits a CREST `{code,reason,message}` (finding 1), sets no
`WWW-Authenticate`, and drops the OAuth2 `error` code. Reproduce all three, even though an RFC-6750
`WWW-Authenticate: Bearer` + an `error` field would be *better*. **Considered and not changed** — adding
them is a wire change no client asked for; revisit as a deliberate hardening item after the flip, alongside
Phase 5's bearer-token handling, not inside a parity migration. Recorded so it is not re-litigated.

<a id="d6"></a>
### D6 — Delete `UmaRouterProvider` + `UMAServiceEndpointApplication` now; the Restlet `AccessTokenProtectionFilter` and `UMAAccessAuditFilter` are shared/deferred

`UmaRouterProvider` (openam-uma) and `UMAServiceEndpointApplication` (openam-rest) are UMA-only and become
dead at the flip → delete in 4b. But two Restlet classes are **not** deleted here:

- **Restlet `AccessTokenProtectionFilter` (openam-oauth2) stays** — `OAuth2GuiceModule` still binds it for
  `resource_set` until **Phase 5c**. 4a adds the CHF filter *alongside* it.
- **Restlet `UMAAccessAuditFilter` (openam-oauth2)** becomes dead once `UmaRouterProvider` goes, but it
  extends `OAuth2AbstractAccessAuditFilter`, the base still shared by `OAuth2AccessAuditFilter` until
  **Phase 5d**. Deleting the leaf now is harmless; deferring it to Phase 8 with the whole Restlet-audit
  cluster keeps 4b's diff focused. **Recommendation: defer** (reconciles plan.md's "delete in Phase 4"
  with [phase-3d-audit.md](phase-3d-audit.md)'s "dies at 5d/8" — the leaf *may* go in 4b, the base cannot).

## Sub-phase 4a — `ChfAccessTokenProtectionFilter` (openam-oauth2, build-ahead)

### New

1. **`org.openidentityplatform.openam.oauth2.http.ChfAccessTokenProtectionFilter`** — CDDL header,
   `Copyright 2026 3A Systems LLC.`, no `@since`. `implements org.forgerock.http.Filter`; ctor
   `(String requiredScope, TokenStore tokenStore, OAuth2RequestFactory requestFactory)` (a `null`
   `requiredScope` skips the scope check, for Phase 5c's `resource_set`). `filter(context, request, next)`:
   the finding-3 logic; on success `return next.handle(...)`, on failure `return` a CREST-body `Response`
   (finding 3, D5). `Debug.getInstance("UmaProvider")` for the `NotFoundException` debug line, as today.

### Modified in place (openam-oauth2; keep package + header, add `Portions` line)

2. **`ChfOAuth2Request`** — seed `"realmObject"` in `attributes()` (the block near line 324 that already
   seeds `"realm"` from `RealmContext`): `attributes.put(REALM_OBJECT, RealmContext.getRealm(context))` when
   a `RealmContext` is present. `RealmContext.getRealm(context)` returns
   `org.forgerock.openam.core.realms.Realm`, the exact type `UmaUrisFactory.get(OAuth2Request)` /
   `OAuth2UrisFactory.get(OAuth2Request)` cast the parameter to. **There is no
   `OAuth2Constants.Custom.REALM_OBJECT` constant today** (only `Custom.REALM`), so add one
   (`REALM_OBJECT = "realmObject"`, openam-core) or reference `RestletRealmRouter.REALM_OBJECT` (already
   imported by `OAuth2UrisFactory` in this module). This is the finding-6 fix — build-ahead, wired to no
   route; its guard is the seed test below and, at 4b, `UmaRouterIT` case 5. Fixes both Phase-4 uris call
   sites and, as a bonus, every Phase-5 `OAuth2UrisFactory.get(OAuth2Request)`.

### Tests (openam-oauth2)

- **`ChfAccessTokenProtectionFilterTest`** — construct a real `Request` + context chain
  ([chf-patterns.md](chf-patterns.md) §5), stub `TokenStore`/`OAuth2RequestFactory`. Assert: no bearer →
  401 CREST body `{code,reason,message}` (`message` = `InvalidTokenException`'s), `application/json`, and
  `next` **not** called; expired/null token → 401; wrong scope → 403 (`InsufficientScopeException(scope)`
  message); `NotFoundException` → 404; `ServerException` → 500; `null` scope skips the check; **success →
  `next` called and `getToken(AccessToken.class)` is the stashed token** on the *same* cached
  `OAuth2Request`; **no** `WWW-Authenticate` header; **no** `error` field in the body (D5). The Restlet
  `AccessTokenProtectionFilter` is the oracle — cite its line numbers; a live A/B is unnecessary (the
  Restlet filter needs a Restlet `Request`/`Response`, and the status/message contract is small enough for
  inline asserts per [chf-patterns.md](chf-patterns.md) §13).
- **`ChfOAuth2RequestTest`** (extend the existing suite) — with a `RealmContext` in the chain,
  `getParameter(REALM_OBJECT)` returns that context's `Realm` object (not `null`), alongside the existing
  `getParameter(REALM)` path. Sole guard that the finding-6 seed is present before 4b wires the uris factories.
- Gate: `grep -rn "org.restlet\|getCurrent()" <the new class>` → 0.

### 4a verification

`mvn -o -pl openam-oauth2 test`; then **`mvn -o -pl openam-oauth2 install -DskipTests`** so 4b compiles
against the new class (the `~/.m2` resolution, [chf-patterns.md](chf-patterns.md) §11).

## Sub-phase 4b — UMA endpoints + the flip (openam-uma, openam-rest, web.xml)

### Modified in place (openam-uma; keep package + header, add `Portions` line)

1. **`PermissionRequestEndpoint`** — drop `extends ServerResource`, `doCatch`, `JacksonRepresentationFactory`.
   `@Post public Response registerPermissionRequest(@Contextual Context ctx, @Contextual Request req)
   throws UmaException, NotFoundException, ServerException`: `oAuth2Request = requestFactory.create(ctx, req)`;
   body via `oAuth2Request.getBody().asMap()` (`getBody()` returns a `JsonValue`, **not** a `Map`
   — `ChfOAuth2Request.java:130-140`; replaces the `JsonRepresentation` parameter + `toMap`); client id /
   resource owner from the stashed `getToken(AccessToken.class)` (unchanged); provider settings via
   `providerSettingsFactory.get(oAuth2Request)` (finding 6); `umaProviderSettingsFactory.get(realm.asPath())`;
   return `new Response(Status.valueOf(201)).setEntity(singletonMap("ticket", ticket))`. `extends
   AbstractUmaHttpEndpoint`.
2. **`AuthorizationRequestEndpoint`** — same shell change. Port the coupling points:
   `getAuthorisationApiToken()` → bearer via `oAuth2Request.getAuthorizationBearerToken()` (replaces
   `getChallengeResponse().getRawValue()`); `pendingRequestsService.createPendingRequest(oAuth2Request.getHttpServletRequest(), …)`
   (replaces `ServletUtils.getRequest(getRequest())`); `auditLogger.log(…, oAuth2Request, …)` (finding 7);
   realm via `oAuth2Request.getParameter("realm")` (seeded); granted → `new Response(Status.valueOf(200)).setEntity({rpt})`,
   denied/pending → throw (unchanged). Preserve the entitlement/pending-request logic **verbatim** — including
   `oAuth2UrisFactory.get(oauth2Request)` at line 126, which stays verbatim **only because 4a seeds
   `"realmObject"`** (finding 6/8); without that seed it NPEs, and it still *compiles*, so this is not
   catch-by-compiler. The one non-mechanical `getRequest()` site is the claim-gathering
   `requestFactory.create(getRequest())` (line ~225) → reuse the already-built `oauth2Request` (compile-forced
   once `getRequest()` is gone, so it cannot slip). `extends AbstractUmaHttpEndpoint`.
3. **`UmaWellKnownConfigurationEndpoint`** — `@Get public Response getConfiguration(@Contextual Context ctx)
   throws NotFoundException, ServerException`: resolve `Realm realm = ctx.asContext(RealmContext.class).getRealm()`;
   `providerSettingsFactory.get(realm.asPath())` and `urisFactory.get(ctx, realm)` (finding 6 — **not**
   `get(oAuth2Request)`); build the same config `JsonValue`; return `new Response(Status.OK).setEntity(config.asMap())`.
   **No** protection filter (public). `extends AbstractUmaHttpEndpoint`.
4. **`UmaAuditLogger`** — `Request` → `OAuth2Request` in `log`/`getResourceName`/`getClientId` (finding 7).
5. **`UmaGuiceModule`** — drop the `@Named("UMARouter")` → `UmaRouterProvider` binding; drop the two
   `@Named(PERMISSION_REQUEST_ENDPOINT/AUTHORIZATION_REQUEST_ENDPOINT)` `Restlet` `@Provides` (the route
   provider builds `Endpoints.from(...)` + `ChfAccessTokenProtectionFilter` directly, so the `Restlet`
   `@Named` indirection is no longer needed); remove the Restlet `AccessTokenProtectionFilter`/`wrap` imports.

### New (openam-uma; `org.openidentityplatform.openam.uma`, new-class convention)

6. **`UmaErrorResponseFactory`** — pure static `Response from(Throwable)` (D3).
7. **`AbstractUmaHttpEndpoint`** — the shared `@ExceptionHandler onError(Throwable)` (D3). No fields, no-arg.
8. **`UmaHttpRouteProvider`** (mirrors [`XacmlHttpRouteProvider`](../../../openam-entitlements/src/main/java/org/forgerock/openam/entitlement/rest/XacmlHttpRouteProvider.java)):
   `@Inject` setters for `AuditEventPublisher`, `AuditEventFactory`, `OAuth2RequestFactory`, `TokenStore`,
   `RealmRoutingFactory`, `RealmContextFilter`, `@Named("InvalidRealmNames") Set<String>`. `get()`:
   ```
   endpointRouter.addRoute(EQUALS "permission_request",
       audited(protect(PermissionRequestEndpoint.class, PAT_SCOPE), jsonAuditor(RESOURCE_SET_ID, SCOPES), noBodyAuditor()));
   endpointRouter.addRoute(EQUALS "authz_request",
       audited(protect(AuthorizationRequestEndpoint.class, AAT_SCOPE), noBodyAuditor(), noBodyAuditor()));
   endpointRouter.addRoute(EQUALS ".well-known/uma-configuration",
       audited(Endpoints.from(UmaWellKnownConfigurationEndpoint.class), noBodyAuditor(), noBodyAuditor()));
   // realm wrapper: same SHAPE as XacmlHttpRouteProvider, minus two XACML-only elements (verified against
   // XacmlHttpRouteProvider.java:106,116-117):
   //  (a) no @Named("RequiredAuthenticationFilter") wrap on the inner chain — XACML gates every op on an SSO
   //      admin token; UMA's auth IS the per-route bearer protection filter (or public, for well-known).
   //  (b) no error filter around the root — XACML wraps chainOf(root, xacmlXmlErrorFilter) solely to render
   //      realm/framework errors as XML; UMA wants those as CREST, which RealmContextFilter already emits
   //      natively (RealmContextFilter.java:88-91: BadRequest→CREST 400, other ResourceException→CREST 500),
   //      so the raw root is correct (D4). Hence NOT injecting an auth filter or an error filter.
   root.addRoute(STARTS_WITH REALM_ROUTE, chainOf(realmRoutingFactory.createRouter(root), createHostnameFilter()));
   root.setDefaultRoute(chainOf(endpointRouter, realmContextFilter));
   return singleton(newHttpRoute(STARTS_WITH, "uma", root));   // raw root — no error-filter wrap
   ```
   where `protect(cls, scope)` = `chainOf(Endpoints.from(cls), new ChfAccessTokenProtectionFilter(scope, tokenStore, requestFactory))`
   and `audited(h, rq, rs)` = `chainOf(h, new UMAHttpAccessAuditFilter(publisher, factory, requestFactory, rq, rs))`
   (audit outermost, finding 5). **No `OAuth2ErrorFilter`** (D4). Register the three endpoint segments into
   `InvalidRealmNames` (`"permission_request"`, `"authz_request"`; `.well-known` is not a realm-collision
   risk) as XACML did with `"policies"` — this guards realm *creation*, not routing
   ([phase-2-integration-tests.md](phase-2-integration-tests.md) case 8).
9. **`openam-uma/src/main/resources/META-INF/services/org.forgerock.openam.http.HttpRouteProvider`** — new
   file (openam-uma has none today), one line: `org.openidentityplatform.openam.uma.UmaHttpRouteProvider`.

### Modified (other modules)

10. **`openam-server-only/.../WEB-INF/web.xml`** — move the `/uma/*` mapping (line ~1143) from the
    `ForgeRockRest` servlet to the `OpenAM` (`HttpFrameworkServlet`, `routing-base=context_path`) servlet,
    next to `/xacml/*`.
11. **`openam-rest/.../rest/RestEndpointServlet.java`** — drop the uma branch: the
    `restletUMAServiceServlet` field + its `service()`/`destroy()` calls, the `UMAServiceEndpointApplication`
    import, and the constructor param. Servlet keeps serving `/oauth2` only (until Phase 5d deletes it).

### Deleted

- `openam-uma/.../uma/rest/UmaRouterProvider.java`
- `openam-uma/.../uma/UmaExceptionHandler.java` (logic ported to `UmaErrorResponseFactory`)
- `openam-rest/.../rest/service/UMAServiceEndpointApplication.java`
- *(optional, D6)* Restlet `UMAAccessAuditFilter` (openam-oauth2) — dead after `UmaRouterProvider` goes;
  defer to Phase 8 with the base if preferred.
- *(optional)* the dead `UmaProviderSettingsFactory.get(Request)` / `UmaUrisFactory.get(Request)` Restlet
  shims once the endpoints stop calling them (removes the `RestletOAuth2Request` import from those files;
  defer to Phase 8 if it widens the diff).

### Tests (openam-uma; TestNG + Mockito)

Port the three endpoint tests + the exception test off Restlet mocks onto CHF request/context scaffolding
([chf-patterns.md](chf-patterns.md) §5 — real `new Request()` + `RootContext → AttributesContext →
RealmContext`, `RealmTestHelper`, `OAuth2RequestFactory` stubbed to return a spy `ChfOAuth2Request`):

- **`PermissionRequestEndpointTest`** — call `registerPermissionRequest(ctx, req)`; stub `getBody()` /
  `getToken`; assert 201 `{ticket}`, and each `UmaException` path (missing/ non-string `resource_set_id`,
  scope-not-allowed, resource-set-not-found).
- **`AuthorizationRequestEndpointTest`** (the big one, ~587 lines) — the entitlement/pending-request cases
  are transport-agnostic and port with signature changes only; re-stub `getAuthorizationBearerToken()` /
  `getHttpServletRequest()` / `auditLogger.log(…, OAuth2Request, …)`.
- **`UmaWellKnownConfigurationEndpointTest`** — call `getConfiguration(ctx)` with a `RealmContext`; assert
  the config JSON + 200.
- **`UmaErrorResponseFactoryTest`** (rewrite of `UmaExceptionHandlerTest`) — `UmaException` → UMA body +
  status + detail; `OAuth2Exception` → UMA body + status; generic `Throwable` → 500 `server_error`;
  dispatch on the throwable **directly** (the `.getCause()` unwrap is gone — assert a bare `UmaException`,
  not a wrapper).
- Gates: `grep -rn "org.restlet\|getCurrent()"` over the three re-based endpoints + `UmaAuditLogger` → 0.

## Integration testing

The migration's highest-risk surface is the **route composition** — realm routing, the protection filter,
the audit wrap, the two error shapes — none of which a layer-1 unit test exercises. Two guards, split on
auth exactly as [phase-2-integration-tests.md](phase-2-integration-tests.md) split them:

### Primary — `UmaRouterIT` (layer 2, in-process, openam-uma)

Model: [`XacmlRouterIT`](phase-2-integration-tests.md#deliverable-2-secondary--openam-entitlementsrestxacmlrouteritjava)
(minimal injector, `InjectorConfiguration.setGuiceModuleLoader(→ empty)`, build the router from
`InjectorHolder.getInstance(UmaHttpRouteProvider.class).get()`) + the composition style of
[`OAuth2AuditRouteCompositionIT`](phase-3d-audit.md#integration-test-build-ahead-in-process-composition)
(capturing `AuditEventPublisher`, stub `TokenStore`). **No pom change** — openam-uma already has
`org.openidentityplatform.commons.guice:test` (`pom.xml:80-81`). Bind the endpoint instances (with mocked
collaborators) so `Endpoints.from(Class)` resolves eagerly ([phase-2-integration-tests.md](phase-2-integration-tests.md)
fact 2). Dispatch real `Request`s and assert:

| # | Request | Assert |
|---|---|---|
| 1 | `POST /uma/permission_request` + valid PAT (stub token, scope `uma_protection`) | reaches handler; realm root; **201 `{ticket}`**; audit `AM_ACCESS_ATTEMPT`+`_OUTCOME`, `request/detail` carries `resource_set_id`+`scopes` (finding 5) |
| 2 | `POST /uma/permission_request`, **no bearer** | **401**, body `{code,reason,message}` (CREST, D5), `application/json`, **no** `error` field, **no** `WWW-Authenticate`; handler **not** reached |
| 3 | `POST /uma/permission_request` + token **without** `uma_protection` | **403** CREST `InsufficientScopeException` message |
| 4 | `POST /uma/permission_request`, valid PAT, body missing `resource_set_id` | **400**, **UMA** body `{error:"invalid_resource_set_id", error_description}` (finding 1 — endpoint path, not CREST) |
| 5 | `POST /uma/authz_request` + valid AAT (bind the **real** `OAuth2UrisFactory`, not a mock, over a mocked realm) | reaches handler (200/403 per stub); `oAuth2UrisFactory.get(oauth2Request)` at line 126 resolves via the seeded `"realmObject"` (finding 6) rather than NPE-ing |
| 6 | `GET /uma/.well-known/uma-configuration` (no token) | **200** config JSON, public — no 401 |
| 7 | `GET /uma/realms/root/permission_request` / `POST /uma/subrealm/permission_request` | modern + legacy path realm resolve (mock realm via `RealmTestHelper`+`CoreWrapper`, per `RestRouterIT.mockRealm`) |
| 8 | `GET /uma/permission_request` (wrong verb) | **405**, **CREST** body (finding 1 — framework path) — proves no `OAuth2ErrorFilter` is present (D4) |
| 9 | `GET /uma/nonsense` | 404 |
| 10 | provider `get()` | `"permission_request"`/`"authz_request"` added to injected `InvalidRealmNames` |
| 11 | `GET /uma/realms/bogus/.well-known/uma-configuration` (unresolvable realm) | realm-resolution failure renders as **CREST** `{code,reason,message}` (native, via `RealmContextFilter` / `createRouter`), **not** empty/HTML — pins that `/uma` needs no error filter over the realm layer, unlike XACML (D4) |

Cases 2/4/8 are the point of this suite: they pin **both** error shapes *in situ* — CREST for the filter
(2) and framework (8), UMA for the endpoint (4) — which is the single most important parity claim of the
phase (finding 1). Case 1 proves the token stash + audit body detail compose in one real request. Case 11
closes the one error path XACML handles with an error filter that `/uma` deliberately omits — it confirms
the realm layer renders CREST natively rather than something empty/HTML.

### Secondary — e2e Playwright (layer 4, `e2e/uma/`)

⚠ **Heavier fixtures than XACML, and net-new** — there is no UMA e2e today, and the oauth2 spec touches no
UMA. A full protected flow needs: a UMA-enabled realm, an OAuth2 resource-server client with the
`uma_protection`/`uma_authorization` scopes, a PAT (client-credentials or RO flow), and a registered
resource set (`POST /oauth2/resource_set`). That is a large `beforeAll`. **Recommendation:** ship the
**public** `GET /uma/.well-known/uma-configuration` case as a cheap over-the-wire smoke first (asserts the
route is mounted, realm-routed, and returns the config JSON with real serialization — no auth fixture), and
**defer** the full permission_request/authz_request e2e until it can share Phase 5's `resource_set` e2e
fixtures (resource_set migrates in 5c; the two are natural neighbours). The layer-2 `UmaRouterIT` already
covers the protected paths deterministically on all 9 CI legs; the e2e adds real auth + wire serialization,
which for UMA is disproportionately expensive to stand up alone. Record the deferral rather than leave it
implicit.

## Verification criteria

**4a (build-ahead, openam-oauth2):**
1. `mvn -o -pl openam-oauth2 test` — `ChfAccessTokenProtectionFilterTest` green **and** `ChfOAuth2RequestTest`'s
   new `realmObject`-seed assertion green (finding 6/8); existing suite unchanged.
2. Restlet/`getCurrent()` import gate on the new class → 0.
3. `mvn -o -pl openam-oauth2 install -DskipTests` (prereq for 4b).

**4b (the flip, openam-uma + openam-rest + web.xml):**
4. `mvn -o -pl openam-uma test` — the four ported unit tests green; delta attributable to the port.
5. `mvn -o -pl openam-uma verify` — `UmaRouterIT` (11 cases) green; runs on all 9 CI legs. (`mvn test` will
   **not** run `*IT.java` — failsafe is bound at the root pom.)
6. **Whole build with `-am`:** `mvn -o install -pl openam-uma,openam-rest -am -DskipTests` — confirms the
   web.xml/WAR wiring, the `RestEndpointServlet` edit, and no dangling refs to the deleted classes; `-am`
   avoids the stale-SNAPSHOT-jar trap (memory: `.m2 stale schema jar trap`).
7. Cargo IT boot check: `mvn -pl openam-server verify -P integration-test` — proves the WAR starts with the
   new route provider bound (a broken Guice binding fails startup). It asserts no UMA behaviour
   ([phase-2-integration-tests.md](phase-2-integration-tests.md)).
8. Restlet/`getCurrent()` import gate over the re-based endpoints + `UmaAuditLogger` → 0.
9. **Both error shapes pinned** — `UmaRouterIT` cases 2 (CREST, filter), 4 (UMA, endpoint), 8 (CREST,
   framework). This is the finding-1 guard; it is the phase's load-bearing assertion.
10. CI (`.github/workflows/build.yml`): JDK 11–26 × 3 OSes on the `features/**` push — cross-version
    coverage of the entity/charset handling for free.

Deferred to post-flip smoke (needs a running WAR): the full UMA protected flow (register resource set → PAT
→ permission_request → authz_request) diffed against pre-flip Restlet output, and risk #13's
`http/request/queryParameters` pre/post diff on the form-less UMA POSTs (UMA bodies are JSON, so the
form-leak is moot, but record it with the OAuth2 smoke at 5d).

## Risks (extends [plan.md](plan.md)'s register)

- **R-4.1 Two error shapes (finding 1).** Highest-severity. If `OAuth2ErrorFilter` is wired (or the CREST
  reproduction is wrong), the protection-filter/framework errors flip from CREST to OAuth2 shape — a silent
  wire change. Guard: `UmaRouterIT` cases 2/4/8; D4.
- **R-4.2 Protection-filter body parity (D5).** The port must emit CREST `{code,reason,message}`, no `error`
  field, no `WWW-Authenticate`. Guard: `ChfAccessTokenProtectionFilterTest` + IT case 2.
- **R-4.3 `@ExceptionHandler` dispatch on the wrong object.** Porting `handleException` and keeping the
  `.getCause()` unwrap would map every real exception to the else-branch 500 (its cause is null on CHF).
  Guard: `UmaErrorResponseFactoryTest` asserts a *bare* `UmaException` maps correctly.
- **R-4.4 Token stash invisibility (risk #1 / finding 4).** If the protection filter and endpoint build
  *different* `OAuth2Request` instances (e.g. one uses `create(request)`, the other `create(context,
  request)`), the stashed `AccessToken` is lost → the endpoint 500s reading a null token. Guard: IT case 1
  (one request through filter + endpoint) asserts the client id resolves.
- **R-4.5 Realm parity (finding 6, risk #9) — the phase's silent-NPE risk.** `"realmObject"` was unseeded on
  CHF; the direct readers `OAuth2UrisFactory.get(OAuth2Request)` (hit at `authz_request:126`) and
  `UmaUrisFactory.get(OAuth2Request)` NPE on the `null`. Uniquely dangerous because line 126 **compiles** after
  the shell change and both the ported unit test and `UmaRouterIT` **mock** `OAuth2UrisFactory`, so neither
  catches it — it would surface only in the deferred e2e. Fixed framework-side by the 4a `ChfOAuth2Request`
  `"realmObject"` seed. Guard: `ChfOAuth2RequestTest` seed assertion + `UmaRouterIT` case 5 exercised through
  the **real** `OAuth2UrisFactory` (do **not** mock it) + IT case 7 (realm styles).
- **R-4.6 Body re-read (risk #1).** Closed by the buffered CHF entity — the audit filter reading
  `permission_request`'s body leaves it for the handler ([chf-patterns.md](chf-patterns.md) §7). Guard: IT
  case 1 reaches the handler after the request auditor ran.
- **R-4.7 `application/json` vs `application/json; charset=UTF-8`.** CHF `setEntity(Map)` appends the
  charset; Restlet emitted none. Benign, universally accepted for JSON in this migration. Recorded, not
  guarded.
- **R-4.8 4a is build-ahead (risk #19).** `ChfAccessTokenProtectionFilter` is wired to no route until 4b;
  its only guard is `ChfAccessTokenProtectionFilterTest` against the Restlet oracle. Retired when 4b wires
  it and `UmaRouterIT` exercises it. (Phase 5c inherits it already tested — a de-risking bonus.)

## Execution order

**4a:** `ChfAccessTokenProtectionFilter` (+ test) → seed `"realmObject"` in `ChfOAuth2Request` (+ test,
finding 6) → gate → `mvn -o -pl openam-oauth2 install -DskipTests`.
**4b:** `UmaErrorResponseFactory` + `AbstractUmaHttpEndpoint` (+ test, rewrite `UmaExceptionHandlerTest`)
→ re-base the three endpoints (+ port their tests) → `UmaAuditLogger` signature change → `UmaHttpRouteProvider`
+ services file → `UmaGuiceModule` edit → `RestEndpointServlet` uma-branch drop → web.xml flip → delete
`UmaRouterProvider` / `UmaExceptionHandler` / `UMAServiceEndpointApplication` → `UmaRouterIT` → `mvn -o -pl
openam-uma test` + `verify` → whole build `-am` → Cargo boot → (optional) `e2e/uma` well-known smoke → mark
Phase 4 `done` in [plan.md](plan.md) + record the deferred full-flow e2e.

<a id="as-built"></a>
## As-built (4b, 2026-07-23)

Landed exactly on the execution order above. Module green: `mvn -o -pl openam-uma verify` = **194 unit** +
**`UmaRouterIT` 11 IT**; the whole `-am` build assembles the WAR; the Restlet/`getCurrent()` import gate over the
three re-based endpoints + `UmaAuditLogger` + `UmaHttpRouteProvider` = **0**. New: `UmaHttpRouteProvider` +
`META-INF/services/org.forgerock.openam.http.HttpRouteProvider` (openam-uma); `web.xml` `/uma/*` moved from
`ForgeRockRest` to the `OpenAM` CHF servlet, beside `/xacml/*`. Deleted: `UmaRouterProvider`, `UmaExceptionHandler`
(+ test), `UMAServiceEndpointApplication`; `RestEndpointServlet` lost its `/uma` branch (now oauth2-only until
Phase 5), test updated.

Plan-gaps resolved in-flight (all minor, each flagged before applying):

- **`UmaException.getDetail()` widened package-private → `public`** — `UmaErrorResponseFactory` (new package)
  flattens `detail` into the error body; [D3](#d3) did not anticipate the cross-package read.
- **`UmaConstants.PAT_SCOPE`/`AAT_SCOPE` widened → `public`** — `UmaHttpRouteProvider`
  (`org.openidentityplatform.openam.uma`, per the new-package convention) wires the per-endpoint scopes; one source
  of truth beats duplicating the literals. The two now-orphaned Restlet binding-name constants
  `PERMISSION_REQUEST_ENDPOINT`/`AUTHORIZATION_REQUEST_ENDPOINT` were **deleted** (only users were the removed
  `@Provides` + `UmaRouterProvider`).
- **`UmaAuditLogger` re-base dropped 2 unused ctor params** (`OAuth2RequestFactory`, `TokenStore`) and a dead
  private `getClientId(Request)` — no caller anywhere, `@Inject`-only construction.
- **`UmaRouterIT` lives in `org.forgerock.openam.uma`**, not `…openidentityplatform.openam.uma`, so it can stub the
  **package-private** `UmaTokenStore.createPermissionTicket`/`readPermissionTicket`; the provider is `public` so it
  is still importable. Same reason `XacmlRouterIT` sits in its handler's package.
- **IT case 11 triggers the realm-layer CREST via an invalid FQDN** — `RealmContextFilter` catches its
  `BadRequestException` and renders **400 CREST** (`RealmContextFilter.java:87-90`), the exact native-CREST path
  [D4](#d4) rests on — rather than the plan's `realms/bogus`. Reason: the modern `realms/{realmId}` branch cannot be
  faithfully driven to its error state in-process. In production an unresolvable realm makes `RealmRoutingFactory`'s
  `Realm.of("bogus")` → `RealmLookup.lookup` **throw** `NoRealmFoundException`, caught at `RealmRoutingFactory.java:149`
  → clean **404 CREST**; no null-realm `RealmContext` is ever built. Under the test's Mockito `RealmLookup`, an
  unstubbed `lookup("bogus")` instead returns **null**, producing a null-realm `RealmContext` that NPEs the shared
  `OAuth2HttpAccessAuditFilter.getRealm` (`:116`) → a **test-only** 500. That NPE is a mock artifact, **not** a
  production defect: every production `RealmContext`-building site (`HostnameFilter:125`, `ChfRealmRouter:148`,
  `RealmContextFilter:265/272`) resolves a real realm or throws (→ 400/404), so `getRealm()` is never handed a null
  realm. The FQDN path pins the same D4 claim without depending on that mock edge. *(This corrects an earlier draft of
  this note that called the 500 a Phase-5 shared-infra follow-up; a code-review re-trace showed it is unreachable in
  production — see [code-review 2026-07-23](#code-review-2026-07-23).)*
- **Test note (case 5, the finding-6 guard):** `OAuth2UrisFactory.get` keys a `ConcurrentHashMap` on `baseUrl`;
  in-process `getHttpServletRequest()` is null, so the mocked `BaseURLProvider` must return a **non-null**
  `getRealmURL`/`getRootURL` (a null key NPEs `ConcurrentHashMap.get`). Case 5 confirms the 4a `"realmObject"` seed
  resolves through the **real** `OAuth2UrisFactory` — the transient 500 seen while writing the test was this mock
  gap at line 107, *past* the realmObject read at line 68, not a seed failure.

**Deferred** (unchanged): the Cargo boot smoke (criterion 7) and the `e2e/uma` well-known over-the-wire smoke, plus
the full register→PAT→permission→authz flow diff. Not yet committed.

<a id="code-review-2026-07-23"></a>
### Code review (2026-07-23)

A `/code-review` over the Phase-4 diff raised five findings; each was re-traced against the code before acting:

- **F1/F2 — null-realm 500 in `OAuth2HttpAccessAuditFilter.getRealm:116` + `ChfOAuth2Request.attributes:326`** —
  *rejected as a production defect.* Traced to the Mockito-default artifact described above: production
  `RealmLookup.lookup` **throws** for an unresolvable realm, so no null-realm `RealmContext` ever reaches these
  sites. Adding null guards to shared `/oauth2`+`/xacml`+`/uma` code would defend an unreachable state; only the
  misleading case-11 note was corrected.
- **F3 — the 405-body fix (`Endpoints.java`) ripples to XACML, unverified** — the core change was already covered by
  `EndpointsTest.unmappedVerbGives405WithA405Body` (a real PATCH dispatch). Fixed the residue: replaced
  `XacmlXmlErrorFilterTest`'s stale canned-501 case (whose comment described superseded behaviour) with a real
  `Endpoints.from` + filter composition asserting XML `<code>405</code>`.
- **F4 — `UmaRouterIT` leaks the empty `GuiceModuleLoader`** (`GuiceTestCase.teardownGuiceModules` restores only the
  `InjectorHolder`, not the loader) — fixed: an `@AfterMethod` resets the loader to the framework default via a
  package-local `GuiceModuleLoaderAccessor` (the default loader's constructor is package-private in
  `org.forgerock.guice.core`). `XacmlRouterIT` shares the same latent leak (unchanged here).
- **F5 — `Endpoints.java` used the `@Deprecated` `ResourceException.getException`** while the sibling
  `ChfAccessTokenProtectionFilter` used `newResourceException` — aligned `Endpoints.java` onto the non-deprecated
  factory (byte-identical output; the review's suggested direction pointed at the deprecated method).
