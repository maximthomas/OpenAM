# Phase 5c — `/oauth2/resource_set` → CHF: Detailed Plan

Execution plan for **step 5c** of [Phase 5](phase-5-oauth2.md) of the Restlet → CHF migration — the last
`/oauth2` endpoint before the flip. Parent tracker: [plan.md](plan.md); umbrella: [phase-5-oauth2.md](phase-5-oauth2.md);
the steps this one builds on: [phase-4-uma.md](phase-4-uma.md) (`ChfAccessTokenProtectionFilter`, the
`UmaHttpRouteProvider` routing template), [phase-5a-2.md](phase-5a-2.md) and [phase-5b-2.md](phase-5b-2.md)
(the `AbstractOAuth2Http*Endpoint` hierarchy); decisions: [decisions.md](decisions.md); reusable CHF patterns:
[chf-patterns.md](chf-patterns.md); test layers: [../../test-infrastructure.md](../../test-infrastructure.md).
Written 2026-07-29; branch `features/restlet-migration`. **All facts below were verified against the tree on
2026-07-29** — file and line references are to that state; the Restlet-internals facts were obtained by
disassembling the resolved fork (`org.openidentityplatform.openam.jakarta:org.restlet:16.2.0-SNAPSHOT`), not
read from upstream `org.restlet.jee:2.4.4` documentation — the fork is what runs.

> **Naming.** [plan.md](plan.md)'s phase table calls this step **5c**. This doc splits it into **5-E4** (a
> test-only live-oracle gate), **5c-1** (error-shape substrate) and **5c-2** (the handler) — the same
> reviewability/risk-isolation split 5a-2, 5b-1 and 5b-2 used.

## Context

The umbrella sizes this step as *"1 handler + 1 filter, Med risk"*
([phase-5-oauth2.md](phase-5-oauth2.md) step table), and by class count that is right:
`ResourceSetRegistrationEndpoint` is 367 L against `AuthorizeResource`'s ~600 L, its business logic is already
transport-free, and every collaborator it touches is neutral ([finding 11](#11--every-collaborator-is-already-transport-neutral)).

Two things the umbrella did not know make it the **least mechanical** of the remaining ports:

- the umbrella says *"guarded by `ChfAccessTokenProtectionFilter(null)`"*. That filter, shipped in 4a and
  **live on `/uma` since Phase 4**, emits a **CREST** error body. On `resource_set` the same rejection is
  **OAuth2-shaped** on the wire today, and the difference is not cosmetic — it is the field a resource server
  dispatches on ([finding 1](#1--the-resource_set-401-is-oauth2-shaped-not-crest--the-4a-filter-cannot-be-reused-unchanged));
- `resource_set` is the **only** endpoint in the whole migration that uses HTTP conditional requests, and
  Restlet's `ServerResource` implemented them *for* the endpoint. `Endpoints.from` has no equivalent, so a
  literal port silently drops lost-update protection
  ([finding 2](#2--restlets-conditional-request-machinery-is-load-bearing-and-chf-has-none)).

Build-ahead as usual for the handler: **nothing is routed** until 5d-1. ⚠ But **5c-1 is not build-ahead** —
it edits a class that is live on `/uma` today. That is why it is its own commit.

> **Convention.** New classes: `org.openidentityplatform.openam.oauth2.http`, CDDL header,
> `Copyright 2026 3A Systems LLC.`, **no `@since`** ([decisions.md](decisions.md)). Classes modified in place
> keep their header and gain a `Portions copyright 2026 3A Systems LLC.` line — except our own 2026 classes,
> which carry no `Portions` line.

## Scope & sizing — split three ways

| Step | Scope | New / changed | Risk |
|---|---|---|---|
| **5-E4** | **The live-Restlet contract lock.** **17 items / 18 rows** (row 2 splits into 2a/2b) added to `e2e/oauth2/oauth2-endpoints-test.spec.mjs` (`/oauth2/resource_set registration` describe), written **by observation**. Test-only, no main code. Gates D3, D4, D5, D6, D7, D9 | e2e spec only (0 main) | **High** — unrecoverable after 5d-1 |
| **5c-1** | **Error-shape substrate.** `ChfAccessTokenProtectionFilter` gains an opt-in error renderer (D2); new CHF `ResourceSetErrorFilter` (D3); new `HttpConditions` conditional-request helper (D6) | 1 modified (**live**) + 2 new + 3 tests | **Med-High** — the modified class is on the live `/uma` path |
| **5c-2** | **The handler.** `ResourceSetRegistrationHandler` + ported unit tests + `ResourceSetRouteCompositionIT` | 1 new + 2 tests + 1 IT | **Med** |

**Total new main classes: 3.** Plus one additive change to a Phase 4 class.

Order: **5-E4 → 5c-1 → 5c-2.** 5-E4 first because **six** of the decisions below are *settled by* what it records
and the [CONTINUE-bug lesson](phase-5b-1.md#2--the-continue-bug-makes-authorizes-filter-validation-unpredictable--record-it-do-not-derive-it)
applies with full force here — this endpoint's error surface has **three** producers
([finding 3](#3--three-error-producers-one-endpoint--and-only-one-of-them-is-the-endpoint)). 5c-1 before 5c-2
because the handler composes all three of its classes, and because isolating the live-path edit keeps the UMA
regression signal readable.

---

## Key research findings

<a id="1--the-resource_set-401-is-oauth2-shaped-not-crest--the-4a-filter-cannot-be-reused-unchanged"></a>
### 1. ⚠ The `resource_set` 401 is **OAuth2-shaped**, not CREST — the 4a filter cannot be reused unchanged

[chf-patterns §16](chf-patterns.md#16-the-restlet-statusservice-renders-a-crest-body-for-bare-error-statuses-phase-4)
established that a Restlet filter which rejects with `response.setStatus(new Status(4xx, throwable))` + `STOP`
leaves the entity null, and the app's outer `StatusFilter` then fills it with a **CREST**
`{code, reason, message}` body. Phase 4 relied on that and made `ChfAccessTokenProtectionFilter` reproduce it
(`ChfAccessTokenProtectionFilter:102-106`), pinned live by `e2e/uma/uma-test.spec.mjs:152`
(*"rejects an unauthenticated request in the CREST shape (phase-4 D5)"*).

**`resource_set` never reaches that `StatusFilter`.** Its Guice-built chain
(`OAuth2GuiceModule:407-413`) is

```
ResourceSetRegistrationExceptionFilter( AccessTokenProtectionFilter( null, …, ResourceSetRegistrationEndpoint ) )
```

so the resource-set exception filter is **outside** the protection filter. Disassembling
`org.restlet.routing.Filter.handle` confirms the ordering that makes this work: `beforeHandle` returning
`STOP` (2) skips only *that* filter's own `afterHandle`; the enclosing filter's `doHandle` still returns
`CONTINUE` (0), so its `afterHandle` runs. The exception filter therefore sees the protection filter's
entity-less 401 first and rewrites it via its
`else if (getStatus().getThrowable() instanceof OAuth2Exception)` branch (`:71-73`) into
`{error, error_description}` at the exception's own status.

Recorded live, and the spec even says so in a comment (`oauth2-endpoints-test.spec.mjs:130-149`):

| Request | Status | Body |
|---|---|---|
| `POST /oauth2/resource_set`, no `Authorization` | **401** | `{"error":"invalid_token", …}` |
| `POST /oauth2/resource_set`, `Bearer not-a-real-token` | **401** | `{"error":"invalid_token", …}` |

⇒ **D2**: `ChfAccessTokenProtectionFilter` needs a per-route error rendering, CREST by default (UMA unchanged,
its e2e row stays green) and OAuth2-shaped for `resource_set`.

⚠ The alternative — *let the CHF filter emit a bare status and have the new `ResourceSetErrorFilter` fill it*
— is **rejected**: CHF has no `StatusFilter` equivalent, so a bare status would reach the client body-less on
`/uma`, breaking a committed, live contract to save a constructor argument.

<a id="2--restlets-conditional-request-machinery-is-load-bearing-and-chf-has-none"></a>
### 2. ⚠ Restlet's conditional-request machinery is load-bearing, and CHF has **none**

`ResourceSetRegistrationEndpoint` looks like it handles conditional requests itself:

```java
private boolean isConditionalRequest() {                       // :301-303
    return !getConditions().getMatch().isEmpty();
}
```

It does not. That method only asks **"was an `If-Match` header sent at all?"**; the *matching* is done by the
framework, before the annotated method is ever called. Disassembled from the fork, 2026-07-29:

- `ServerResource.<init>` sets `conditional = true` (and `existing = true`, `negotiated = true`,
  `annotated = true`). `ResourceSetRegistrationEndpoint` never calls `setConditional(false)`.
- `ServerResource.handle()` → `if (isConditional()) doConditionalHandle()`.
- `doConditionalHandle()` → `if (getConditions().hasSome())` → because `existing` is true, it takes the
  info branch → `doGetInfo(Variant)` → `doHandle(MethodAnnotationInfo, Variant)`, **which invokes the
  `@Get` method** — `readOrListResourceSet()` — purely to obtain the current representation's `Tag`.
- `Conditions.getStatus(Method, RepresentationInfo)` compares with `Tag.equals(obj, /* checkWeakness */ false)`,
  so weakness is **ignored**: `If-Match: "123"` and `If-Match: W/"123"` both match a tag named `123`.
  A mismatch yields `Status.CLIENT_ERROR_PRECONDITION_FAILED` (**412**) with **no entity**, which the
  resource-set exception filter then renders as `{"error":"precondition_failed"}` (`:69-70`).

So the live contract is **two** conditions, not one:

| Request | Enforced by | Result |
|---|---|---|
| `PUT`/`DELETE` with **no** `If-Match` | the endpoint (`:188`, `:278`) | throws `ResourceException(512, "precondition_failed", …)` → see [finding 4](#4--the-512-throw-never-reaches-the-wire-as-512) |
| `PUT`/`DELETE` with a **stale** `If-Match` | **Restlet**, before the method runs | 412 + `{"error":"precondition_failed"}` |
| `GET` with `If-None-Match` matching | **Restlet** | 304 (`noneMatch` branch of the same method) |

⚠ **A literal port keeps only the first row.** `Endpoints.from` has no conditional-request support at all
(`Endpoints.java:60-63` dispatches on verb and nothing else; `@Consumes`/`@Payload`/`@PayloadTranslator` are
declared in `openam-http` and **never read** — [finding 9](#9--openam-https-consumespayload-annotations-are-dead-api)).
Porting `isConditionalRequest()` as *"is the header present"* — which is exactly what the Java reads like —
would make `If-Match: anything-at-all` succeed, **silently removing lost-update protection** from the endpoint
whose entire concurrency story it is. This is the single highest-value finding in the step, and it is
invisible in the endpoint's own source.

⇒ **D6**: implement conditional evaluation explicitly, in a small tested helper.

The GET-invoked-to-derive-the-tag detail is an *implementation* of Restlet's, not a contract: the port computes
the current ETag from the same `ResourceSetDescription` it already reads. Two observable consequences of
Restlet's route are worth knowing at 5d-1 all the same — a conditional `PUT`/`DELETE` performs an **extra store
read** today, and a conditional `DELETE` of an unknown `rsid` fails from the *GET's* `NotFoundException` rather
than the delete's. Both end at the same 404 body.

<a id="3--three-error-producers-one-endpoint--and-only-one-of-them-is-the-endpoint"></a>
### 3. Three error producers, one endpoint — and only one of them is the endpoint

Every `/oauth2/resource_set` error body comes from one of three places, and they do **not** share a shape
source:

| # | Producer | Trigger | Shape |
|---|---|---|---|
| A | `doCatch` → `ExceptionHandler.handle(Throwable, Response)` (`:296-299`) | anything the annotated method throws | `{error, error_description}` from `OAuth2RestletException.asMap()`, at the exception's status |
| B | `ResourceSetRegistrationExceptionFilter.afterHandle` (`:64-78`) | an error status the filter finds with **`getEntity() == null`** | 405 → `{"error":"unsupported_method_type"}`; 412 → `{"error":"precondition_failed"}`; status-throwable is an `OAuth2Exception` → that exception's `{error, error_description}`; **else** → 500 `server_error` |
| C | the app `StatusFilter` / `JSONRestStatusService` | an entity-less error that survived B | CREST `{code, reason, message}` |

Producer **C is unreachable on this route**: B fills the entity in every branch, so the CREST shape that
governs `/uma` never appears here. That is the whole of [finding 1](#1--the-resource_set-401-is-oauth2-shaped-not-crest--the-4a-filter-cannot-be-reused-unchanged).

⚠ **B's `else` branch NPEs.** `setExceptionResponse` (`:80-87`) reads
`response.getStatus().getThrowable()` and dereferences `throwable.getMessage()` with no null check. An
entity-less error status set by the *engine* (rather than by a filter that attached a throwable) has a null
throwable, so the branch designed to produce `500 server_error` instead throws an NPE out of `afterHandle`.
The most likely trigger is a media-type rejection — [finding 9](#9--openam-https-consumespayload-annotations-are-dead-api).
**5-E4 row 12 records what a client actually sees.** Do not reproduce a crash: whatever the observation, the
CHF port answers a real body ([D3](#d3)).

<a id="4--the-512-throw-never-reaches-the-wire-as-512"></a>
### 4. The `512` throw never reaches the wire as 512 — it is a **400 `server_error`**

`updateResourceSet:188-191` and `deleteResourceSet:278-281` throw
`new ResourceException(512, "precondition_failed", "Require If-Match header to …", null)`. That looks like it
pairs with the filter's `412` branch. It does not — the two are unrelated paths:

- the throw goes to producer **A**. `toOAuth2RestletException` (`ExceptionHandler:160-176`) tests
  `instanceof OAuth2RestletException` (no), `getCause() instanceof OAuth2RestletException` (the cause is
  **`null`** — the 4th constructor argument), `getCause() instanceof OAuth2Exception` (no), and falls to
  `new ServerException(throwable)` → **400**, error **`server_error`**
  ([chf-patterns §17](chf-patterns.md#17-oauth2exception--http-status-quirks-phase-5a-2b): `ServerException`
  is 400, not 500), message preserved;
- the filter's `412` branch is fed only by Restlet's own precondition evaluation
  ([finding 2](#2--restlets-conditional-request-machinery-is-load-bearing-and-chf-has-none)).

Confirmed live (`oauth2-endpoints-test.spec.mjs:97-104`): `PUT` without `If-Match` → **400**, `error_description`
contains `Require If-Match header to update Resource Set`. The spec does not currently assert `error`;
**5-E4 row 4 must pin it** so the port is not free to choose.

⇒ the port throws `ServerException("Require If-Match header to update Resource Set")` and lets the JSON base
map it. Neither `512` nor `precondition_failed` appears on this path.

<a id="5--etag-emission-and-format"></a>
### 5. ETag emission and format

`createJsonResponse` (`:317-330`) attaches `generateETag` (`:338-347`) to the representation, and Restlet's
HTTP layer turns that into an `ETag` response header. Facts:

- the tag is `new Tag(Integer.toString(resourceSetDescription.hashCode()), true)` — the `true` is
  `weak`, so the header is `ETag: W/"<hashCode>"`, and the value can be **negative** (`W/"-1543219"`);
- `generateETag` mutates the description to stabilise the hash: when `labels` is undefined it puts a null
  `labels`, re-hashes, then removes it (`:341-345`). Reproduce verbatim — the value is the client's
  concurrency token, and any change to how it is computed invalidates every ETag a resource server holds
  across the upgrade;
- it is attached on **POST (201)**, **PUT (200)** and **read GET (200)**, and **not** on
  `listResourceSets()` (`:249-263` returns a bare representation) nor on the 204 delete;
- e2e already proves an `ETag` header is present on POST and GET
  (`oauth2-endpoints-test.spec.mjs:78`, `:88`), but asserts only truthiness. **5-E4 row 5 pins the exact
  bytes** — the `W/` prefix is the part a naive port drops.

⚠ CHF sets no ETag for you. The handler writes `response.getHeaders().put("ETag", …)` itself.

**What the tag actually hashes, and why it is not the same on every route** (traced on the fifth pass,
2026-07-29 — [finding 17](#17--the-conditional-comparison-tag-comes-from-the-read-model-labels-and-all)
turns this into a decision):

`ResourceSetDescription.hashCode()` (`:263-270`) is
`id ⊕ clientId ⊕ policyUri ⊕ description.asMap().hashCode()`. It is **portable**: `String`, `List` and `Map`
hash codes are specified by the JLS, and a resource-set description holds only JSON-native values — so an ETag
issued before an upgrade still matches after one, which is the property [D5](#d5) leans on. But
`description` is **not the same map on every route**:

| Route | `labels` in the hashed description |
|---|---|
| `POST` / `PUT` response | from the **request body** (or `[]` when absent) — `:158-168`, `:200-207` |
| `GET` read response | from **`umaLabelsStore`**, resolved to label *names* — `:235-245` |
| `GET` list response | no tag at all — `:249-263` |

<a id="6--rsid-the-three-attachments-and-the-list-vs-read-split"></a>
### 6. `rsid`, the three attachments, and the list-vs-read split

`OAuth2RouterProvider:129-133` attaches **one** Restlet to three templates, in this order:

```java
router.attach("/resource_set/{rsid}", resourceSetRegistrationEndpoint);
router.attach("/resource_set",        resourceSetRegistrationEndpoint);
router.attach("/resource_set/",       resourceSetRegistrationEndpoint);
```

`getResourceSetId()` (`:305-307`) reads the `rsid` **request attribute**, which Restlet populates from the URI
template; on the two collection routes it is absent, and `readOrListResourceSet` (`:221-229`) branches on
`null || isEmpty` to list rather than read. `PUT`/`DELETE` on a collection route therefore reach
`store.read(null, owner)` — whatever that does is today's behaviour, and **5-E4 row 9** records it rather than
guessing.

On CHF the value arrives through the same mechanism the migration already uses: `ChfOAuth2Request.attributes()`
(`ChfOAuth2Request.java:379-399`) walks the context chain and merges every
`UriRouterContext.getUriTemplateVariables()` — **including nested ones**, which
[finding 12](#12--the-trailing-slash-route-cannot-be-expressed-with-equals-in-chf) relies on — so
`o2.getAttribute("rsid")` resolves with **no handler-side routing code**, exactly as
[phase-3a](phase-3a-oauth2request.md) designed.

⚠ *"Register all three matchers"* is what [plan.md](plan.md) risk #8 says, and it **does not work on CHF** —
see [finding 12](#12--the-trailing-slash-route-cannot-be-expressed-with-equals-in-chf) and [D9](#d9).

The list response is a JSON **array** built from a `HashSet<String>` (`:256-262`), so its **order is
unspecified**. Assert membership, never sequence — the existing e2e row already does (`toContain`), and a
port-side test that asserts an ordered array would be green by luck.

<a id="7--audit-matrix-and-the-body-contention-it-creates"></a>
### 7. Audit matrix — and the one place body contention is real

`OAuth2RouterProvider:128-130` wraps the endpoint in

```java
auditWithOAuthFilter(getRestlet(RSR_ENDPOINT), jsonAuditor(NAME, SCOPES), jacksonAuditor("_id"))
```

⇒ on CHF, per [3d](phase-3d-audit.md) (where `jsonAuditor` and `jacksonAuditor` collapse into one):

| Route | Request auditor | Response auditor |
|---|---|---|
| `resource_set`, `resource_set/`, `resource_set/{rsid}` | `HttpBodyAuditor.jsonAuditor("name", "scopes")` | `HttpBodyAuditor.jsonAuditor("_id")` |

This is the **first** CHF route in the migration where the audit filter and the handler both read the
**request** body — every earlier body-auditing route was `/access_token`-style form data the handler consumed
through `OAuth2Request`, and all three of 5b-2's endpoints used `noBodyAuditor` deliberately
([phase-5b-2 finding 8](phase-5b-2.md#8--none-of-the-three-gets-cache-headers)).

⚠ **Correcting this doc's own first two drafts** (fourth review pass, 2026-07-29). They said *"risk #1 is live
here"* and left it to a test. It is not live, and the mechanism matters more than the reassurance:

- `Entity.getJson()` **memoises** — `if (json == null) { … json = readJson(reader); } return json;`
  (commons `Entity.java:235-242`). The second reader gets the cached object; there is no stream to exhaust.
  Risk #1 is a **form**-body concern (`Form.fromRequestEntity`, the charset trap), not a JSON one;
- `AbstractHttpAccessAuditFilter.filter` (`:78-93`) calls `auditAccessAttempt(request, context)` **before**
  `next.handle(...)`, so the request detail is captured, and `getJson()` first memoised, *before* the handler
  runs at all.

Two consequences the plan had wrong. **(a)** The handler receives the *same map instance* the audit filter
parsed — see the mutation caution in [D8](#d8). **(b)** Composition IT row 2 as originally specified
(*"assert the audited detail after the handler has run"*) **cannot** catch a mutating handler, because the
audit event was already built. It still earns its place as the cheap proof that both readers coexist; it is
just not the guard [D8](#d8) needs, and D8 says so.

<a id="8--the-restlet-resources-package-is-not-deletable-at-5d-2"></a>
### 8. ⚠ `org.forgerock.oauth2.restlet.resources` is **not** wholly deletable at 5d-2

The package holds three classes, and only one of them is Restlet-coupled:

| Class | Restlet imports | Fate |
|---|---|---|
| `ResourceSetRegistrationExceptionFilter` | yes (`Filter`, `Request`, `Response`, `Status`) | delete at **5d-2** |
| `ResourceSetRegistrationHook` | **none** — `(String realm, ResourceSetDescription)` | **must survive**: implemented by `UmaResourceSetRegistrationHook` (openam-uma) and multibound in `UmaGuiceModule:69-70` |
| `ResourceSetDescriptionValidator` | **none** — pure `JsonValue` validation | **must survive**: the handler's validator |

[plan.md](plan.md)'s Phase 5d-2 bullet says *"delete `org.forgerock.oauth2.restlet.*`"*. Taken literally that
breaks the build in another module. Recorded here so 5d-2 does not have to rediscover it; the package **rename**
(to `org.forgerock.oauth2.resources`, updating the two openam-uma importers) belongs in **Phase 8**'s sweep, not
in a flip commit. The matching Guice cleanup is
[finding 15](#15--5d-2-must-also-unbind-the-guice-provider) — the two go in the same commit.

<a id="9--openam-https-consumespayload-annotations-are-dead-api"></a>
### 9. `openam-http`'s `@Consumes` / `@Payload` / `@PayloadTranslator` are dead API

`grep -rn "Consumes\|Payload\|PayloadTranslator" openam-http/src/main/java` outside the three declaration
files returns **nothing**: the annotations exist, are `@Retention(RUNTIME)`, are documented as *"the content
type that is consumed by the method"* — and are read by no code. `AnnotatedMethod` binds only `@Contextual`
parameters and the `Request`; `Endpoints.from` dispatches on verb alone.

Consequence for this port: Restlet's `@Post createResourceSet(JsonRepresentation entity)` declares its input
variant *through the parameter type*, and Restlet refuses a request whose `Content-Type` does not convert —
almost certainly **415**, which then meets producer B's NPE branch
([finding 3](#3--three-error-producers-one-endpoint--and-only-one-of-them-is-the-endpoint)). CHF, having no
media-type check, would accept the same request and try to parse the body.

**5-E4 row 12 decides what happens next** — see [D7](#d7) and the
[framework backlog](#framework-items-openam-http-is-ours) entry.

<a id="10--what-e2e-already-records-and-what-5-e4-must-add"></a>
### 10. What e2e already records, and what 5-E4 must add

Already green in `e2e/oauth2/oauth2-endpoints-test.spec.mjs:61-149` — keep, and treat as recorded oracle rows:

| Row | Records |
|---|---|
| POST create | **201**, `_id`, `user_access_policy_uri` containing `#uma/share/<id>`, an `ETag` (truthiness only) |
| GET read | 200, `name`/`scopes`/`type` round-trip, an `ETag` |
| GET list via `resource_set/?_queryId=*` | 200, array containing the id — pins the **trailing-slash attachment** |
| PUT without `If-Match` | **400** + `error_description` `Require If-Match header to update Resource Set` |
| PUT with `If-Match: *` | 200 and the update is applied |
| DELETE with `If-Match: *` | **204** |
| GET after delete | **404** `{"error":"not_found"}`, description contains the id |
| POST no bearer / unknown bearer | **401** `{"error":"invalid_token"}` |

`e2e/uma/uma-test.spec.mjs` additionally registers resource sets through this endpoint
(`:54`, and `oauth2-fixtures.mjs:410`) for its 11 UMA rows — so after 5d-1 the **UMA suite doubles as a
cross-check** on the port. Note it in the 5d-1 diff notes.

Missing, and only recordable before 5d-1 (**5-E4**):

1. `PUT` with a **stale** `If-Match` (a syntactically valid tag that is not current) → 412? body? (gates **D6**)
2. `PUT`/`DELETE` with `If-Match` echoing the **exact** `ETag` value the server returned, **including the
   `W/` prefix** → must succeed (proves weakness is ignored, per finding 2). ⚠ **Split by origin and run
   both against a resource set that HAS labels**
   ([finding 17](#17--the-conditional-comparison-tag-comes-from-the-read-model-labels-and-all)):
   **2a** ETag taken from a `GET` → expected to match; **2b** ETag taken from the `POST`/`PUT` response →
   **may 412**, because the two hash different `labels` sources. Record whichever happens; do not assume
   they agree, and do not "fix" a 412 into a match
3. `GET` with `If-None-Match: <current ETag>` → **304**? and with a stale one → 200 (gates **D6**).
   **Capture the 304's headers**: Restlet reaches it through `setStatus` with a null entity, so it is expected
   to carry **no `ETag`** and no body — record that rather than assuming RFC 7232's SHOULD was followed
4. `PUT` without `If-Match`: the `error` **field**, not just the description (gates **D4**)
5. the **exact `ETag` bytes** on POST/PUT/GET — `W/"…"` vs `"…"` (gates **D5**)
6. `DELETE` without `If-Match` → status + `error` (the delete twin of row 4)
7. `POST` with a duplicate name for the same owner → the in-band 400 built at `:150-155`
   (`error` is `Status.CLIENT_ERROR_BAD_REQUEST.getReasonPhrase()` — literally **`"Bad Request"`**, a
   reason phrase in an `error` field; record it, do not tidy it)
8. `POST` with an invalid description (missing `name`, missing `scopes`, non-array `scopes`) → the
   `BadRequestException` texts from `ResourceSetDescriptionValidator`
9. `PUT` and `DELETE` on the **collection** routes (`/resource_set`, `/resource_set/`) — `rsid` is null
   (finding 6). ⚠ **Record both `If-Match` forms**, because they take different paths: with `If-Match: *`
   the conditional layer passes (the list representation exists) and the method runs into
   `store.read(null, owner)` → `query(equalTo(RESOURCE_SET_ID, null))` → expected
   `NotFoundException("Resource set does not exist with id null")` → 404; with a **concrete** tag the
   conditional layer 412s first, because `listResourceSets()` (`:249-263`) attaches **no** `Tag`
10. `GET`/`PUT`/`DELETE` for an `rsid` owned by a **different** resource owner → 404 vs 403
11. `PATCH` (a verb the endpoint does not map) → the framework 405 and whether the body is
    `{"error":"unsupported_method_type"}` (this is producer B's 405 branch, and it is **not**
    `method_not_allowed` — contrast [D10](phase-5b-2.md#d10))
12. `POST` with `Content-Type: text/plain` and with **no** `Content-Type` → status and body (gates **D7**;
    expected to expose finding 3's NPE)
13. cache headers on every verb (expected: none — `resource_set` is not `OAuth2Filter`-wrapped,
    [phase-5b-2 finding 8](phase-5b-2.md#8--none-of-the-three-gets-cache-headers))
14. `Content-Type` of success and error bodies (`application/json`, with or without `charset`) — CHF's
    `setEntity(Map)` adds `; charset=UTF-8` ([chf-patterns §6](chf-patterns.md#6-headerentity-gotchas-chf-response)),
    so this row decides whether a divergence row is owed, as it was for `/tokeninfo` in 5a-2
15. **`HEAD`** on `/resource_set` and `/resource_set/{rsid}` → 200-with-no-body (Restlet maps HEAD→GET) or
    something else (gates [finding 13](#13--head-is-served-by-restlet-and-405d-by-chf--and-it-is-not-a-5c-problem);
    the answer is owed to **every** Phase 5 endpoint, not just this one)
16. `POST` to `/resource_set/{rsid}` — the same resource is attached to all three templates, so a create
    against the item URL is presumably accepted with `rsid` ignored. Record it
17. `GET /oauth2/resource_set/a/b` — two segments below the endpoint, matching no attachment. Restlet's
    **router** answers this *outside* the exception filter ⇒ expected CREST 404, not
    `{"error":…}` (gates the filter placement in [D9](#d9))

<a id="11--every-collaborator-is-already-transport-neutral"></a>
### 11. Every collaborator is already transport-neutral

Verified by import scan — no class below carries a Restlet type, so **none is ported**, only injected:
`ResourceSetDescriptionValidator`, `ResourceSetRegistrationHook`, `ResourceSetLabelRegistration`,
`ExtensionFilterManager` / `ResourceRegistrationFilter`, `UmaLabelsStore`, `ResourceSetStore`,
`OAuth2ProviderSettingsFactory`. The only two Restlet-shaped members of the endpoint are
`JacksonRepresentationFactory` (a response builder, replaced by `response.setEntity(map)`) and the
`ExceptionHandler` (replaced by the JSON base's `@ExceptionHandler`).

Client id and resource owner come from the stashed token —
`requestFactory.create(request).getToken(AccessToken.class).getClientId()` (`:309-315`) — which
`ChfAccessTokenProtectionFilter:84` already stashes on the **cached** `OAuth2Request`
([phase-5b-2 finding 14](phase-5b-2.md#14--the-request-cache-is-load-bearing-here-and-nothing-tests-it) is the
reason that sharing must be tested with the *real* factory, not a mock).

<a id="12--the-trailing-slash-route-cannot-be-expressed-with-equals-in-chf"></a>
### 12. ⚠ The trailing-slash route **cannot be expressed with `EQUALS`** in CHF

Found reviewing this plan's own [D9](#d9), 2026-07-29, by reading commons
`org.forgerock.http.routing.UriRouteMatcher` (`../commons/commons/http-framework/core`). Risk #8's
instruction — *"register all three CHF routes; trailing-slash is a distinct CHF route"* — is **not
implementable as written**:

- `UriTemplateParser.createRegex` (`:194-252`) begins with
  `removeTrailingSlash(removeLeadingSlash(uriTemplate))`. So the template `resource_set/` compiles to the
  **same** regex as `resource_set` — `(\Qresource_set\E)` — and the two `addRoute` calls are duplicates, not
  distinct routes;
- the URI they are matched against **keeps its trailing slash**. `evaluate` (`:94-119`) matches
  `joinPath(pathElements)`, and `Paths.getPathElements` (`:67-90`) splits with
  `PATH_SPLIT_PATTERN.split(rawPath, -1)` — limit `-1` **preserves trailing empty elements** — so
  `resource_set/` → `["resource_set", ""]` → `"resource_set/"`.

⇒ **`EQUALS "resource_set/"` matches nothing, and `EQUALS "resource_set"` does not match `/oauth2/resource_set/`
either.** A literal reading of risk #8 ships a **404 on a live, e2e-covered URL** — `oauth2-endpoints-test.spec.mjs:92`
lists through `/oauth2/resource_set/?_queryId=*` and expects 200.

The 5d-1 e2e re-run would have caught it, which is the good news. It is recorded here so the flip does not
spend a debugging cycle on it, and because the fix is a **routing shape**, not a matcher string —
see [D9](#d9). Two supporting facts, both verified in the same read:

- a template variable compiles to `([^/]+)` (`:212`), which **cannot match an empty segment** — so
  `{rsid}` alone never covers the collection routes;
- `EQUALS ""` compiles to `(\Q\E)` and matches the empty remaining URI, which is what makes the nested-router
  fix work.

⚠ This is a **commons** behaviour, not an openam-http one, so it is routed around rather than fixed
([docs/framework-ownership.md](../../framework-ownership.md): a commons fix costs a release cycle, and
changing trailing-slash semantics in `UriRouteMatcher` would move every CHF route in the ecosystem).

<a id="13--head-is-served-by-restlet-and-405d-by-chf--and-it-is-not-a-5c-problem"></a>
### 13. ⚠ `HEAD` is served by Restlet and **405'd by CHF** — and it is not a 5c problem

`ServerResource.doHandle(Method, Form, Representation)` opens with, in bytecode,
`if (Method.HEAD.equals(method)) method = Method.GET;` before looking up the annotation — so **every** Restlet
resource with a `@Get` answers `HEAD` today, the connector stripping the body.

`Endpoints.from` builds its map from `{DELETE, GET, POST, PUT}` only (`Endpoints.java:60-63`); `HEAD` finds no
entry and takes the unmapped-verb branch → **405**
([chf-patterns §2](chf-patterns.md#2-endpointsfrom--semantics-that-matter) already records the 405, but not
that Restlet answered 200).

⇒ this is a **cross-cutting Phase 5 divergence affecting all 15 endpoints**, not a resource_set one. It has
never been recorded: [plan.md](plan.md)'s divergence row 3 and row 8 are about the *body* of a 405 both stacks
produce, which is a different case. 5-E4 row 15 pins it cheaply on this endpoint; the umbrella decision — fix
(`Endpoints` maps `HEAD` → the `GET` method, ~2 lines, [C3](#framework-items-openam-http-is-ours)) or record —
belongs to **5d-1**, and must be made before the flip, since after it there is no oracle left to ask.

<a id="14--the-protection-filters-chosen-status-is-overridden-by-the-exceptions-and-a-500-becomes-a-400"></a>
### 14. ⚠ The protection filter's chosen status is **overridden by the exception's** — a 500 becomes a 400

Found on the third review pass, 2026-07-29, by reading the four OAuth2 exception constructors rather than
trusting their names. Producer B does **not** keep the status the protection filter set:

```java
setExceptionResponse(response, exception.getStatusCode(), exception.getError());   // :73
…
response.setStatus(new Status(statusCode, response.getStatus().getThrowable()));   // :86
```

So the wire status comes from `OAuth2Exception.getStatusCode()`, not from the `new Status(n, e)` the filter
built. Verified constructors:

| Protection-filter catch (`AccessTokenProtectionFilter:59-92`) | Status it sets | `getStatusCode()` | `getError()` | **Wire** |
|---|---|---|---|---|
| no/expired/invalid token | 401 | 401 | `invalid_token` | 401 `invalid_token` |
| scope check fails | 403 | 403 | `insufficient_scope` | 403 `insufficient_scope` |
| `NotFoundException` | 404 | 404 | `not_found` | 404 `not_found` |
| **`ServerException`** | **500** | **400** | `server_error` | ⚠ **400 `server_error`** |

The last row is the trap. `ServerException(String)` is `super(400, "server_error", …)`
([chf-patterns §17](chf-patterns.md#17-oauth2exception--http-status-quirks-phase-5a-2b)), so a token-store
failure that the filter deliberately reported as a **500** reaches the client as a **400**. The same
`ServerException` on `/uma` — which has no exception filter — stays a **500** CREST body, because
`ChfAccessTokenProtectionFilter.crestError(500, e)` uses the *passed* code.

⇒ [D2](#d2) must derive **both** the status and the error from the exception in `OAUTH2` mode, and keep the
passed code in `CREST` mode. A renderer that only swaps the body shape and reuses `crestError`'s status
argument answers 500 where Restlet answers 400 — on the one path nobody will think to test.

⚠ Not practically reachable from e2e (it needs the token store to fail), so this one is **derived from
source**, not recorded. That is a deliberate exception to the step's "record it, do not derive it" rule and it
is flagged as such: the trace above is short and total, and composition IT row 10 pins the port.

<a id="15--5d-2-must-also-unbind-the-guice-provider"></a>
### 15. 5d-2 must also delete the Guice provider, not just the classes

`OAuth2GuiceModule:405-413` provides `@Named(OAuth2Constants.Custom.RSR_ENDPOINT) Restlet` — the only
consumer of `ResourceSetRegistrationExceptionFilter` and of `AccessTokenProtectionFilter`. It is read by
`OAuth2RouterProvider:128` via `getRestlet(...)`. At **5d-2** all three go together: the provider method, the
`RSR_ENDPOINT` lookup, and the two Restlet filter classes. `RSR_ENDPOINT` itself lives in **openam-core**
(`OAuth2Constants.java:808`) and is a plain `String` constant — leave it or clean it in Phase 8, but do not
delete openam-core's constant from a 5d commit.

<a id="16--the-create-path-needs-the-realm-object-and-the-phase-4-urisfactory-trap-does-not-recur"></a>
### 16. The create path needs the **realm object**, and the Phase 4 `UrisFactory` trap does **not** recur

Traced on the fourth pass because `user_access_policy_uri` — asserted by the e2e 201 row — is not built by the
endpoint at all. `OpenAMResourceSetStore.create` (`:67-78`) does:

```java
resourceSetDescription.setId(idGenerator.generateTokenId(null));
String policyEndpoint = oauth2UrisFactory.get(request).getResourceSetRegistrationPolicyEndpoint(id);
resourceSetDescription.setPolicyUri(policyEndpoint);
```

`oauth2UrisFactory.get(OAuth2Request)` is exactly the collaborator whose CREST-`HttpContext` assumption made
`/uma/.well-known/uma-configuration` **500 on every request** after the Phase 4 flip ([plan.md](plan.md)
Phase 4 row). Two things checked rather than assumed:

- **The trap does not recur.** `get(OAuth2Request)` (`:68-71`) delegates to `get(OAuth2Request, Realm)`
  (`:106-117`), which reads `oAuth2Request.getHttpServletRequest()` — on CHF that is
  `ChfOAuth2Request:267` → `ChfContexts.servletRequest(context)`, the Phase 4 fix. No `HttpContext` is
  consulted on this overload at all. ✓ (The `HttpContext`-aware overload is `get(Context, Realm)` at `:80`,
  which this path never takes.)
- ⚠ **But it needs the realm object.** `get(OAuth2Request)` starts with
  `Realm realm = request.getParameter(RestletRealmRouter.REALM_OBJECT)` and immediately calls
  `realm.asPath()` — **no null guard**. `ChfOAuth2Request.attributes()` seeds
  `OAuth2Constants.Custom.REALM_OBJECT` (`:396`, the same `"realmObject"` literal) only when a `RealmContext`
  is in the chain. ⇒ a `resource_set` route mounted **outside** `RealmContextFilter` NPEs on every create.
  [D9](#d9) mounts it inside, exactly as UMA does, so this is satisfied by construction — and it is written
  down because it is invisible from the handler's own source.

⚠ **Consequence for the composition IT, which this plan had wrong.** The IT chain as first specified was
`RootContext` + `AttributesContext` + `UriRouterContext` — **no `RealmContext`**. With a mocked
`ResourceSetStore` the create row would still pass, because `oauth2UrisFactory` lives *inside* the store and
is never called; and `hook.resourceSetCreated(o2.getParameter("realm"), …)` would receive a silent `null`
against a mocked hook. The IT must carry a `RealmContext` and assert the realm reaches the hook (row 12),
or it certifies a chain that cannot serve a real request.

<a id="17--the-conditional-comparison-tag-comes-from-the-read-model-labels-and-all"></a>
### 17. ⚠ The conditional comparison tag comes from the **read model** — labels and all

Fifth pass, 2026-07-29. [Finding 2](#2--restlets-conditional-request-machinery-is-load-bearing-and-chf-has-none)
established that Restlet invokes the `@Get` method to obtain the tag it compares `If-Match` against. Combined
with the table in [finding 5](#5--etag-emission-and-format), that has a consequence neither finding stated:

> the tag a conditional `PUT`/`DELETE` is compared against is **`readResourceSet`'s** tag — computed over a
> description whose `labels` came from **`umaLabelsStore`**, not from the store row and not from the request.

⇒ **the port must not compute the current ETag from a bare `store.read`.** Doing so — the obvious
implementation, since the handler already reads the description to update it — yields a different hash for
**every resource set that has labels**, so every conditional request from a real client would 412. The port
must rebuild `readResourceSet`'s exact model first: `store.read`, then
`umaLabelsStore.forResourceSet(realm, owner, id, false)` mapped to `getName()`, then
`description.put("labels", …)`, then hash.

Two further facts, both verified and both **pre-existing**, neither to be "fixed" here:

- **`umaLabelsStore.query` returns a `new HashSet<>()`** (`UmaLabelsStore.java:256-286`), and
  `readResourceSet` iterates it into a `List` (`:235-241`) whose `hashCode` is **order-sensitive**. For a
  resource set with two or more labels the ETag therefore depends on `HashSet` iteration order — deterministic
  for given content within a JVM, but not a property anyone designed. **Reproduce the iteration verbatim; do
  not sort.** Sorting would look like a cleanup and would invalidate every ETag in the field.
- **A `POST`/`PUT` response ETag need not equal the `GET` ETag for the same resource set**, because the two
  hash different `labels` sources (finding 5's table). A client that stores the ETag from its create response
  and sends it as `If-Match` on the next update can therefore get a **412** where a client that re-reads first
  succeeds. That is today's behaviour on live Restlet; 5-E4 rows 2a/2b record it rather than assuming the two
  agree.

⚠ This is the finding that makes [D6](#d6) more than a header parser, and it is the one most likely to be
missed: every unit test written with an unlabelled resource set passes either way.

<a id="18--the-extension-point-sees-a-description-without-labels-and-without-an-id"></a>
### 18. The extension point sees a description **without labels and without an id**

Sixth pass, 2026-07-29 — the last collaborator this plan had not traced.
`ResourceRegistrationFilter` (`org.forgerock.openam.oauth2.extensions`) has **zero implementations in-tree**:
it is a pure SPI for deployments to plug into, and `ExtensionFilterManager.getFilters(...)` returns an empty
list on a stock install. So nothing exercises it, nothing tests it, and a port that got the ordering wrong
would look perfectly green.

Its javadoc makes the ordering a contract: *"changes made to the `resourceSet` object will be persisted"*
(before) versus *"will **not** be persisted"* (after). The exact create sequence (`:158-181`):

| # | Step | State the extension sees |
|---|---|---|
| 1 | `labels` captured, then **removed** from the description (`:158-159`) | — |
| 2 | `beforeResourceRegistration(desc)` (`:160-162`) | **no `labels`**, **no `_id`**, **no `policyUri`** — the store assigns both in step 3 (`OpenAMResourceSetStore:69-72`) |
| 3 | `store.create(request, desc)` (`:163`) | — |
| 4 | `labels` re-added, or `[]` when absent (`:164-168`) | — |
| 5 | `labelRegistration.updateLabelsForNewResourceSet(desc)` (`:169`) | — |
| 6 | `afterResourceRegistration(desc)` (`:170-172`) | `labels` present, `_id` and `policyUri` populated |
| 7 | `ResourceSetRegistrationHook`s (`:176-178`), then **201** | — |

⇒ port the sequence exactly, and do **not** "tidy" the labels strip/re-add into a single pass around
`store.create`: steps 2 and 6 are the observable boundary, and moving either changes what a customer
extension receives. Note also that step 2 runs *after* the duplicate-name check (`:149-156`), so an extension
never sees a request that is about to be rejected as a duplicate.

⚠ **A dead branch, faithfully reproduced.** `generateETag`'s guard `if (!description.isDefined(LABELS))`
(`:341-345`) is **unreachable on every response path**: `createJsonResponse` has exactly three callers —
create, update and read — and all three define `labels` before calling it (steps 4/5 above, `:200-207`,
`:245`). Reproduce it anyway ([D5](#d5) — it costs three lines and removing it is a behaviour change nobody
can prove safe), but do not spend time reasoning about when it fires. It does not.

---

## Design decisions

<a id="d1"></a>
### D1 — `ResourceSetRegistrationHandler` extends `AbstractOAuth2HttpJsonEndpoint`

`doCatch` calls the **2-arg** `ExceptionHandler.handle(Throwable, Response)` (`:296-299`) — the JSON entry
point — so by the [5b-2 finding 1](phase-5b-2.md#1--only-one-of-the-three-is-a-browser-endpoint-the-doccatch-arity-decides)
rule this is a JSON endpoint. The base's `onError` maps `OAuth2Exception → {error, error_description}` at the
exception's status, which is byte-identical to producer **A**.

⚠ The base also appends `state` when the request carries one
([expected divergence row 10](plan.md#expected-divergences-at-the-flip)). A resource server has no reason to
send `state`, so this is inert here — but it is the same shared behaviour, so the row already covers it.

**Do not override `onError`** — an override drops the annotation.

<a id="d2"></a>
### D2 — `ChfAccessTokenProtectionFilter` gains an opt-in error renderer; CREST stays the default

```java
public enum ErrorShape { CREST, OAUTH2 }

public ChfAccessTokenProtectionFilter(String requiredScope, TokenStore ts, OAuth2RequestFactory rf) {
    this(requiredScope, ts, rf, ErrorShape.CREST);          // existing ctor delegates -- UMA untouched
}
public ChfAccessTokenProtectionFilter(String requiredScope, TokenStore ts, OAuth2RequestFactory rf,
        ErrorShape errorShape) { … }
```

`CREST` keeps `ResourceException.newResourceException(code, msg).toJsonValue().getObject()` verbatim
(`:102-106`) **at the code the call site passed**. `OAUTH2` ignores that code and takes **both** the status and
the error from the exception:

```java
// OAUTH2: producer B's setExceptionResponse -- exception.getStatusCode(), exception.getError(), getMessage()
OAuth2Error e2 = OAuth2Error.of(e.getStatusCode(), e.getError(), e.getMessage());
Response r = new Response(Status.valueOf(e2.getStatusCode()));
r.setEntity(e2.asMap());
```

⚠ **The status must come from the exception, not from `crestError`'s argument** — that is
[finding 14](#14--the-protection-filters-chosen-status-is-overridden-by-the-exceptions-and-a-500-becomes-a-400):
`ServerException` is reported by the filter as **500** and reaches the client as **400**. Reusing the passed
code would be the natural implementation and would be wrong on exactly that path.

Values, all read from the constructors: `InvalidTokenException` → 401 `invalid_token`;
`InsufficientScopeException` → 403 `insufficient_scope`; `NotFoundException` → 404 `not_found`;
`ServerException` → **400** `server_error`.

⚠ **The `null`-scope case is not the differentiator.** `resource_set` passes `null` (validity-only, per
`OAuth2GuiceModule:411`), but so could a future UMA route; the shape is a *route* property, not a scope
property. Keying the shape off `requiredScope == null` would be a coincidence dressed as a rule.

*Alternative rejected:* a second filter class. It would duplicate the token-reading logic — the part with the
`InvalidGrantException`/`NotFoundException`/`ServerException` mapping that is easy to get subtly wrong — to
vary four lines of rendering.

**Blast radius:** `/uma` is live. The commit's gate is `mvn -o -pl openam-uma test` **plus** the 11-row
`e2e/uma` suite, whose `:152` row asserts the CREST shape explicitly.

<a id="d3"></a>
### D3 — a CHF `ResourceSetErrorFilter`, scoped to the three routes, mounted **inside** `OAuth2ErrorFilter`

Ports producer **B** as a CHF response-rewriting `Filter` (the `XacmlXmlErrorFilter` shape), with the
NPE branch closed.

**Guard first, exactly as Restlet's `entity == null` did**: the filter acts only on a response that is
`>= 400` **and** whose body is either absent or CREST-shaped (`code` present, `error` absent). Anything
already carrying `error` is returned untouched — that is what makes it idempotent under the root
`OAuth2ErrorFilter`, and it is a **guard, not a table row**, so the rows below cannot be read as
unconditional:

| Status in | Body out |
|---|---|
| 405 | `{"error":"unsupported_method_type"}` |
| 412 | `{"error":"precondition_failed"}` |
| any other ≥ 400 | `{"error":"server_error","error_description":"<message, or null>"}` at **500** |

The third row is the honest translation of B's `else`: on Restlet the branch was reached with a null throwable
and crashed, so *"what it did"* is not a contract worth reproducing — it produced whatever the engine makes of
an NPE. The port answers the shape B was **written** to answer, and 5-E4 row 12 records how far that is from
what a client sees today. If the observation shows something else entirely (say Restlet answers a clean 415
before the filter runs), adjust this row and record the difference; do not adjust it to reproduce a stack trace.

**Ordering is load-bearing.** At 5d-1 the whole `/oauth2` root is wrapped in `OAuth2ErrorFilter`
([phase-5-oauth2 §5d-1](phase-5-oauth2.md#oauth2httprouteprovider-new-orgforgerockopenamoauth2rest--5d-1)),
which rewrites any ≥400 JSON body that has `code` and no `error` (`OAuth2ErrorFilter:77`). So:

```
OAuth2ErrorFilter( … router … ResourceSetErrorFilter( audit( protect( Endpoints.from(handler) ) ) ) )
```

`ResourceSetErrorFilter` runs first on the way out and always leaves an `error` key, so `OAuth2ErrorFilter`
sees an already-OAuth2-shaped body and returns it untouched — **idempotent by construction**, which is exactly
the property its `containsKey("error")` guard was written for. Without the inner filter a 405 here would become
`method_not_allowed` ([D10](phase-5b-2.md#d10)) instead of `unsupported_method_type`, silently retargeting
this endpoint's spec-defined error onto the generic one.

⚠ **`resource_set` is the one `/oauth2` route that keeps a non-generic error vocabulary** — the same carve-out
UMA got in [phase-4 D4](phase-4-uma.md), for the same reason
([draft-hardjono-oauth-resource-reg-04 §3](https://tools.ietf.org/html/draft-hardjono-oauth-resource-reg-04#section-3)).

<a id="d4"></a>
### D4 — the missing-`If-Match` rejection is a `ServerException`, not a 412 (**gated on 5-E4 rows 4, 6**)

```java
throw new ServerException("Require If-Match header to update Resource Set");   // -> 400 server_error
```

Per [finding 4](#4--the-512-throw-never-reaches-the-wire-as-512): 400 + `server_error` + the verbatim message
is what live Restlet emits, and `ServerException` is the exception whose `getStatusCode()` is 400
([chf-patterns §17](chf-patterns.md#17-oauth2exception--http-status-quirks-phase-5a-2b)). The delete twin keeps
its own wording (`"Require If-Match header to delete Resource Set"`).

⚠ Do **not** "fix" this to 428 `Precondition Required` or to the 412 the filter can produce. It is a wire
contract a resource server may branch on, and it is a parity migration; if it is worth changing it is worth a
post-migration ticket ([T5](#post-migration-tickets)).

<a id="d5"></a>
### D5 — ETag is written by the handler, weak, from the unchanged hash (**gated on 5-E4 row 5**)

```java
response.getHeaders().put("ETag", "W/\"" + etagValue(description) + "\"");
```

`etagValue` is `generateETag`'s body ported verbatim, **including** the `!isDefined(LABELS)` round-trip
(`:341-345`) — which is **dead code on every response path**, reproduced because removing it is a behaviour
change nobody can prove safe ([finding 18](#18--the-extension-point-sees-a-description-without-labels-and-without-an-id)).
Attach on POST/PUT/read-GET; **not** on list-GET or the 204 delete
([finding 5](#5--etag-emission-and-format)).

**Portability is established, not assumed** (fifth pass): `ResourceSetDescription.hashCode()` (`:263-270`)
combines `id`, `clientId`, `policyUri` and `description.asMap().hashCode()`, and the `String`/`List`/`Map`
hash codes it bottoms out in are **specified by the JLS**. A description holds only JSON-native values, so an
ETag issued before an upgrade still matches after one. The port **must not** reformat the value — no
`Math.abs`, no padding, no switch to a digest.

⚠ **"Verbatim" has a precise scope here**, and it is wider than `generateETag`. It covers (a) the dead
`!isDefined(LABELS)` round-trip, (b) `Integer.toString` + weak tag, **and (c) the model the hash is taken
over** — which differs per route and is what
[finding 17](#17--the-conditional-comparison-tag-comes-from-the-read-model-labels-and-all) is about. Note the
asymmetry in effort: (a) is unreachable and costs three lines, while (c) is reachable on every conditional
request and is where the port actually goes wrong. Getting (a) and (b) right while hashing the wrong
description produces a plausible ETag that matches nothing.

<a id="d6"></a>
### D6 — conditional evaluation in a small tested helper, not in the framework (**gated on 5-E4 rows 1–3**)

New `HttpConditions` (package-private-ish value type in `org.openidentityplatform.openam.oauth2.http`):

```java
static HttpConditions of(Request request);        // parses If-Match / If-None-Match
boolean hasIfMatch();                             // == Restlet's isConditionalRequest()
boolean matches(String currentEtagValue);         // "*" matches; weakness ignored; comma lists supported
boolean noneMatches(String currentEtagValue);
```

Matching rules copied from the disassembled `Conditions.getStatus`
([finding 2](#2--restlets-conditional-request-machinery-is-load-bearing-and-chf-has-none)): `*` matches any
existing entity; otherwise compare **tag names only**, so `W/"x"` ≡ `"x"`; a comma-separated list matches if
any member does.

Handler use:

- `PUT`/`DELETE`: `if (!c.hasIfMatch()) throw ServerException(...)` (D4); then compute the **current** ETag
  and `if (!c.matches(etag)) return precondition-failed` — a **412 whose body `ResourceSetErrorFilter`
  supplies**, so the two filters' contracts stay in one place rather than being duplicated inline;
- `GET` read: `if (c.noneMatches(etag)) return 304` with no body.

⚠ **"the current ETag" means `readResourceSet`'s tag, not the store row's.** Extract one
`currentEtag(rsid, owner)` helper that rebuilds the read model — `store.read`, `umaLabelsStore` labels,
`description.put("labels", …)`, then `generateETag` — and call it from the `GET`, `PUT` and `DELETE` paths
alike, exactly as Restlet reached one `@Get` method from all three
([finding 17](#17--the-conditional-comparison-tag-comes-from-the-read-model-labels-and-all)). Two separate
hash sites is how the labels source drifts between them.

⚠ **Test with a labelled resource set.** Every conditional row written against an unlabelled one passes
whether or not the model is right — the same false-green shape as 5b-2's unstubbed mocks.

**Why not in `openam-http`.** The migration's standing rule is
[fix the framework, don't work around it](chf-patterns.md#14-framework-defects-fix-them-dont-pattern-around-them-2026-07-21) —
but that rule is about **defects** (F1–F4 were things `Endpoints` did wrongly). Conditional-request support is a
*missing generic feature* with exactly **one** consumer in the codebase, and putting it in `Endpoints` means
designing an ETag-production hook for every annotated endpoint that will never use one. A ~60-line helper in
the OAuth2 package, fully unit-tested, is the proportionate answer.

⚠ If review disagrees, the framework version is a clean additive change (an optional
`@Etag`-producing method discovered like `@ExceptionHandler` already is) and this decision should be revisited
**before** 5c-2 lands, not after — the handler's shape depends on it. Recorded in the
[framework backlog](#framework-items-openam-http-is-ours).

<a id="d7"></a>
### D7 — media-type behaviour is **recorded, then decided** (**gated on 5-E4 row 12**)

Three outcomes, and the plan commits to the response for each rather than to a guess:

| 5-E4 row 12 shows | 5c-2 does |
|---|---|
| Restlet answers a clean **415** with a body | reproduce: guard the body parse and return 415 through `ResourceSetErrorFilter` |
| Restlet answers a **500 / stack trace** (finding 3's NPE) | **do not reproduce.** Parse the body regardless of `Content-Type`, as `ChfOAuth2Request.getBody()` already does, and record an expected divergence: a request Restlet crashed on now succeeds. A widening, and it can only turn a 500 into a 2xx |
| Restlet **accepts** it | accept it; no divergence |

The umbrella's standing rule holds either way: this is one of the *"record it, do not derive it"* cases, and
the CONTINUE-bug precedent ([phase-5b-1](phase-5b-1.md#2--the-continue-bug-makes-authorizes-filter-validation-unpredictable--record-it-do-not-derive-it))
is that this provider's media-type handling has already surprised the plan once.

<a id="d8"></a>
### D8 — handler shape

```java
// org.openidentityplatform.openam.oauth2.http
public class ResourceSetRegistrationHandler extends AbstractOAuth2HttpJsonEndpoint {
    @Post   public Response create(@Contextual Context ctx, @Contextual Request request) throws OAuth2Exception
    @Get    public Response readOrList(@Contextual Context ctx, @Contextual Request request) throws OAuth2Exception
    @Put    public Response update(@Contextual Context ctx, @Contextual Request request) throws OAuth2Exception
    @Delete public Response delete(@Contextual Context ctx, @Contextual Request request) throws OAuth2Exception
}
```

The base class is `AbstractOAuth2HttpJsonEndpoint` per [D1](#d1), so the four methods may `throw` and the
inherited `onError` renders the OAuth2 JSON body — and none of them may override it.

Collaborators by constructor `@Inject`, mirroring the Restlet endpoint minus `ExceptionHandler` and
`JacksonRepresentationFactory` ([finding 11](#11--every-collaborator-is-already-transport-neutral)). Business
logic ported **verbatim**, including the two behaviours that look like bugs and are contract:

- the duplicate-name 400 is built **in-band** (`:150-155`), not thrown — so it keeps its
  `error: "Bad Request"` reason-phrase value (5-E4 row 7);
- `labels` are stripped from the description before `store.create`/`store.update` and re-added afterwards
  (`:158-168`, `:200-207`), with an **empty list** when absent. ⚠ Not an implementation detail to tidy: the
  strip/re-add **brackets the `ResourceRegistrationFilter` calls**, and the seven-step order in
  [finding 18](#18--the-extension-point-sees-a-description-without-labels-and-without-an-id) is the contract a
  customer extension is written against. Nothing in-tree implements that SPI, so no test will tell you if it
  moves.

⚠ **Copy the parsed body before mutating it.** `Entity.getJson()` **memoises** its result
(commons `Entity.java:235-242`), and `ChfOAuth2Request.getBody()` wraps that same instance — so the map the
handler receives is the one the audit filter parsed and the one `getParameter` falls through to. Restlet's
`toMap` built a fresh map from `entity.getJsonObject().toString()` on every call, so the endpoint could mutate
freely; on CHF the `labels` strip/re-add above writes through to the shared entity. Build the
`ResourceSetDescription` from a defensive copy.

**Honest status: this is hygiene, not a live defect, and no test in this plan guards it.** Audit captures its
detail before the handler runs ([finding 7](#7--audit-matrix-and-the-body-contention-it-creates)),
nothing re-reads the request body afterwards, and the only later consumer — the JSON base's `onError` doing
`getParameter("state")` — does not read a key the handler touches. It is written down because the next person
to add a post-handler body reader (a response auditor that echoes the request, a retry filter) would inherit a
silent corruption, and because the reason it is safe is three non-obvious facts deep. Do not manufacture a
test for it; do not skip the copy either.

<a id="d9"></a>
### D9 — routing at 5d-1: a **nested** router, not three sibling matchers (**revised at review, 2026-07-29**)

[Finding 12](#12--the-trailing-slash-route-cannot-be-expressed-with-equals-in-chf) rules out the obvious
shape. One `STARTS_WITH` parent plus a two-route child covers all three Restlet attachments exactly:

```java
Handler chain = Handlers.chainOf(Endpoints.from(ResourceSetRegistrationHandler.class),
        new OAuth2HttpAccessAuditFilter(publisher, factory, requestFactory,      // outermost
                jsonAuditor(NAME, SCOPES), jsonAuditor("_id")),
        new ResourceSetErrorFilter(),                                            // then the error shape
        new ChfAccessTokenProtectionFilter(null, tokenStore, requestFactory, OAUTH2));

Router resourceSetRouter = new Router();
resourceSetRouter.addRoute(requestUriMatcher(EQUALS, ""),        chain);   // resource_set, resource_set/
resourceSetRouter.addRoute(requestUriMatcher(EQUALS, "{rsid}"),  chain);   // resource_set/{rsid}
endpointRouter.addRoute(requestUriMatcher(STARTS_WITH, "resource_set"), resourceSetRouter);
```

The parent's `STARTS_WITH` regex is `(\Qresource_set\E)(/(.*))?`, so `resource_set`, `resource_set/` and
`resource_set/x` all match and the child sees a remaining URI of `""`, `""` and `"x"` respectively — which is
precisely Restlet's three-way split, with the two collection forms collapsing to one route the way they always
behaved. `{rsid}` still lands in a `UriRouterContext`, and `ChfOAuth2Request.attributes()` merges **nested**
router contexts (`:379-399`), so `getAttribute("rsid")` works unchanged
([finding 6](#6--rsid-the-three-attachments-and-the-list-vs-read-split)).

⚠ **Filter ordering, and why it changed with the routing.** Outermost → innermost: **audit → error shape →
protection → endpoint**, which reproduces Restlet's
`auditWithOAuthFilter( ResourceSetRegistrationExceptionFilter( AccessTokenProtectionFilter( endpoint ) ) )`
(`OAuth2GuiceModule:407-413`, `OAuth2RouterProvider:128`) exactly. The chain wraps the **handler**, not the
child router — deliberately. Wrapping the router would put `ResourceSetErrorFilter` outside the child's
**no-match 404**, and [D3](#d3)'s catch-all row would turn `GET /oauth2/resource_set/a/b` — a 404 under
Restlet, produced by the router *outside* its exception filter — into a **500**. Wrapping the handler leaves
router 404s in the CREST shape, where the root `OAuth2ErrorFilter` normalises them like every other
`/oauth2` 404. 5-E4 row 17 records the live answer.

`resource_set` joins `@Named("InvalidRealmNames")`. This is the only `/oauth2` route that mounts an extra
error filter; everything else relies on the root `OAuth2ErrorFilter`.

---

## New / modified / tests

### 5-E4 — test-only

- `e2e/oauth2/oauth2-endpoints-test.spec.mjs` — extend the `/oauth2/resource_set registration` describe with
  [finding 10](#10--what-e2e-already-records-and-what-5-e4-must-add)'s 17 items (18 rows -- row 2 splits into 2a/2b).
- Label every new row `(5-E4, live Restlet)` so the 5d-1 re-run can select them.
- Reuse the existing `RS_CLIENT_ID` / `protectionApiToken` / `registerResourceSet` fixtures
  (`e2e/common/oauth2-fixtures.mjs`); add a helper that returns the raw `ETag` header so rows 1–3 can
  round-trip it.
- ⚠ **Rows 2a/2b need a resource set that actually has labels.** Get one by sending
  `labels: ["alpha", "beta"]` in the create body — `labelRegistration.updateLabelsForNewResourceSet`
  provisions them, so a subsequent `GET` reads them back out of `umaLabelsStore` and the two ETag sources can
  diverge ([finding 17](#17--the-conditional-comparison-tag-comes-from-the-read-model-labels-and-all)). **Two**
  labels, so the order-sensitive `List.hashCode` is exercised. A single-label or unlabelled fixture makes both
  rows pass vacuously, which is the whole failure this gate exists to prevent.

### 5c-1

**New:** `ResourceSetErrorFilter`, `HttpConditions` (`org.openidentityplatform.openam.oauth2.http`).
**Modified (⚠ live path):** `ChfAccessTokenProtectionFilter` — additive `ErrorShape` ctor overload (D2), our
own 2026 class, no `Portions` line.
**Tests:** `ResourceSetErrorFilterTest` (each status row incl. idempotency against `OAuth2ErrorFilter`),
`HttpConditionsTest` (`*`, exact, weak-vs-strong, comma lists, absent, malformed),
`ChfAccessTokenProtectionFilterTest` **extended** — every existing CREST row kept unchanged plus the
OAuth2-shape rows.

### 5c-2

**New:** `ResourceSetRegistrationHandler`.
**Tests:** `ResourceSetRegistrationHandlerTest` — port of `ResourceSetRegistrationEndpointTest`'s cases onto
constructed CHF `Request`/context chains, plus the conditional rows D6 adds;
`ResourceSetRouteCompositionIT` — see below.
**Unmodified, deliberately:** `AbstractOAuth2HttpJsonEndpoint`, `OAuth2ErrorFilter`, every collaborator.

---

## Verification criteria

Baseline to beat, from the 5b-2b as-built: **1180 surefire + 25 failsafe** in `openam-oauth2`;
`npx playwright test oauth2` **63 passed**; `e2e/uma` **11 passed**.

**Per step — all must hold before the next step starts:**

| Gate | 5-E4 | 5c-1 | 5c-2 |
|---|---|---|---|
| `npx playwright test oauth2` | **81 passed** (63 + 18), all against **live Restlet** | 81 (unchanged) | 81 (unchanged) |
| `npx playwright test uma` | 11 | **11 — the load-bearing gate for D2** | 11 |
| `mvn -o -pl openam-oauth2 test` | 1180 (unchanged) | ≥ 1180 + ~25 | ≥ 1180 + ~55 |
| `mvn -o -pl openam-uma test` | — | **green, count unchanged** | — |
| `mvn -o -pl openam-oauth2 verify` (failsafe) | 25 | 25 | **25 + ~13** |
| `mvn -o install -DskipTests -am -pl openam-oauth2` | — | clean | clean |
| doclint (`mvn -o -pl openam-oauth2 javadoc:javadoc`) | — | clean | clean |
| Restlet import gate: `grep -rn "org\.restlet" <new/changed main classes>` | — | **0** | **0** |
| Route gate: `grep -rn "ResourceSetRegistrationHandler" --include=*.java openam-*/src/main` | — | — | **only its own file** (build-ahead: routed nowhere until 5d-1) |

⚠ Build with `-am` — a same-version SNAPSHOT schema jar left in `~/.m2` by another branch produces false
compile errors — and be wary of `target/` surefire reports that survived a branch switch: a green report is
not evidence unless the run in front of you produced it.

**Step-specific acceptance:**

- **5-E4** — every row asserts an observed value, none asserts a predicted one; each row's title carries
  `(5-E4, live Restlet)`; the container the rows ran against is built from **this tree** (as 5-E2 and 5-E3
  were), and the as-built section records the date and the four gated decisions' outcomes
  (D3 row 12, D4 rows 4/6, D5 row 5, D6 rows 1–3, D7 row 12).
- **5c-1** — the `e2e/uma` CREST row (`uma-test.spec.mjs:152`) is green **without edit**. If it needs editing,
  D2 has been implemented wrongly.
- **5c-2** — `ResourceSetRouteCompositionIT` is **mutation-checked**: deleting the ETag write turns the
  conditional rows red, and deleting the `ResourceSetErrorFilter` from the chain turns the 405 row red. State
  the result in the as-built, as 5b-2b did for its request-cache row.
- **5c-2 routing** — row 8 passes with the [D9](#d9) wiring **and fails** if the three routes are registered as
  `EQUALS "resource_set"` / `EQUALS "resource_set/"` / `EQUALS "resource_set/{rsid}"`. Check that explicitly
  once: it is the only evidence that [finding 12](#12--the-trailing-slash-route-cannot-be-expressed-with-equals-in-chf)
  is understood rather than worked around by accident.

**Whole-phase exit criteria (before 5d-1 may start):**

1. All three steps' gates green.
2. Every 5-E4 row has a corresponding CHF-side assertion — unit, IT or both — **except the two whose decision
   owner is 5d-1**: row 15 (`HEAD`, a Phase-5-wide question, [C3](#framework-items-openam-http-is-ours)) and
   row 17 (the router-level 404, which no 5c class produces). Those two are recorded now and *answered* at the
   flip; list them explicitly in the as-built so they are not mistaken for oversights. Any other recorded row
   without a port-side test is an oracle that will expire unused at 5d-2.
3. The [expected-divergence table](plan.md#expected-divergences-at-the-flip) has a row for each deliberate
   difference this step introduces (candidates: D3's `else` branch, D7's media-type outcome, and any
   `ETag`/`Content-Type` byte difference row 5/14 exposes).
4. `docs/migration/restlet/plan.md`'s phase table row for 5c is updated with the as-built, including
   anything the plan got wrong — every step since 5a-2 has found at least one such thing, and the record of
   *what the plan mispredicted* has been the most reused part of these documents.

---

## Integration testing

Three layers, per [../../test-infrastructure.md](../../test-infrastructure.md):

**Layer 2 — in-process composition (`ResourceSetRouteCompositionIT`, failsafe).** Models
`DeviceCodeRouteCompositionIT`. Builds the **real** chain in [D9](#d9)'s order — audit filter →
`ResourceSetErrorFilter` → `ChfAccessTokenProtectionFilter(null, …, OAUTH2)` →
`Endpoints.from(ResourceSetRegistrationHandler.class)` — behind the **real** nested `Router`, over a
`RootContext` + `AttributesContext` + **`RealmContext`** + `UriRouterContext`, with mocked stores.

⚠ The `RealmContext` is **not optional scaffolding**: without it the seeded `realmObject` is absent and the
create path NPEs on a real request while the IT stays green
([finding 16](#16--the-create-path-needs-the-realm-object-and-the-phase-4-urisfactory-trap-does-not-recur)).

⚠⚠ **This IT wires the router itself, and that is a real limit on what row 8 proves.** `OAuth2HttpRouteProvider`
does not exist until 5d-1, so — like `DeviceCodeRouteCompositionIT` (`:309`, `:349`) and unlike `UmaRouterIT`
(`:266-271`, which drives the **real** provider through `HttpRouteAccessor`) — this IT must reproduce
[D9](#d9)'s shape inline. It therefore proves the shape **works**; it cannot prove 5d-1 **uses** it. The
trailing-slash bug ([finding 12](#12--the-trailing-slash-route-cannot-be-expressed-with-equals-in-chf)) would
sail past a green IT that encodes the right shape while the provider encodes the wrong one. Closing that is a
**5d-1 handoff item**, not something 5c can do — see [R-5c.12](#risk-register-extends-the-phase-5-register).
Named rows:

1. **the request cache is shared** — the **real** `OAuth2RequestFactory` (not a mock), so the token the
   protection filter stashes is the token the handler reads
   ([phase-5b-2 finding 14](phase-5b-2.md#14--the-request-cache-is-load-bearing-here-and-nothing-tests-it));
2. **both readers coexist** — one POST, audit filter reads `name`/`scopes` **and** the handler creates the
   resource set; assert both the audited detail and the 201. ⚠ Scope claim honestly: audit runs *before* the
   handler and `getJson()` memoises, so this row proves coexistence, **not** that the handler left the body
   alone ([finding 7](#7--audit-matrix-and-the-body-contention-it-creates));
3. **`rsid` arrives from the URI template** — via `UriRouterContext`, with no handler-side parsing (finding 6);
4. **405 keeps the resource-set vocabulary** — `PATCH` yields `unsupported_method_type`, and adding
   `OAuth2ErrorFilter` outside the chain does **not** rewrite it to `method_not_allowed` (D3's idempotency
   claim, proven rather than argued);
5. **401 is OAuth2-shaped** — no bearer → `{"error":"invalid_token"}`, not `{"code":401,…}` (D2 — the whole
   reason 5c-1 exists);
6. **412 composes** — the handler signals a precondition failure and the filter supplies the body (D6 + D3
   together, which is where a seam bug would hide);
7. **204 delete carries no body and no ETag**;
8. **the three URL forms route** — `resource_set`, **`resource_set/`** and `resource_set/{rsid}` each reach
   the handler, the first two as a collection (no `rsid`) and the third with `rsid` populated from the
   **nested** `UriRouterContext`. ⚠ This row is the guard for
   [finding 12](#12--the-trailing-slash-route-cannot-be-expressed-with-equals-in-chf) and must be written
   against the **real** `Router` wiring of [D9](#d9), not against `Endpoints.from` alone — a test that calls
   the handler directly cannot fail the way the bug fails;
9. **a no-match below the endpoint stays CREST** — `resource_set/a/b` reaches no route and is **not** rewritten
   by `ResourceSetErrorFilter` (the D9 filter-placement claim; pairs with 5-E4 row 17);
10. **a token-store `ServerException` answers 400, not 500** — mock `tokenStore.readAccessToken` to throw it
    and assert `400 {"error":"server_error"}`. This is the one row pinning a **derived** rather than recorded
    fact ([finding 14](#14--the-protection-filters-chosen-status-is-overridden-by-the-exceptions-and-a-500-becomes-a-400)),
    so it carries the source trace in a comment;
11. **`/uma` is unaffected** — the same filter with the default `CREST` shape still emits
    `{code, reason, message}` at the code the call site passed. Cheap, and it puts the D2 regression risk in
    the same file as the change rather than only in another module's suite;
12. **the realm reaches the collaborators** — assert `hook.resourceSetCreated` is called with the
    `RealmContext`'s realm, not `null`. This is the row that would have failed on the IT chain this plan
    originally specified ([finding 16](#16--the-create-path-needs-the-realm-object-and-the-phase-4-urisfactory-trap-does-not-recur));
13. **the conditional tag folds in labels** — stub `umaLabelsStore.forResourceSet` to return **two** labels,
    take the ETag from a `GET`, replay it as `If-Match` on a `PUT`, and assert the update **succeeds**.
    Mutation-check it: make `currentEtag` hash the bare `store.read` description and the row must go red
    ([R-5c.11](#risk-register-extends-the-phase-5-register)). Two labels, not one, so the order-sensitive
    `List.hashCode` is actually exercised.

**Layer 3 — e2e against a live container (`e2e/oauth2/oauth2-endpoints-test.spec.mjs`).** 5-E4 records
against Restlet; the **same rows** are re-run and byte-diffed after 5d-1. This is the only layer that sees the
real CTS-backed `ResourceSetStore`, the real `UmaResourceSetRegistrationHook` (which creates policy resource
types as a side effect of a 201 — a failure mode no mock reproduces), and the real container's header
handling. ⚠ `e2e/uma`'s 11 rows register their resource sets through this endpoint, so after 5d-1 they are a
**second, independent** consumer of the port; run both suites in the 5d-1 soak and treat a UMA failure as a
resource_set regression until proven otherwise.

**Not attempted:** a Cargo-booted resource_set IT. The endpoint needs a provisioned OAuth2 provider, a
resource-server client and a PAT; that setup already exists in the e2e fixtures and duplicating it in
failsafe would buy a slower copy of layer 3.

---

## Risk register (extends the Phase 5 register)

- **R-5c.1 — the 401 shape regression is silent.** If D2 is skipped, `resource_set` starts answering
  `{"code":401,"reason":"Unauthorized"}` and every resource server's error branch stops matching. No unit test
  on the handler can see it (the filter is not the handler). **Guard:** composition IT row 5 + 5-E4's two
  recorded 401 rows.
- **R-5c.2 — lost-update protection disappears.** The literal reading of `isConditionalRequest()` ships a PUT
  that accepts any `If-Match`. **Guard:** 5-E4 rows 1–3 record the real behaviour; `HttpConditionsTest`
  + composition IT row 6 pin the port. **This is the step's top risk** — it is a data-integrity change that
  every functional test still passes.
- **R-5c.3 — D2 breaks `/uma`.** The filter is live. **Guard:** the existing CREST row must stay green
  **unedited**; 5c-1 is a separate commit so a revert is one commit, not a bisect.
- **R-5c.4 — ~~audit/handler body contention~~ downgraded on the fourth pass.** `Entity.getJson()` memoises
  and audit runs before the handler, so there is no stream to contend for
  ([finding 7](#7--audit-matrix-and-the-body-contention-it-creates)). What remains is that the two share **one
  mutable map**, which is a hygiene requirement ([D8](#d8)), not a risk with a live failure mode. **Guard:**
  composition IT row 2 for coexistence; the defensive copy is a code-review item, deliberately untested.
- **R-5c.5 — the error filters fight.** Two response rewriters on one route; get the order wrong and
  `unsupported_method_type` becomes `method_not_allowed`. **Guard:** composition IT row 4 asserts the
  composed pair, not each filter alone.
- **R-5c.6 — ETag byte drift.** A reformatted or non-weak tag invalidates every token a resource server holds
  across the upgrade, and the current e2e only asserts truthiness. **Guard:** 5-E4 row 5 + a unit assertion on
  the exact header.
- **R-5c.7 — 5d-2 deletes a class openam-uma needs** ([finding 8](#8--the-restlet-resources-package-is-not-deletable-at-5d-2)).
  **Guard:** recorded here and to be echoed in the 5d-2 checklist; the whole-build `-am` gate catches it, but
  after the fact.
- **R-5c.8 — `/oauth2/resource_set/` 404s after the flip.** Risk #8's *"register all three routes"* is not
  implementable with `EQUALS` on CHF ([finding 12](#12--the-trailing-slash-route-cannot-be-expressed-with-equals-in-chf)),
  and the failure mode is a **404 on a URL the UMA UI and the e2e list row both use**. **Guard:** the nested
  router of [D9](#d9), composition IT row 8 (all three forms), and the existing e2e list row at 5d-1. ⚠ Note
  this risk is *created by the plan*, not by the code — it is here because the obvious implementation is wrong.
- **R-5c.9 — `HEAD` regresses from 200 to 405 across all of Phase 5**
  ([finding 13](#13--head-is-served-by-restlet-and-405d-by-chf--and-it-is-not-a-5c-problem)). Not 5c's to fix,
  but 5c is where it was found and 5-E4 row 15 is the cheapest place to record it. **Guard:** the recorded row
  + an explicit 5d-1 decision (fix [C3](#framework-items-openam-http-is-ours) or add a divergence row). ⚠ If
  neither happens, the flip ships an undocumented status change on every `@Get` endpoint.
- **R-5c.10 — the composition IT certifies a chain that cannot serve a real request.** With a mocked store and
  no `RealmContext`, every row can pass while the real create path NPEs on `realm.asPath()`
  ([finding 16](#16--the-create-path-needs-the-realm-object-and-the-phase-4-urisfactory-trap-does-not-recur)).
  **Guard:** IT row 12 + the `RealmContext` requirement stated in the IT section. ⚠ Same failure shape as
  5b-2's two false greens — a test that exercises less than it appears to.
- **R-5c.11 — the conditional ETag is computed over the wrong model.** The obvious implementation hashes the
  `store.read` result the handler already has; the correct one hashes `readResourceSet`'s model with
  `umaLabelsStore` labels folded in
  ([finding 17](#17--the-conditional-comparison-tag-comes-from-the-read-model-labels-and-all)). The failure is
  **invisible on unlabelled resource sets** and total on labelled ones — every conditional request 412s.
  **Guard:** the single `currentEtag` helper of [D6](#d6), 5-E4 rows 2a/2b against a *labelled* set, and IT
  row 13. ⚠ Rank this beside R-5c.2: both are silent, both are about conditional requests, and both pass
  every test written with a simple fixture.
- **R-5c.12 — 5d-1's route provider does not inherit 5c's routing shape.** The composition IT wires
  [D9](#d9) inline because `OAuth2HttpRouteProvider` does not exist yet, so a green 5c leaves the *provider*
  unverified; whoever writes it at 5d-1 can still register three `EQUALS` siblings and reintroduce
  [finding 12](#12--the-trailing-slash-route-cannot-be-expressed-with-equals-in-chf). **Guard — a 5d-1 handoff
  item, listed here because 5c cannot discharge it:** `OAuth2RouterIT` (already named in
  [plan.md](plan.md)'s 5d-1 row) must drive the **real** provider the way `UmaRouterIT:266-271` does, and must
  cover `resource_set`, `resource_set/` **and** `resource_set/{rsid}`. The e2e list row is the backstop, but it
  fires a whole flip later.

---

## Framework items (`openam-http` is ours)

Raised by this step; neither blocks it.

- **C1 — `@Consumes`, `@Payload`, `@PayloadTranslator` are dead API**
  ([finding 9](#9--openam-https-consumespayload-annotations-are-dead-api)). They are declared, documented and
  never read, which is worse than absent: a future port will reasonably assume `@Consumes("application/json")`
  does something. **Options:** implement `@Consumes` (415 on mismatch, ~20 lines in `AnnotatedMethod`), or
  delete all three. **Recommendation:** decide with D7 — if 5-E4 row 12 shows Restlet enforcing media types,
  implementing `@Consumes` is the parity-preserving fix *and* clears the dead API; otherwise delete them in a
  standalone commit. Either way **not bundled into 5c-2**.
- **C2 — no conditional-request support in `Endpoints`**
  ([finding 2](#2--restlets-conditional-request-machinery-is-load-bearing-and-chf-has-none)). D6 answers it
  locally on purpose. Revisit if a second endpoint ever needs ETags; the additive design (an `@Etag` method
  discovered the way `@ExceptionHandler` already is) is sketched in D6.
- **C3 — `Endpoints.from` does not map `HEAD` to the `GET` method**
  ([finding 13](#13--head-is-served-by-restlet-and-405d-by-chf--and-it-is-not-a-5c-problem)). Restlet did
  (`doHandle(Method, Form, Representation)` rewrites `HEAD` → `GET` before annotation lookup); CHF answers
  **405** on every `@Get` endpoint. **Proposed fix:** two lines in `Endpoints.java:60-63` —
  `methods.put("HEAD", methods.get("GET"))` — leaving body suppression to the servlet container, which already
  does it. **Blast radius:** every `Endpoints.from` consumer gains a working `HEAD` where it currently 405s;
  additive, no existing behaviour moves. ⚠ **Decision owner is 5d-1, not 5c** — this is a Phase-5-wide
  divergence and the fix (or the divergence row) has to cover all 15 endpoints at once. Recorded now because
  5-E4 row 15 is the last cheap chance to record the incumbent behaviour.

Both are additions to
[decisions.md's CHF cleanup backlog](decisions.md#chf-cleanup-backlog); the existing entries are untouched by
5c.

---

## Post-migration tickets

Raised by the port, deliberately **not** fixed in it — same treatment as
[T1–T4](plan.md#post-migration-tickets--raised-by-the-port-deliberately-not-fixed-in-it).

| # | Ticket | Reproduced by |
|---|---|---|
| **T5** | **The missing-`If-Match` rejection is a 400 `server_error`**, not a 412/428, and it is built by throwing a status the code never uses (`512`). Semantically wrong on the wire and confusing in the source | `ResourceSetRegistrationHandler` (5c-2), per [D4](#d4) |
| **T6** | **The duplicate-name rejection puts a reason phrase in the `error` field** — `{"error":"Bad Request"}` (`:150-155`), where every other error on the endpoint uses a snake_case code | `ResourceSetRegistrationHandler` (5c-2), per [D8](#d8) |
| **T7** | **`ResourceSetRegistrationExceptionFilter.setExceptionResponse` NPEs on a throwable-less error status** (`:80-87`) — a latent 500 on the live Restlet endpoint. Dies with the class at 5d-2; recorded so the CHF replacement's differing behaviour is understood as a fix, not a drift | closed by [D3](#d3) |

---

## Checklist

1. **5-E4** — write the 17 items (18 rows); run against a container built from this tree; `playwright test oauth2` = 81.
2. Record the as-built: the four gated decisions' outcomes, verbatim bodies, and anything that contradicts
   this plan.
3. **5c-1 S1** — `HttpConditions` + `HttpConditionsTest`.
4. **5c-1 S2** — `ResourceSetErrorFilter` + `ResourceSetErrorFilterTest` (incl. the `OAuth2ErrorFilter`
   idempotency row).
5. **5c-1 S3** — `ChfAccessTokenProtectionFilter` `ErrorShape` overload + extended test; **run `openam-uma`
   tests and `e2e/uma`**; commit.
6. **5c-2 S4** — `ResourceSetRegistrationHandler`, business logic ported verbatim.
7. **5c-2 S5** — port `ResourceSetRegistrationEndpointTest`; add the conditional and ETag rows.
8. **5c-2 S6** — `ResourceSetRouteCompositionIT`, all 13 rows; mutation-check three of them (rows 8, 10 and 13).
9. **5c-2 S7** — full gates; commit.
10. Update [plan.md](plan.md)'s phase table row 5c, the expected-divergence table, and the post-migration
    ticket table (T5–T7).
11. **Hand off to 5d-1 explicitly** — three items 5c records but cannot close:
    [R-5c.12](#risk-register-extends-the-phase-5-register) (`OAuth2RouterIT` must drive the real provider over
    all three URL forms), [C3](#framework-items-openam-http-is-ours) (`HEAD`, decided once for all 15
    endpoints), and 5-E4 rows 15/17. Put them in the 5c as-built, not only here: the as-built is what the flip
    reads.
