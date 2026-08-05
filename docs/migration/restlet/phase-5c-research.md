# Phase 5c — `/oauth2/resource_set` → CHF: key research findings

Background for [phase-5c.md](phase-5c.md) — the findings that drove its design. Read once; the spec is what you re-read while implementing.

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
CHF port answers a real body ([D3](phase-5c.md#d3)).

<a id="4--the-512-throw-never-reaches-the-wire-as-512"></a>
### 4. The `512` throw never reaches the wire as 512 — it is a **400 `server_error`**

`updateResourceSet:188-191` and `deleteResourceSet:278-281` throw
`new ResourceException(512, "precondition_failed", "Require If-Match header to …", null)`. That looks like it
pairs with the filter's `412` branch. It does not — the two are unrelated paths:

- the throw goes to producer **A**. `toOAuth2RestletException` (`ExceptionHandler:160-176`) tests
  `instanceof OAuth2RestletException` (no), `getCause() instanceof OAuth2RestletException` (the cause is
  **`null`**, and necessarily so: the overload is `ResourceException(int, String, String, String)` whose 4th
  parameter is the **URI** — the cause-carrying form is the 5-arg one, so this throw cannot have a cause),
  `getCause() instanceof OAuth2Exception` (no), and falls to
  `new ServerException(throwable)` → **400**, error **`server_error`**
  ([chf-patterns §17](chf-patterns.md#17-oauth2exception--http-status-quirks-phase-5a-2b): `ServerException`
  is 400, not 500), message preserved;
- the filter's `412` branch is fed only by Restlet's own precondition evaluation
  ([finding 2](#2--restlets-conditional-request-machinery-is-load-bearing-and-chf-has-none)).

Confirmed live (`oauth2-endpoints-test.spec.mjs:97-104`): `PUT` without `If-Match` → **400**, `error_description`
contains `Require If-Match header to update Resource Set`. That lifecycle row asserts no `error` field, which
is why **5-E4 row 4 pins it** — done: `server_error`, plus the full formatted `error_description` above.

⇒ the port throws a `ServerException` and lets the JSON base map it. ⚠ **Corrected 2026-07-29 by 5-E4 row 4**:
the message must be the Restlet `ResourceException`'s *formatted* one —
`"precondition_failed (512) - Require If-Match header to update Resource Set"` — because producer A passes
`throwable.getMessage()` through untouched. This section originally prescribed the bare sentence, which would
have dropped the `precondition_failed (512) - ` prefix; see [D4](phase-5c.md#d4) and the
[as-built](phase-5c-asbuilt.md#as-built-5-e4--recorded-2026-07-29). So `512` never reaches the *status*, but both `512` and
`precondition_failed` do reach the wire, inside `error_description`.

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
issued before an upgrade still matches after one, which is the property [D5](phase-5c.md#d5) leans on. But
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
see [finding 12](#12--the-trailing-slash-route-cannot-be-expressed-with-equals-in-chf) and [D9](phase-5c.md#d9).

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
([phase-5b-2 finding 8](phase-5b-2-research.md#8--none-of-the-three-gets-cache-headers)).

⚠ **Correcting this doc's own first two drafts** (fourth review pass, 2026-07-29). They said *"risk #1 is live
here"* and left it to a test. It is not live, and the mechanism matters more than the reassurance:

- `Entity.getJson()` **memoises** — `if (json == null) { … json = readJson(reader); } return json;`
  (commons `Entity.java:235-242`). The second reader gets the cached object; there is no stream to exhaust.
  Risk #1 is a **form**-body concern (`Form.fromRequestEntity`, the charset trap), not a JSON one;
- `AbstractHttpAccessAuditFilter.filter` (`:78-93`) calls `auditAccessAttempt(request, context)` **before**
  `next.handle(...)`, so the request detail is captured, and `getJson()` first memoised, *before* the handler
  runs at all.

Two consequences the plan had wrong. **(a)** The handler receives the *same map instance* the audit filter
parsed — see the mutation caution in [D8](phase-5c.md#d8). **(b)** Composition IT row 2 as originally specified
(*"assert the audited detail after the handler has run"*) **cannot** catch a mutating handler, because the
audit event was already built. It still earns its place as the cheap proof that both readers coexist; it is
just not the guard [D8](phase-5c.md#d8) needs, and D8 says so.

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

**5-E4 row 12 decides what happens next** — see [D7](phase-5c.md#d7) and the
[framework backlog](phase-5c.md#framework-items-openam-http-is-ours) entry.

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
    [phase-5b-2 finding 8](phase-5b-2-research.md#8--none-of-the-three-gets-cache-headers))
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
    `{"error":…}` (gates the filter placement in [D9](phase-5c.md#d9))

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
([phase-5b-2 finding 14](phase-5b-2-research.md#14--the-request-cache-is-load-bearing-here-and-nothing-tests-it) is the
reason that sharing must be tested with the *real* factory, not a mock).

<a id="12--the-trailing-slash-route-cannot-be-expressed-with-equals-in-chf"></a>
### 12. ⚠ The trailing-slash route **cannot be expressed with `EQUALS`** in CHF

Found reviewing this plan's own [D9](phase-5c.md#d9), 2026-07-29, by reading commons
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
see [D9](phase-5c.md#d9). Two supporting facts, both verified in the same read:

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
(`Endpoints` maps `HEAD` → the `GET` method, ~2 lines, [C3](phase-5c.md#framework-items-openam-http-is-ours)) or record —
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

⇒ [D2](phase-5c.md#d2) must derive **both** the status and the error from the exception in `OAUTH2` mode, and keep the
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
  [D9](phase-5c.md#d9) mounts it inside, exactly as UMA does, so this is satisfied by construction — and it is written
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

⚠ This is the finding that makes [D6](phase-5c.md#d6) more than a header parser, and it is the one most likely to be
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
`:245`). Reproduce it anyway ([D5](phase-5c.md#d5) — it costs three lines and removing it is a behaviour change nobody
can prove safe), but do not spend time reasoning about when it fires. It does not.

---

