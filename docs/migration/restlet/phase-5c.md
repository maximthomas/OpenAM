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
transport-free, and every collaborator it touches is neutral ([finding 11](phase-5c-research.md#11--every-collaborator-is-already-transport-neutral)).

Two things the umbrella did not know make it the **least mechanical** of the remaining ports:

- the umbrella says *"guarded by `ChfAccessTokenProtectionFilter(null)`"*. That filter, shipped in 4a and
  **live on `/uma` since Phase 4**, emits a **CREST** error body. On `resource_set` the same rejection is
  **OAuth2-shaped** on the wire today, and the difference is not cosmetic — it is the field a resource server
  dispatches on ([finding 1](phase-5c-research.md#1--the-resource_set-401-is-oauth2-shaped-not-crest--the-4a-filter-cannot-be-reused-unchanged));
- `resource_set` is the **only** endpoint in the whole migration that uses HTTP conditional requests, and
  Restlet's `ServerResource` implemented them *for* the endpoint. `Endpoints.from` has no equivalent, so a
  literal port silently drops lost-update protection
  ([finding 2](phase-5c-research.md#2--restlets-conditional-request-machinery-is-load-bearing-and-chf-has-none)).

Build-ahead as usual for the handler: **nothing is routed** until 5d-1. ⚠ But **5c-1 is not build-ahead** —
it edits a class that is live on `/uma` today. That is why it is its own commit.

> **Convention.** New classes: `org.openidentityplatform.openam.oauth2.http`, CDDL header,
> `Copyright 2026 3A Systems LLC.`, **no `@since`** ([decisions.md](decisions.md)). Classes modified in place
> keep their header and gain a `Portions copyright 2026 3A Systems LLC.` line — except our own 2026 classes,
> which carry no `Portions` line.

## Scope & sizing — split three ways

| Step | Scope | New / changed | Risk |
|---|---|---|---|
| **5-E4** | **The live-Restlet contract lock.** **17 items / 20 rows** (items 1, 2 and 3 each split in two) added to `e2e/oauth2/oauth2-endpoints-test.spec.mjs` as their own describe, written **by observation**. Test-only, no main code. Gates D3, D4, D5, D6, D7, D9 | e2e spec only (0 main) | **High** — unrecoverable after 5d-1 |
| **5c-1** | **Error-shape substrate.** `ChfAccessTokenProtectionFilter` gains an opt-in error renderer (D2); new CHF `ResourceSetErrorFilter` (D3); new `HttpConditions` conditional-request helper (D6) | 1 modified (**live**) + 2 new + 3 tests | **Med-High** — the modified class is on the live `/uma` path |
| **5c-2** | **The handler.** `ResourceSetRegistrationHandler` + ported unit tests + `ResourceSetRouteCompositionIT` | 1 new + 2 tests + 1 IT | **Med** |

**Total new main classes: 3.** Plus one additive change to a Phase 4 class.

Order: **5-E4 → 5c-1 → 5c-2.** 5-E4 first because **six** of the decisions below are *settled by* what it records
and the [CONTINUE-bug lesson](phase-5b-1-research.md#2--the-continue-bug-makes-authorizes-filter-validation-unpredictable--record-it-do-not-derive-it)
applies with full force here — this endpoint's error surface has **three** producers
([finding 3](phase-5c-research.md#3--three-error-producers-one-endpoint--and-only-one-of-them-is-the-endpoint)). 5c-1 before 5c-2
because the handler composes all three of its classes, and because isolating the live-path edit keeps the UMA
regression signal readable.

---

## Design decisions

<a id="d1"></a>
### D1 — `ResourceSetRegistrationHandler` extends `AbstractOAuth2HttpJsonEndpoint`

`doCatch` calls the **2-arg** `ExceptionHandler.handle(Throwable, Response)` (`:296-299`) — the JSON entry
point — so by the [5b-2 finding 1](phase-5b-2-research.md#1--only-one-of-the-three-is-a-browser-endpoint-the-doccatch-arity-decides)
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
[finding 14](phase-5c-research.md#14--the-protection-filters-chosen-status-is-overridden-by-the-exceptions-and-a-500-becomes-a-400):
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
OAuth2ErrorFilter( … router … audit( ResourceSetErrorFilter( protect( Endpoints.from(handler) ) ) ) )
```

⚠ **Corrected 2026-07-30 (S7 review).** This line originally read
`ResourceSetErrorFilter( audit( protect( … ) ) )`, putting audit *inside* the error filter — which contradicts
[D9](#d9)'s code block, the shape `ResourceSetRouteCompositionIT` gates, and the one 5d-1 will build. The
ordering of those two is **not** cosmetic: `AbstractHttpAccessAuditFilter.filter` audits the **response**
(`auditAccessFailure(request, context, response)`), and `OAuth2HttpAccessAuditFilter` is constructed with a
response-body auditor, so whichever filter is inner decides whether the audit log records the OAuth2-shaped
body the client received or the CREST one it did not. Audit **outermost** is correct — you audit what was
sent. The argument below is unaffected by the swap; only the diagram was wrong.

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
// ⚠ CORRECTED by 5-E4 — the prefix is part of the wire contract, see below.
throw new ServerException("precondition_failed (512) - Require If-Match header to update Resource Set");
```

⚠ **The message above is not the endpoint's string.** 5-E4 row 4 measured the live
`error_description` as `precondition_failed (512) - Require If-Match header to update Resource Set` — Restlet's
`ResourceException.getMessage()` formats as `"<reason> (<code>) - <description>"`, and producer A passes
`throwable.getMessage()` through untouched. This decision originally proposed throwing the bare sentence, which
would have dropped the prefix and changed bytes on a path the existing e2e already exercises
([as-built](phase-5c-asbuilt.md#as-built-5-e4--recorded-2026-07-29), correction 2). The general rule, which the handler should
encode once rather than per throw site: **every non-`OAuth2Exception` throwable on this endpoint reaches the
wire as 400 `server_error` with `error_description` = the Restlet `ResourceException`'s formatted message.**

Per [finding 4](phase-5c-research.md#4--the-512-throw-never-reaches-the-wire-as-512): 400 + `server_error` + the message
is what live Restlet emits, and `ServerException` is the exception whose `getStatusCode()` is 400
([chf-patterns §17](chf-patterns.md#17-oauth2exception--http-status-quirks-phase-5a-2b)). The delete twin takes
the **same treatment**: `"precondition_failed (512) - Require If-Match header to delete Resource Set"` — prefix
included, only the verb word differing. 5-E4 row 6 pins it, so dropping the prefix on the destructive verb is
a red row at the flip just as it is on `PUT`.

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
change nobody can prove safe ([finding 18](phase-5c-research.md#18--the-extension-point-sees-a-description-without-labels-and-without-an-id)).
Attach on POST/PUT/read-GET; **not** on list-GET or the 204 delete
([finding 5](phase-5c-research.md#5--etag-emission-and-format)).

**Portability is established, not assumed** (fifth pass): `ResourceSetDescription.hashCode()` (`:263-270`)
combines `id`, `clientId`, `policyUri` and `description.asMap().hashCode()`, and the `String`/`List`/`Map`
hash codes it bottoms out in are **specified by the JLS**. A description holds only JSON-native values, so an
ETag issued before an upgrade still matches after one. The port **must not** reformat the value — no
`Math.abs`, no padding, no switch to a digest.

⚠ **"Verbatim" has a precise scope here**, and it is wider than `generateETag`. It covers (a) the dead
`!isDefined(LABELS)` round-trip, (b) `Integer.toString` + weak tag, **and (c) the model the hash is taken
over** — which differs per route and is what
[finding 17](phase-5c-research.md#17--the-conditional-comparison-tag-comes-from-the-read-model-labels-and-all) is about. Note the
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

⚠ **`noneMatches` gained a second parameter at S4** — `noneMatches(String currentEtagValue, boolean
checkWeakness)`, with **no** one-argument convenience. Row 21 measured the flag varying by verb
(`GET`/`HEAD` compare weakness, every other verb does not), so a default would be a hidden verb assumption of
exactly the kind that produced the S1 divergences. `hasIfNoneMatch()` was added alongside it, because a
non-`GET` now has to distinguish "no `If-None-Match`" from "one that did not match".

Matching rules copied from the disassembled `Conditions.getStatus`
([finding 2](phase-5c-research.md#2--restlets-conditional-request-machinery-is-load-bearing-and-chf-has-none)): `*` matches any
existing entity; otherwise compare **tag names only**, so `W/"x"` ≡ `"x"`; a comma-separated list matches if
any member does. ⚠ Both of those are *too loose* — see the [S1 review correction](phase-5c-asbuilt.md#as-built--s1-2026-07-29):
the wildcard holds only as the **first** element and only strong, and name-only comparison is `If-Match`'s
rule alone, not `If-None-Match`'s. The signature above is what shipped; the sentence is not.

⚠ **Three amendments from 5-E4, all measured** ([as-built](phase-5c-asbuilt.md#as-built-5-e4--recorded-2026-07-29)). The version
above would have diverged on each:

- **`hasIfMatch()` is "did it parse", not "was the header sent".** An `If-Match` Restlet cannot parse —
  unquoted, empty, `!!!` — leaves an **empty** match list, so `isConditionalRequest()` says *no*, and the
  request takes D4's missing-header 400. A helper that reports *present but unmatched* answers 412 where
  Restlet answers 400. Pinned by row 1b.
- **`noneMatches` must NOT treat `*` as a match.** `If-None-Match: *` answers **200** on live Restlet, not
  the 304 RFC 7232 §3.2 asks for, so carrying the `*`-matches-anything rule across from `matches()` would
  invert it. Pinned by row 3. (The mechanism, found later: Restlet's `noneMatch` wildcard test is reachable
  only when the current tag is `null`.)
- **`noneMatches` must also compare weakness *on a `GET`*, which `matches` never does.** Read off
  `Conditions.getStatus` during the S1 review, and **measured at S4 by row 21**: the flag is
  `checkWeakness = GET || HEAD`, so on a `GET` only `W/"<name>"` yields the 304 and the strong form yields 200
  and the body — while on a `PUT` the *same* strong form matches, and matching there is a 412.
  ⚠ The S1 review recorded this as "weakness always counts, because GET/HEAD are the only verbs that reach
  the comparison". The conclusion was right for the `GET` and the reason was wrong, which is why the helper
  shipped a one-argument `noneMatches`.
- **The 304 carries the `ETag` and no `Content-Type`.**

<a id="d6-uniform"></a>
#### ⚠ Handler use — **corrected 2026-07-29 by rows 18–20**, measured while planning S4

The version of this section that shipped with the plan gave each verb its own conditional rules: `If-Match` on
`PUT`/`DELETE`/`GET`, `If-None-Match` on `GET` alone. **That is not what Restlet does.**
`doConditionalHandle` runs *before* the annotated method **whatever the verb is**, so one precondition pass
guards all four — and the three rows added at S4 measure every branch of it:

```java
// ONE pre-check, shared by @Post, @Get, @Put and @Delete -- Restlet's doConditionalHandle, in the handler.
String tag = readOrListTag(o2);        // the tag the @Get would answer: null at the COLLECTION url
HttpConditions c = HttpConditions.of(request);
if (c.hasIfMatch()   && !c.matches(tag))     -> 412
if (c.hasIfNoneMatch() && c.noneMatches(tag)) -> GET: 304 (+ ETag, no Content-Type); any other verb: 412
// only then does the verb's own body run -- including PUT/DELETE's missing-If-Match throw (D4)
```

| Fact | Row | What a per-verb port would have done |
|---|---|---|
| `If-None-Match` matching on `PUT`/`DELETE` → **412**, never 304 | 18 | performed the write |
| `If-None-Match` *not* matching on `PUT` → falls through to D4's **400** | 18 | — (it agrees) |
| a **winning `If-Match` does not stop `If-None-Match`** — both are evaluated, in that order | 18 | performed the write |
| `POST` is conditional too: `If-Match: *` → 201, a stale tag → **412** | 19 | created |
| the **collection** representation has *no tag*, so `matches(null)` = "was the wildcard first" | 20, 9 | — |
| ⇒ `GET` collection + stale `If-Match` → **412 carrying the whole id array**, no `ETag` | 20 | 200 |
| ⇒ `GET` collection + `If-None-Match: *` → **304** — the opposite of row 3's item answer | 20 | 200 |
| ⇒ `POST` collection + `If-None-Match: *` → **412**; the RFC "create only if absent" idiom is refused | 20 | created |
| `If-None-Match` weakness is compared **only on `GET`/`HEAD`**: the strong form of the weak tag is 200 on a `GET` and **412 on a `PUT`** | 21 | one answer for both |
| `If-None-Match: W/*` is not the wildcard, just as `If-Match: W/*` is not | 21 | — |

⚠ **The 412's body is not one shape.** On `PUT`/`DELETE`/`POST` the handler returns a **bare** 412 and
[`ResourceSetErrorFilter`](#d3) fills in `{"error":"precondition_failed"}`. On a `GET` the representation is
already in hand — Restlet ran the `@Get` to get the tag — so the 412 carries **the full body and the `ETag`**
(item, row 3b) or **the id array and no `ETag`** (collection, row 20), and the filter's empty-entity guard
spares both. Getting this wrong in either direction is invisible to a status-only test.

⚠ **"the current ETag" means `readResourceSet`'s tag, not the store row's.** Extract one
`currentEtag(rsid, owner)` helper that rebuilds the read model — `store.read`, `umaLabelsStore` labels,
`description.put("labels", …)`, then `generateETag` — and call it from the `GET`, `PUT` and `DELETE` paths
alike, exactly as Restlet reached one `@Get` method from all three
([finding 17](phase-5c-research.md#17--the-conditional-comparison-tag-comes-from-the-read-model-labels-and-all)). Two separate
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
the CONTINUE-bug precedent ([phase-5b-1](phase-5b-1-research.md#2--the-continue-bug-makes-authorizes-filter-validation-unpredictable--record-it-do-not-derive-it))
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

⚠ **Re-stamp `Content-Type` to bare `application/json` after every `setEntity`**, per
[S2's as-built](phase-5c-asbuilt.md#as-built-s2) — except row 7's in-band duplicate-name 400, which sends `;charset=UTF-8`.
`setJson` adds the charset; 5-E4 row 14 asserts its absence exactly.

Collaborators by constructor `@Inject`, mirroring the Restlet endpoint minus `ExceptionHandler` and
`JacksonRepresentationFactory` ([finding 11](phase-5c-research.md#11--every-collaborator-is-already-transport-neutral)). Business
logic ported **verbatim**, including the two behaviours that look like bugs and are contract:

- the duplicate-name 400 is built **in-band** (`:150-155`), not thrown — so it keeps its
  `error: "Bad Request"` reason-phrase value (5-E4 row 7);
- `labels` are stripped from the description before `store.create`/`store.update` and re-added afterwards
  (`:158-168`, `:200-207`), with an **empty list** when absent. ⚠ Not an implementation detail to tidy: the
  strip/re-add **brackets the `ResourceRegistrationFilter` calls**, and the seven-step order in
  [finding 18](phase-5c-research.md#18--the-extension-point-sees-a-description-without-labels-and-without-an-id) is the contract a
  customer extension is written against. Nothing in-tree implements that SPI, so no test will tell you if it
  moves.

⚠ **Copy the parsed body before mutating it.** `Entity.getJson()` **memoises** its result
(commons `Entity.java:235-242`), and `ChfOAuth2Request.getBody()` wraps that same instance — so the map the
handler receives is the one the audit filter parsed and the one `getParameter` falls through to. Restlet's
`toMap` built a fresh map from `entity.getJsonObject().toString()` on every call, so the endpoint could mutate
freely; on CHF the `labels` strip/re-add above writes through to the shared entity. Build the
`ResourceSetDescription` from a defensive copy.

**Honest status: this is hygiene, not a live defect, and no test in this plan guards it.** Audit captures its
detail before the handler runs ([finding 7](phase-5c-research.md#7--audit-matrix-and-the-body-contention-it-creates)),
nothing re-reads the request body afterwards, and the only later consumer — the JSON base's `onError` doing
`getParameter("state")` — does not read a key the handler touches. It is written down because the next person
to add a post-handler body reader (a response auditor that echoes the request, a retry filter) would inherit a
silent corruption, and because the reason it is safe is three non-obvious facts deep. Do not manufacture a
test for it; do not skip the copy either.

<a id="d9"></a>
### D9 — routing at 5d-1: a **nested** router, not three sibling matchers (**revised at review, 2026-07-29**)

[Finding 12](phase-5c-research.md#12--the-trailing-slash-route-cannot-be-expressed-with-equals-in-chf) rules out the obvious
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
([finding 6](phase-5c-research.md#6--rsid-the-three-attachments-and-the-list-vs-read-split)).

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

## Framework items (`openam-http` is ours)

Raised by this step; neither blocks it.

- **C1 — `@Consumes`, `@Payload`, `@PayloadTranslator` are dead API**
  ([finding 9](phase-5c-research.md#9--openam-https-consumespayload-annotations-are-dead-api)). They are declared, documented and
  never read, which is worse than absent: a future port will reasonably assume `@Consumes("application/json")`
  does something. **Options:** implement `@Consumes` (415 on mismatch, ~20 lines in `AnnotatedMethod`), or
  delete all three. **Recommendation:** decide with D7 — if 5-E4 row 12 shows Restlet enforcing media types,
  implementing `@Consumes` is the parity-preserving fix *and* clears the dead API; otherwise delete them in a
  standalone commit. Either way **not bundled into 5c-2**.
- **C2 — no conditional-request support in `Endpoints`**
  ([finding 2](phase-5c-research.md#2--restlets-conditional-request-machinery-is-load-bearing-and-chf-has-none)). D6 answers it
  locally on purpose. Revisit if a second endpoint ever needs ETags; the additive design (an `@Etag` method
  discovered the way `@ExceptionHandler` already is) is sketched in D6.
- **C3 — `Endpoints.from` does not map `HEAD` to the `GET` method**
  ([finding 13](phase-5c-research.md#13--head-is-served-by-restlet-and-405d-by-chf--and-it-is-not-a-5c-problem)). Restlet did
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
| **T8** | **`/oauth2/resource_set` parses request bodies with `org.json`, which is lenient** — see below | `ResourceSetRegistrationHandler` (5c-2), deliberately |

<a id="t8"></a>
### T8 — move the request-body parse from `org.json` to Jackson

**Why it is a ticket and not a 5c change.** The port reproduces the incumbent parser because 5-E4
[row 22](phase-5c-asbuilt.md#the-recorded-rows) measured it deciding **five** wire outcomes, not just an error string. Changing
it inside the migration would ship an unrelated behaviour change under cover of a port, on a path where the
symptom (a plausible `400 bad_request`) points nowhere near the cause. After 5d-1 it can be done on its own
merits, with its own divergence row and its own release note.

**What changes on the wire**, all measured against live Restlet:

| Request body | Today | After T8 |
|---|---|---|
| `{'name':'x','scopes':['read']}` (single-quoted) | **201** | 400 |
| `{name:"x",scopes:["read"]}` (unquoted keys) | **201** | 400 |
| `{"name":"x","scopes":["read"],}` (trailing comma) | **201** | 400 |
| `{"name":"a","name":"b"}` (duplicate keys) | **400** `Duplicate key "name" at 33 [character 34 line 1]` | **201**, last value wins |
| `[1,2]`, `hello` | 400 `A JSONObject text must begin with '{' at 1 [character 2 line 1]` | 400, a Jackson message |
| key order **within** the parsed body | not preserved — `JSONObject` is `HashMap`-backed | preserved (Jackson → `LinkedHashMap`) |

⇒ **the first three are the reason this needs a release note.** A resource server that has been sending
sloppy-but-accepted JSON since 13.0.0 stops working at upgrade, and nothing in the response suggests the
parser changed. The duplicate-key row moves the other way — silently accepting what is now rejected — which
is arguably worse and argues for keeping *that* check explicitly rather than inheriting whatever Jackson does.

The last row is **harmless here and worth knowing anyway** (found at S5, by an assertion that wrongly assumed
order): this endpoint never echoes the request body — a create/update answers `_id` and the policy URI, and
a read is built from the *store's* description — so no response's key order comes from the parse. A future
handler that does echo a parsed body would silently change its field order the day T8 lands.

**Shape of the change** (small, and the tests already exist):

- replace `new JSONObject(json).toString()` → Jackson with a single `JsonValueBuilder.toJsonValue(json)`;
- ⚠ catch **`JsonException`**, which is *unchecked* — left uncaught it reaches
  `ResourceSetRegistrationHandler.guarded` and becomes row 9's 400 `server_error` instead of the
  400 `bad_request` this path owes;
- decide explicitly whether duplicate keys stay rejected; if yes, that check has to be written, not inherited;
- update **5-E4 row 22** and the two unit rows (`theBodyParserIsLenientTheWayOrgJsonIsLenient`,
  `aDuplicateKeyIsRejectedWithOrgJsonsMessageWhereJacksonWouldTakeTheLastOne`) — they are the executable
  statement of what T8 changes, so they should be *edited with the ticket*, never relaxed to make it pass;
- ⚠ **keep** the `org.json:json` dependency in `openam-oauth2/pom.xml`. An earlier draft of this line said to
  drop it "if nothing else needs it", which reads as an invitation and is wrong: **five other main classes in
  this module import `org.json`** — `RealmOAuth2ProviderSettings`, `ClaimsParameterValidator`,
  `StatefulTokenStore`, `OpenAMScopeValidator`, `TokenRevocationResource` — and none of them dies at 5d-2.
  (A sixth, `ResourceSetRegistrationEndpoint`, does.) Removing the declaration would not even fail the build,
  because the module resolves `org.json` transitively through `openam-core`; it would silently restore exactly
  the fragility the `<dependency>` comment was added to prevent. T8 removes **a use**, not the dependency.

**Upside:** one JSON library on the path instead of two, one parse instead of two, and the project's normal
`JsonValueBuilder` idiom. The cost is entirely in the compatibility break above, which is why it wants a
deliberate decision rather than a port's side effect.

---

