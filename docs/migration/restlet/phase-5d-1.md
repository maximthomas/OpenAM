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
  migration (§ [5-E5](phase-5d-1-asbuilt.md#as-built-5-e5--recorded-2026-08-04));
- **two of the handed-down defects are `openam-http`'s, not the migration's** — `HEAD` and the missing `Allow`
  header ([5c *Handed to 5d-1*](phase-5c-asbuilt.md#handed-to-5d-1)). The F1–F4 precedent says framework defects get
  their own commit with their own tests, never bundled into a migration commit
  ([openam-http-framework.md](openam-http-framework.md));
- **registering the route provider is itself a production change even before the flip** — see
  [finding 3](phase-5d-1-research.md#3--the-provider-instantiates-all-15-handlers-when-the-router-is-built-and-that-router-is-the-whole-chf-servlets).
  So it gets a commit of its own, ahead of the mapping move.

> **Convention.** New classes: `org.openidentityplatform.openam.*`, CDDL header,
> `Copyright 2026 3A Systems LLC.`, **no `@since`** ([decisions.md](decisions.md)). Classes modified in place
> keep their header and gain a `Portions copyright 2026 3A Systems LLC.` line — except our own 2026 classes,
> which carry no `Portions` line.

## Scope & sizing — split four ways

| Step | Scope | New / changed | Risk |
|---|---|---|---|
| **5-E5** ✅ **done 2026-08-04** ([as-built](phase-5d-1-asbuilt.md#as-built-5-e5--recorded-2026-08-04)) | **The last live-Restlet gate.** 14 items: realm styles (`?realm=`, legacy path realm, bogus realm), an unknown `Host`, `HEAD` and `Allow` on non-`resource_set` endpoints, unrouted-path shapes, `X-HTTP-Method-Override`, `?_api`/`?_crestapi`, `OPTIONS`, path-form edge cases. Test-only. Gates D4, D5 and D11 — and its **row 13 can redesign [D1](#d1)'s route table** | e2e spec only (0 main) | **High** — unrecoverable after 5d-1c |
| **5d-1a** ✅ **done 2026-08-05** ([as-built](phase-5d-1-asbuilt.md#as-built-5d-1a--recorded-2026-08-05)) | **`openam-http` verb fixes.** `HEAD` → the `@Get` method; `Allow` on both 405 producers. Own commit, own tests, no migration code. Closes two [decisions.md backlog](decisions.md#chf-cleanup-backlog) items | 2 modified + tests | **Med** — reaches every `Endpoints.from` consumer; three already-live endpoints start answering `HEAD` ([finding 6](phase-5d-1-research.md#6--head-after-the-fix-lands-on-code-paths-that-are-already-correct)) |
| **5d-1b** ✅ **done 2026-08-05** ([as-built](phase-5d-1-asbuilt.md#as-built-5d-1b--recorded-2026-08-05)) | **`OAuth2HttpRouteProvider` + `META-INF/services` + `OAuth2RouterIT`.** The full 18-attachment table, the audit matrix, the nested `resource_set` router, the root error filter, the two-route no-cache filter, the synthesized 404 (+ one line in `OAuth2ErrorFilter` and two deliberate pin edits). **`/oauth2` still served by Restlet** | 2 new main + 1 line + 1 services line + 1 IT + 2 edited pins | **High** — a broken Guice graph here breaks the *whole* CHF router, `/json` included ([finding 3](phase-5d-1-research.md#3--the-provider-instantiates-all-15-handlers-when-the-router-is-built-and-that-router-is-the-whole-chf-servlets)) |
| **5d-1c** | **The flip.** One `<servlet-mapping>` line; then Cargo boot, the e2e re-run + byte-diff, the audit smoke, the soak record. Revert = revert this commit | 1 line + docs | **High** — the wire change |

**Total new main classes: 2.** Order: **5-E5 → 5d-1a → 5d-1b → 5d-1c**. 5-E5 first because three of its rows
decide later work — rows 5 and 6 (`HEAD` and `Allow` beyond `resource_set`) are what 5d-1a is measured
against, and row 13 (trailing slash) can force every route into [D2](#d2)'s nested shape — and because
every row of it is worthless after 5d-1c. 5d-1a before 5d-1b so the IT can assert the fixed behaviour rather
than the divergence. 5d-1b before 5d-1c so the only difference between "the graph builds" and "the graph
serves" is one line.

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
2](phase-5d-1-asbuilt.md#the-recorded-rows) adds a second, live half of the same guard: a realm failure on `/access_token` carries
**no** cache headers today, because the stamping filter sits inside the realm layer — which the shape above
preserves.

✅ **The flat `EQUALS` table is measured-correct.** [5-E5 row 13](phase-5d-1-asbuilt.md#the-recorded-rows) sent a trailing slash, a
case change and an empty segment at every shape of endpoint: all 404. Only `resource_set` needs [D2](#d2)'s
nested router (R-5d1.8 discharged).

<a id="d2"></a>
### D2 — `resource_set` is a nested router, and the chain wraps the **handler**

Verbatim from [5c D9](phase-5c.md#d9), which exists because
[5c finding 12](phase-5c-research.md#12--the-trailing-slash-route-cannot-be-expressed-with-equals-in-chf) proved three
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
   ([5c finding 1](phase-5c-research.md#1--the-resource_set-401-is-oauth2-shaped-not-crest--the-4a-filter-cannot-be-reused-unchanged));
   passing the wrong one is a silent 401-shape regression that only
   `e2e/oauth2/oauth2-endpoints-test.spec.mjs:130-149` and `OAuth2RouterIT` catch.

`ResourceSetRouteCompositionIT` already proves this shape **works** in process; it cannot prove the provider
**uses** it (its router is wired inline). That is R-5c.12 and it is discharged by `OAuth2RouterIT` driving the
real provider over all three URL forms ([D9](#d9)).

<a id="d3"></a>
### D3 — the audit matrix is copied, and the copy is checked mechanically

[Finding 2](phase-5d-1-research.md#2--the-route-table-is-18-attachments-and-7-distinct-auditor-pairs-lift-both-verbatim)'s table is
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
| `HEAD` on `/authorize` | ⚠ **405** — measured, [5-E5 correction 2](phase-5d-1-asbuilt.md#5-e5-correction-2) | 405 | **keep the 405** — `AuthorizeHandler` refuses `HEAD` explicitly, or the fix above turns it into a flow that **issues codes** |
| `Allow` on any 405 | `Allow: POST, PUT, GET, DELETE` on `resource_set`; **`Allow: GET`** on the single-`@Get` endpoints, **absent** on the two filter-produced 405s — measured, [5-E5 row 6](phase-5d-1-asbuilt.md#the-recorded-rows) | **absent** | **fix** — stamped on both 405 producers, **excluding `HEAD`** ([finding 5](phase-5d-1-research.md#5--openam-http-has-two-405-producers-and-the-allow-fix-belongs-where-the-verb-map-is)) |
| `PATCH` on `resource_set` | routed to `@Put`: a working **full replace**, 200 | **405** | **record** — divergence row 14 |
| `PATCH` elsewhere | ⚠ runs the `@Get` **first**, then 405s — so the `@Get`'s errors and side effects are on the wire ([5-E5 correction 4](phase-5d-1-asbuilt.md#5-e5-correction-4)) | 405, nothing run | **record** — row 14, widened |

`HEAD` and `Allow` are fixed because both are *specification* obligations (`Allow` is mandatory on a 405, RFC
7231 §6.5.5; `GET` and `HEAD` are the two methods every general-purpose server must support, §4.1, and §4.3.2
defines `HEAD` as `GET` without the body) and both are two-line, purely additive changes
to code we own. `PATCH` is **not** fixed at source: aliasing `PATCH` → `PUT` in `Endpoints.from` would give
every CHF endpoint with a `@Put` full-replace `PATCH` semantics, which RFC 5789 §2 explicitly forbids — trading
one wire regression on one endpoint for a wrong framework-wide default. Nor is it worth a route-scoped rewrite
filter: `PATCH` on `resource_set` is unused by the UMA UI and by every e2e row except the one that discovered
it. The `HEAD` fix's blast radius beyond `/oauth2` — three already-live CHF endpoints, one of them expensive —
is enumerated in [finding 6](phase-5d-1-research.md#6--head-after-the-fix-lands-on-code-paths-that-are-already-correct) and is
5d-1a's to verify, not the flip's.

⚠ **Revised 2026-08-04 by [5-E5](phase-5d-1-asbuilt.md#as-built-5-e5--recorded-2026-08-04).** The `HEAD` fix is unchanged in
principle and now carries one exception: `/authorize` answers **405** today, so mapping `HEAD` → `@Get` without
a guard would make a `HEAD` run the authorization flow and hand out a code — a capability *addition* on the
endpoint that issues credentials, and precisely the direction [risk #20](plan.md#risk-register-behavioral-compatibility)
says not to take silently. The guard belongs in `AuthorizeHandler` (which owns an explicit verb contract
already, [5b-1 D8](phase-5b-1.md)) rather than in `Endpoints.from`, which must stay generic — `/json` endpoints
gain `HEAD` correctly. `TokenEndpointHandler` needs nothing: it is `@Post`-only, so `HEAD` hits the sentinel
405 either way.

⚠ **A body byte-diff at the flip shows nothing for any of these three.** `HEAD`'s change is a status; `Allow`
is a header; `PATCH`'s 405 body is identical to the shape [D3](phase-5c.md#d3) already produces. The rows that
catch them are 5-E4 row 11, 5-E4 row 15 and [5-E5](phase-5d-1-asbuilt.md#as-built-5-e5--recorded-2026-08-04) rows 5–6 — all header/status
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
  `/oauth2/resource_set/a/b` is exactly the path [5-E4 row 17](phase-5c-asbuilt.md#as-built-5-e4--recorded-2026-07-29)
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
  ([finding 15](phase-5d-1-research.md#15--the-realm-layer-has-its-own-404-and-400-and-they-are-crest-shaped)), which would leave
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
- **this buys vocabulary consistency, not parity** — measured, [5-E5 correction 3](phase-5d-1-asbuilt.md#5-e5-correction-3).
  Restlet renders the *cause's* message (`No mapping organization found for organization identifier: /bogus`),
  not the description its router wrote, because `RestStatusService.toRepresentation:42-52` prefers
  `status.getThrowable().getMessage()`. So no CHF body can be byte-identical here. `case 404 → not_found`
  stands on its sufficient ground — it keeps `/oauth2` saying one word for a 404 — while the body diverges in
  message as well as shape. Divergence row 15 records it.

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
([finding 8](phase-5d-1-research.md#8--an-unrouted-oauth2-path-is-a-bodiless-404-on-chf)). The choice is between *a 404 with a
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
consume ([finding 13](phase-5d-1-research.md#13--invalidrealmnames-is-a-realm-creation-guard-not-a-router-input)):
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
### D8 — the audit smoke is a scripted pre/post capture, recorded in the as-built

Decided 2026-07-30. [Risk #13](plan.md#risk-register-behavioral-compatibility)'s residual (the FAILED-path
`reason` string, the `queryParameters` fix, the `:-1` port) is discharged by capturing real audit records
either side of the flip rather than by new e2e machinery.

⚠ **Revised 2026-08-05, after taking the pre-flip capture.** The procedure below was written from the plan
and four of its assumptions turned out to be wrong against a live container; it is restated here as what
actually works. It is now a script rather than a manual sequence, because the post-flip capture happens on a
**rebuilt container** — the only thing that makes the two artefacts comparable is that the same code created
the same fixtures and sent the same bytes.

```
node   e2e/tools/d8-audit-capture.mjs pre-flip     # before the flip   (done, 2026-08-05)
node   e2e/tools/d8-audit-capture.mjs post-flip    # after  the flip
python3 e2e/tools/d8-audit-diff.py docs/migration/restlet/artefacts/d8-audit-pre-flip.csv  > /tmp/pre
python3 e2e/tools/d8-audit-diff.py docs/migration/restlet/artefacts/d8-audit-post-flip.csv > /tmp/post
diff -u /tmp/pre /tmp/post
```

The capture drives D8's fixed 8-request sequence (client_credentials token, a bad-secret token, an
unauthenticated authorize, an authorize success, tokeninfo, introspect, a resource_set create, a 405),
brackets it with a line marker in `access.csv`, and writes the rows those 8 requests produced to
`docs/migration/restlet/artefacts/d8-audit-<label>.csv`. Fixtures come from `e2e/common/oauth2-fixtures.mjs`
unchanged, and the artefact header records the md5 of both the tool and the fixtures so a diff taken across
an edit to either is detectable rather than silently wrong.

**What the plan got wrong, and what is true instead:**

| Plan said | Actually |
|---|---|
| step 1: "enable the file-based access-audit handler for the OAuth topic" | **Already enabled.** A `Global CSV Handler` ships with `enabled=true` and topics `[access, activity, config, authentication]`, writing `$OPENAM_DATA_DIR/$OPENAM_PATH/log/access.csv`. Nothing to turn on |
| *(not mentioned)* | **`csvBuffering.bufferingEnabled` must be turned off**, and this is the one config change the smoke needs. It ships `true` with `autoFlush=false`, and the buffer is FIFO with no bounded latency: a flush after the 8 requests emits the *oldest* pending records, so line-offset extraction silently yields someone else's traffic. Observed directly — the first capture attempt returned 0 rows while the file grew by 8192 bytes of unrelated SAML traffic. The tool disables it (and that flushes the backlog as a side effect) |
| diff `http.request.detail` / `http.response.detail` | **No such columns.** `AMAccessAuditEventBuilder:145` calls `addDetail(detail, REQUEST)` and `AccessAuditEventBuilder:84` has `REQUEST = "request"`, so the auditor detail is at **`request.detail`** and **`response.detail`** |
| an attempt **and** an outcome event per request | **Outcome only, 8 rows not 16.** `AM-ACCESS-ATTEMPT` is blacklisted unless the JVM property `org.forgerock.openam.audit.access.attempt.enabled` is set (`AuditServiceConfigurationProviderImpl:221`). Decided 2026-08-05 to leave it off: enabling it needs a restart on **both** sides of the flip, and the only field it adds — `request.detail`, the request-side auditor field lists — is already pinned in-process by `OAuth2RouterIT.theAccessTokenAuditDetailIsExactlyTheConfiguredFieldList`. Everything the residual actually rides on is on the outcome event |
| "an authorize **301**" | **302.** Measured on `openam-e2e:5d1b`, both unauthenticated and authenticated |

Diff these, per row: `eventName`, `component`, `realm`, `userId`, `http.request.secure`,
`http.request.method`, `http.request.path`, `http.request.queryParameters`, `request.detail`,
`response.status`, `response.statusCode`, `response.detail`, plus `http.request.headers`/`cookies`.
`d8-audit-diff.py` prints exactly these and blanks the fields that vary run to run regardless of the flip
(`_id`, `timestamp`, `transactionId`, `trackingIds`, ip/port, `elapsedTime`, and issued UUIDs inside a
detail blob). It is validated in both directions: two captures of one unchanged container normalise to
byte-identical output, and mutating a `reason` string still shows up in the diff.

Expected differences: the `reason` string on failures (`getReasonPhrase()` vs Restlet `getDescription()` — the
accepted residual). The pre-flip artefact pins the two exact strings the flip should change:

| Row | Now (Restlet) | Expected after the flip |
|---|---|---|
| 2 — bad-secret token, 401 | `{"reason":"The request requires user authentication"}` | `{"reason":"Unauthorized"}` |
| 8 — `PROPFIND /oauth2/tokeninfo`, 405 | `{"reason":"The method specified in the request is not allowed for the resource identified by the request URI"}` | `{"reason":"Method Not Allowed"}` |

`http.request.path`'s `:-1` port ([backlog](decisions.md#chf-cleanup-backlog)) does **not** reproduce here —
the pre-flip capture shows `:8080` on every row, so a `:-1` appearing post-flip *is* a regression, not the
known issue. Anything else is a regression. Record the diff verbatim in the as-built — it is the only record
that survives 5d-2.

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
[finding 3](phase-5d-1-research.md#3--the-provider-instantiates-all-15-handlers-when-the-router-is-built-and-that-router-is-the-whole-chf-servlets)'s
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
### D11 — `X-HTTP-Method-Override`: settled, nothing done to `Endpoints.from`

✅ **Settled 2026-08-04 by [5-E5 row 10](phase-5d-1-asbuilt.md#the-recorded-rows).** Restlet **honours** the
header, so the POST case is parity and **nothing is done to `Endpoints.from`** — gating it off would move
CREST behaviour on `/json`, which shares the code. The measurement also found two shapes the decision did not
anticipate — the header on a *non*-POST, and Restlet's `?method=` query tunnel — both recorded as
**divergence row 20** rather than fixed ([correction 5](phase-5d-1-asbuilt.md#5-e5-correction-5)).

---

## New / modified / tests

The file tables for **5-E5**, **5d-1a** and **5d-1b** are in the [as-built](phase-5d-1-asbuilt.md), which
records what actually landed rather than what was planned.

### 5d-1c — the flip (own commit)

| File | Change |
|---|---|
| `openam-server-only/src/main/webapp/WEB-INF/web.xml` | move `/oauth2/*` from `ForgeRockRest` (`:1143-1146`) into the `OpenAM` block (after `:1136`) |
| `e2e/oauth2/*.spec.mjs`, `e2e/uma/*.spec.mjs` | **only** the rows the divergence table licenses — each edit citing its row |
| `docs/migration/restlet/phase-5d-1.md`, `plan.md` | as-built, the byte-diff record, the audit-smoke diff, new divergence rows |

---

## Verification criteria

Criteria **1–11** belong to 5-E5, 5d-1a and 5d-1b and are all green; the measured numbers they produced —
surefire/failsafe baselines, the Cargo boot, the 131-row e2e pass — are recorded in the
[as-built](phase-5d-1-asbuilt.md). What follows is what 5d-1c still owes. The numbering is preserved because
the as-built cites these criteria by number.

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

**Still live at 5d-1c:**

- **R-5d1.2 — the oracle expires mid-step.** Any question that only live Restlet can answer must be asked
  **before** the flip commit, not after. **Guard:** checklist step 13, which re-reads every open question
  immediately before the flip.
- **R-5d1.6 — realm-style parity.** [Finding 9](phase-5d-1-research.md#9--realm-resolution-is-a-different-implementation-and-its-oauth2-behaviour-is-unrecorded):
  two different implementations, one of which dies here. The Restlet side is fully recorded
  ([5-E5 rows 1–4](phase-5d-1-asbuilt.md#the-recorded-rows)); the flip's e2e re-run is what proves CHF matches it.
- **R-5d1.7 — the revert is not actually one line.** If 5d-1c accretes a "small fix", the lever breaks.
  **Guard:** [D6](#d6), enforced by review of the commit's file list.
- **R-5d1.9 — an unknown `Host` answers differently.** Downgraded 2026-08-04: [5-E5 row 14](phase-5d-1-asbuilt.md#the-recorded-rows)
  measured **500 on both URL styles** today, so the flip changes 500 → 400 rather than breaking a working
  integration. No e2e row can catch it (the suite always uses the container's hostname) ⇒ divergence row 17
  plus a **release-note line**: `/oauth2` now requires the request host to be a valid FQDN or realm alias.

**Discharged, kept as one line each so the flip's reviewer knows they were checked:**

- ✅ **R-5d1.1** — the provider breaking the whole CHF router (`/json` included). Discharged by 5d-1b's
  [Cargo boot + 131-row e2e](phase-5d-1-asbuilt.md#5d-1b-criterion-10-is-not-vacuous), run with `/oauth2` still on Restlet.
- ✅ **R-5d1.3** — a transcription slip in the 18-row table. Discharged by the probe rows and
  [D3](#d3)'s field-list assertions, both [mutation-checked](phase-5d-1-asbuilt.md#mutation-checks).
- ✅ **R-5d1.4** — the no-cache filter drifting to the root. Discharged by [D1](#d1)'s negative row, mutation-checked.
- ✅ **R-5d1.5** — `HEAD` activating untested paths. Discharged by 5d-1a's
  [live smoke](phase-5d-1-asbuilt.md#the-live-smoke--openam-e2e5d1a) on the three non-OAuth2 endpoints, and by
  `AuthorizeHandler`'s explicit `HEAD` refusal ([correction 2](phase-5d-1-asbuilt.md#5-e5-correction-2)) —
  without which a `HEAD` would issue authorization codes.
- ✅ **R-5d1.8** — the trailing-slash shape. [5-E5 row 13](phase-5d-1-asbuilt.md#the-recorded-rows) measured a 404 on every
  endpoint, so [D1](#d1)'s flat `EQUALS` table is right and only `resource_set` needs [D2](#d2)'s nested shape.

---

## Checklist

Steps **1–12** (5-E5, 5d-1a, 5d-1b) are done; what each of them actually produced is in the
[as-built](phase-5d-1-asbuilt.md).

**5d-1c — what is left**

13. Re-read every open question in this doc; anything still needing live Restlet stops the flip.
14. ~~Enable audit + capture the pre-flip audit artefact ([D8](#d8) steps 1–3).~~ — **done 2026-08-05**,
    ahead of the flip while the 5d-1b containers were still up
    ([as-built](phase-5d-1-asbuilt.md#the-pre-flip-audit-capture--recorded-2026-08-05)). D8 itself was rewritten:
    four of its assumptions were wrong, and the capture is now `e2e/tools/d8-audit-capture.mjs`.
    ⚠ The post-flip capture must run **`node e2e/tools/d8-audit-capture.mjs post-flip`** on the rebuilt
    container — the tool disables `csvBuffering` itself, so there is no separate config step.
15. Move the one web.xml line. Nothing else in the commit.
16. Rebuild the container; criteria 12–16.
17. Write the as-built: the byte-diff, the audit diff, the new divergence rows, the answers to 5-E4 rows 15/17,
    and the `HEAD` `Content-Length` measurement ([finding 7](phase-5d-1-research.md#7--content-length-on-a-head-is-tomcats-decision)).
18. Update [plan.md](plan.md): 5d-1 row → done, the stale "hook re-sign" text
    ([finding 1](phase-5d-1-research.md#1--the-hook-re-sign-is-already-done)) removed, divergence rows 14/15 added.

---

## Divergence rows this step adds to [plan.md](plan.md)

Drafted here so the flip's operator has them before the diff, not after. The first two are *decided*, not
discovered — they follow from [D4](#d4) and [D5](#d5) and no measurement can change them:

| # | What differs | Restlet | CHF | Why |
|---|---|---|---|---|
| 14 | `PATCH /oauth2/resource_set/{rsid}` | routed to the `@Put` method: a working **full replace**, 200 + new `ETag` ([5-E4 row 11](phase-5c-asbuilt.md#as-built-5-e4--recorded-2026-07-29)) | **405** `{"error":"unsupported_method_type"}` + `Allow: …` | [D4](#d4) — aliasing `PATCH` to `PUT` in `Endpoints.from` would impose RFC 5789-wrong full-replace `PATCH` on every CHF endpoint with a `@Put`. Scoped to `resource_set`: it is the only ported endpoint with a `@Put`. ⚠ **The body byte-diff shows nothing** — the 405 shape is identical to the one [D3](phase-5c.md#d3) already produces for `OPTIONS`/`PROPFIND`. Only the *verb's* outcome changed |
| 15 | The two routing-layer failures that stay **404** on both stacks — an unrouted path, and `/oauth2/realms/<bogus>/…` | unrouted path: 404 **CREST** naming a realm lookup — `{"code":404,"reason":"Not Found","message":"No mapping organization found for organization identifier: /resource_set"}` ([5-E4 row 17](phase-5c-asbuilt.md#as-built-5-e4--recorded-2026-07-29)), because Restlet's `/oauth2` router consumes any unmatched element as a sub-realm ([finding 8](phase-5d-1-research.md#8--an-unrouted-oauth2-path-is-a-bodiless-404-on-chf)). Unknown realm: 404 CREST `{"code":404,…,"message":"Realm \"bogus\" not found"}` (`RealmRoutingFactory`'s inner `RestletRealmRouter:254-257`; **confirmed by 5-E5 row 4**) | `{"error":"not_found","error_description":…}` for both — the endpoint router's default route for the path case ([D5](#d5)), `ChfRealmRouter`'s CREST 404 rewritten by `errorFor`'s new `case 404` for the realm case | [D5](#d5). **Status is preserved; only the shape moves.** For the realm case even the `error_description` is byte-identical to Restlet's `message`. For the path case parity is unavailable — CHF's realm filter breaks out rather than looking the element up, so Restlet's message has no counterpart, and commons' `Router` would otherwise answer a **bodiless** 404 |

Two further rows are **provisional**: the source says they will be needed, but each is licensed only by its
5-E5 measurement, and if the measurement contradicts the source the *measurement* wins.

| # | What differs | Restlet (predicted from source) | CHF | Why |
|---|---|---|---|---|
| 16 ⚠ *provisional, confirmed or dropped by [5-E5](phase-5d-1-asbuilt.md#as-built-5-e5--recorded-2026-08-04) row 2* | `?realm=<bogus>` on any `/oauth2` endpoint | **404** `{"code":404,…,"message":"Realm \"bogus\" not found"}` — `RestletRealmRouter:86-90` → `:102-104` | **400** `{"error":"invalid_request","error_description":"Invalid realm, bogus"}` — `RealmContextFilter:255-257` | The two realm layers classify the same failure differently: Restlet as *not found*, CHF as *bad request*. Not worth "fixing" in `RealmContextFilter`, which `/json` has depended on since 14.0 — but a client that branches on 404 sees a 400 |
| 17 ⚠ *provisional, confirmed or dropped by [5-E5](phase-5d-1-asbuilt.md#as-built-5-e5--recorded-2026-08-04) row 14* | A request whose `Host` OpenAM does not know | `/oauth2/realms/root/…` **works**; `/oauth2/…` **500** | **400** for both — `HostnameFilter:123-131` and `RealmContextFilter:229-231` | [Finding 16](phase-5d-1-research.md#16--the-flip-adds-host-validation-to-oauth2-that-restlet-never-did). The only row here that can break a deployment that works today, and therefore the one that needs a release-note line rather than just a table entry |

All four rows are added to the table **in 5d-1c's commit**, with the measured bytes rather than these drafts.
⚠ Rows 16 and 17 have since been **measured** — see the [5-E5 as-built](phase-5d-1-asbuilt.md#as-built-5-e5--recorded-2026-08-04),
which confirms 16's status while correcting its body, **rewrites 17**, and adds four more.

---

