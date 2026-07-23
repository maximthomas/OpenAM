# Phase 3d — Audit layer (`HttpBodyAuditor`, `OAuth2HttpAccessAuditFilter`, `UMAHttpAccessAuditFilter`)

Detailed execution plan for **sub-phase 3d** of the Restlet → CHF migration. Parent tracker:
[plan.md](plan.md) (Phase 3); research & sizing: [phase-3-research.md](phase-3-research.md); reusable CHF
patterns: [chf-patterns.md](chf-patterns.md); predecessors: [phase-3a-oauth2request.md](phase-3a-oauth2request.md),
[phase-3b-collaborators.md](phase-3b-collaborators.md), [phase-3c-1-renderer.md](phase-3c-1-renderer.md),
[phase-3c-2-error-layer.md](phase-3c-2-error-layer.md); framework-fix precedent:
[openam-http-framework.md](openam-http-framework.md), [docs/framework-ownership.md](../../framework-ownership.md);
test layers: [docs/test-infrastructure.md](../../test-infrastructure.md). Written 2026-07-23; branch
`features/restlet-migration`. All facts below were verified against the tree and jar bytecode on 2026-07-23.

## Context

Phase 3d ports the OAuth2/UMA **access-audit** filters and their body-detail extraction from the Restlet
transport onto CHF. It is the last of the four Phase-3 sub-phases.

> **⚠ Correction to an earlier framing (and to [phase-3-research.md](phase-3-research.md) §3, which pre-dates
> this design).** 3d is **not** "purely additive build-ahead." It splits into two parts with **different risk
> profiles**, and conflating them is the mistake this doc previously made:
> - **3d-2 — the new OAuth2/UMA classes** *are* build-ahead: wired to no route until Phase 4 (UMA) / Phase 5
>   (OAuth2), so they carry no live guard and lean on the parity oracle (finding 9).
> - **3d-1 — the `AbstractHttpAccessAuditFilter` enhancement** is a **live-path change**. That class serves the
>   `/json` **authenticate** and **docs** audit filters **in production today** (`AuthenticationAccessAuditFilter`,
>   `DocsAccessAuditFilter`). Modifying it is exactly the kind of shared-class edit 3a/3b treated as live —
>   there **is** a live guard (the `/json` audit path + `AbstractHttpAccessAuditFilterTest` must stay green), and
>   "behaviour-neutral for `/json`" is a claim to **verify**, not assert. It is verified below
>   ([finding 5](#5-the-chf-base-audits-3xx-as-failed-restlet-audits-it-as-success) / [D2](#d2--3xx-classified-as-success-fix-in-the-base)):
>   authenticate emits only 200/401/4xx/5xx and docs only 200/404 — **no 3xx** — and the new hook paths are
>   dormant for `/json` (detail hooks return null, context overloads delegate). So the base change is neutral
>   for `/json` *today*, but it is a modification to live code, reviewed and guarded as such.

The parity oracle ([chf-patterns.md](chf-patterns.md) §13) remains the primary instrument for 3d-2, and it is
unusually cheap here because the piece with real transform logic (`HttpBodyAuditor`) is a **pure function
`bytes → JsonValue`**.

**What "audit" is here.** Two `AM_ACCESS` events per request — `AM_ACCESS_ATTEMPT` before the handler and
`AM_ACCESS_OUTCOME` after — carrying `userId`, `trackingIds`, `realm`, HTTP client/server/request detail, and
optionally a **body-detail** JSON object (selected fields lifted out of the request/response body). The
Restlet implementation is `AbstractRestletAccessAuditFilter` (openam-rest) + `OAuth2AbstractAccessAuditFilter`
/ `OAuth2AccessAuditFilter` / `UMAAccessAuditFilter` (all three in **openam-oauth2**) + `RestletBodyAuditor`
(openam-rest). The CHF base already exists: `AbstractHttpAccessAuditFilter` (openam-audit-core), with two live
subclasses on the `/json` side — `AuthenticationAccessAuditFilter` and `DocsAccessAuditFilter`.

**Outcome:** CHF replacements for the three Restlet OAuth2/UMA audit filters and `RestletBodyAuditor`, plus
the minimal enhancement to the shared CHF base that lets them carry body detail and read the OAuth2 request.
Phase 4/5d construct them per-route (see [work item 3](#3-oauth2httpaccessauditfilter-3d-2)).

## Scope & sizing (decided)

**3 new classes + 1 enhanced shared class + ~5 test classes.** ~250 LOC main, ~600 LOC test. Smaller than
3c-2 in size — but **not** simpler in risk: it mixes a **live-path** shared-class change with build-ahead new
classes, so it lands as **two commits** (3d-1 live, 3d-2 build-ahead — see the commit split below), never one.

- **New (openam-oauth2), package `org.openidentityplatform.openam.oauth2.audit`** per
  [decisions.md](decisions.md) — CDDL header, `Copyright 2026 3A Systems LLC.`, **no `@since`**:
  `HttpBodyAuditor`, `OAuth2HttpAccessAuditFilter`, `UMAHttpAccessAuditFilter`. (The UMA filter lives in
  openam-oauth2, mirroring today's `UMAAccessAuditFilter`; openam-uma depends on openam-oauth2 and consumes it
  in Phase 4.)
- **Modified (openam-audit-core), in place:** `AbstractHttpAccessAuditFilter` — additive, behaviour-neutral;
  keeps its `org.forgerock.openam.audit` package and gains a `Portions copyright … 3A Systems LLC.` line
  ([decisions.md](decisions.md) "modified in place" rule). Its test `AbstractHttpAccessAuditFilterTest` gains
  cases.
- **No pom change** — `AbstractHttpAccessAuditFilter`, `AuditEventPublisher`, `AuditEventFactory`,
  `AuditRequestContext` are already on openam-oauth2's compile path (transitively — neither
  `openam-oauth2/pom.xml` nor `openam-rest/pom.xml` names openam-audit-core directly, yet
  `OAuth2AccessAuditFilter`/`OAuth2RouterProvider` import these classes and compile today). http-framework
  `core` 3.1.1 is a direct dep (`openam-oauth2/pom.xml:62-63`). **Sanity-check with `mvn -o -pl openam-oauth2
  dependency:tree` before relying on this**; a one-line direct `openam-audit-core` dep is the trivial fallback
  if the transitive edge ever changes.
- **Adds no Guice bindings** — the OAuth2/UMA filters are **not** MapBinder singletons (see finding 2); they
  are constructed per-route. `HttpBodyAuditor`'s factories are static. 3b's binding-guard concern does not
  recur.
- **Deletes nothing.** `AbstractRestletAccessAuditFilter`, `RestletBodyAuditor`,
  `OAuth2AbstractAccessAuditFilter`, `OAuth2AccessAuditFilter`, `UMAAccessAuditFilter` die at Phase 5d /
  Phase 8 (the `AbstractRestletAccessAuditFilter` + `RestletBodyAuditor` deletion is Phase 8 step 4).

### Commit split — driven by risk profile, not just tidiness

The split is **mandatory here**, because the two halves have different risk profiles (see the Context
correction) and the repo convention is that **shared-class changes land as their own commit with their own
tests, never bundled into a migration commit** (the F1–F4 and
[D2](phase-3c-2-error-layer.md#d2--serverexception--400-on-the-contract-path-reproduce) precedents):

- **3d-1 — `AbstractHttpAccessAuditFilter` enhancement (openam-audit-core) — a LIVE-PATH change.** It touches
  the class behind `/json` authenticate + docs audit. Behaviour-neutral **for the current `/json` traffic**
  (verified: no 3xx there; new hook paths dormant), and it folds in a genuine latent-bug fix (3xx → success,
  [D2](#d2--3xx-classified-as-success-fix-in-the-base)) that benefits `/json` too. **Live guard: the `/json`
  audit path + `AbstractHttpAccessAuditFilterTest` must stay green.** Reviewable in isolation as a framework
  change — and it *must* be, because a regression here hits production `/json` audit, not a dormant build-ahead
  class. It **also carries the [D3](#d3--forrequest-query-param-leak-fix-separately) `forRequest` query-only
  fix** (same openam-audit-core builder, same live guard, its own one-line diff + test) — decided folded in
  2026-07-23.
- **3d-2 — OAuth2/UMA audit filters + `HttpBodyAuditor` (openam-oauth2) — build-ahead.** Wired to no route until
  Phase 4/5; no live guard; leans on the parity oracle. Depends on 3d-1's hooks and on 3a's
  `OAuth2RequestFactory.create(Context, Request)` + neutral accessors.

See [D6](#d6--modify-the-shared-base-vs-reimplement-to-stay-build-ahead) for the design fork this raises (fix
the shared base vs. keep 3d fully build-ahead by reimplementing) and why 3d-1 is still the right call.

Land as two commits or one, but keep the two diffs conceptually separate.

## Key research findings (drove this plan)

### 1. The CHF base has **no body auditing**, and its outcome hooks lack the request

`AbstractHttpAccessAuditFilter` (openam-audit-core) is a stripped-down port of the Restlet base. Two gaps make
it insufficient for OAuth2/UMA as-is:

- **No body detail at all.** `auditAccessAttempt` never sets `requestDetail`; `auditAccessSuccess` calls
  `.response(SUCCESSFUL, "", elapsed, MILLISECONDS)` — never `responseWithDetail`. The Restlet base
  (`AbstractRestletAccessAuditFilter:124-126,150-162`) drives a `RestletBodyAuditor` on attempt (request body)
  and success (response body). The plumbing to carry it already exists on the event builder —
  `AMAccessAuditEventBuilder.requestDetail(JsonValue)` (`:144`) and `responseWithDetail(…, JsonValue)`
  (`:191`) — the base simply never calls them.
- **The outcome hooks take only `Response`.** Restlet:
  `getUserIdForAccessOutcome(Request, Response)` / `getTrackingIdsForAccessOutcome(Request, Response)`. CHF:
  `getUserIdForAccessOutcome(Response)` / `getTrackingIdsForAccessOutcome(Response)` — **no request, no
  context**. The OAuth2 port needs both to build an `OAuth2Request` (`requestFactory.create(context, request)`)
  and read its tokens. The **attempt** hooks (`getUserIdForAccessAttempt(Request)` etc.) have the request but
  still lack the context.

**Both gaps are in a class we own** (openam-audit-core is in-tree), so [work item 1](#1-abstracthttpaccessauditfilter-enablement-3d-1)
fixes the base rather than working around it — the same call the framework-ownership doc mandates. The fix is
**additive and behaviour-neutral**: new context-bearing overloads whose defaults delegate to the existing
signatures, plus two null-returning detail hooks the base consults. The two live `/json` subclasses override
the old narrow signatures and keep working unchanged via delegation; the base test stays green.

### 2. ⚠ Audit is wired **per-route with per-endpoint body auditors** — not one filter per component

This is the load-bearing difference from `/json`. `/json` binds **one** `AbstractHttpAccessAuditFilter` per
`Component` through a `MapBinder<Component, AbstractHttpAccessAuditFilter>` and pulls it with
`HttpAccessAuditFilterFactory.createFilter(Component)` (`CoreRestAuthenticationGuiceModule:64-66,82`). One
filter, whole route, no body detail.

OAuth2/UMA attach a **fresh filter instance per endpoint**, each with a different body-auditor pair
(`OAuth2RouterProvider.auditWithOAuthFilter(...)`, `UmaRouterProvider.auditWithUmaFilter(...)`). The full
matrix, verified 2026-07-23 — reproduce it exactly in the Phase 4/5d route providers:

| Route (OAuth2, `Component.OAUTH`) | request auditor | response auditor |
|---|---|---|
| `/authorize` | — | — |
| `/access_token` | `form`(`response_type,grant_type,client_id,username,scope,redirect_uri`) | `json`(`scope,token_type`) |
| `/tokeninfo` | — | `json`(`scope,token_type`) |
| `/introspect` | `form`(`token_type_hint`) | `json`(`scope,token_type,client_id,username,active`) |
| `/connect/register` | `json`(`client_name,application_type,redirect_uris`) | `json`(`client_id,client_name,application_type,redirect_uris`) |
| `/userinfo` | — | — |
| `/idtokeninfo` | — | — |
| `/connect/checkSession` | — | — |
| `/connect/endSession` | — | — |
| `/connect/jwk_uri` | — | — |
| `/resource_set`, `/resource_set/`, `/resource_set/{rsid}` | `json`(`name,scopes`) | `json`(`_id`) |
| `/.well-known/openid-configuration` | — | — |
| `/device/user` | — | — |
| `/device/code` | `form`(`response_type,grant_type,client_id,scope`) | — |
| `/token/revoke` | — | — |

| Route (UMA, `Component.OAUTH`) | request auditor | response auditor |
|---|---|---|
| `/permission_request` | `json`(`resource_set_id,scopes`) | — |
| `/authz_request` | — | — |
| `/.well-known/uma-configuration` | — | — |

⇒ The CHF filters must be **plain constructible classes** (public ctor taking the two `HttpBodyAuditor`s),
built per-route — **not** Guice-bound singletons. Do not route them through the `Component` MapBinder /
`HttpAccessAuditFilterFactory`; that mechanism binds one filter per component and cannot vary body auditors per
endpoint. (`—` above = `HttpBodyAuditor.noBodyAuditor()`, i.e. `null`, exactly as `RestletBodyAuditor.noBodyAuditor()` today.)

**Both OAuth2 and UMA log under `Component.OAUTH`** (`UMAAccessAuditFilter:50`). `UMAHttpAccessAuditFilter`
still exists as a distinct class only because it overrides the outcome methods (finding 6).

### 3. `jsonAuditor` and `jacksonAuditor` **collapse into one** on CHF

`RestletBodyAuditor` has two JSON variants for a Restlet reason, not a semantic one:

- `jsonAuditor` parses via `org.restlet.ext.json.JsonRepresentation` → `org.json.JSONObject` (`.opt(field)`).
- `jacksonAuditor` parses via `org.restlet.ext.jackson.JacksonRepresentation` → `Map` (`.get(field)`).

The split is a **Restlet-representation-type** distinction, not a semantic one: a resource surfaces a body as
either an org.json `JsonRepresentation` or a Jackson `Map` depending on which representation *that resource*
created/consumed. It does **not** line up with request-vs-response — the finding-2 matrix mixes them
(`/introspect` *response* uses `jsonAuditor`; `/connect/register` *request* uses `jsonAuditor`). On CHF there
is one entity API — `Entity.getJson()` returns `Object` (a `Map` for a JSON object; verified `Entity.java:235`)
for request and response alike — so **one `HttpBodyAuditor.jsonAuditor(fields)` covers every case**: guard
`o instanceof Map`, lift each field via `((Map<?,?>)o).get(field)`, put non-null values in `fields` order.

⚠ **One near-unreachable divergence between the two Restlet variants that a single CHF auditor cannot honour
both ways.** For an **explicitly-null** JSON field (`"scope": null`), org.json `.opt` returns
`JSONObject.NULL` (non-null) so `jsonAuditor` **emits** the field as null, whereas Jackson `.get` returns Java
`null` so `jacksonAuditor` **omits** it. The collapsed CHF auditor reads a Jackson `Map`, so it matches
`jacksonAuditor` (omits) and diverges from `jsonAuditor` only on explicit-null fields. This is
**accepted** — audit body fields are scalars that are *absent* rather than explicitly `null` in every real
producer, and omitting a null field is the more sensible audit shape anyway. The parity test asserts
`chf == jacksonAuditor` universally and pins the explicit-null case as the documented `jsonAuditor` quirk we do
not reproduce ([D1](#d1--jsonauditor--jacksonauditor-collapse-fix)).

`Entity.getJson()` returns Jackson-parsed types (String/Boolean/Number/Map/List), so a boolean field like
`active` (introspect) and numeric fields come through as the same Java types the Jackson path produced — the
parity test covers a non-string field to prove it.

`formAuditor` maps to `new Form().fromFormString(entity.getString())` — **not** `Form.fromRequestEntity`,
which exact-matches the whole `Content-Type` header and silently empties a
`application/x-www-form-urlencoded;charset=UTF-8` body ([chf-patterns.md](chf-patterns.md) §7). Each form
auditor is only ever wired to a form endpoint, so unconditional form parsing matches Restlet's
`new Form(representation)`.

### 4. The CHF entity is **buffered** — no `BufferingRepresentation` wrap needed

The Restlet base has to guard against single-shot streams: `beforeHandle` wraps a transient entity in a
`BufferingRepresentation` so the body survives being read by the auditor **and** by downstream auth
(`AbstractRestletAccessAuditFilter:87-92`). On CHF, `Entity.getString()`/`getJson()` do not consume the
stream and both cache ([chf-patterns.md](chf-patterns.md) §7). Reading the request body in the audit filter
(before the handler) leaves it re-readable for the handler — **already proven in production** by
`AuthenticationAccessAuditFilter:80`, which reads `request.getEntity().getString()` in a CHF audit filter
while the auth handler reads it afterward. So `HttpBodyAuditor` needs **no** buffering ceremony, and risk #1
(form-POST body re-reading) is closed for the audit path by the entity model itself.
⇒ **Verify** the response body is still written to the wire after the response auditor reads it (finding 8's IT
asserts this).

### 5. ⚠ The CHF base audits **3xx as FAILED**; Restlet audits it as success

`AbstractHttpAccessAuditFilter.filter():76` branches on `response.getStatus().isSuccessful()` — and CHF
`Status.isSuccessful()` is **2xx only** (`Family.SUCCESSFUL`; verified in `Status.java:128`, which also has
`isRedirection()`/`isClientError()`/`isServerError()` and **no `isError()`**). The Restlet base
(`AbstractRestletAccessAuditFilter:105`) branches on `response.getStatus().isError()`, which (bytecode-verified)
is `isClientError() || isServerError() || isConnectorError() || isGlobalError()` — i.e. 4xx/5xx plus Restlet's
**internal** 6xx (global) and 10xx (connector) pseudo-statuses that have **no CHF wire equivalent**. So on a
real HTTP response Restlet audits 4xx/5xx as failure and everything else — including every **3xx** — as
`AM_ACCESS_OUTCOME` **SUCCESSFUL**.

OAuth2/OIDC lives on 3xx: `/authorize` **success** is a **302** to `redirect_uri`; the error layer emits
**301** (login redirect) and **302** (error redirect) ([phase-3c-2](phase-3c-2-error-layer.md)). Ship the base
unchanged and every successful authorize redirect flips from SUCCESSFUL to FAILED in the audit log at the
Phase-5d flip — a silent audit regression on the single most common OAuth2 browser flow.

**Fix in the base** ([D2](#d2--3xx-classified-as-success-fix-in-the-base)): failure iff
`isClientError() || isServerError()`, i.e. reproduce Restlet's `!isError()`. Behaviour-neutral for `/json`
(authentication/docs do not emit 3xx) and restores OAuth2 parity. This is exactly the kind of "issue in CHF
that makes migration harder" we eliminate at source because we own the code.

⚠ **Related, accepted divergence on the FAILED path — the `reason` string.** The Restlet failure path writes
`http/response/detail/reason` from `Status.getDescription()` (`AbstractRestletAccessAuditFilter:178` — e.g. 400
→ "The request could not be understood by the server due to malformed syntax"); the CHF base uses
`Status.getReasonPhrase()` (`AbstractHttpAccessAuditFilter:132` — 400 → "Bad Request"). So the *reason string*
inside an already-FAILED outcome event differs. This is **unavoidable** (CHF `Status` has no `getDescription()`
equivalent) and **pre-existing** (already how `/json` 4xx audits today), so 3d does **not** change it — but it
*is* an OAuth2-audit-parity divergence that surfaces at the 5d flip for every 4xx/5xx, so record it in 5d's
audit smoke alongside risk #13. Only the reason text differs; `status`/`statusCode`/classification are
identical.

### 6. UMA's outcome overrides — reproduce verbatim

`UMAAccessAuditFilter` overrides both outcome methods to **not** re-derive identity from the response
(`:60-75`): `getUserIdForAccessOutcome` returns whatever is already in `AuditRequestContext` (USER_ID or `""`);
`getTrackingIdsForAccessOutcome` returns `getAllAvailableTrackingIds()`. Only the **attempt** path derives
identity from tokens/SSO (inherited from `OAuth2AbstractAccessAuditFilter`). `UMAHttpAccessAuditFilter` must
reproduce this: inherit the OAuth2 attempt behaviour, override the two outcome hooks to the context-only forms.

### 7. userId / trackingId extraction — the token+SSO logic to port

`OAuth2AbstractAccessAuditFilter` seeds `AuditRequestContext` on both attempt and outcome, then the base reads
it back. Port the private helpers onto the CHF request via the 3a neutral accessors:

- **userId** (`getUserId`, `:152-167`): first token whose type is `IntrospectableToken` →
  `getResourceOwnerId()`, or `OpenIdConnectToken` → `get(sub).asString()`; else the SSO token's
  `UNIVERSAL_IDENTIFIER`. Tokens come from `requestFactory.create(context, request).getTokens()`; the SSO token
  from `SSOTokenManager.createSSOToken(oauth2Request.getHttpServletRequest())` (replaces
  `ServletUtils.getRequest(restletRequest)`).
- **trackingIds** (`putTrackingIdsIntoAuditRequestContext`, `:129-150`): each token's
  `getAuditTrackingIdKey()` → `getAuditTrackingId()`; plus the session tracking id — from the SSO token's
  `Constants.AM_CTX_ID` property, or, when there is no SSO token, from a **request attribute** `AM_CTX_ID`.
  On CHF the request-attribute fallback is `oauth2Request.getAttribute(Constants.AM_CTX_ID)` (the internal
  attribute map introduced in 3a — `OAuth2Request.getAttribute`), **not** a servlet attribute.

⚠ **`AM_CTX_ID` request-attribute fallback is a soft edge.** [phase-3-research.md](phase-3-research.md) §2b
found `AM_CTX_ID` is written on the **Restlet request** by `ClientAuthenticator:183` and has *no reader off
request attributes anywhere in the repo* — the audit fallback here is its only apparent consumer, and it fires
only when there is no SSO token. Whether it ever lands in `ChfOAuth2Request`'s attribute map depends on how
`ClientAuthenticator` is ported (3a/5). **Reproduce the read** (`getAttribute(AM_CTX_ID)`); flag it low-risk
and note it in 5d's audit smoke — if the value is absent on CHF, the session tracking id is simply omitted in
the no-SSO-token case, which is a corner of a corner.

### 8. `forRequest(request, context)` vs `forHttpServletRequest(servletRequest)` — the HTTP-detail path

The Restlet base sets HTTP client/server/request detail via
`AMAccessAuditEventBuilder.forHttpServletRequest(servletRequest)` (`AbstractRestletAccessAuditFilter:195-200`);
the CHF base uses `forRequest(request, context)` (`AbstractHttpAccessAuditFilter:97,118,142`). Both exist on
the builder. One divergence is baked into `forRequest`:

⚠ **`forRequest` reads query parameters from `request.getForm()`** (`AMAccessAuditEventBuilder:123`), which is
`fromRequestQuery` **then** `fromRequestEntity` merged ([chf-patterns.md](chf-patterns.md) §7). So on a form
POST with `Content-Type: application/x-www-form-urlencoded` (no charset), the **POST body params leak into
`http/request/queryParameters`** of the audit event — where the Restlet `forHttpServletRequest` path
(servlet query string only) would not. With a `;charset=…` suffix they do *not* leak (the exact-match trap),
so the behaviour is also self-inconsistent. This is **risk #13**. Two options:

- **(recommended)** Fix `forRequest` to use `Form.fromRequestQuery(request)` — query only. Behaviour-neutral
  for `/json` (JSON bodies parse to an empty form anyway) and closes the leak for `/oauth2` form endpoints. A
  separate one-line commit with its own test, like [D2](phase-3c-2-error-layer.md#d2--serverexception--400-on-the-contract-path-reproduce)
  — **not** bundled into 3d, because it touches a shared builder method used by `/json` and every CHF audit
  path. Filed here as [D3](#d3--forrequest-query-param-leak-fix-separately); leave it out of 3d unless the
  reviewer wants it folded in.
- Accept and document the divergence (the leaked fields are `grant_type`/`scope`/etc., not secrets — the token
  never appears — but `client_secret` on a form POST **would** leak into the audit log, which argues for the
  fix).

**Decided (2026-07-23):** take the fix, folded into 3d-1 ([D3](#d3--forrequest-query-param-leak-fix-separately)).
Separately, the *root* CHF sharp edge behind the self-inconsistency — `Form.fromRequestEntity`'s exact
whole-header content-type match (`Form.java:231-239`), which silently empties a `;charset=UTF-8` form body — is
**tracked as a standalone CHF cleanup** ([decisions.md § CHF cleanup backlog](decisions.md#chf-cleanup-backlog)).
3d does not depend on it: the audit path uses `fromRequestQuery`/`fromFormString` and never calls
`fromRequestEntity`.

### 9. The parity oracle is cheap here — `HttpBodyAuditor` is a pure `bytes → JsonValue`

The only component with real transform logic is `HttpBodyAuditor`; the filters are plumbing. So the
[3-way golden oracle](chf-patterns.md#13-the-3-way-golden-oracle-phase-3c--how-parity-survives-restlets-deletion)
reduces to a tiny A/B: feed the **same body bytes** to a `RestletBodyAuditor` and an `HttpBodyAuditor` and
assert identical `JsonValue`. No golden file needed — the two implementations *are* each other's oracle while
Restlet is on the classpath ([chf-patterns.md](chf-patterns.md) §13 "inline asserts beat a golden file for
small maps"). This runs `RestletBodyAuditor.jsonAuditor` **and** `jacksonAuditor` against the collapsed CHF
`jsonAuditor` (finding 3), and `formAuditor` against `formAuditor`, over: normal bodies, empty bodies, missing
fields, non-ASCII values, and the `;charset=UTF-8` content type. Degrades to a plain characterization test
after Phase 5d deletes the Restlet leg.

## Work items

### 1. `AbstractHttpAccessAuditFilter` enablement (3d-1)

Additive, behaviour-neutral changes to the openam-audit-core base. **No existing subclass is edited** — every
change is a new overload with a delegating default, or a new null-returning hook.

- **Context-bearing hooks** (base's private audit methods call these; defaults delegate to the existing
  signatures so `AuthenticationAccessAuditFilter`/`DocsAccessAuditFilter` keep working unchanged):
  ```java
  protected String getUserIdForAccessAttempt(Context context, Request request) {
      return getUserIdForAccessAttempt(request);
  }
  protected Set<String> getTrackingIdsForAccessAttempt(Context context, Request request) {
      return getTrackingIdsForAccessAttempt(request);
  }
  protected String getUserIdForAccessOutcome(Context context, Request request, Response response) {
      return getUserIdForAccessOutcome(response);
  }
  protected Set<String> getTrackingIdsForAccessOutcome(Context context, Request request, Response response) {
      return getTrackingIdsForAccessOutcome(response);
  }
  ```
  `auditAccessAttempt` now calls the `(context, request)` forms; `auditAccessSuccess`/`auditAccessFailure` call
  the `(context, request, response)` forms. Keep the old signatures — the existing subclasses and the base test
  invoke them directly.
- **Body-detail hooks** (default null; **both declare `throws AuditException`** so the base — not each subclass —
  owns Restlet's two *divergent* policies: a request-detail `AuditException` skips the whole attempt event, a
  response-detail one is swallowed to no-detail. This keeps the subclass overrides trivial — just
  `return auditor == null ? null : auditor.apply(entity)` (work item 3), with no per-subclass catch to drift.
  The base consults them where Restlet drives the body auditors — request on attempt, response on **success
  only**, never on failure, per `AbstractRestletAccessAuditFilter`):
  ```java
  protected JsonValue getRequestDetail(Context context, Request request) throws AuditException { return null; }
  protected JsonValue getResponseDetail(Context context, Request request, Response response) throws AuditException { return null; }
  ```
  - `auditAccessAttempt`: `JsonValue d = getRequestDetail(context, request); if (d != null) builder.requestDetail(d);`
    Wrap the attempt body in `try { … } catch (AuditException e) { debug.error(…); }` **with `tryPublish` inside
    the try**, so a request-body parse failure **skips the whole attempt event** (no event published) rather
    than publishing a detail-less one — reproducing Restlet exactly, where the `AuditException` from
    `requestDetailCreator.apply` (`AbstractRestletAccessAuditFilter:125`) propagates *past* `tryPublish`
    (`:130`) and is caught in `beforeHandle` (`:93-97`). (The current CHF base has no such catch because it
    never parsed a body.) The [test](#tests) "request-detail `AuditException` skips the attempt event" pins
    this — a catch that wrapped only the detail extraction would publish a detail-less attempt event and fail it.
  - `auditAccessSuccess`: `JsonValue d = getResponseDetail(…); if (d != null) …responseWithDetail(SUCCESSFUL, "", elapsed, MILLISECONDS, d); else …response(SUCCESSFUL, "", elapsed, MILLISECONDS);`
    Catch `AuditException` **internally**, log at warn, treat as no detail — reproducing
    `AbstractRestletAccessAuditFilter:150-162`.
- **3xx classification** ([D2](#d2--3xx-classified-as-success-fix-in-the-base)): change `filter()`'s branch to
  `if (response.getStatus().isClientError() || response.getStatus().isServerError()) auditAccessFailure(...); else auditAccessSuccess(...);`
- **Add a logger.** The CHF base currently has **no** logger field (unlike `AbstractRestletAccessAuditFilter`,
  which has `Debug.getInstance("amAudit")`); the new catch blocks need one — add `Debug.getInstance("amAudit")`
  to match.
- **Leave `getRealm(Context)` abstract.**
- **Fix the `forRequest` query-param leak** ([D3](#d3--forrequest-query-param-leak-fix-separately) — decided
  folded into 3d-1): in `AMAccessAuditEventBuilder.forRequest`, read query parameters via
  `Form.fromRequestQuery(request)` instead of `request.getForm()`, so form-POST body fields (incl.
  `client_secret`) stop leaking into `http/request/queryParameters`. Behaviour-neutral for `/json`
  (`application/json` never matches `fromRequestEntity`'s form content-type guard); its own test. Leave the
  `forRequest(request, context)` HTTP-detail call otherwise as-is.

Guard the whole thing with additions to `AbstractHttpAccessAuditFilterTest`: a `MockAccessAuditFilter` that
returns a request/response detail and overrides a context-bearing hook, asserting (a) detail lands under
`request/detail` and `response/detail`, (b) a 302 response audits **SUCCESSFUL**, (c) the delegating defaults
still return the `AuditRequestContext` value when only the narrow signature is overridden.

### 2. `HttpBodyAuditor` (3d-2)

CHF replacement for `RestletBodyAuditor`, over `org.forgerock.http.protocol.Entity`.

```java
public abstract class HttpBodyAuditor implements Function<Entity, JsonValue, AuditException> {
    public static HttpBodyAuditor jsonAuditor(String... fields);   // collapses Restlet json+jackson (finding 3)
    public static HttpBodyAuditor formAuditor(String... fields);
    public static HttpBodyAuditor noBodyAuditor();                 // returns null (matches Restlet)
}
```

- `jsonAuditor`: if `entity.isDecodedContentEmpty()` → `json(object())` (guard first — `getJson()` on an empty
  entity throws `IOException`, verified in [phase-3c-2 finding 7](phase-3c-2-error-layer.md#7--the-filter-cannot-catch--and-endpointsfroms-500-has-an-empty-body));
  else `Object o = entity.getJson();` and if `o instanceof Map`, lift each field via `((Map<?,?>)o).get(field)`,
  putting non-null values. `catch (IOException) → throw new AuditException("Could not parse body as JSON …", e)`
  (matches `RestletBodyAuditor:82-84`).
- `formAuditor`: `new Form().fromFormString(entity.getString())` then `form.getFirst(field)` (finding 3). Empty
  body → empty form → empty result, matching `new Form(emptyRepresentation)`.
- Field-selection contract identical to `RestletBodyAuditor.extractValues`: only listed fields, non-null values
  only, order = `fields` order (into a `json(object())`).

### 3. `OAuth2HttpAccessAuditFilter` (3d-2)

```java
public class OAuth2HttpAccessAuditFilter extends AbstractHttpAccessAuditFilter {
    public OAuth2HttpAccessAuditFilter(AuditEventPublisher publisher, AuditEventFactory factory,
            OAuth2RequestFactory requestFactory,
            HttpBodyAuditor requestDetail, HttpBodyAuditor responseDetail);   // Component.OAUTH
    // overrides: getUserIdForAccessAttempt(ctx,req), getTrackingIdsForAccessAttempt(ctx,req),
    //            getUserIdForAccessOutcome(ctx,req,resp), getTrackingIdsForAccessOutcome(ctx,req,resp),
    //            getRequestDetail(ctx,req), getResponseDetail(ctx,req,resp), getRealm(ctx)
}
```

- **Not `@Inject`/singleton** — constructed per-route by the Phase-5d `OAuth2HttpRouteProvider` with the
  body-auditor pair from finding 2's matrix (mirrors `OAuth2RouterProvider.auditWithOAuthFilter`).
- Port the identity logic (finding 7) onto `requestFactory.create(context, request)` + the neutral accessors.
  Keep the seed-then-read-back shape: attempt/outcome hooks call `putUserIdInAuditRequestContext` /
  `putTrackingIdsIntoAuditRequestContext` then `super.getUserIdForAccessAttempt(...)` etc. (so
  `AuditRequestContext` remains the single source, exactly as today).
- `getRequestDetail` → `requestDetail == null ? null : requestDetail.apply(request.getEntity())`;
  `getResponseDetail` → `responseDetail == null ? null : responseDetail.apply(response.getEntity())`.
- `getRealm(context)`: `context.containsContext(RealmContext.class) ? context.asContext(RealmContext.class).getRealm().asPath() : null`.
  `null == AuditConstants.NO_REALM` (`AuditConstants.java:300` — `NO_REALM = null`), so this is **exact
  parity** with the Restlet base's `isBlank(realm) ? NO_REALM : realm` and matches the `/json` subclasses.
- Logger `"oauth2"` for the same debug lines as the Restlet filter.

**Wiring position (a Phase 4/5d concern, flagged here).** The filter must sit **per-route and outermost of the
per-route chain** — mirroring the Restlet per-endpoint `Filter` wrap — so it (a) sees the *final* response
status for the 3xx/4xx classification and (b) is *inside* the realm router, so realm-resolution failures
(400/404 before the endpoint) are **not** audited, matching Restlet (those are handled by the status service
today, and by `OAuth2ErrorFilter` post-flip). Order relative to `OAuth2ErrorFilter` (3c-2) is not critical for
classification: the error filter rewrites the error *body* but **preserves the status**, so the audit
success/failure verdict is the same whichever is outer. It does matter for the *failure* path's audited body —
but the failure path audits only the status **reason**, never the body ([finding 1](#1-the-chf-base-has-no-body-auditing-and-its-outcome-hooks-lack-the-request)),
and the success body auditor reads a body the handler set before either filter runs. Net: audit-outermost is
the safe, faithful placement; confirm in 5d's chain assembly.

### 4. `UMAHttpAccessAuditFilter` (3d-2)

Subclass of `OAuth2HttpAccessAuditFilter` (or of the base with the same attempt logic), overriding **only** the
two outcome hooks to the context-only forms (finding 6): `getUserIdForAccessOutcome` → `AuditRequestContext`
USER_ID or `""`; `getTrackingIdsForAccessOutcome` → `getAllAvailableTrackingIds()`. Same `Component.OAUTH`,
same per-route construction (by the Phase-4 `UmaHttpRouteProvider`).

## Decisions

<a id="d1--jsonauditor--jacksonauditor-collapse-fix"></a>
### D1 — `jsonAuditor` + `jacksonAuditor` collapse into one: **fix (simplify)**

The two Restlet JSON auditors differ only by Restlet representation type, not by contract (finding 3). CHF's
single `Entity.getJson()` makes one `jsonAuditor` cover both request and response. The parity test asserts the
collapsed auditor against **both** Restlet variants, so the simplification is proven, not assumed. Recorded so
Phase 4/5d wiring writes `jsonAuditor(...)` wherever the Restlet table had either `jsonAuditor` or
`jacksonAuditor`.

<a id="d2--3xx-classified-as-success-fix-in-the-base"></a>
### D2 — 3xx classified as success: **fix in the base**

The CHF base audits 3xx as FAILED (`isSuccessful()` = 2xx only); Restlet audits it as success (finding 5).
Reproduce Restlet: `auditAccessFailure` iff `isClientError() || isServerError()` — the faithful CHF mapping of
Restlet's `isError()`, since its extra `isConnectorError()`/`isGlobalError()` families are internal
pseudo-statuses with no CHF wire equivalent. Behaviour-neutral for `/json` (no 3xx there), restores parity for
OAuth2's 301/302 flows. In-tree class, our fix. Asserted in `AbstractHttpAccessAuditFilterTest`
(302 → SUCCESSFUL) and in the IT.

<a id="d3--forrequest-query-param-leak-fix-separately"></a>
### D3 — `forRequest` query-param leak (risk #13): **fix — folded into the 3d-1 commit** (decided 2026-07-23)

`forRequest` reads query params from `request.getForm()`, leaking POST-body form fields (and, on a form token
request, `client_secret`) into `http/request/queryParameters` (finding 8). The fix is one line — swap
`request.getForm()` for `Form.fromRequestQuery(request)` (query only). Verified at source: `Request.getForm()`
merges `fromRequestQuery` (always) with the content-type-guarded `fromRequestEntity` (`Request.java:79-88`), and
`fromRequestEntity` parses the body only on an exact `application/x-www-form-urlencoded` header match
(`Form.java:231-239`). So the fix is **behaviour-neutral for `/json`** (a JSON body's `application/json` never
matches that guard — `getForm()` is already query-only there) and closes the leak for `/oauth2` form endpoints.

**Decided (2026-07-23): fold it into the 3d-1 commit.** The change lands in `AMAccessAuditEventBuilder.forRequest`
— the same openam-audit-core class family touched by the base enhancement — so it belongs to the same live-path
commit, carries its own test (`forRequest` records query params only, not form-POST body fields), and shares
3d-1's live guard. It benefits `/json` too. Still reviewable as a distinct one-line diff within that commit.

*Distinct from the root CHF sharp edge.* `fromRequestEntity`'s exact whole-header match (which silently empties a
`;charset=UTF-8` form body and makes the leak self-inconsistent) is **not** fixed here — 3d never calls it — and
is tracked separately in [decisions.md § CHF cleanup backlog](decisions.md#chf-cleanup-backlog).

<a id="d4--per-route-construction-not-mapbinder-reproduce"></a>
### D4 — Per-route filter construction, not the `Component` MapBinder: **reproduce**

OAuth2/UMA need a different body-auditor pair per endpoint (finding 2), which the one-filter-per-component
`MapBinder` + `HttpAccessAuditFilterFactory` cannot express. The CHF filters are plain constructible classes,
built per-route in the route providers — exactly as `OAuth2RouterProvider`/`UmaRouterProvider` do today. No
Guice binding, no binding-guard concern.

<a id="d5--no-warn-on-every-error"></a>
### D5 — logging level: keep the Restlet filter's existing behaviour

Unlike [phase-3c-2 §3 D5-analogue](phase-3c-2-error-layer.md#3-oauth2errorresponsefactory) (which downgraded
`ExceptionHandler`'s warn-on-every-4xx), the audit filters do not log per error — the base only debug-logs SSO
lookup failures. Port those debug lines verbatim; no logging change needed here.

<a id="d6--modify-the-shared-base-vs-reimplement-to-stay-build-ahead"></a>
### D6 — Modify the shared base (live-path) **vs.** reimplement to stay build-ahead: **modify the base**

The Context correction exposes a genuine fork, because the two Phase-3 sub-phases before this one were purely
build-ahead and this one cannot be if it enhances the shared base:

- **Design A (chosen) — enhance `AbstractHttpAccessAuditFilter`.** Add the context-bearing + detail hooks and
  the 3xx fix to the shared base (work item 1). *Cost:* 3d-1 is a **live-path** change to `/json` audit; needs
  the live guard and isolated-commit treatment. *Benefit:* no duplication of the ~40-line audit-event pipeline;
  fixes the 3xx latent bug for every CHF audit filter (present and future); matches what
  [plan.md](plan.md)'s 3d bullet already says ("extend `AbstractHttpAccessAuditFilter`"); aligns with
  "fix the framework, don't work around it" ([chf-patterns.md](chf-patterns.md) §14) — the base's missing
  body-detail and request-less outcome hooks are real limitations of a class **we own**.
- **Design B (rejected) — leave the base untouched, reimplement in an OAuth2-specific filter.** Have
  `OAuth2HttpAccessAuditFilter implements Filter` directly (or via a new `OAuth2AbstractHttpAccessAuditFilter`),
  duplicating the attempt/outcome/publish pipeline so 3d stays 100% build-ahead with zero `/json` risk. *Cost:*
  ~40 lines of duplicated audit-event plumbing that then drifts from the base (the exact failure mode
  [phase-3c-2 finding 4](phase-3c-2-error-layer.md#4--get-and-post-have-different-no-redirect-sets--and-post-has-an-open-redirect)
  documents for `AuthorizeResource`); leaves the 3xx bug in the shared base; contradicts the tracker.

**Chosen: A.** The base gaps are worth fixing at source, the change is verified neutral for `/json` today, and
the duplication in B is precisely the kind of copy-that-drifts this migration keeps getting burned by. The
price — treating 3d-1 as a live-path commit with a live guard — is paid explicitly rather than hidden behind a
"build-ahead, no guard" label.

## Tests

Baseline before 3d: **3c-2 as-built** (see [its as-built](phase-3c-2-error-layer.md#as-built) for the exact
count) — re-derive with `mvn -pl openam-oauth2 test` before starting so the delta is attributable.

- **`AbstractHttpAccessAuditFilterTest` additions (3d-1, openam-audit-core):** request/response detail lands
  under `request/detail`+`response/detail`; 302 → SUCCESSFUL ([D2](#d2--3xx-classified-as-success-fix-in-the-base));
  delegating defaults preserve the narrow-override path; request-detail `AuditException` skips the attempt
  event; response-detail `AuditException` publishes without detail. Existing cases stay green (proves
  behaviour-neutrality for `/json`).
- **`AMAccessAuditEventBuilder` `forRequest` test (3d-1, [D3](#d3--forrequest-query-param-leak-fix-separately)):**
  a form POST (`application/x-www-form-urlencoded`, with and without `;charset=UTF-8`) records the URL query
  parameters **only** — POST-body fields and `client_secret` do **not** land in `http/request/queryParameters`;
  a JSON POST behaves identically (query-only). Guards the leak fix against a `getForm()` regression.
- **`HttpBodyAuditorTest` (3d-2):** `json`/`form` field selection, empty-body → `{}`, missing field omitted,
  non-ASCII value preserved, `;charset=UTF-8` content type parsed (not silently emptied), `noBodyAuditor()` ==
  null.
- **`RestletAuditParityTest` (3d-2) — the oracle (finding 9), and the *first* coverage of this behaviour:**
  same bytes → `HttpBodyAuditor.jsonAuditor` **equals** `RestletBodyAuditor.jacksonAuditor` **universally**, and
  equals `RestletBodyAuditor.jsonAuditor` **except** for an explicitly-`null` JSON field (the documented
  `JSONObject.NULL` quirk we do not reproduce — [D1](#d1--jsonauditor--jacksonauditor-collapse-fix)); `formAuditor`
  vs `formAuditor`. Cover a **boolean/numeric** field (`active`) to pin Java types, a non-ASCII value, an empty
  body, a missing field, and the `;charset=UTF-8` content type. Pin UTF-8 on both legs. Runs while Restlet is on
  the classpath; degrades to characterization after 5d.
- **`OAuth2HttpAccessAuditFilterTest` / `UMAHttpAccessAuditFilterTest` (3d-2):** userId from
  `IntrospectableToken`/`OpenIdConnectToken`/SSO; trackingIds from token keys + session `AM_CTX_ID`
  (+ the request-attribute fallback, finding 7); realm from `RealmContext`; UMA outcome overrides
  (finding 6). Use the [chf-patterns.md](chf-patterns.md) §5 scaffolding (real context chain
  `RootContext → AttributesContext → RealmContext → UriRouterContext`, `RealmTestHelper`), a capturing
  `AuditEventPublisher` mock, and a spy/stub on `OAuth2RequestFactory`/`SSOTokenManager` for the token seams.

### Integration test (build-ahead, in-process composition)

Model on [`OAuth2ErrorRouteCompositionIT`](phase-3c-2-error-layer.md#c-oauth2errorroutecompositionit--in-process-composition-second-highest-value)
(3c-2's first module IT). `OAuth2AuditRouteCompositionIT`: build a real CHF chain
`Handlers.chainOf(handler, new OAuth2HttpAccessAuditFilter(publisher, factory, requestFactory, form(...), json(...)))`
with a capturing `AuditEventPublisher`, drive a `Request` with a form body + a token, and assert:

1. Two events published — `AM_ACCESS_ATTEMPT` then `AM_ACCESS_OUTCOME`.
2. `request/detail` carries the selected request-body fields; `response/detail` the response-body fields.
3. `userId`/`trackingIds` populated from the token.
4. A **302** handler response → OUTCOME **SUCCESSFUL** ([D2](#d2--3xx-classified-as-success-fix-in-the-base)).
5. The response body is **intact on the returned `Response`** after the auditor read it (finding 4 — proves the
   entity re-read does not consume the body destined for the wire).

This proves the filter composes in a real CHF chain **before** Phase 4/5 wires it to a live route — the earliest
point the build-ahead risk (#19) can be retired for the audit layer.

## Verification criteria

1. **Module-scoped:** `mvn -o -pl openam-audit/openam-audit-core test` (3d-1) then
   `mvn -o -pl openam-oauth2 install -DskipTests` followed by `mvn -o -pl openam-oauth2 test` (3d-2). The
   `install` between is required — openam-oauth2 resolves openam-audit-core from `~/.m2`, not the reactor, when
   built module-scoped ([chf-patterns.md](chf-patterns.md) §11); after a base API change, a stale installed jar
   fails the openam-oauth2 compile.
2. **Whole build with `-am`:** `mvn -o install -pl openam-oauth2,openam-audit/openam-audit-core -am -DskipTests`
   — openam-audit-core is low in the graph, so many modules recompile against it. Build with `-am` to avoid the
   stale-SNAPSHOT-jar trap (memory: `.m2 stale schema jar trap`).
3. **3d-1 has a LIVE guard; 3d-2 has none.** The two halves differ (Context correction):
   - **3d-1 (base change)** touches live `/json` audit. Its guard is the **existing `/json` audit behaviour +
     `AbstractHttpAccessAuditFilterTest`**: every pre-existing case must pass unchanged (proves neutrality for
     authenticate/docs), plus the new 302→SUCCESSFUL / dormant-detail-hook cases. Run
     `mvn -o -pl openam-core-rest test` too, since `AuthenticationAccessAuditFilter`/`DocsAccessAuditFilter`
     subclass the changed base.
   - **3d-2 (new OAuth2/UMA classes)** has **no** live guard — and confirmed 2026-07-23 there are **no** Restlet
     audit tests to keep green either (`OAuth2AccessAuditFilterTest`, `UMAAccessAuditFilterTest`,
     `OAuth2AbstractAccessAuditFilterTest`, `AbstractRestletAccessAuditFilterTest`, `RestletBodyAuditorTest` all
     **do not exist**; the OAuth2/UMA audit path ships **untested** today). So 3d-2 **writes the first coverage
     of this behaviour**, exactly as F1–F4 did for openam-http, and the parity oracle is its **primary**
     correctness instrument, not a substitute.
4. **Parity oracle green** — `RestletAuditParityTest` (finding 9) drives the real legacy `RestletBodyAuditor`
   alongside `HttpBodyAuditor` while Restlet is on the classpath. It is the only thing that pins the CHF auditor
   to *observed* legacy behaviour rather than to this plan's belief about it — write it first, per
   [phase-3b as-built #2](phase-3b-collaborators.md) (characterization tests written before a strip failed 3/4
   against the unmodified code).
5. **No new `getCurrent()` / Restlet import** in the 3d-2 classes:
   `grep -rn "org.restlet\|getCurrent()" openam-oauth2/src/main/java/org/openidentityplatform/openam/oauth2/audit`
   → 0.
6. **CI** (`.github/workflows/build.yml`): JDK 11–26 × 3 OSes on push — cross-version coverage of the entity
   parsing and charset handling for free.

Deferred to Phase 4/5d (needs a live route): the full `AM_ACCESS` event captured against a running WAR and
diffed against pre-flip Restlet output (risk #13 — record `http/request/queryParameters` on `/access_token`
pre-flip; confirm no body-field leak post-flip, verifying [D3](#d3--forrequest-query-param-leak-fix-separately)
closed it in 3d-1).

## Risks (extends [plan.md](plan.md)'s register)

- **R-3d.1 Body re-read (risk #1).** Closed for audit by the buffered CHF entity (finding 4); the IT step 5
  proves the response body survives the read.
- **R-3d.2 3xx audited as failure (risk #13, new).** [D2](#d2--3xx-classified-as-success-fix-in-the-base) fixes
  it in the base; without the fix every authorize-success 302 flips to FAILED at 5d. Highest-severity finding
  in 3d.
- **R-3d.3 Query-param leak on form POST (risk #13).** [D3](#d3--forrequest-query-param-leak-fix-separately) —
  **fixed in 3d-1** (`forRequest` → `Form.fromRequestQuery`), closing the `client_secret`-on-form-token leak.
  Retired for the audit path once 3d-1 lands; 5d smoke still confirms the pre/post-flip `queryParameters` diff.
- **R-3d.4 `jsonAuditor`/`jacksonAuditor` collapse.** [D1](#d1--jsonauditor--jacksonauditor-collapse-fix);
  proven by `RestletAuditParityTest` against both variants.
- **R-3d.5 `AM_CTX_ID` request-attribute fallback (finding 7).** Low — its only reader is this filter and only
  in the no-SSO-token case; depends on `ClientAuthenticator`'s CHF port populating the attribute map. Reproduce
  the read; verify in 5d smoke.
- **R-3d.6 3d-2 is build-ahead, no live guard (risk #19).** Applies to the **new OAuth2/UMA classes only**.
  Mitigated by the parity oracle + the composition IT; fully retired when Phase 4/5 wires the routes.
- **R-3d.7 3d-1 is a live-path change to `/json` audit (new, and the assumption this review corrected).** The
  base enhancement modifies the class behind production authenticate/docs audit. Verified neutral today (no 3xx
  on those endpoints; new hook paths dormant), but a mistake regresses **live** `/json` audit, not a dormant
  class. Guard: existing `AbstractHttpAccessAuditFilterTest` + `openam-core-rest` audit tests stay green; land
  3d-1 as its own commit ([D6](#d6--modify-the-shared-base-vs-reimplement-to-stay-build-ahead)). This is the
  opposite risk profile from R-3d.6 — do not treat the two halves of 3d the same way.

## As-built

_Completed 2026-07-23 on `features/restlet-migration`. Landed as **two commits**, per the mandated split:_

- **3d-1** `666ea57318` — *audit base enablement + `forRequest` query-only fix* (live-path, openam-audit-core).
- **3d-2** `41170fb92a` — *OAuth2/UMA CHF audit filters (build-ahead) + 3d review fixes* (openam-oauth2). The
  post-review cleanups to the 3d-1 base (below) were folded into this commit rather than a third.

### Final classes

**New (openam-oauth2, `org.openidentityplatform.openam.oauth2.audit`)** — CDDL + `Copyright 2026 3A Systems LLC.`, no `@since`:

| Class | Shape |
|---|---|
| `HttpBodyAuditor` | `abstract … implements Function<Entity, JsonValue, AuditException>`; static `jsonAuditor` / `formAuditor` / `noBodyAuditor`; one private `select(fields, valueOf)` helper both auditors reuse (review #2) |
| `OAuth2HttpAccessAuditFilter` | extends `AbstractHttpAccessAuditFilter` under `Component.OAUTH`; overrides the 4 context-bearing hooks (seed-then-read-back), `getRequestDetail`/`getResponseDetail`, `getRealm`; `protected getSSOToken(OAuth2Request)` testability seam |
| `UMAHttpAccessAuditFilter` | extends the OAuth2 filter; overrides **only** the two outcome hooks so the outcome does not re-derive identity |

**Modified in place** (`org.forgerock.openam.audit`, `Portions Copyrighted 2026 3A Systems LLC.`):

| Class | Change |
|---|---|
| `AbstractHttpAccessAuditFilter` | 4 context-bearing hook overloads (delegating defaults) + 2 null detail hooks; attempt/success/failure rewired to consult them; **3xx→SUCCESSFUL** fix (`isClientError()||isServerError()`, D2); `Debug` logger field (`private static final`, review #4) |
| `AMAccessAuditEventBuilder` | `forRequest` query params via `new Form().fromRequestQuery(request)` — query-only, no form-POST body leak (D3) |

**No pom change** — the transitive `openam-audit-core` edge held (`mvn -o -pl openam-oauth2 install` clean); no direct dependency needed.

### Tests

| Class | Module | Count | Kind |
|---|---|---|---|
| `AbstractHttpAccessAuditFilterTest` (+6) / `AMAccessAuditEventBuilderTest` (+1 `forRequest` query-only) | openam-audit-core | **18** (both classes) | 3d-1 unit |
| `HttpBodyAuditorTest` | openam-oauth2 | 7 | 3d-2 characterization (survives 5d) |
| `RestletAuditParityTest` | openam-oauth2 | 10 | 3d-2 **parity oracle** |
| `OAuth2HttpAccessAuditFilterTest` | openam-oauth2 | 8 | 3d-2 unit |
| `UMAHttpAccessAuditFilterTest` | openam-oauth2 | 4 | 3d-2 unit |
| `OAuth2AuditRouteCompositionIT` | openam-oauth2 | 2 | 3d-2 IT (failsafe) |

3d-2 adds **29 unit + 2 IT**. Full `openam-oauth2 test` observed **916 green** (no regression). Verification
criteria #5 (Restlet-import gate) = **0** in the new main classes. The parity oracle drives the real legacy
`RestletBodyAuditor` (`jsonAuditor` + `jacksonAuditor` + `formAuditor`) against `HttpBodyAuditor` on identical
bytes — green, so the finding-3 collapse and the field-selection contract are pinned to *observed* legacy output.

### Resolved / confirmed at implementation

- **D3 folded into 3d-1** as decided — not deferred.
- **Finding-2 matrix: no correction.** 3d-2 constructs no live routes, so the per-endpoint auditor matrix
  (§ finding 2) was not exercised; it remains a Phase 4/5d wiring input, unchanged.
- **`AM_CTX_ID` fallback (finding 7 / R-3d.5) reproduced and de-risked.** The read is
  `oAuth2Request.getAttribute(Constants.AM_CTX_ID)`; `OAuth2HttpAccessAuditFilterTest` pins it via a mocked
  `getAttribute`. Confirmed during review *why* it will work end-to-end: `OAuth2RequestFactory.create(context,
  request)` caches one `ChfOAuth2Request` on the `AttributesContext`, so the audit filter and `ClientAuthenticator`
  share the same request instance and its attribute map — so once `ClientAuthenticator` is ported (Phase 5) and
  writes `AM_CTX_ID` there, this fallback reads it. Still confirm in 5d smoke.
- **`OpenIdConnectToken` does not implement `IntrospectableToken`** (verified), so the `instanceof` order in
  `getUserId` is safe — an OIDC token takes the `sub` branch, not the resource-owner branch.
- **Explicit-null divergence (D1) confirmed by the oracle**, not just asserted: `HttpBodyAuditor.jsonAuditor`
  matches `jacksonAuditor` (omits an explicitly-`null` field) and diverges from the org.json `jsonAuditor`
  (which emits `JSONObject.NULL`) — the accepted, deliberately-not-reproduced quirk.
- **Parity-oracle empty-body limitation (test-infra gotcha).** A production empty body is a truly-empty
  `Representation` (`isEmpty()==true`), which a hand-built `JacksonRepresentation` wrapping `""` **cannot**
  reproduce — it tries to parse `""` and throws. So the empty-body parity row A/Bs against the **org.json
  `jsonAuditor`** leg only (which guards `isEmpty()` on the representation), documented inline in the test. This
  is a limitation of driving the legacy Jackson leg in-process, not a CHF-auditor defect.

### Review fixes (folded into 3d-2 `41170fb92a`)

The `/code-review` "reuse / don't reinvent" pass produced 5 findings; **#2, #4, #5 applied**, verified
behaviour-neutral (audit-core 18, oauth2 29 + IT 2, parity oracle green):

- **#2** — folded the duplicated per-field selection loop in `jsonAuditor`/`formAuditor` into one reused
  `HttpBodyAuditor.select(...)` (mirrors legacy `RestletBodyAuditor.extractValues`).
- **#4** — `Debug` logger `private final` → `private static final` (matches `AbstractRestletAccessAuditFilter`).
- **#5** — stripped internal review-artifact tags (`finding N` / `D1` / `D2` / `D3`) from production and test
  comments, keeping the self-contained explanation.

**Left for the CHF-cleanup phase (both parity-faithful, deliberately not changed under a parity-first migration):**

- **#1** `AMAccessAuditEventBuilder.forRequest` builds `http/request/path` with `uri.getPort()` == `-1` on
  default-port URIs — pre-existing, affects Restlet and CHF identically, already in
  [decisions.md § CHF cleanup backlog](decisions.md#chf-cleanup-backlog) (`:-1` bullet).
- **#3** `getSSOToken` (an uncached `SSOTokenManager.createSSOToken` lookup) runs up to **4× per audited
  request** — twice per attempt (`getUserId` + `putTrackingIds`), twice per outcome. This is faithful to the
  Restlet original (`OAuth2AbstractAccessAuditFilter` calls `getSSOToken` in both helpers too); caching it for
  the request lifetime would diverge from the parity oracle and belongs in the later CHF-cleanup pass.
