# Phase 3b — Transport-neutral collaborators (verifiers, `ClientCredentialsReader`, `OAuth2Utils`)

Detailed execution plan for **sub-phase 3b** of the Restlet → CHF migration. Parent tracker:
[plan.md](plan.md) (Phase 3); research & sizing: [phase-3-research.md](phase-3-research.md); reusable CHF
patterns: [chf-patterns.md](chf-patterns.md); predecessor: [phase-3a-oauth2request.md](phase-3a-oauth2request.md);
inventory: [inventory.md](inventory.md). Written 2026-07-11; branch `features/restlet-migration`.
**Verified against the tree 2026-07-16** — the corrections are folded in below and recorded in
[Plan review](#plan-review-2026-07-16); the [Integration tests](#integration-tests) section was added by the
same review. Execute from this text, not from the pre-review version.

## Context

Phase 3 makes the OAuth2 core transport-neutral so UMA (Phase 4) and OAuth2/OIDC (Phase 5) can migrate
incrementally, while `/oauth2`+`/uma` still run on Restlet. 3a delivered the neutral `OAuth2Request`
abstraction (`RestletOAuth2Request` + `ChfOAuth2Request` + `BasicAuthHeader`). **3b removes the remaining
Restlet coupling from the *shared* OAuth2 collaborators**: the three access-token verifiers, and
`OAuth2Utils`. `ClientCredentialsReader` was already migrated in the 3a commit — 3b only verifies it and
back-fills its test coverage.

**No route flips.** After 3b, `/oauth2`+`/uma` still run on Restlet exactly as today; the only observable
change is internal. Every edit touches code the **live Restlet path** executes, so the guardrail is
unchanged: the existing Restlet-path unit suite must stay green (`RestletOAuth2Request` implements each new
neutral accessor with today's exact Restlet call).

**Outcome:** the three `AccessTokenVerifier` implementations become transport-neutral (in
`org.openidentityplatform.openam.oauth2.core`, driven only by `OAuth2Request` accessors); the three `Restlet*` verifier
classes are deleted; `OAuth2Utils` is Restlet-free; `OAuthProblemException`'s dead Restlet-request plumbing
is stripped; `ClientCredentialsReader`'s failure path is fully neutral end-to-end.

## Scope & sizing (decided)

- **OAuth2Utils: full clear.** Do the small `OAuthProblemException` enabling edit and delete the entire
  Restlet half of `OAuth2Utils`, removing every `org.restlet` import from it.
- **Failure-factory: pull forward.** Make `OpenAMClientAuthenticationFailureFactory.hasAuthorizationHeader`
  neutral now (behaviour-identical on Restlet, de-risks Phase 5's CHF token endpoint).
- **`getFormParameter`: verbatim, no entity restore** (decided 2026-07-16). The verifier drains the entity
  today (`new Form(body)` with no `setEntity`), unlike `RestletOAuth2Request.getParameter:91-93` which
  restores it. Preserve the drain — 3b's contract is no observable change. Comment the asymmetry so it is
  not "fixed" later; revisit in Phase 5. See [review D5](#d5--two-form-readers-one-class-different-entity-semantics).
- **`OAuth2Utils`: drop the `jacksonRepresentationFactory` field + ctor param** (decided 2026-07-16). It is
  read only by the code 3b deletes. Sole call site to update: `OAuth2UtilsTest.java:48`.

- **Integration tests: in scope** (decided 2026-07-16). Extend the existing e2e Playwright OAuth2 spec to
  cover all three token locations, and add a `OAuth2GuiceModuleTest` binding guard. See
  [Integration tests](#integration-tests).

**~3 new classes** (the neutral verifiers), **~9 modified**, **~4 deleted** (3 Restlet verifiers + net
method deletions), plus tests: 4 new Java test classes (3 verifier + `OAuth2GuiceModuleTest`), 3 extended,
and ~5 new e2e cases. Medium risk — live path, basic-auth ISO-8859-1 charset, and preserving the
header/form/query token-location distinction.

## Key research findings (drove this plan)

1. **`ClientCredentialsReader` is already done** (migrated in commit `4d49958884`). It reads
   `request.getBasicAuthCredentials()` and checks `request.getEndpointType() == TOKEN_ENDPOINT`; both
   `org.restlet` imports are gone. No source change in 3b. **Gap:** its test
   (`ClientCredentialsReaderTest`) only exercises the `private_key_jwt` path — the migrated basic-auth and
   endpoint-type branches have **no** coverage. 3b adds it.
2. **The three Restlet verifiers each read exactly one token location** via the deprecated
   `OAuth2Request.getRequest()`: Header = Bearer from `Authorization`; FormBody = `access_token` from an
   `application/x-www-form-urlencoded` body; QueryParam = `access_token` from the query
   (`getOriginalRef().getQueryAsForm()`). This location distinction is load-bearing: `UserInfoService`
   wires HEADER+FORM_BODY (OIDC userinfo must not accept a query token); `TokenInfoService` wires
   HEADER+QUERY_PARAM (must not accept a form-body token). **Preserve it** — do not collapse to a merged
   `getParameter`.
3. **`getAuthorizationBearerToken()` / `getAcceptedLanguages()` still don't exist** (deferred from 3a).
   3b needs `getAuthorizationBearerToken()` (header verifier). It does **not** need `getAcceptedLanguages()`
   — its only consumers are the Restlet consent/device pages, ported in Phase 5b. Leave
   `getAcceptedLanguages()` for whoever ports those.
4. **Full `OAuth2Utils` deletion is blocked by one shared-package caller.**
   `OAuth2Utils.getRequestParameter(Request,…)` is called only from `OAuthProblemException`'s private
   `(OAuthError, Request)` constructor (`:188,192,194`) — but **every runtime caller now passes `null`**
   (all 7 SERVER_ERROR sites use `handle(String)`; **all three** `handle(Request,String)` callers pass
   `null` — `RealmOAuth2ProviderSettings:132`, `OAuth2ProviderSettingsFactory:91`, and
   **`openam-uma/.../UmaSettingsImpl:82`**). So the Restlet-request branch is dead. Verified callerless
   and removable with it: `pushException()`, `popException(Request)`, `getErrorForm()`, `getErrorMessage()`.
   `OAuthProblemException` keeps `extends org.restlet.resource.ResourceException` and
   `org.restlet.data.Status` (pervasive — Phase 5).
   > **Corrected 2026-07-16.** The pre-review text said "the only two `handle(Request,String)` callers" and
   > missed `UmaSettingsImpl:82`, in a **different module**. Deleting the overload without retargeting it is
   > a compile break that `mvn -pl openam-oauth2` cannot catch. See
   > [review D1](#d1--handlerequest-string-has-three-callers-not-two-compile-break).
5. **Package correction:** the class the parent plan called `org.forgerock.oauth2.core.OAuth2Utils` is
   actually `org.forgerock.openam.oauth2.OAuth2Utils`.

### Token-location map (must be preserved)

| Verifier (Restlet, to delete) | Reads from | Neutral accessor (3b) | Injected by (`@Named`) |
|---|---|---|---|
| `RestletHeaderAccessTokenVerifier` | `Authorization: Bearer` | `getAuthorizationBearerToken()` | `HEADER` (UserInfoService), `REALM_AGNOSTIC_HEADER` (TokenInfoService), unqualified default (OpenIdConnectClientRegistrationService) |
| `RestletFormBodyAccessTokenVerifier` | `access_token` in form body | `getFormParameter(ACCESS_TOKEN)` | `FORM_BODY` (UserInfoService) |
| `RestletQueryParameterAccessTokenVerifier` | `access_token` in query (`getOriginalRef`) | `getQueryParameter(ACCESS_TOKEN)` | `REALM_AGNOSTIC_QUERY_PARAM` (TokenInfoService) |

(`QUERY_PARAM` and `REALM_AGNOSTIC_FORM_BODY` named bindings/providers exist but have no injecting
consumer today — keep the bindings to minimise churn.)

## Work items

### 1. New neutral accessors on `OAuth2Request` (openam-oauth2, `org.forgerock.oauth2.core`)

Add three accessors, following 3a's convention (throwing default on the base, overridden by both
transports; `IdTokenInfo.ValidateIdTokenRequest` delegates all three).

- **`String getAuthorizationBearerToken()`** — Bearer token from the `Authorization` header, or `null`.
  **Not strictly "Bearer" on Restlet:** on a non-Bearer scheme the Restlet impl falls back to the parsed
  `ChallengeResponse` and returns its raw value, so a `Basic` header yields a credential blob; CHF returns
  `null`. Inherent (CHF has no `ChallengeResponse`) and unobservable at the `verify()` boundary — a garbage
  token id fails `readAccessToken` → `INVALID_TOKEN`, same as `null`. Javadoc it; do not "unify" it.
  See [review D3](#d3--the-header-verifier-mutates-the-request-and-falls-back-to-non-bearer).
- **`String getQueryParameter(String name)`** — first value from the **original, pre-routing** query string,
  or `null`. **It is _not_ a read companion to `setQueryParameter`** — that writes `getResourceRef()`, while
  this reads `getOriginalRef()`, so on Restlet a `setQueryParameter` is invisible here (on CHF it is
  visible; both go through the URI). Divergence is latent and accepted — parity with
  `RestletQueryParameterAccessTokenVerifier` wins. See
  [review D2](#d2--getqueryparameter-is-not-the-read-companion-to-setqueryparameter).
- **`String getFormParameter(String name)`** — first value from a POST `application/x-www-form-urlencoded`
  body, or `null` when the body is absent / not form-encoded.

**`OAuth2Request.java`** (base): add the three as throwing defaults (mirrors 3a as-built deviation #4).

**`RestletOAuth2Request.java`** — implement with today's exact verifier logic (verbatim, so the Restlet
path is byte-for-byte unchanged):
- `getAuthorizationBearerToken()` ← the Bearer-parse body of
  `RestletHeaderAccessTokenVerifier.getChallengeResponse(request)` (guard `request instanceof HttpRequest`;
  read the raw `Authorization` header; split on the first space; scheme `Bearer` (case-insensitive) →
  return the value; else fall back to `request.getChallengeResponse()`).
  **Keep the `request.setChallengeResponse(result)` write** (`RestletHeaderAccessTokenVerifier:85`) — it
  looks like a smell in a getter, but `OpenAMClientAuthenticationFailureFactory.hasAuthorizationHeader`
  reads that exact field. Comment it. See [review D3](#d3--the-header-verifier-mutates-the-request-and-falls-back-to-non-bearer).
  **The `instanceof HttpRequest` guard is load-bearing and untestable with a plain `Request`** — it brings
  `org.restlet.engine.adapter` into this class, and the branch behind it is only reachable under real HTTP
  dispatch or from `mock(HttpRequest.class)`. See [review D6](#d6--the-bearer-parse-is-unreachable-from-a-plainly-constructed-restlet-request).
- `getFormParameter(name)` ← `RestletFormBodyAccessTokenVerifier` body: guard
  `MediaType.APPLICATION_WWW_FORM.equals(entity.getMediaType())`, then `new Form(entity).getFirstValue(name)`
  — **no entity re-set**, matching the verifier today and deliberately unlike `getParameter:91-93`.
  See [review D5](#d5--two-form-readers-one-class-different-entity-semantics).
- `getQueryParameter(name)` ← `request.getOriginalRef().getQueryAsForm().getFirstValue(name)` (**note
  `getOriginalRef()`**, matching `RestletQueryParameterAccessTokenVerifier`). **Rename the existing private
  `getQueryParameter(Request, String)` (`RestletOAuth2Request:231`) → `getResourceRefQueryParameter`** — it
  reads `getResourceRef()`, the opposite source, and the name collision is a live trap for Phase 5.

**`ChfOAuth2Request.java`** — implement with the existing helpers:
- `getAuthorizationBearerToken()` — parse `request.getHeaders().getFirst(AUTHORIZATION_HEADER)`; if the
  scheme is `Bearer`, return the token (same header plumbing as `getBasicAuthCredentials()`).
- `getFormParameter(name)` — reuse the private `formBody()` helper (content-type-guarded) → `.getFirst(name)`.
- `getQueryParameter(name)` — reuse the private `queryForm()` helper → `.getFirst(name)`.

**`IdTokenInfo.ValidateIdTokenRequest`** (`org.forgerock.openidconnect.restlet`) — add delegating overrides
for the three new accessors (consistent with 3a; `/oauth2/idtokeninfo` runs through it).
`RealmOnlyOAuth2Request` inherits the throwing defaults (not on a verifier path).

### 2. Three transport-neutral `AccessTokenVerifier`s + Guice rebind

**New** (openam-oauth2, **`org.openidentityplatform.openam.oauth2.core`** — new-class convention, see
[decisions.md](decisions.md); no ForgeRock copyright, no `@since`) — each `@Singleton`,
`@Inject(TokenStore)`, overriding `obtainTokenId(OAuth2Request)`:
- `HeaderAccessTokenVerifier` → `request.getAuthorizationBearerToken()`.
- `FormBodyAccessTokenVerifier` → `request.getFormParameter(ACCESS_TOKEN)`.
- `QueryParameterAccessTokenVerifier` → `request.getQueryParameter(ACCESS_TOKEN)`.

**Deleted:** `RestletHeaderAccessTokenVerifier`, `RestletFormBodyAccessTokenVerifier`,
`RestletQueryParameterAccessTokenVerifier` (`org.forgerock.oauth2.restlet`).

**Modified — `OAuth2GuiceModule.java`** (`org.forgerock.openam.oauth2.guice`) — imports (~lines 87–89) →
the three new `org.openidentityplatform.openam.oauth2.core` classes, then **seven** binding sites.
Consumers unchanged (see the token-location map above).

| Line | Kind | Key | New target |
|---|---|---|---|
| 180 | `.to()` | `AccessTokenVerifier` (**unqualified default** — `OpenIdConnectClientRegistrationService`) | `HeaderAccessTokenVerifier` |
| 181 | `.to()` | `@Named(HEADER)` | `HeaderAccessTokenVerifier` |
| 182 | `.to()` | `@Named(FORM_BODY)` | `FormBodyAccessTokenVerifier` |
| 183 | `.to()` | `@Named(QUERY_PARAM)` | `QueryParameterAccessTokenVerifier` |
| 316 | `@Provides` | `@Named(REALM_AGNOSTIC_HEADER)` | `new HeaderAccessTokenVerifier(tokenStore)` |
| 325 | `@Provides` | `@Named(REALM_AGNOSTIC_FORM_BODY)` | `new FormBodyAccessTokenVerifier(tokenStore)` |
| 334 | `@Provides` | `@Named(REALM_AGNOSTIC_QUERY_PARAM)` | `new QueryParameterAccessTokenVerifier(tokenStore)` |

> **It is seven, not six** — the pre-review text and the first pass of this review both said "six". A missed
> site leaves a binding pointing at a deleted class: a `CreationException` **at server start**, not a compile
> error, so neither the module build nor the whole-reactor build catches it. This is what the
> [Guice binding guard](#b-guice-binding-guard--oauth2guicemoduletest) exists to prevent.

`AccessTokenVerifier` (the abstract base, `org.forgerock.oauth2.core`) is untouched — only its subclasses
change package/impl.

### 3. `ClientCredentialsReader` — verify + back-fill tests

No source change (already neutral since 3a: `ClientCredentialsReader.java` reads
`request.getBasicAuthCredentials()` and `request.getEndpointType() == TOKEN_ENDPOINT`). Add to
`ClientCredentialsReaderTest` (`openam-oauth2/src/test/.../openam/oauth2/ClientCredentialsReaderTest.java`):
a case stubbing `getBasicAuthCredentials()` → a real `BasicAuthHeader` (asserts `CLIENT_SECRET_BASIC` + the
multiple-auth-methods conflict — the `InvalidRequestException` at `ClientCredentialsReader:84`), and a case
stubbing `getEndpointType()` → `TOKEN_ENDPOINT` (asserts the `token_endpoint_auth_method` enforcement
branch).

> **The endpoint-type case must also stub `getAllowedScopes()` to a set containing `openid`.** The existing
> test stubs it to `Collections.emptySet()` (`ClientCredentialsReaderTest:123`), so `scopes.contains(OPENID)`
> short-circuits and the endpoint-type condition at `:111` is **never evaluated** — a test that stubs only
> `getEndpointType()` would pass without exercising the branch it claims to cover. Existing coverage is
> narrower than "only `private_key_jwt`" implies: `getBasicAuthCredentials()` is stubbed `null` in **every**
> test (`:146`) and `getEndpointType()` is **never** stubbed (unstubbed mock → `null` ≠ `TOKEN_ENDPOINT`).
> The `CLIENT_SECRET_POST` branch is entirely unexercised, and the one positive test swallows
> `RuntimeException` (`:128-132`), so it cannot catch a return-value regression.

### 4. Failure-factory pull-forward

**`OpenAMClientAuthenticationFailureFactory.java`** (`org.forgerock.oauth2.restlet`, `hasAuthorizationHeader`
~line 51–54): `return request.getBasicAuthCredentials() != null;` and drop the `org.restlet` import if now
unused. Behaviour-identical on Restlet (`getBasicAuthCredentials() != null ⇔ getChallengeResponse() != null`
on `RestletOAuth2Request`), and it stops throwing on a `ChfOAuth2Request`, so `ClientCredentialsReader`'s
failure path is neutral end-to-end. (The class stays in the `.restlet` package — its full port is Phase 5.)

### 5. `OAuth2Utils` full clear + `OAuthProblemException` enabling edit

**`OAuthProblemException.java`** (`org.forgerock.openam.oauth2`) — strip dead Restlet-request plumbing.
**Order matters — do step 1 first, and keep step 3's two deletions in one step:**
1. Retarget **all three** `handle(null, message)` callers to `handle(message)`:
   `RealmOAuth2ProviderSettings:132`, `OAuth2ProviderSettingsFactory:91`, and
   **`openam-uma/src/main/java/org/forgerock/openam/uma/UmaSettingsImpl.java:82`**. Semantically identical —
   a `null` request already skips the Restlet branch (`:185-199`).
2. delete `handle(Request)` (`:142`) and `handle(Request, String)` (`:146`).
3. replace the private `(OAuthError, Request)` constructor (`:180`) with `(OAuthError)`
   (redirect_uri/state/scope = null); `handle(String)` calls it.
4. delete the `request` field (`:170`), **`pushException()` and `popException(Request)` together**,
   `getErrorForm()`, `getErrorMessage()`, and the now-unused `oAuth2Utils` field (`:177`) with its
   `InjectorHolder` static-injection wart.
5. remove imports `org.restlet.Request`, `org.restlet.data.Form`. **Keep**
   `extends org.restlet.resource.ResourceException` and `org.restlet.data.Status` (Phase 5).
6. rewrite the stale `OAuth2Utils.OAuthProblemExceptionRedirector#getRedirector` reference in
   `handle(String)`'s javadoc (`:153`) — **that class does not exist**; the real member is the private
   `OAuth2Utils.ParameterLocation#getRedirector`, which 3b deletes. `{@code}`, so not fatal, but it will
   name deleted code.

> **Doclint is fatal now** (commit `3c45ff8d53` enabled `-Xdoclint:all,-missing` + `failOnWarnings`).
> `pushException`'s javadoc (`:299-308`) contains `{@link OAuthProblemException#popException(org.restlet.Request)}`
> — a dangling `{@link}` is a **build error**. Deleting both members together removes the link with the
> javadoc; deleting `popException` alone breaks the build. See
> [review D4](#d4--doclint-is-now-fatal-so-deletion-order-matters).

**`OAuth2Utils.java`** (`org.forgerock.openam.oauth2`) — delete the Restlet half: `getRealm(Request)`
(`:178`), `getRealm(HttpServletRequest)` (`:183`, dead once the former is gone), `getLocale(Request)`
(`:191`), `getRequestParameter(Request,…)` (`:199`), `getRequestParameters(Request)` (`:216`),
`getParameters(Request)` (`:242`), and the private `ParameterLocation` enum (`:251`, incl. `getRedirector`
at `:306`). Remove all ten `org.restlet.*` imports (`:39-45,47-49`) and the `ServletUtils` import (`:46`).
Also drop the `jacksonRepresentationFactory` field (`:59`) **and the ctor param** (`:66`) — read only by
the deleted code (`:245,247,255,286`); update `OAuth2UtilsTest.java:48` (`new OAuth2Utils(factory)` →
`new OAuth2Utils()`). Guice JIT-binds the no-arg `@Inject` ctor; that test is the only construction site
repo-wide. **Keep** (all Restlet-free): `getDeploymentURL(HttpServletRequest)`,
`getConfirmationKey(OAuth2Request)`, and the string helpers (`isEmpty/isBlank/isNotBlank/join/joinStatic/
split`). *(Note: `getDeploymentURL` is currently callerless but is on the KEEP list — leave it.)*

Live callers that pin the KEEP list: `getConfirmationKey` ← `StatefulTokenStore:545`,
`StatelessTokenStore:286`, `ConfirmationKeyValidator:58`; `join` ← `DeviceCodeVerificationResource:233,248`;
`joinStatic` ← `ConsentRequiredResource:105`; `split` ← `DeviceCodeResource:107`; `isNotBlank` ←
`OAuthProblemException:331,356,362` (all inside code 3b deletes, so it survives on internal use only).
*(Beware two decoys: `OAuth2ProviderSettingsFactory:89` / `RealmOAuth2ProviderSettings:130` contain
`"OAuth2Utils::Unable to construct…"` **string literals**, not calls; and `ExceptionHandler:41` imports
`isEmpty` from a different class, `org.forgerock.oauth2.core.Utils`.)*

## Tests

- **New** `HeaderAccessTokenVerifierTest`, `FormBodyAccessTokenVerifierTest`,
  `QueryParameterAccessTokenVerifierTest` — construct real `ChfOAuth2Request` **and** `RestletOAuth2Request`
  (per [chf-patterns.md](chf-patterns.md) §5/§11 scaffolding), assert token extraction from the right
  location and `null` from the wrong one (e.g. form verifier ignores a query token).
  **Exception — the header verifier on Restlet:** a real `RestletOAuth2Request` over a plain
  `new Request(...)` cannot reach the Bearer parse ([D6](#d6--the-bearer-parse-is-unreachable-from-a-plainly-constructed-restlet-request)).
  Cover it two ways: `mock(HttpRequest.class)` with a stubbed `getHttpCall().getRequestHeaders()` for the raw-header
  path, and a plain `Request` with a programmatic `setChallengeResponse(...)` for the fallback path.
- Extend `ChfOAuth2RequestTest` / `RestletOAuth2RequestTest` for the three new accessors:
  `getAuthorizationBearerToken` (Bearer present / absent / non-Bearer scheme — assert the **divergence**:
  Restlet returns the challenge raw value, CHF returns `null`), `getQueryParameter`, `getFormParameter`
  (form vs non-form content type, incl. `;charset=UTF-8` — [chf-patterns.md](chf-patterns.md) §7).
  **Pin the D2 asymmetry**: after `setQueryParameter(n, v)`, `getQueryParameter(n)` returns the **old**
  value on Restlet and the **new** value on CHF. Follow the established parallel-naming convention for
  transport-parity pairs (e.g. `ChfOAuth2RequestTest:286` ↔ `RestletOAuth2RequestTest:168`).
  Scaffolding: `ChfOAuth2RequestTest` helpers at `:346-382`; `RestletOAuth2RequestTest` helper at `:181-186`.
  Note the existing `aNonBasicChallengeResponseStillYieldsCredentials` test already documents the
  programmatic-`ChallengeResponse` shape — reuse it as the template for the D6 fallback case.
- **New** `OAuth2GuiceModuleTest` and **new/extended e2e specs** — see
  [Integration tests](#integration-tests) below.
- `ClientCredentialsReaderTest` — the two new cases from work item 3 (**note the `getAllowedScopes()` trap**).
- `OAuth2UtilsTest` — its only two tests cover `getConfirmationKey` (`:52`, `:66`), which 3b keeps, so
  **no cases need removing**; the sole edit is `new OAuth2Utils(factory)` → `new OAuth2Utils()` at `:48`.
  There is no `OAuthProblemExceptionTest`; the nearest indirect coverage
  (`AgentClientRegistrationTest`, `OpenAMClientRegistrationTest` via `expectedExceptions`) exercises only
  the `handle(String)` path and stays green.
- **Existing Restlet-path suite stays green unchanged** — the acceptance gate for behaviour parity.

## Integration tests

Added to the plan 2026-07-16. The repo's test layers, runners, CI wiring and gotchas are documented once in
[docs/test-infrastructure.md](../../test-infrastructure.md) — read it first; only the 3b-specific decisions
are below. Two gaps make this more than a nice-to-have:

- **Nothing at any level tests five of the seven bindings.** Only the `HEADER` verifier has end-to-end
  coverage today (via the existing e2e spec). `FORM_BODY`, `QUERY_PARAM` and all three realm-agnostic keys
  are untested everywhere.
- **No test in `openam-oauth2` or `openam-uma` wires a Guice injector**, so nothing can catch a broken
  binding — and 3b rewires seven of them. (Repo-wide, the only injector-wiring test is
  `openam-rest/src/test/java/org/forgerock/openam/rest/RestRouterIT.java`.)

### A. e2e Playwright — token-location coverage

`e2e/oauth2/oauth2-test.spec.mjs` already drives authorize → `POST /oauth2/access_token` →
`GET /oauth2/userinfo` with a Bearer header against real Tomcat + OpenDJ in Docker. CI runs it **unqualified**
in the `build-docker` job (`.github/workflows/build.yml:299`, `npx playwright test`), so additions run
automatically with no wiring. Extend the existing `test.describe("OAuth Service test")` block, reusing the
module-scoped `accessToken` from the first test:

| New test | Exercises | Assert |
|---|---|---|
| userinfo, token in POST form body | `@Named(FORM_BODY)` | 200, `sub === 'demo'` |
| userinfo, token in **header + form body** | HEADER vs FORM_BODY distinction | error — `UserInfoService:90` throws `ServerException("Access Token cannot be provided in both form and header")` |
| `GET /oauth2/tokeninfo?access_token=…` | `@Named(REALM_AGNOSTIC_QUERY_PARAM)` | 200, token fields |
| `GET /oauth2/tokeninfo` + Bearer header | `@Named(REALM_AGNOSTIC_HEADER)` | 200, token fields |
| tokeninfo, token in **header + query** | both realm-agnostic keys at once | 400 `invalid_request` — `TokenInfoService:125` |

The **both-locations** rows are the high-value ones. `UserInfoService:84-93` and `TokenInfoService:114-129`
each call two verifiers and **error when both succeed** — so the load-bearing location distinction is
observable as pure black-box behaviour, with no knowledge of internals. If a 3b regression let the form
verifier also read the header, those tests flip from error to 200. Nothing else in the repo can catch that.

Route confirmed: `OAuth2RouterProvider.java:106` attaches `/tokeninfo` → `ValidationServerResource`.
Helpers from `../common/openam-commons.mjs`: `OPENAM_BASE`, `getAdminToken`, `getAuthToken`, `USERNAME`,
`PASSWORD`. The existing fixture (`test_client_app`, scope `profile`, public client + PKCE) is reusable as-is
— no new setup.

This **replaces the manual pre/post curl smoke** in verification step 4 with something repeatable that runs
on every push, and it is the only coverage of the real `HttpRequest` path ([D6](#d6--the-bearer-parse-is-unreachable-from-a-plainly-constructed-restlet-request)).

### B. Guice binding guard — `OAuth2GuiceModuleTest`

New: `openam-oauth2/src/test/java/org/forgerock/openam/oauth2/guice/OAuth2GuiceModuleTest.java` (new package
dir). Named `*Test`, so **surefire** runs it under `mvn test` — deliberate; the point is a fast gate on the
seven-site rebind, not a slow one.

- **The four `.to()` binds** — `Elements.getElements(new OAuth2GuiceModule())` records the binding graph
  *without creating an injector*: no dependency resolution, no SMS, no eager singletons. Visit for
  `LinkedKeyBinding` on `Key.get(AccessTokenVerifier.class)` and `Key.get(AccessTokenVerifier.class, named(HEADER))`
  etc., asserting the linked key is the new neutral class. **Include the unqualified `:180` key** — no
  `@Named`, easiest to forget, and it is the one feeding `OpenIdConnectClientRegistrationService`.
- **The three `@Provides`** — they are *package-private*
  (`AccessTokenVerifier getRealmAgnostic…(TokenStore)`), so a test in the same package calls them directly
  with a `mock(TokenStore.class)` and asserts `isInstanceOf(...)`. No reflection, no injector.

No new dependency: `mockito-core`, `assertj-core` and `testng` are already test-scoped in
`openam-oauth2/pom.xml`, and Guice arrives compile-scope via `org.openidentityplatform.commons.guice:core`.
(`commons.guice:test` is **not** on this module and stays off.)

**Do not use the `RestRouterIT` pattern here.** Guice validates the whole binding graph at `createInjector`,
and `OAuth2GuiceModule` binds `TokenStore`→`OpenAMTokenStore`, an `OpenAMSettings` provider, multibinders and
assisted-inject factories — it would need sibling modules plus broad mock scaffolding merely to construct.
Not worth it for what is, in substance, an assertion about seven lines.

**Honest limitation:** this is a unit test, not an IT. It pins the binding *targets*; it does not prove the
graph resolves at runtime. (A) is what proves the wiring actually works. Together they cover the seven
bindings; neither alone does.

### Considered and rejected (recorded so it is not re-litigated)

- **Cargo/Selenium IT in `openam-server`** — the harness is real (`CargoBaseTest`, fresh Tomcat per test
  method, `mvn verify -P integration-test`, Linux-only in CI) but drives only the installer UI
  (`IT_Setup`, `IT_SetupWithOpenDJ`). Adding OAuth2 there duplicates (A) at far higher cost and runtime.
- **In-process Restlet dispatch IT** — would yield a genuine `HttpRequest` in-process and so close D6 without
  Docker, but there is **no precedent in the repo** (no `Component`, no `restlet.Client`, no restlet test jar
  anywhere), and Phase 5 deletes the Restlet path outright. (A) covers the same ground via the real server.

## Verification

1. `mvn -o -pl openam-oauth2 install -DskipTests` (openam-uma resolves openam-oauth2 from `~/.m2` —
   [chf-patterns.md](chf-patterns.md) §11) → `mvn -o -pl openam-oauth2,openam-uma test`.
   Baseline to beat (3a as-built): openam-oauth2 **655**, openam-uma **192**, 0 failures/errors/skips.
2. `mvn install -DskipTests` (whole reactor; no dangling refs / signature breaks). **Non-negotiable** — it
   is the only gate that catches the `UmaSettingsImpl` caller (D1) and the doclint trap (D4); neither is
   visible to a `-pl openam-oauth2` build.
3. Grep gates:
   - `grep -n "org.restlet" openam-oauth2/src/main/java/org/forgerock/openam/oauth2/OAuth2Utils.java` → 0.
   - the three `Restlet*AccessTokenVerifier` files are gone; no references remain
     (`grep -rn "RestletHeaderAccessTokenVerifier\|RestletFormBodyAccessTokenVerifier\|RestletQueryParameterAccessTokenVerifier" --include=*.java .` → 0).
   - `grep -rn "handle(null" --include=*.java . | grep -v /target/` → 0 (**catches D1**).
   - `grep -rn "getCurrent()" openam-oauth2/src/main --include=*.java | grep -v /restlet/ | grep -v RestletOAuth2Request.java` → still 0 (no regressions).
4. No route flip ⇒ no Cargo IT behaviour change expected. The token-verifier smoke is now **automated** —
   the [e2e specs](#a-e2e-playwright--token-location-coverage) cover userinfo (header / form body / both) and
   tokeninfo (header / query / both). Run `npx playwright test oauth2` against a local container. Keep a
   **manual** curl check for the one thing e2e does not reach: a dynamic client-registration read, which is
   the only consumer of the unqualified `:180` default.
5. CI (`.github/workflows/build.yml`) — `build-maven` runs 9 matrix legs on the `features/**` push (ubuntu ×
   JDK 11/17/21/25/26, macOS × 11/26, windows × 11/26), then `build-docker` (`needs: build-maven`) runs the
   e2e specs.

> **`mvn test` vs `mvn verify`.** The root pom binds `maven-failsafe-plugin` **unconditionally** in
> `<build><plugins>` (`:1843-1856`; goals `integration-test`+`verify`; no profile, no skip), so `*IT.java`
> runs on `mvn verify` in *every* module but is **invisible to `mvn test`**. CI runs `verify` (`build.yml:61`),
> adding `-P integration-test` on `ubuntu-latest` only (that profile gates openam-server's Cargo tests, which
> 3b does not touch). 3b's new Java tests are all `*Test`, so steps 1–2 above cover them. The e2e specs are
> **not** in the Maven reactor at all — they run only in the `build-docker` job. Full detail:
> [docs/test-infrastructure.md](../../test-infrastructure.md).

## Parity checklist

| Item | Guard |
|---|---|
| Token-location distinction (header vs form vs query) preserved | 3 verifier tests assert wrong-location returns null; consumers' `@Named` wiring unchanged; **e2e "token in both locations" ⇒ error** on userinfo and tokeninfo |
| Restlet path byte-for-byte unchanged | `RestletOAuth2Request` accessors = verbatim verifier bodies; existing suite green + e2e specs |
| Bearer parse parity | `getAuthorizationBearerToken` ports `getChallengeResponse` Bearer logic incl. non-Bearer fallback |
| Bearer parse actually executes (D6) | unit test via `mock(HttpRequest.class)`; **e2e is the only real-`HttpRequest` coverage** |
| All seven Guice bindings retargeted | `OAuth2GuiceModuleTest` (`Elements` SPI + direct `@Provides` calls) — otherwise a miss surfaces only as a `CreationException` at server start |
| Form content-type trap (`;charset=UTF-8`) | CHF `getFormParameter` uses the content-type-guarded `formBody()` helper; test with charset param |
| Query source parity | Restlet uses `getOriginalRef()` (not `getResourceRef()`); asserted |
| Basic-auth ISO-8859-1 (risk #5) | `ClientCredentialsReaderTest` basic-auth case via `BasicAuthHeader` |
| Endpoint-type enforcement (risk #12) | `ClientCredentialsReaderTest` `TOKEN_ENDPOINT` case **+ `openid` in `getAllowedScopes()`**, else the branch is never reached |
| `handle(Request,…)` deletion doesn't break openam-uma (D1) | all three `handle(null,…)` retargeted; `grep -rn "handle(null"` → 0; whole-reactor build |
| Doclint survives the deletions (D4) | `pushException` + `popException` deleted together; whole-reactor build |
| CHF failure path no longer throws | failure-factory pull-forward + `getBasicAuthCredentials()` |
| `OAuthProblemException` behaviour unchanged | request branch was already dead (always-null); redirect_uri/state/scope readers are callerless |

## Execution order

new accessors on `OAuth2Request` base (throwing defaults) → impl in `RestletOAuth2Request` (verbatim) +
`ChfOAuth2Request` (helpers) + delegate in `ValidateIdTokenRequest` → three neutral verifier classes →
rebind `OAuth2GuiceModule` (**all seven** bindings) → delete the three `Restlet*` verifiers →
failure-factory pull-forward → `OAuthProblemException` enabling edit (**retarget all three
`handle(null,…)` callers first — incl. `UmaSettingsImpl` in openam-uma**; delete `pushException` +
`popException` together) → `OAuth2Utils` delete-half (+ `OAuth2UtilsTest:48`) →
`mvn -o -pl openam-oauth2 install -DskipTests` → `mvn -o -pl openam-oauth2,openam-uma test` →
**whole-reactor build** → grep gates → tests (incl. `OAuth2GuiceModuleTest`) → **e2e specs** against a local
container → manual curl for the `:180` dynamic-client-registration default → record an **As-built** section
here (3a convention) → mark 3b done in [plan.md](plan.md) and start [phase-3c] from
[phase-3-research.md](phase-3-research.md).

Write `OAuth2GuiceModuleTest` **in the same step as the rebind**, not after — it is the only gate on the
seven sites, and a miss is otherwise invisible until a server starts. The e2e specs can be written any time
after the verifiers land; they need a container, so keep them off the inner loop.

## Plan review (2026-07-16)

Every load-bearing claim in the pre-review text was checked against the tree on
`features/restlet-migration` (HEAD `0b389aed4e`). **The plan is sound and executable** — the research was
accurate on almost every point — but six defects (D1–D6) are folded into the sections above, along with a
new [Integration tests](#integration-tests) section. No code was changed by this review.

D1–D5 came from the first pass. **D6 and the seven-vs-six binding-count correction came from a second pass**
that asked what could actually be integration-tested; both are cases where the plan's own verification steps
would not have done what they claim. Two themes worth carrying into 3c/4/5:

- **Restlet's server-adapter internals leak into testability.** D6 is not an isolated quirk — anything reading
  raw headers on the Restlet side is reachable only under real dispatch or via engine mocks.
- **Guice binding errors are invisible to the build.** They surface at server start. Any phase that rebinds
  needs its own guard; the whole-reactor build is not one.

### D1 — `handle(Request, String)` has three callers, not two (compile break)

The pre-review text: *"the only two `handle(Request,String)` callers, `RealmOAuth2ProviderSettings:132` and
`OAuth2ProviderSettingsFactory:91`, pass `null`"*. There is a **third**:

```
openam-oauth2/src/main/java/org/forgerock/oauth2/core/RealmOAuth2ProviderSettings.java:132
openam-oauth2/src/main/java/org/forgerock/oauth2/core/OAuth2ProviderSettingsFactory.java:91
openam-uma/src/main/java/org/forgerock/openam/uma/UmaSettingsImpl.java:82          ← missed
```

All three pass literal `null`. Deleting the overload leaves no 2-arg candidate, so `handle(null, message)`
fails to compile. The miss is in **openam-uma**, a different module — `mvn -pl openam-oauth2` (verification
step 1) cannot see it. Fixed in work item 5 step 1; gated by `grep -rn "handle(null"` and the
whole-reactor build.

### D2 — `getQueryParameter` is not the "read companion" to `setQueryParameter`

Work item 1 called it *"read companion to the existing `setQueryParameter`"* while also — correctly —
requiring `getOriginalRef()`. **The two requirements contradict.** In `RestletOAuth2Request`:
`setQueryParameter`/`removeQueryParameterValue` (`:197-216`) write **`getResourceRef()`**; `getOriginalRef()`
is the pre-routing URI and never sees those writes. So on Restlet the pair is **asymmetric**, while on CHF
it is symmetric (`writeQuery`/`queryForm` both go through `Request.getUri()`) — the same abstraction behaves
differently per transport. A name collision compounds it: a private `getQueryParameter(Request, String)`
already exists (`:231`) reading the **opposite** source.

**Resolution:** keep `getOriginalRef()` — parity with `RestletQueryParameterAccessTokenVerifier` outranks
API tidiness, and the divergence is latent (the only consumer is the query verifier on `/oauth2/tokeninfo`,
where nothing mutates the query; `alterMaxAge`/`removeLoginPrompt` are `/authorize`-only). Correct the
javadoc claim, rename the private helper to `getResourceRefQueryParameter`, and pin the asymmetry with a
test so Phase 5 inherits a documented contract instead of a surprise.

### D3 — The header verifier mutates the request, and falls back to non-Bearer

Two undocumented behaviours in `RestletHeaderAccessTokenVerifier`, both of which a "verbatim" port must
carry:

1. **`request.setChallengeResponse(result)` (`:85`)** — a write inside the Bearer parse. It reads as a smell
   and invites deletion, but `OpenAMClientAuthenticationFailureFactory.hasAuthorizationHeader` reads that
   exact field. (Side note: this makes `hasAuthorizationHeader` **order-dependent** on whether the header
   verifier ran first — pre-existing, out of scope, worth knowing for Phase 5.)
2. **Non-Bearer fallback (`:91`)** — a non-`Bearer` scheme (or a non-`HttpRequest`) falls through to
   `request.getChallengeResponse()`, whose raw value `obtainTokenId` returns. So Restlet's
   `getAuthorizationBearerToken()` can return a **Basic** credential blob; CHF returns `null`. Keep it: the
   fallback is the only path that works when a `ChallengeResponse` was set programmatically rather than
   parsed from a raw header (reachable from openam-uma's directly-constructed `RestletOAuth2Request`s). The
   divergence is unobservable at the `verify()` boundary — a garbage token id fails `readAccessToken` →
   `INVALID_TOKEN`, identical to `null` → `INVALID_TOKEN`.

### D4 — Doclint is now fatal, so deletion order matters

Commit `3c45ff8d53` enabled `-Xdoclint:all,-missing` with `failOnWarnings`.
`OAuthProblemException:303` — inside **`pushException`'s javadoc** (`:299-308`) — contains
`{@link OAuthProblemException#popException(org.restlet.Request)}`. A dangling `{@link}` is a build **error**.
Deleting `pushException` and `popException` **together** removes the link along with the javadoc and is safe;
deleting `popException` alone breaks the build. Separately, `handle(String)`'s javadoc (`:153`) names
`OAuth2Utils.OAuthProblemExceptionRedirector#getRedirector` — **a class that does not exist** anywhere in the
repo (the real member is the private `OAuth2Utils.ParameterLocation#getRedirector`). It is `{@code}`, so not
fatal, but it is wrong today and names deleted code after 3b.

### D5 — Two form readers, one class, different entity semantics

`RestletFormBodyAccessTokenVerifier:57` does `new Form(body)` with **no** `setEntity` — it drains the
(non-rewindable) entity. `RestletOAuth2Request.getParameter:91-93` does the same read but explicitly
restores: `request.setEntity(form.getWebRepresentation())` with the comment *"restore the entity body"*.
Porting the verifier verbatim therefore puts **two form readers with opposite entity semantics in one class**.

**Decided: verbatim, no restore.** 3b's contract is no observable change, and restoring would be a live-path
behaviour change (later `getParameter` calls on a POST-form userinfo request would newly see a body where
today they see a drained one — arguably a latent bug fix, but not 3b's to make). Comment the asymmetry;
revisit in Phase 5.

### Latent issue found, deliberately not fixed

`OAuthProblemException.oAuth2Utils` (`:177`) is assigned **only** inside `if (null != this.request)`
(`:186`), but `getErrorMessage()` (`:331`) and `getErrorForm()` (`:356,362`) dereference it
unconditionally — so any exception built via `handle(String)`, `handle(null, msg)`, or either public
constructor (`:203`, `:213`) **NPEs** on those getters. Harmless today because both getters are dead, which
is exactly what makes `handle(String)`'s safety argument load-bearing. 3b deletes both getters and the
field, which removes the hazard, `OAuthProblemException`'s last dependency on `OAuth2Utils`, and the
`InjectorHolder` static-injection wart — no separate fix needed. **Do not revive either getter without
fixing field init.**

### Claims verified correct — no action

- `ClientCredentialsReader` is fully de-Restleted: zero `org.restlet` imports, `getBasicAuthCredentials()`
  at `:68`, `getEndpointType()` at `:111`. No source change in 3b, as planned.
- The token-location map is accurate, incl. `getOriginalRef()` for the query verifier and the
  `MediaType.APPLICATION_WWW_FORM.equals` guard for the form verifier.
- Callerless as claimed: `getRealm(Request)`, `getRealm(HttpServletRequest)`, `getLocale(Request)`,
  `getRequestParameters`, `getParameters`, `getDeploymentURL`, `ParameterLocation`/`getRedirector`,
  `handle(Request)`, `pushException`, `popException`, `getErrorMessage`. `getErrorForm`/`getRedirectUri`
  are reachable only from the dead `getRedirector` (transitively dead). `getScope` is write-only.
- **No existing test references any of the three `Restlet*AccessTokenVerifier` classes** — the new verifier
  tests are net-new coverage, not replacements.
- The Guice `AccessTokenVerifier` bindings are as described in kind and target (`:180-183` via `.to()`,
  `:316/325/334` via `new` with the realm-agnostic `TokenStore`). `:180` is the unqualified default feeding
  `OpenIdConnectClientRegistrationService`; `REALM_AGNOSTIC_FORM_BODY` is provided but has no consumer.
  **Count corrected: seven, not six** — see the table in [work item 2](#2-three-transport-neutral-accesstokenverifiers--guice-rebind).
- `AccessTokenVerifier`'s sole abstract is `protected abstract String obtainTokenId(OAuth2Request)` (`:98`);
  `verify()` is concrete and unoverridden. The base is already transport-neutral.

### D6 — The Bearer parse is unreachable from a plainly-constructed Restlet `Request`

`RestletHeaderAccessTokenVerifier:73` gates the **entire** `Authorization`-header read behind
`request instanceof org.restlet.engine.adapter.HttpRequest` — a Restlet **server-adapter internal**, present
only under real HTTP dispatch. Any other `Request` skips the branch and falls through to
`request.getChallengeResponse()` (the D3 fallback). Two consequences the pre-review text does not account for:

1. **The planned unit test cannot work as written.** "Construct a real `RestletOAuth2Request`" (Tests §1) does
   not reach the Bearer parse: `RestletOAuth2RequestTest`'s own helper (`:181-186`) builds
   `new Request(Method.GET, uri)`, which is not an `HttpRequest`. A test that sets a raw `Authorization`
   header on such a request and asserts `null` **passes while proving nothing**. To exercise the parse you
   must `mock(HttpRequest.class)` and stub `getHttpCall().getRequestHeaders()` to return a
   `Series<Header>` — i.e. mock a Restlet engine internal. Do that, and say in the test why.
2. **The verbatim port pulls `org.restlet.engine.adapter` into `RestletOAuth2Request`**, which today imports
   only public Restlet API. Accept it (the class dies in Phase 5) but do not "simplify away" the `instanceof`:
   without it, `((HttpRequest) request).getHttpCall()` would `ClassCastException` on every programmatically
   built request, including openam-uma's.

This is the reason the [e2e leg](#a-e2e-playwright--token-location-coverage) is not optional: it is the
**only** test at any level that runs a genuine `HttpRequest`, and therefore the only one that can prove the
ported Bearer parse works at all.

### Cosmetics noted, out of scope

`OAuth2Utils.getParameters` (`:242-249`) has **byte-identical `if`/`else` branches** (both `HTTP_QUERY`) —
the `Method.GET`/`EmptyRepresentation` test has no effect. Moot: 3b deletes the method.
`AccessTokenVerifier` has an unused `jakarta.inject.Inject` import (`:25`). The three verifier classes carry
`@Singleton` **and** are `new`-ed in `@Provides` methods, so each class has two live instances with different
`TokenStore`s — intentional, but the class-level annotation is misleading. Carry the same shape onto the
neutral classes to keep 3b's diff behaviour-only.

## As-built (3b delivered — 2026-07-16)

Delivered as planned — no route flips; `/oauth2` and `/uma` still run on Restlet — with five
deviations/discoveries worth recording. Gates: openam-oauth2 **716** tests (3a baseline 655),
openam-uma **192**, whole-reactor `mvn install -DskipTests` BUILD SUCCESS, all grep gates 0,
e2e **7/7 passed** against a local container built from this tree.

1. **The new classes live in `org.openidentityplatform.openam.oauth2.core`, and 3a's were moved
   there too.** Convention locked mid-phase (see [decisions.md](decisions.md)): classes *authored*
   by the migration go under `org.openidentityplatform.openam.<area>` with a
   `Copyright 2026 3A Systems LLC.` CDDL header and no `@since`; modified-in-place classes keep
   their package and get a `Portions copyright` bump. `ChfOAuth2Request` and `BasicAuthHeader`
   (3a) moved alongside 3b's `HeaderAccessTokenVerifier`, `FormBodyAccessTokenVerifier`,
   `QueryParameterAccessTokenVerifier`. Exception precedent: a test class for a legacy class stays
   in the legacy package (`OAuthProblemExceptionTest` in `org.forgerock.openam.oauth2`).

2. **`OAuthError#handle(String)`'s real contract differs from what its javadoc implied** —
   characterization tests written *before* the strip failed 3/4 against the unmodified code.
   Restlet's `Status(Status, Throwable, String)` constructor overrides the **reason phrase**, so
   once `description(...)` is set, `getError()` (= `getStatus().getReasonPhrase()`) returns the
   *description string*, not the enum's OAuth2 error name, while `getStatus().getDescription()`
   keeps the enum's canned text. Every live `handle(...)` caller passes a message, so every
   serialized error produced through this path has that shape. Pinned as-is in
   `OAuthProblemExceptionTest`; Phase 5's CHF error path must either reproduce this or change it
   consciously.

3. **`OAuth2Utils.ParameterLocation#getRedirector` was deleted in the `OAuthProblemException`
   step, not the `OAuth2Utils` step.** It was the sole compile-time caller of the deleted
   `getErrorForm()` and itself callerless; separating the two deletions would have left an
   intermediate broken build.

4. **`OAuth2Utils` lost its constructor and the `jacksonRepresentationFactory` field entirely**
   (the plan implied keeping a no-arg `@Inject` ctor). Guice JIT-binds the implicit default
   constructor, so the three `OAuth2GuiceModule` provider methods injecting `OAuth2Utils` are
   unchanged. `getRealm(HttpServletRequest)` went too — reachable only via the deleted
   `getRealm(Request)`.

5. **The e2e leg and the `:180` manual check both ran locally against this tree**, not just in CI:
   image built from the locally built war (CI `build-docker` IDP recipe, minimal context),
   OpenDJ + OpenAM containers, configurator, demo user, then `npx playwright test oauth2` →
   7/7 (2 pre-existing + 5 new token-location cases, including both "token in both locations ⇒
   error" tests). The unqualified `:180` binding was then exercised live: open dynamic
   registration enabled, anonymous `POST /oauth2/connect/register`, and
   `GET /oauth2/connect/register?client_id=…` with the registration access token as Bearer →
   HTTP 200 through the neutral header verifier.
