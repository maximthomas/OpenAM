# Phase 3b — Transport-neutral collaborators (verifiers, `ClientCredentialsReader`, `OAuth2Utils`)

Detailed execution plan for **sub-phase 3b** of the Restlet → CHF migration. Parent tracker:
[plan.md](plan.md) (Phase 3); research & sizing: [phase-3-research.md](phase-3-research.md); reusable CHF
patterns: [chf-patterns.md](chf-patterns.md); predecessor: [phase-3a-oauth2request.md](phase-3a-oauth2request.md);
inventory: [inventory.md](inventory.md). Written 2026-07-11; branch `features/restlet-migration`.

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
`org.forgerock.oauth2.core`, driven only by `OAuth2Request` accessors); the three `Restlet*` verifier
classes are deleted; `OAuth2Utils` is Restlet-free; `OAuthProblemException`'s dead Restlet-request plumbing
is stripped; `ClientCredentialsReader`'s failure path is fully neutral end-to-end.

## Scope & sizing (decided)

- **OAuth2Utils: full clear.** Do the small `OAuthProblemException` enabling edit and delete the entire
  Restlet half of `OAuth2Utils`, removing every `org.restlet` import from it.
- **Failure-factory: pull forward.** Make `OpenAMClientAuthenticationFailureFactory.hasAuthorizationHeader`
  neutral now (behaviour-identical on Restlet, de-risks Phase 5's CHF token endpoint).

**~3 new classes** (the neutral verifiers), **~9 modified**, **~4 deleted** (3 Restlet verifiers + net
method deletions), plus tests. Medium risk — live path, basic-auth ISO-8859-1 charset, and preserving the
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
   `(OAuthError, Request)` constructor — but **every runtime caller now passes `null`** (all 7 SERVER_ERROR
   sites use `handle(String)`; the only two `handle(Request,String)` callers,
   `RealmOAuth2ProviderSettings:132` and `OAuth2ProviderSettingsFactory:91`, pass `null`). So the
   Restlet-request branch is dead. Verified callerless and removable with it: `pushException()`,
   `popException(Request)`, `getErrorForm()`, `getErrorMessage()`. `OAuthProblemException` keeps
   `extends org.restlet.resource.ResourceException` and `org.restlet.data.Status` (pervasive — Phase 5).
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
- **`String getQueryParameter(String name)`** — first query-string value, or `null` (read companion to the
  existing `setQueryParameter`).
- **`String getFormParameter(String name)`** — first value from a POST `application/x-www-form-urlencoded`
  body, or `null` when the body is absent / not form-encoded.

**`OAuth2Request.java`** (base): add the three as throwing defaults (mirrors 3a as-built deviation #4).

**`RestletOAuth2Request.java`** — implement with today's exact verifier logic (verbatim, so the Restlet
path is byte-for-byte unchanged):
- `getAuthorizationBearerToken()` ← the Bearer-parse body of
  `RestletHeaderAccessTokenVerifier.getChallengeResponse(request)` (read the raw `Authorization` header off
  `HttpRequest`; scheme `Bearer` → return the value; else fall back to `request.getChallengeResponse()`).
- `getFormParameter(name)` ← `RestletFormBodyAccessTokenVerifier` body: guard
  `MediaType.APPLICATION_WWW_FORM.equals(entity.getMediaType())`, then `new Form(entity).getFirstValue(name)`
  (no entity re-set — matches the verifier today).
- `getQueryParameter(name)` ← `request.getOriginalRef().getQueryAsForm().getFirstValue(name)` (**note
  `getOriginalRef()`**, matching `RestletQueryParameterAccessTokenVerifier`).

**`ChfOAuth2Request.java`** — implement with the existing helpers:
- `getAuthorizationBearerToken()` — parse `request.getHeaders().getFirst(AUTHORIZATION_HEADER)`; if the
  scheme is `Bearer`, return the token (same header plumbing as `getBasicAuthCredentials()`).
- `getFormParameter(name)` — reuse the private `formBody()` helper (content-type-guarded) → `.getFirst(name)`.
- `getQueryParameter(name)` — reuse the private `queryForm()` helper → `.getFirst(name)`.

**`IdTokenInfo.ValidateIdTokenRequest`** (`org.forgerock.openidconnect.restlet`) — add delegating overrides
for the three new accessors (consistent with 3a; `/oauth2/idtokeninfo` runs through it).
`RealmOnlyOAuth2Request` inherits the throwing defaults (not on a verifier path).

### 2. Three transport-neutral `AccessTokenVerifier`s + Guice rebind

**New** (openam-oauth2, `org.forgerock.oauth2.core`) — each `@Singleton`, `@Inject(TokenStore)`, overriding
`obtainTokenId(OAuth2Request)`:
- `HeaderAccessTokenVerifier` → `request.getAuthorizationBearerToken()`.
- `FormBodyAccessTokenVerifier` → `request.getFormParameter(ACCESS_TOKEN)`.
- `QueryParameterAccessTokenVerifier` → `request.getQueryParameter(ACCESS_TOKEN)`.

**Deleted:** `RestletHeaderAccessTokenVerifier`, `RestletFormBodyAccessTokenVerifier`,
`RestletQueryParameterAccessTokenVerifier` (`org.forgerock.oauth2.restlet`).

**Modified — `OAuth2GuiceModule.java`** (`org.forgerock.openam.oauth2.guice`):
- imports (~lines 87–89) → the three new `org.forgerock.oauth2.core` classes.
- the four `configure()` binds (~180–183: unqualified default + `@Named(HEADER/FORM_BODY/QUERY_PARAM)`) and
  the three realm-agnostic `@Provides` (~314, ~319–326, ~328–335) → `new`/`.to()` the neutral classes.
  Consumers unchanged (see the token-location map above).

`AccessTokenVerifier` (the abstract base, `org.forgerock.oauth2.core`) is untouched — only its subclasses
change package/impl.

### 3. `ClientCredentialsReader` — verify + back-fill tests

No source change (already neutral since 3a: `ClientCredentialsReader.java` reads
`request.getBasicAuthCredentials()` and `request.getEndpointType() == TOKEN_ENDPOINT`). Add to
`ClientCredentialsReaderTest` (`openam-oauth2/src/test/.../openam/oauth2/ClientCredentialsReaderTest.java`):
a case stubbing `getBasicAuthCredentials()` → a real `BasicAuthHeader` (asserts `CLIENT_SECRET_BASIC` + the
multiple-auth-methods conflict), and a case stubbing `getEndpointType()` → `TOKEN_ENDPOINT` (asserts the
`token_endpoint_auth_method` enforcement branch).

### 4. Failure-factory pull-forward

**`OpenAMClientAuthenticationFailureFactory.java`** (`org.forgerock.oauth2.restlet`, `hasAuthorizationHeader`
~line 51–54): `return request.getBasicAuthCredentials() != null;` and drop the `org.restlet` import if now
unused. Behaviour-identical on Restlet (`getBasicAuthCredentials() != null ⇔ getChallengeResponse() != null`
on `RestletOAuth2Request`), and it stops throwing on a `ChfOAuth2Request`, so `ClientCredentialsReader`'s
failure path is neutral end-to-end. (The class stays in the `.restlet` package — its full port is Phase 5.)

### 5. `OAuth2Utils` full clear + `OAuthProblemException` enabling edit

**`OAuthProblemException.java`** (`org.forgerock.openam.oauth2`) — strip dead Restlet-request plumbing:
- delete `handle(Request)` and `handle(Request, String)`; retarget the two `handle(null, message)` callers
  (`RealmOAuth2ProviderSettings:132`, `OAuth2ProviderSettingsFactory:91`) to `handle(message)`.
- replace the private `(OAuthError, Request)` constructor with `(OAuthError)` (redirect_uri/state/scope =
  null); `handle(String)` calls it.
- delete the `request` field, `pushException()`, `popException(Request)`, `getErrorForm()`,
  `getErrorMessage()`, and the now-unused `oAuth2Utils` field.
- remove imports `org.restlet.Request`, `org.restlet.data.Form`. **Keep**
  `extends org.restlet.resource.ResourceException` and `org.restlet.data.Status` (Phase 5).

**`OAuth2Utils.java`** (`org.forgerock.openam.oauth2`) — delete the Restlet half: `getRealm(Request)`,
`getRealm(HttpServletRequest)` (dead once the former is gone), `getLocale(Request)`,
`getRequestParameter(Request,…)`, `getRequestParameters(Request)`, `getParameters(Request)`, and the private
`ParameterLocation` enum (incl. `getRedirector`). Remove all ten `org.restlet.*` imports and the
`ServletUtils` import. **Keep** (all Restlet-free): ctor, `getDeploymentURL(HttpServletRequest)`,
`getConfirmationKey(OAuth2Request)`, and the string helpers (`isEmpty/isBlank/isNotBlank/join/joinStatic/
split`). *(Note: `getDeploymentURL` is currently callerless but is on the KEEP list — leave it.)*

## Tests

- **New** `HeaderAccessTokenVerifierTest`, `FormBodyAccessTokenVerifierTest`,
  `QueryParameterAccessTokenVerifierTest` — construct real `ChfOAuth2Request` **and** `RestletOAuth2Request`
  (per [chf-patterns.md](chf-patterns.md) §5/§11 scaffolding), assert token extraction from the right
  location and `null` from the wrong one (e.g. form verifier ignores a query token).
- Extend `ChfOAuth2RequestTest` / `RestletOAuth2RequestTest` for the three new accessors:
  `getAuthorizationBearerToken` (Bearer present / absent / non-Bearer scheme), `getQueryParameter`,
  `getFormParameter` (form vs non-form content type, incl. `;charset=UTF-8` — [chf-patterns.md](chf-patterns.md) §7).
- `ClientCredentialsReaderTest` — the two new cases from work item 3.
- `OAuth2UtilsTest` (if present) — remove cases for deleted methods; keep the kept-method cases.
- **Existing Restlet-path suite stays green unchanged** — the acceptance gate for behaviour parity.

## Verification

1. `mvn -o -pl openam-oauth2 install -DskipTests` (openam-uma resolves openam-oauth2 from `~/.m2` —
   [chf-patterns.md](chf-patterns.md) §11) → `mvn -o -pl openam-oauth2,openam-uma test`.
2. `mvn install -DskipTests` (whole reactor; no dangling refs / signature breaks).
3. Grep gates:
   - `grep -n "org.restlet" openam-oauth2/src/main/java/org/forgerock/openam/oauth2/OAuth2Utils.java` → 0.
   - the three `Restlet*AccessTokenVerifier` files are gone; no references remain
     (`grep -rn "RestletHeaderAccessTokenVerifier\|RestletFormBodyAccessTokenVerifier\|RestletQueryParameterAccessTokenVerifier" --include=*.java .` → 0).
   - `grep -rn "getCurrent()" openam-oauth2/src/main --include=*.java | grep -v /restlet/ | grep -v RestletOAuth2Request.java` → still 0 (no regressions).
4. No route flip ⇒ no Cargo IT behaviour change expected. Smoke the token-verifier paths on the live Restlet
   server: userinfo with the token in the `Authorization` header **and** in a POST form body (both must
   succeed); tokeninfo/introspect with the token in the header **and** in the query string; dynamic
   client-registration read (unqualified/default header verifier). Record pre/post curl — must match.
5. CI (`.github/workflows/build.yml`) — JDK 11–26 × 3 OSes on the `features/**` push.

## Parity checklist

| Item | Guard |
|---|---|
| Token-location distinction (header vs form vs query) preserved | 3 verifier tests assert wrong-location returns null; consumers' `@Named` wiring unchanged |
| Restlet path byte-for-byte unchanged | `RestletOAuth2Request` accessors = verbatim verifier bodies; existing suite green + pre/post curl |
| Bearer parse parity | `getAuthorizationBearerToken` ports `getChallengeResponse` Bearer logic incl. non-Bearer fallback |
| Form content-type trap (`;charset=UTF-8`) | CHF `getFormParameter` uses the content-type-guarded `formBody()` helper; test with charset param |
| Query source parity | Restlet uses `getOriginalRef()` (not `getResourceRef()`); asserted |
| Basic-auth ISO-8859-1 (risk #5) | `ClientCredentialsReaderTest` basic-auth case via `BasicAuthHeader` |
| Endpoint-type enforcement (risk #12) | `ClientCredentialsReaderTest` `TOKEN_ENDPOINT` case |
| CHF failure path no longer throws | failure-factory pull-forward + `getBasicAuthCredentials()` |
| `OAuthProblemException` behaviour unchanged | request branch was already dead (always-null); redirect_uri/state/scope readers are callerless |

## Execution order

new accessors on `OAuth2Request` base (throwing defaults) → impl in `RestletOAuth2Request` (verbatim) +
`ChfOAuth2Request` (helpers) + delegate in `ValidateIdTokenRequest` → three neutral verifier classes →
rebind `OAuth2GuiceModule` → delete the three `Restlet*` verifiers → failure-factory pull-forward →
`OAuthProblemException` enabling edit (retarget the two `handle(null,…)` callers first) → `OAuth2Utils`
delete-half → `mvn -o -pl openam-oauth2 install -DskipTests` → `mvn -o -pl openam-oauth2,openam-uma test` →
whole build → grep gates → tests → smoke/curl → mark 3b done in [plan.md](plan.md) and start
[phase-3c] from [phase-3-research.md](phase-3-research.md).
