## 1. Baseline and audit (before any code changes)

- [ ] 1.1 Against a running server, capture the current status and body for a missing
      authorization code on both paths: an OAuth2 protocol endpoint, and
      `/json/users/{user}/oauth2/applications`. Expect `400`/`server_error` and `500`
      respectively. This is the before-baseline for spec Requirements 1 and 4.
- [ ] 1.2 Re-derive the throw-site inventory from the code and confirm it is the fifteen sites in
      design D3 — five in `StatefulTokenStore`, five in `OpenAMClientRegistration`, one in
      `OpenIdConnectToken`, `Utils.createException`, and three service-listener constructors. An
      earlier hand-built version of this list was wrong in two places; do not trust it.
- [ ] 1.3 Enumerate consumers of the statuses that change — XUI, the console, published SDKs —
      for `/json/users/{user}/oauth2/applications` and the OAuth2 endpoints. Record whether any
      branches on the current `400`/`500`.
- [ ] 1.4 Confirm no test beyond the seven known `expectedExceptions = OAuthProblemException.class`
      assertions depends on the type. Check `StatefulTokenStoreTest` specifically, since it
      exercises three of the retargeted methods.
- [ ] 1.5 Record what Restlet actually hands to `doCatch` for an exception thrown from a resource
      method — the throwable itself, or a wrapper. This sizes the cause-chain walk in D2 and
      confirms whether the existing depth-1 checks were compensating for real wrapping.

## 2. Carrier and renderer — commit 1, additive

- [ ] 2.1 Add `UncheckedOAuth2Exception extends RuntimeException` in
      `org.openidentityplatform.openam.oauth2`, holding an `OAuth2Exception` and passing it to
      `super(cause)`, per design D1. Follow the repo convention for migration-authored classes:
      no ForgeRock copyright header, no `@since`.
- [ ] 2.2 Replace the fixed-depth checks in `ExceptionHandler.toOAuth2RestletException` with a
      bounded walk of the cause chain per D2, returning the first `OAuth2RestletException` or
      `OAuth2Exception` found nearest the thrown exception, and falling back to `ServerException`
      only when neither appears at any depth.
- [ ] 2.3 Add `ExceptionHandler` tests — none exist today. Cover: an `OAuth2Exception` at depth
      0, 1 and 3 each preserving status and error code; the carrier preserving them; an unrelated
      throwable yielding `server_error`; and a self-referential cause chain terminating rather
      than hanging.
- [ ] 2.4 Confirm commit 1 changes nothing observable — re-run 1.1 and diff against the baseline.
      Nothing throws the carrier yet, so any difference here is a defect in the walk.

## 3. Retarget the sites whose contract already permits it — commit 2

- [ ] 3.1 Retarget `StatefulTokenStore.updateAuthorizationCode`, `updateAccessToken` and the two
      non-not-found throws in `deleteAuthorizationCode` to `ServerException`.
- [ ] 3.2 Retarget the `CLIENT_ERROR_NOT_FOUND` throw in `deleteAuthorizationCode` to
      `NotFoundException`. This is the site Requirement 1's first scenario tests.
- [ ] 3.3 Confirm tasks 3.1 and 3.2 required no signature change, because `TokenStore` already
      declares `throws NotFoundException, ServerException` on all three methods. A needed
      signature change means the D3 table is wrong — stop and re-check.
- [ ] 3.4 Add `ServerException` to `OpenIdConnectToken.createJwt`'s throws and retarget its throw.
      Confirm `getTokenId()` and `toMap()` need no change, as both already declare it.
- [ ] 3.5 Update `StatefulTokenStoreTest` for the retargeted methods, asserting `NotFoundException`
      specifically at the not-found site rather than any `OAuth2Exception`.

## 4. Retarget the remaining sites and delete the class — commit 3

- [ ] 4.1 Change `Utils.createException` to return `UncheckedOAuth2Exception` wrapping a
      `ServerException`, preserving the `logException` call that records the underlying
      `IdRepoException`/`SSOException` the OAuth2 error deliberately does not expose.
- [ ] 4.2 Confirm the ~20 `throw Utils.createException(...)` sites in `OpenAMClientRegistration`
      and `AgentClientRegistration` compile with no textual change. Any site needing an edit
      means the returned type became checked — the carrier's entire purpose is defeated.
- [ ] 4.3 Retarget the five throws in `OpenAMClientRegistration`'s private JWT-verification
      helpers (`byJWKs`, `byJWKsURI` ×2, `byX509Key`, `getAttribute`) to the carrier.
- [ ] 4.4 Retarget the three service-listener constructor throws in
      `OAuth2ProviderSettingsFactory`, `RealmOAuth2ProviderSettings` and `UmaSettingsImpl`.
- [ ] 4.5 Delete `OAuthProblemException.java` and the dead `OAuth2Utils.getRedirector`. Confirm
      by compilation that `getRedirector` had no callers.
- [ ] 4.6 Retarget the seven `expectedExceptions = OAuthProblemException.class` assertions in
      `OpenAMClientRegistrationTest` and `AgentClientRegistrationTest` to assert the **wrapped**
      `OAuth2Exception` type. Asserting only the carrier passes while testing nothing.
- [ ] 4.7 Confirm no `org.restlet` import remains in `Utils`, `OpenAMClientRegistration`,
      `AgentClientRegistration`, `StatefulTokenStore`, `OpenIdConnectToken`,
      `OAuth2ProviderSettingsFactory`, `RealmOAuth2ProviderSettings` or `UmaSettingsImpl`.

## 5. JSON administrative endpoint mapping — commit 4

- [ ] 5.1 In `OAuth2UserApplications`, split `NotFoundException` out of the combined catch in both
      `queryCollection` and `deleteInstance`, returning `org.forgerock.json.resource.NotFoundException`
      as `deleteInstance` already does on its other not-found path. Leave `InvalidClientException`
      mapping to `500`, per D4's scope boundary.
- [ ] 5.2 Update the `@ApiError` descriptors on both operations, which declare only `500`, to
      declare `404` as well.
- [ ] 5.3 Add tests for Requirement 4: the same missing-resource condition reports `404` through
      an OAuth2 endpoint and through the JSON administrative endpoint, and the two agree.

## 6. Verification

- [ ] 6.1 Re-run the 1.1 baseline and confirm every difference is one a spec requires. Any other
      difference is a defect.
- [ ] 6.2 Confirm every scenario in `specs/oauth2/error-responses` has a corresponding test,
      including the Requirement 2 field-omission scenarios and the Requirement 3 redirect
      scenarios, which this change must preserve rather than alter.
- [ ] 6.3 If 1.3 found a consumer branching on the old statuses, coordinate or document the break
      before commit 4 lands.
- [ ] 6.4 Build the affected modules with `-am` so no stale same-version SNAPSHOT resolves from
      `~/.m2`, and run the `openam-oauth2` and `openam-uma` test suites.
- [ ] 6.5 Run `openspec validate decouple-oauth2-errors-from-restlet --strict`.
