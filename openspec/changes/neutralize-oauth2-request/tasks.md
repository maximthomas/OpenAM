## 1. Baseline and characterisation (before any code changes)

- [ ] 1.1 Write the ACR parity test against **unmodified** code: an authorization request naming
      `acr_values` that matches an authentication method issues an ID token carrying that `acr`,
      and one that matches none carries `0`. It must pass before anything moves. A test that only
      passes afterwards proves nothing about the channel it exists to protect.
- [ ] 1.2 Re-derive from the code the set of files that reach through `OAuth2Request` for the raw
      Restlet request. Design D1 says sixteen non-endpoint classes plus the three access-token
      verifiers. Confirm the list rather than trusting it; an earlier hand-built inventory in this
      migration was wrong in two places.
- [ ] 1.3 Confirm `getParameterNames()` and `getParameterCount()` still have exactly one production
      caller each. D3 changes their semantics on that basis. A second caller means D3 needs
      re-scoping before commit 3.
- [ ] 1.4 Capture the current response for each Requirement 3 and Requirement 4 scenario against a
      running server: repeated query parameter, repeated form parameter, once-in-each, Basic plus
      `client_id`, Basic plus client assertion. Two of these will change; record which and how.
- [ ] 1.5 Characterise `ValidateIdTokenRequest`'s inherited empty token map — does anything on the
      id_token validation path set or read a token through it? D6 makes the decorator total, which
      changes this. If the emptiness turns out to be load-bearing, D6's collapse must preserve it
      deliberately.
- [ ] 1.6 Record how Restlet parses `Authorization: Bearer <token>` into a challenge response —
      case handling, whitespace, and what it does with a scheme carrying no token. D8 replaces this
      with hand-rolled parsing and must match it.

## 2. The abstract base and the Restlet adapter — commit 1, additive

- [ ] 2.1 Make `OAuth2Request` abstract with the twelve primitives of design D2 abstract, keeping
      `getParameter`, `getParameterNames`, `getParameterCount`, `getBody` and the state accessors
      concrete. Leave `getRequest()` in place for now so every existing caller still compiles.
- [ ] 2.2 Add `RestletOAuth2Request` in `org.openidentityplatform.openam.oauth2` implementing the
      twelve primitives. Repo convention for migration-authored classes: no ForgeRock copyright
      header, no `@since`.
- [ ] 2.3 Point `OAuth2RequestFactory` at the new implementation. Its `@Inject @Assisted`
      constructor has no assisted-injection factory behind it, so no Guice binding changes.
- [ ] 2.4 Add the neutral credentials value type of D4 — identifier plus `char[]` secret —
      distinguishing *absent* from *present with an empty secret*. Requirement 4 has a scenario for
      each and they are not the same for a public client.
- [ ] 2.5 Write the base's behaviour tests as a suite that runs against any implementation, not
      against `RestletOAuth2Request` specifically. Every Requirement 1 and Requirement 2 scenario
      belongs here. This suite is what a future CHF adapter is held to.
- [ ] 2.6 Confirm commit 1 changes nothing observable — re-run 1.1 and 1.4 and diff. The base
      re-implements existing behaviour over new primitives; any difference is a defect in that
      re-implementation, and this is the only point where it is cheap to see.

## 3. Move the call sites and delete the escape hatch — commit 2

- [ ] 3.1 Move the sites confirmed in 1.2 onto the facade. Group by primitive rather than by file —
      all `getServletRequest()` sites together, all attribute sites together — so a mistake in one
      primitive shows up as a cluster.
- [ ] 3.2 Replace `Request.getCurrent()` in `ClientAuthenticator` and `Response.getCurrent()` in
      `CsrfProtection` and `ResourceOwnerAuthenticator` with facade members. `ClientAuthenticator`
      already holds the `OAuth2Request` at the site where it reaches for the thread-local.
- [ ] 3.3 Delete the `UmaProviderSettingsFactory.get(Request)` and `UmaUrisFactory.get(Request)`
      bridges and pass the existing `OAuth2Request` straight through from
      `UmaTokenIntrospectionHandler`. Confirm the introspection path no longer constructs a second
      request object — the discarded client registration and token map were the defect.
- [ ] 3.4 Express the `alterMaxAge` and `removeLoginPrompt` mutations as D7's two named mutators.
      Confirm the goto URL read back later in the same request still reflects both mutations.
- [ ] 3.5 Delete `OAuth2Request.getRequest()`.
- [ ] 3.6 Delete the Restlet-typed half of `OAuth2Utils` — `getRealm(Request)`, `getLocale(Request)`,
      `getRequestParameter`, `getRequestParameters`, `getParameters` and the private
      `ParameterLocation` enum. Confirm by compilation that all five were callerless.
- [ ] 3.7 Confirm no `org.restlet` import remains in any file from 1.2's list. This is the change's
      headline claim; check it mechanically, not by reading.
- [ ] 3.8 Rewrite the tests that stub `getRequest()` to return a mock Restlet request —
      `ResourceOwnerSessionValidatorTest`, `ClientCredentialsReaderTest`,
      `OpenAMClientRegistrationStoreTest` and `OAuth2RequestFactoryTest` among them. They must stub
      the facade members the code now calls, not a request object it no longer sees.
- [ ] 3.9 Re-run 1.1 and 1.4. Commit 2 is behaviour-preserving; both must be unchanged.

## 4. Requirement 3 — duplicate parameters — commit 3, wire-visible

- [ ] 4.1 Make `getParameterNames()` return the union of query names and, for a POST, body names.
- [ ] 4.2 Make `getParameterCount(name)` return the **maximum** of the query and body occurrence
      counts, not the sum.
- [ ] 4.3 Assert that a parameter appearing once in the query and once in the body is **not**
      rejected. This is the tripwire for 4.2: a sum passes every other Requirement 3 scenario and
      fails only this one, while contradicting Requirement 1's precedence rule.
- [ ] 4.4 Add the Requirement 3 scenarios as tests, including the POST form-body repeat that fails
      against pre-change code.
- [ ] 4.5 Check the console and XUI authorization flows for any request that would now be rejected.
      A duplicated parameter that works today starts returning `invalid_request`.

## 5. Requirement 4 — one client-authentication mechanism — commit 4, wire-visible

- [ ] 5.1 Replace the two independent multi-mechanism checks with one, performed before either
      branch, reporting `invalid_request`. The Basic-plus-assertion case currently reports
      `invalid_client` from inside JWT verification, *after* the assertion has been fully validated;
      the single check must run before that work.
- [ ] 5.2 Add the Requirement 4 scenarios as tests, including Basic-plus-assertion and the Basic
      header carrying an identifier with an empty secret.
- [ ] 5.3 Confirm the registered-authentication-method check at the token endpoint still fires, and
      still distinguishes client secret basic, client secret post and private key JWT. Moving the
      multi-mechanism check must not disturb which mechanism is recorded.

## 6. Verifiers and decorators — commit 5

- [ ] 6.1 Make the three access-token verifiers framework-neutral over `getHeader`,
      `getQueryParameter` and `getFormParameter`. Drop the `Restlet` prefix and rename their Guice
      bindings with them.
- [ ] 6.2 Implement bearer scheme parsing per RFC 7235 §2.1 to match 1.6's findings. Test lowercase
      `bearer`, extra whitespace between scheme and token, and a scheme with no token at all.
- [ ] 6.3 Replace `RealmOnlyOAuth2Request` and `ValidateIdTokenRequest` with one total decorator
      that delegates every member and overrides one parameter, per D6. Keep a dedicated
      implementation for `forRealm(String)`, which has no request to wrap, but make it throw
      explicitly from each unsupported member rather than inherit one that dereferences null.
- [ ] 6.4 Apply 1.5's finding. If the inherited empty token map was load-bearing, preserve it
      deliberately with a comment explaining why; otherwise let the decorator see the delegate's.

## 7. Verification

- [ ] 7.1 Confirm every scenario in `specs/oauth2/request-parameters` has a test, and that the
      Requirement 1 and 2 scenarios run through the shared suite of 2.5 rather than against one
      implementation.
- [ ] 7.2 Re-run the 1.4 baseline. Exactly two responses should differ — the Requirement 3 form-body
      repeat and the Requirement 4 Basic-plus-assertion code. Any third difference is a defect.
- [ ] 7.3 Confirm `getServletRequest()` and `getServletResponse()` are the only remaining paths to
      an HTTP type in the sixteen classes, and that no thread-local request or response lookup
      survives anywhere in the OAuth2 or UMA core.
- [ ] 7.4 Build the affected modules with `-am` so no stale same-version SNAPSHOT resolves from
      `~/.m2`, and run the `openam-oauth2`, `openam-uma` and `openam-oauth2-saml2` test suites.
- [ ] 7.5 Run `openspec validate neutralize-oauth2-request --strict`.
