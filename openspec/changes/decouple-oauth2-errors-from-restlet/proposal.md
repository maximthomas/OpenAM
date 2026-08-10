## Why

`OAuthProblemException` extends `org.restlet.resource.ResourceException` and carries an
`org.restlet.data.Status`. It is thrown from fifteen places in the OAuth2, OpenID Connect and
UMA core — none of them an endpoint — and it drags `org.restlet` into every class that throws
it. Seven of those sites reach for the thread-local `org.restlet.Request.getCurrent()` purely to
construct it. That ambient request is the single largest obstacle to making the OAuth2 core
framework-agnostic, and it exists to feed one constructor.

It feeds nothing. The constructor reads `redirect_uri`, `state` and `scope` off the request,
and no live code reads them back: `redirectUri()`, `state()`, `scope()` and `errorUri()` have no
callers, `getErrorForm()` is reached only from `OAuth2Utils.getRedirector(...)`, which is itself
uncalled, and `pushException()`/`popException()` are dead. The redirect-on-error behaviour these
were written for lives elsewhere, in `OAuth2RestletException`, and works.

Worse, the status is discarded before it reaches a client. Every OAuth2 Restlet resource routes
`doCatch` into `ExceptionHandler`, which recognises only `OAuth2RestletException` and flattens
everything else:

```java
final ServerException serverException = new ServerException(throwable);
```

So `StatefulTokenStore`'s deliberate `404 Not found` is reported to the client as
`server_error`. The Restlet coupling buys nothing today, and it blocks
`neutralize-oauth2-request`, which cannot remove `org.restlet` from the OAuth2 core while the
core's own exception type is a Restlet type.

There is already a framework-neutral error hierarchy for exactly this: `OAuth2Exception` and its
twenty-nine subclasses. `OAuthProblemException` duplicates it badly. This change deletes the
duplicate rather than porting it.

## What Changes

- Retarget all fifteen `OAuthProblemException` throw sites onto `OAuth2Exception` subclasses.
  Five of them — `StatefulTokenStore`'s `updateAuthorizationCode`, `updateAccessToken` and
  `deleteAuthorizationCode` — need no signature change, because `TokenStore` already declares
  `throws NotFoundException, ServerException` on precisely those methods. Retargeting makes the
  implementation honour a contract it already publishes.
- Add one small unchecked carrier, in `org.openidentityplatform.openam.oauth2`, wrapping an
  `OAuth2Exception` for the ten remaining sites. `OAuth2Exception` is checked and
  `OAuthProblemException` is not; the sites that would have to change are `ClientRegistration`'s
  getters (thirteen of its seventeen methods declare no `throws`, and roughly twenty throw sites
  sit behind them) and three service-listener constructors. Propagating checked-ness across that
  surface is a real change with its own blast radius and does not belong here.
- Teach the OAuth2 error handler to unwrap the carrier, so the wrapped exception's status and
  error code reach the client instead of being flattened to `server_error`. **BREAKING** for any
  client that pattern-matches on the current, incorrect status.
- Delete `OAuthProblemException` (421 lines) and the dead `OAuth2Utils.getRedirector` (38 lines).
  Deleting the class also removes a latent `NullPointerException`: `getErrorMessage()` and
  `getErrorForm()` dereference an `oAuth2Utils` field that is only assigned when the exception
  was constructed with a non-null request.
- Retarget seven `@Test(expectedExceptions = OAuthProblemException.class)` assertions in
  `OpenAMClientRegistrationTest` and `AgentClientRegistrationTest`.

Not in scope: `OAuth2RestletException`, `ExceptionHandler`'s redirect logic and the error page
template. They are Restlet-typed and stay that way until the endpoints move; this change makes
what they receive framework-neutral, not how they render it.

## Capabilities

### New Capabilities

- `oauth2/error-responses`: the observable contract of an OAuth2 error — the body fields, the
  relationship between the failure condition and the reported HTTP status, and which failures
  redirect to a validated `redirect_uri` rather than rendering directly. This is the oracle for
  the status-fidelity change above and for every later endpoint change that must not alter it.

### Modified Capabilities

None.

## Impact

**Code.** `openam-oauth2` — `OAuthProblemException` (deleted), `OAuth2Utils`, `Utils`,
`OpenAMClientRegistration`, `AgentClientRegistration`, `StatefulTokenStore`,
`OAuth2ProviderSettingsFactory`, `RealmOAuth2ProviderSettings`, `OpenIdConnectToken`,
`ExceptionHandler`. `openam-uma` — `UmaSettingsImpl`. One new class.

**Behaviour.** Error responses whose underlying condition is not a server error stop reporting
`server_error`. That is the point of the change and the reason it needs a spec: the correction is
wire-visible, and without a recorded contract a later endpoint change could silently revert it.
`Utils.createException` logs before throwing; the logging must survive the retarget.

**Sequencing.** Independent of `fix-chf-framework-gaps` — it touches no framework code and needs
no commons release. It is a prerequisite for `neutralize-oauth2-request`: removing these throw
sites removes seven of the ten ambient-request lookups in the OAuth2 core, leaving only the three
`Response.getCurrent()` servlet lookups, which that change resolves.

**Risk.** The retarget is mechanical but wide. The fifteen throw sites are reached from both
Restlet OAuth2 endpoints and CREST `/json` endpoints, and the two paths render errors
differently today — under CREST an `OAuthProblemException` is an uncaught `RuntimeException`.
Both paths must be characterised before the change lands, not after.
