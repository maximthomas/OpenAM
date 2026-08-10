## Why

`OAuth2Request` already exists to do this job. Its own javadoc says so:

> An abstraction of the actual request so as to allow the core of the OAuth2 provider to be
> agnostic of the library used to translate the HTTP request.

It holds a `private final Request request` and publishes `public Request getRequest()`. The
abstraction is a wrapper with a hole in it, and the hole is load-bearing: 130 main-source files
reference `OAuth2Request`, but only **18** reach through it for the raw `org.restlet.Request`.
The other 112 are already framework-agnostic and would compile against any implementation.

Those 18 files are what keeps `org.restlet` in the OAuth2 core. Sixteen non-endpoint classes
across `openam-oauth2` and `openam-uma` import it, and every endpoint change that follows —
`/xacml`, `/uma/*`, `/oauth2/*`, WebFinger, discovery — is blocked behind them. An endpoint
cannot serve CHF traffic while the services it calls demand a Restlet request.

The neutral shape is not speculative. `OAuth2ProviderSettingsFactory` already publishes
`get(Context)` beside `get(OAuth2Request)`, and `OAuth2UrisFactory` already publishes
`get(Context, Realm)` — `org.forgerock.services.context.Context`, the CHF type, resolving the same
provider settings on the CREST path today. `openam-oauth2` already depends on
`org.openidentityplatform.commons.http-framework`. Half of the destination ships in the current
build; this change makes the other half stop asking for Restlet.

Two of the eighteen sites are not merely coupled but wrong. `UmaTokenIntrospectionHandler` holds
an `OAuth2Request` and calls:

```java
UmaProviderSettings providerSettings = providerSettingsFactory.get(request.<Request>getRequest());
UmaUris umaUris = umaUrisFactory.get(request.<Request>getRequest());
```

Both factories immediately re-wrap: `get(new OAuth2Request(jacksonRepresentationFactory, req))`.
The round trip constructs a *fresh* `OAuth2Request`, discarding the client registration, session
id and token map carried by the original — twice per introspection. Removing the escape hatch
removes the defect, because there is nothing left to unwrap.

## What Changes

- Make `OAuth2Request` framework-agnostic and **delete `getRequest()`**. Ship a
  `RestletOAuth2Request` adapter behind it; `ChfOAuth2Request` arrives with the endpoints. The
  core sees neither `org.restlet.*` nor `org.forgerock.http.*` — per the locked decision, this
  change neutralises, it does not migrate.

- Give the facade the members the 18 unwrap sites actually need. Derived from the call sites, not
  from Restlet's API:

  | Member | Serves | Today |
  |---|---|---|
  | `get/setAttribute(String)` | ACR channel, `AM_CTX_ID`, realm | `request.getAttributes()` |
  | `getServletRequest()` | 10 sites | `ServletUtils.getRequest(req)` |
  | `getServletResponse()` | 3 sites | `Response.getCurrent()` — thread-local |
  | `getQueryParameter(String)` | bearer-token-in-query, `getParameterCount` | `getQueryAsForm()` |
  | `getFormParameter(String)` | bearer-token-in-body | `new Form(entity)` |
  | `getHeader(String)` | bearer-token-in-header | `ChallengeResponse.getRawValue()` |
  | `getBasicCredentials()` | `ClientCredentialsReader`, failure factory | `getChallengeResponse()` |
  | `getUri()`, mutable query | `alterMaxAge`, `removeLoginPrompt`, goto URL | `getResourceRef()` |
  | `getLastPathSegment()` | userinfo detection, `getEndpointType()` | `getLastSegment()` |

- Change or delete the three signatures that take a raw `org.restlet.Request`:
  `ResourceOwnerAuthenticator.authenticate(Request, …)` (private), and the package-private
  `UmaProviderSettingsFactory.get(Request)` / `UmaUrisFactory.get(Request)` bridges described
  above, which are deleted outright.

- Delete the dead Restlet half of `OAuth2Utils` — `getRealm(Request)`, `getLocale(Request)`,
  `getRequestParameter`, `getRequestParameters`, `getParameters` and the private
  `ParameterLocation` enum. `getRequestParameter` is called only from `OAuthProblemException`,
  which `decouple-oauth2-errors-from-restlet` deletes; the other four have no callers at all.

- Remove the last four ambient-request lookups in the core — `Response.getCurrent()` in
  `CsrfProtection` and `ResourceOwnerAuthenticator` (×2), and
  `ServletUtils.getRequest(Request.getCurrent())` in `ClientAuthenticator`. Under CHF these are
  unnecessary: `HttpFrameworkServlet` puts both servlet objects into `AttributesContext`.

Three existing behaviours must be decided rather than reproduced by reflex, because the facade is
where they are implemented:

- **Duplicate-parameter detection does not work on a POST authorization request.**
  `DuplicateRequestParameterValidator` iterates `getParameterNames()` — which returns *body* names
  for a POST — and counts with `getParameterCount()`, which counts *query* occurrences only. On a
  `GET /authorize` both sides read the query and the check works; on a `POST /authorize` the names
  come from the body and the counts from an empty query, so no repeat is ever found. RFC 6749
  §3.1 forbids repeated parameters and explicitly permits POST to the authorization endpoint.
  (The validator is bound only as an `AuthorizeRequestValidator`; the token endpoint has no
  duplicate-parameter check at all, which is a separate gap and not this change's business.)
- **Two ways of using two client-authentication mechanisms report two different errors.**
  A request combining HTTP Basic with a `client_id` parameter is rejected as `invalid_request`; a
  request combining HTTP Basic with a JWT client assertion is rejected as `invalid_client`. RFC
  6749 §5.2 assigns `invalid_request` to a request that "utilizes more than one mechanism for
  authenticating the client", without qualification. The spec requires `invalid_request` for both,
  which makes the second path a wire-visible correction.
- **`getEndpointType()` derives the endpoint by string surgery** on
  `RestletRealmRouter.REALM_URL`. It is routing-shape dependent and will fail silently under CHF's
  matched/remaining URI split.
- **`alterMaxAge` and `removeLoginPrompt` mutate the request URI in place**, and the mutation is
  read back later in the same request. Expressible in CHF via `MutableUri`, but it is a
  side-effecting request object that this change should record as debt rather than launder.

Not in scope: the Restlet endpoints, routers, `AccessTokenProtectionFilter`, the audit filters,
Guice wiring, and the CHF adapter itself. They stay Restlet-typed and keep serving all traffic.
Whether the three `Restlet*AccessTokenVerifier` classes become neutral or gain CHF twins is a
design decision, not a scope question.

## Capabilities

### New Capabilities

- `oauth2/request-parameters`: how an OAuth2 request's inputs are read — the precedence between
  request attributes, query string and body; the treatment of repeated parameters; whether the
  body survives being read; how client credentials and bearer tokens may be presented; and how
  values derived during a request stay available to later stages of it. This is protocol-visible
  behaviour (RFC 6749 §2.3.1, §3.2; RFC 6750 §2) that currently exists only as the body of one
  class. Swapping the layer that implements it without first writing it down is the single
  largest risk in this migration.

### Modified Capabilities

None. `oauth2/error-responses` is unchanged by this change and must stay that way.

## Impact

**Code.** Sixteen non-endpoint classes: `openam-oauth2` — `OAuth2Request`, `OAuth2RequestFactory`,
`OAuth2Utils`, `OAuth2UrisFactory`, `ClientAuthenticator`, `ClientCredentialsReader`,
`CsrfProtection`, `ResourceOwnerAuthenticator`, `ResourceOwnerSessionValidator`, `TokenInfoService`,
`OpenAMScopeValidator`, `StatefulTokenStore`, `IdTokenResponseTypeHandler`; `openam-uma` —
`UmaProviderSettingsFactory`, `UmaUrisFactory`, `UmaTokenIntrospectionHandler`. Plus the three
`Restlet*AccessTokenVerifier` classes and one new adapter. 23 test files reference `OAuth2Request`;
those that stub `getRequest()` to return a mock Restlet request must be rewritten against the
facade.

**Behaviour.** Intended to be wire-invisible. That intent is the reason the change needs a spec:
without a written contract, a facade that resolves parameters in a subtly different order passes
every existing test and breaks a client. The three behaviours flagged above are the exceptions,
and each is an explicit decision in `design.md`.

**Sequencing.** Depends on `decouple-oauth2-errors-from-restlet`, which removes the seven
`Request.getCurrent()` lookups and the `OAuthProblemException` Restlet field, and which makes
`OAuth2Utils`'s Restlet surface dead rather than merely unwanted. Depends on
`fix-chf-framework-gaps` only for the eventual CHF adapter — `getFormParameter` needs its
media-type fix and `getBasicCredentials` needs its `AuthorizationHeader` — so this change can land
against Restlet alone and take the CHF dependency later. It blocks every endpoint change.

**Risk.** The ACR value is a request-scoped channel between components: `ResourceOwnerSessionValidator`
writes it as a request attribute, `StatefulTokenStore` reads it back when minting the ID token. If
the facade does not preserve attribute identity across the request, `acr` silently disappears from
issued ID tokens — no exception, no failing test, a standards-conformance regression visible only
to a relying party that checks it. The parity test for that channel is the first thing this change
should write.
