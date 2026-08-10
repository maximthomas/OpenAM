## Context

See `proposal.md` — Why. Requirements are in `specs/oauth2/request-parameters/`; this document
covers only how they are met.

Five facts about the existing code shape the approach:

1. Of 130 main-source files that reference `OAuth2Request`, only 18 reach through it. Keeping the
   type's *name* keeps 112 files untouched; the work is confined to the 18 and to the class itself.
2. `OAuth2Request` already carries framework-neutral state — the token map, session id, cached
   body and client registration — and already has two subclasses. It is not a pure interface
   pretending to be a class; it is a base class with one leaky member.
3. Both existing subclasses are **partial**. `RealmOnlyOAuth2Request` and `IdTokenInfo`'s
   `ValidateIdTokenRequest` both call `super(null, null)`, override some members and inherit the
   rest. `ValidateIdTokenRequest` inherits the token map, session and client registration, so it
   silently keeps its *own* empty copies rather than the delegate's; and it inherits
   `getEndpointType()`, which dereferences the null request.
4. `getParameterNames()` and `getParameterCount()` have exactly one production caller each, both
   in `DuplicateRequestParameterValidator`. Their semantics can be corrected without a survey.
5. `OAuth2Request` is not bound in Guice. `OAuth2RequestFactory` constructs it directly; the
   `@Inject @Assisted` constructor annotation has no assisted-injection factory behind it. The
   constructor is free to change.

## Goals / Non-Goals

**Goals:**

- Remove `org.restlet` from the sixteen non-endpoint classes that import it, by deleting
  `OAuth2Request.getRequest()` rather than by finding a neutral spelling for each call.
- Implement the `oauth2/request-parameters` requirements **once, above the adapter seam**, so a
  future CHF adapter cannot get parameter precedence, duplicate detection or credential
  presentation subtly wrong.
- Leave Restlet serving every request.

**Non-Goals:**

- Removing `jakarta.servlet` types from the core. The servlet API is the substrate under both
  Restlet and CHF here; it is not the framework being removed. `getServletRequest()` is a member
  of the neutral surface, not a leak through it.
- Writing `ChfOAuth2Request`. It arrives with the first endpoint that needs it.
- Changing what any endpoint returns, beyond the two corrections the spec requires.

## Decisions

### D1 — `OAuth2Request` keeps its name and becomes abstract

The framework-touching members become abstract; the neutral state and logic stay concrete in the
base. `RestletOAuth2Request` — in `org.openidentityplatform.openam.oauth2` — is the only
implementation this change ships. `getRequest()` is deleted, not deprecated.

*Why not extract an interface:* the base holds real state (token map, session id, body cache,
client registration) and real logic (parameter precedence). An interface would push all of it into
each implementation, which is the opposite of D2.

*Why not keep the class concrete with an injected source object:* it adds an indirection whose
only benefit is avoiding the word `abstract`, and it leaves `getRequest()` a plausible thing to
re-add.

*Consequence worth naming:* abstract members force both existing subclasses to be total (D6).
That is the mechanism by which fact 3's latent bugs surface at compile time.

### D2 — The spec'd behaviour lives in the base, over a narrow primitive set

Requirement 1 (precedence), Requirement 2 (body re-readability) and Requirement 3 (duplicates) are
implemented **once**, concretely, in the abstract base. Adapters supply only primitives that cannot
be expressed neutrally:

| Abstract primitive | Why it cannot be neutral |
|---|---|
| `getRequestMethod()` | R1 consults the body only for POST |
| `getAttribute` / `setAttribute` | request-scoped state (R6) |
| `getQueryParameterNames` / `getQueryParameterValues` | query parsing |
| `getFormParameterNames` / `getFormParameterValues` | body parsing, and R2's re-readability |
| `getJsonBody()` | body parsing |
| `getHeader(String)` | header access |
| `getBasicCredentials()` | credential decoding (R4) |
| `getServletRequest()` / `getServletResponse()` | substrate access |
| `getUri()`, `setQueryParameterValue`, `removeQueryParameterValue` | URI reading and D7's mutation |
| `getLastPathSegment()` | path access |
| `getLocale()` | R6 |
| `getEndpointType()` | routing (D5) |

Concrete in the base: `getParameter`, `getParameterNames`, `getParameterCount`, `getBody` and its
cache, and all the state accessors.

The proposal sketched a nine-member surface derived from the call sites. This is the refined
version: the count went up because the call sites needed *counts and names*, not just values, once
Requirement 3 had to be implementable.

*This is the load-bearing decision.* A CHF adapter that implements twelve mechanical primitives
cannot reorder parameter precedence. One that implements `getParameter` can, and no existing test
would catch it.

### D3 — Duplicate detection compares per source, not across sources

`getParameterNames()` returns the union of query names and — for a POST — body names.
`getParameterCount(name)` returns the **maximum** of the query occurrence count and the body
occurrence count, not their sum.

The maximum is what makes Requirement 3's third scenario work: a parameter appearing once in the
query and once in the body counts as one, so it is not a repeat, and Requirement 1's precedence
rule settles which value is used. A sum would reject it, contradicting R1.

Today `getParameterNames()` returns body names for a POST and `getParameterCount()` counts query
occurrences, so the two never describe the same source. That mismatch is the defect; the union and
the maximum remove it.

### D4 — One neutral credentials type, and both multi-mechanism paths report `invalid_request`

`getBasicCredentials()` returns an OpenAM-owned value type carrying an identifier and a `char[]`
secret, or nothing when no Basic header is present. It must distinguish *absent* from *present
with an empty secret* — Requirement 4 has a scenario for each, and they are not the same for a
public client.

The check that rejects a request using two mechanisms moves out of the two places that currently
perform it independently. Today the Basic-plus-`client_id` path throws `invalid_request` and the
Basic-plus-assertion path throws `invalid_client` from inside JWT verification, after the assertion
has already been validated. One check, before either branch, reporting `invalid_request` per RFC
6749 §5.2.

*Not a neutral CHF type:* the core must not import `org.forgerock.http.*` under this change's
premise, so `AuthorizationHeader` from `fix-chf-framework-gaps` is used *by the CHF adapter later*,
not by the core.

### D5 — The endpoint type is derived by the adapter, because it is a routing fact

`getEndpointType()` becomes abstract. The Restlet adapter keeps the existing derivation —
subtracting the realm URL attribute from the resource reference — and caches it. A CHF adapter will
read the router's matched/remaining split instead.

*Why not keep it in the base over `getUri()`:* the derivation depends on how the router records
what it matched, which is precisely what differs between the two frameworks. Leaving it in the base
would make it look portable and fail silently under CHF, producing a wrong endpoint type rather
than an error.

### D6 — Both partial subclasses collapse into one total decorator

`RealmOnlyOAuth2Request` and `ValidateIdTokenRequest` are the same idea: an `OAuth2Request` with
one parameter answered differently. Replace both with a single decorator that delegates **every**
member to a wrapped request and overrides one parameter.

This fixes fact 3's two latent bugs as a side effect: the decorator no longer keeps a private empty
token map that shadows the delegate's, and no longer inherits an `getEndpointType()` that
dereferences null.

`OAuth2Request.forRealm(String)` has no request to wrap, so it keeps a dedicated implementation —
but as a total one that throws explicitly from each unsupported member rather than inheriting
methods that NPE.

### D7 — The URI mutation is reproduced, but as two named operations

`alterMaxAge` and `removeLoginPrompt` mutate the request's query string in place, and the mutation
is read back later in the same request as the goto URL. The behaviour is preserved.

It is expressed as `setQueryParameterValue(name, value)` and `removeQueryParameterValue(name,
value)` on the facade rather than by handing out a mutable URI object. Two named mutators with two
callers each are greppable; a mutable reference is not.

*Recorded as debt, not fixed:* the right shape is to compute the goto URL from the parameters
without mutating the request. That is a change to the login-redirect path with its own blast
radius, and this change is already carrying two wire-visible corrections.

### D8 — The three access-token verifiers become framework-neutral

`RestletHeaderAccessTokenVerifier`, `RestletQueryParameterAccessTokenVerifier` and
`RestletFormBodyAccessTokenVerifier` unwrap only to read a header, a query parameter and a form
parameter. Given those primitives they are neutral, so they need no CHF twins: three classes, not
six. They lose the `Restlet` prefix and their Guice bindings are renamed with them.

The header verifier currently relies on Restlet parsing `Authorization: Bearer xyz` into a
challenge response. It must now do that itself: split on the first space and compare the scheme
case-insensitively, per RFC 7235 §2.1. This is the one place in D8 where behaviour could drift, and
Requirement 5's header scenario is its test.

### D9 — Five commits, deletions last

1. Introduce the abstract base and `RestletOAuth2Request`, with `getRequest()` still present.
   Nothing else changes; every existing caller still compiles.
2. Move the 18 unwrap sites onto the facade. Delete `getRequest()`. Delete the two UMA bridges and
   the dead Restlet half of `OAuth2Utils`. The core stops importing `org.restlet`.
3. Requirement 3 — the union-and-maximum change (D3). Wire-visible.
4. Requirement 4 — the single multi-mechanism check (D4). Wire-visible.
5. The verifier neutralisation and rename (D8), and the decorator collapse (D6).

Commits 1 and 2 are behaviour-preserving and carry the bulk of the diff. 3 and 4 are small and are
the only ones that change a response. Isolating them means a bisect lands on ten lines, not on the
refactor.

## Risks / Trade-offs

- **The ACR channel breaks silently or not at all.** `ResourceOwnerSessionValidator` writes the
  matched `acr` as a request attribute; `StatefulTokenStore` reads it back when minting the ID
  token. If the adapter does not preserve attribute identity across the request, the claim
  disappears with no exception and no failing test — visible only to a relying party that checks
  it. → Requirement 6's two `acr` scenarios are written first, before any production code moves.

- **`ValidateIdTokenRequest`'s partiality may be load-bearing.** It has inherited its own empty
  token map since it was written. Making the decorator total means it now sees the delegate's
  tokens. That is the correct behaviour, but it is a behaviour change in ID token validation that
  nobody asked for. → Characterise the id_token validation path before commit 5, and if the
  inherited emptiness turns out to matter, keep it deliberately and comment why.

- **Requirement 3's fix can reject requests that work today.** A client POSTing a duplicated
  parameter to `/authorize` starts getting `invalid_request`. That is the point, and it is why
  commit 3 is alone. → Check the console and XUI authorization flows before it lands.

- **Bearer scheme parsing is a hand-rolled replacement for library code.** Restlet's challenge
  parser handled the `Authorization` header; D8 replaces it with a split. Case, extra whitespace
  and a missing token are all ways to get it wrong. → Requirement 5's scenarios, plus explicit
  cases for lowercase `bearer` and a scheme with no token.

- **Twelve abstract primitives is a wide seam to implement twice.** The CHF adapter has twelve
  methods to get right rather than one. → That is the trade being made deliberately: twelve
  mechanical methods with a shared test suite, against one method with room for judgement. The
  base's tests run against every implementation.

## Migration Plan

Land the five commits of D9 in order across `openam-oauth2` and `openam-uma`. No released artifact
and no version bump, so nothing to coordinate.

Depends on `decouple-oauth2-errors-from-restlet` landing first: it removes the seven
`Request.getCurrent()` sites and makes `OAuth2Utils.getRequestParameter` callerless, which is what
lets commit 2 delete that half of the class outright rather than porting it.

**Rollback.** Commits 3, 4 and 5 revert independently. Commits 1 and 2 revert together.

## Open Questions

- Whether `getServletRequest()` should survive the CHF adapter or be replaced by narrower members
  (cookies, remote address, locale) at each of its ten call sites. It is answerable only when the
  first CHF endpoint exists, and it changes nothing in this change.
