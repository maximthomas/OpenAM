## Context

See `proposal.md` — Why. Requirements are in `specs/oauth2/error-responses/`; this document covers
only how they are met.

Four facts about the existing code shape the approach:

1. `ExceptionHandler.toOAuth2RestletException` already contains a branch that reads
   `getStatusCode()` and `getError()` off an `OAuth2Exception` found one level down the cause
   chain and preserves both. Nothing currently reaches it from these throw sites, because an
   `OAuthProblemException` is neither an `OAuth2Exception` nor caused by one. Most of the
   status-fidelity fix is already written.
2. `TokenStore` declares `throws NotFoundException, ServerException` on the three methods where
   `StatefulTokenStore` throws `OAuthProblemException` instead. The implementation is violating a
   contract its own interface publishes, and callers already handle the declared types.
3. `OAuth2Exception` is checked. `ClientRegistration` declares `throws ServerException` on 2 of
   its 17 methods, and roughly twenty throw sites sit behind the other fifteen. Making those
   checked is a change to the client-registration API surface and every caller of it.
4. `Utils.createException` *returns* the exception; its callers write `throw
   Utils.createException(...)`. If the returned type stays unchecked, every one of those call
   sites compiles unchanged.

## Goals / Non-Goals

**Goals:**

- Remove `org.restlet` from the OAuth2, OpenID Connect and UMA core classes that throw errors.
- Make the status of a failure survive the trip to the client, on both the OAuth2 endpoints and
  the JSON administrative endpoints.
- Keep the diff proportional: no change to the `ClientRegistration` API surface, and no textual
  change at the ~20 sites that throw through `Utils.createException`.

**Non-Goals:**

- Changing what status a given failure reports. `ServerException` is `400`/`server_error` today
  and stays that way; this change stops a *more specific* status being overwritten by it.
- Touching `OAuth2RestletException`, the redirect logic, or `error.ftl`. They stay Restlet-typed
  until the endpoints move.
- Making `OAuth2Exception` unchecked. That would remove compiler enforcement across the whole
  OAuth2 core to solve a problem confined to two call surfaces.

## Decisions

### D1 — One unchecked carrier, wrapping an `OAuth2Exception` as its cause

`UncheckedOAuth2Exception extends RuntimeException`, in
`org.openidentityplatform.openam.oauth2`, holding an `OAuth2Exception` and passing it to
`super(cause)`. It exists only to carry a checked neutral exception through a call surface that
cannot declare it.

*Precedent:* `java.io.UncheckedIOException`, which exists for exactly this reason and is named for
exactly this reason. The name states the compromise rather than hiding it behind something that
reads like a first-class error type.

*Alternative rejected:* declaring `throws ServerException` up the `ClientRegistration` surface.
Fifteen interface methods and every caller of them, to remove a wrapper. That is a defensible
change, but it is not this change, and bundling it would make the Restlet removal impossible to
review.

*Alternative rejected:* making `OAuth2Exception` unchecked. It is caught by name throughout the
provider; unchecking it silently converts every one of those `catch` clauses from a compiler-
enforced obligation into an optional courtesy.

### D2 — The renderer walks the cause chain rather than checking two fixed depths

`toOAuth2RestletException` currently tests `throwable` and `throwable.getCause()` for
`OAuth2RestletException`, then `throwable.getCause()` for `OAuth2Exception`. Replace the fixed
depths with a bounded walk of the cause chain looking for either type, falling back to
`ServerException` only when neither appears at any depth.

*Why not a branch for the carrier type:* it would work, but it assumes the carrier arrives at a
known depth. Restlet wraps thrown exceptions on some paths — the existing depth-1 checks are
evidence of that — and a walk is correct regardless of how many layers sit in between. It also
means the carrier needs no special-casing: any `OAuth2Exception` wrapped by anything renders
correctly.

The walk must be bounded and must tolerate a self-referential cause, or a malformed chain turns a
rendering path into a hang.

### D3 — Six sites become checked because their contract already declares it

| Throw site | Enclosing contract | Target |
|---|---|---|
| `StatefulTokenStore.updateAuthorizationCode` | `TokenStore` declares `NotFoundException, ServerException` | `ServerException` |
| `StatefulTokenStore.updateAccessToken` | same | `ServerException` |
| `StatefulTokenStore.deleteAuthorizationCode` ×2 | same | `ServerException` |
| `StatefulTokenStore.deleteAuthorizationCode` (`CLIENT_ERROR_NOT_FOUND`) | same | `NotFoundException` |
| `OpenIdConnectToken.createJwt` | callers `getTokenId()` and `toMap()` already declare `throws ServerException` | `ServerException` |

The remaining nine — five in `OpenAMClientRegistration`'s private JWT-verification helpers,
reached through `verifyJwtIdentity` which declares nothing; `Utils.createException`; and three
service-listener constructors — use the D1 carrier.

The split rule is a contract test, not a convenience test: **use the checked type wherever the
enclosing method's published contract already permits it, and the carrier only where it does
not.** Any later use of the carrier that fails that test is a defect.

### D4 — Requirement 4 is met by splitting not-found out of two `catch` blocks

`OAuth2UserApplications` catches `ServerException | InvalidClientException | NotFoundException`
in `queryCollection` and again in `deleteInstance`, mapping all three to
`InternalServerErrorException`. Split `NotFoundException` into its own clause returning
`org.forgerock.json.resource.NotFoundException`, which `deleteInstance` already returns on its
other not-found path. Update the `@ApiError` descriptors on both methods, which currently
declare only `500`.

*Scope boundary:* `InvalidClientException` also maps to `500` there and arguably should not.
Requirement 4 constrains not-found only, so that stays as it is. Recorded, not fixed.

### D5 — `Utils.createException` returns the carrier, so its callers do not change

Its signature becomes `static UncheckedOAuth2Exception createException(...)`, still returning
rather than throwing, still logging first. Because the returned type is unchecked, every
`throw Utils.createException(...)` site in `OpenAMClientRegistration` and
`AgentClientRegistration` compiles unchanged. This is the whole reason the carrier is worth
having.

The logging call must survive the retarget; it is the only record of the underlying
`IdRepoException` or `SSOException`, which the OAuth2 error deliberately does not expose.

### D6 — Four commits, additive first

1. Add `UncheckedOAuth2Exception` and generalise the renderer walk (D1, D2). No behaviour change:
   nothing throws the carrier yet, and the walk finds what the fixed-depth checks found.
2. Retarget the six checked sites (D3). Behaviour changes: a missing authorization code starts
   reporting not-found on the OAuth2 endpoints.
3. Retarget the nine carrier sites, delete `OAuthProblemException` and the dead
   `OAuth2Utils.getRedirector`, retarget the seven test assertions.
4. The JSON administrative mapping and API descriptors (D4).

Commit 1 is safe to land alone. Commits 2 and 3 are where the wire changes.

## Risks / Trade-offs

- **The status corrections are wire-visible, and that is the point.** Failures that reported
  `400 server_error` on the OAuth2 endpoints and `500` on `/json/users/{user}/oauth2/applications`
  begin reporting `404`. Any client branching on the current values breaks. → Requirement 4's
  scenarios are the regression suite; the XUI and console consumers of the user-applications
  endpoint must be checked before commit 4.

- **The carrier is a hole in the type system and will attract misuse.** Once it exists, wrapping
  is easier than declaring. → D3's split rule is the guard, and it is mechanically checkable:
  every carrier use must sit behind a method whose contract cannot declare the checked type.

- **Retargeted tests can get weaker without failing.** The seven
  `@Test(expectedExceptions = OAuthProblemException.class)` assertions have an obvious lazy
  translation — expect the carrier — which would pass while asserting nothing about the error.
  → They must assert the wrapped `OAuth2Exception` type, and at the not-found site, that it is
  `NotFoundException` specifically.

- **The cause-chain walk could hang or mis-target.** A cycle, or an unrelated `OAuth2Exception`
  deeper in the chain than the real one, both produce wrong answers. → Bound the walk and take
  the first match, nearest the thrown exception.

- **`ServerException` reports `400` for a server failure.** RFC 6749 §5.2 pairs `server_error`
  with `500`. Changing it would alter every endpoint that already throws `ServerException`, far
  beyond this change. → Recorded here and deliberately excluded by the spec, which constrains
  overwriting rather than assignment.

## Migration Plan

Land the four commits of D6 in order within `openam-oauth2` and `openam-uma`. No released
artifact is involved and no version bump is needed, so there is no lead time and nothing to
coordinate with `fix-chf-framework-gaps`.

**Rollback.** Commits 3 and 4 revert independently. Reverting commit 2 restores the previous
flattening; reverting commit 1 is only possible after 2 and 3 are reverted, since they depend on
the carrier.

## Open Questions

- Whether `InvalidClientException` should stop mapping to `500` in `OAuth2UserApplications`
  alongside the not-found fix. Outside Requirement 4, changes no task here, and is better decided
  when the `/oauth2` endpoints move.
