## 1. Audit and baseline (before any code changes)

- [ ] 1.1 Enumerate every production class reaching `Endpoints.from`: `ApiService`,
      `ApiDocsService`, `AuthenticationServiceV1`, `AuthenticationServiceV2`, and the
      `authenticateResource` and `dashboardResource` instances routed via `Routers.toService(...)`.
      Confirm the list is complete and record it.
- [ ] 1.2 For each class from 1.1, record which verbs it actually serves — both `@Get`/`@Post`/
      `@Put`/`@Delete` annotations **and** unannotated public methods named `get`/`post`/`put`/
      `delete`, which `AnnotatedMethod.findMethod` also dispatches. The name-matched fallback is
      the trap; a class with a plain `get()` becomes `HEAD`-reachable.
- [ ] 1.3 Audit every `GET` handler identified in 1.2 for side effects (counters, session
      touches, log-once, lazy initialisation). Record the verdict per handler. `HEAD` will begin
      invoking these; a side-effecting `GET` blocks task 4.2 until resolved.
- [ ] 1.4 Capture the current `405` response body for both paths against a running server — an
      unmapped verb (`PATCH`) and a declarable-but-undeclared verb (`GET` on a `@Post`-only
      endpoint) — as the before-baseline for task 5.
- [ ] 1.5 Enumerate consumers that parse `405` bodies from `/json/*` (XUI, console, published
      SDKs) and record whether any depends on the `code` field.

## 2. Commons — form entity parsing

- [ ] 2.1 Change `Form.fromRequestEntity` to compare `ContentTypeHeader.valueOf(request).getType()`
      against `application/x-www-form-urlencoded`, case-insensitively, per design D1.
- [ ] 2.2 Add tests for every scenario in `specs/http-framework/request-form-parsing`
      Requirement 1: bare media type, `charset=UTF-8`, differing case, unrecognised parameter,
      `application/json`, and absent `Content-Type`.
- [ ] 2.3 Add tests for Requirement 2: a parameter present in both query and entity is resolvable
      from each view independently, and the combined view orders the query value first.
- [ ] 2.4 Add tests for Requirement 3: the combined view over an unreadable entity returns the
      query half without error; the entity-only view propagates the failure; a well-formed empty
      entity yields no parameters and no error.
- [ ] 2.5 Verify no existing commons test asserts the old strict media-type behaviour; if one
      does, confirm it encoded the defect rather than a contract, and update it.

## 3. Commons — authentication headers

- [ ] 3.1 Add `AuthorizationHeader` extending `Header`, with static `valueOf(Message)` and
      `valueOf(String)` factories. Do **not** register it in `HeaderFactory.HEADER_NAMES` or
      `FACTORIES` — see design D2.
- [ ] 3.2 Add `WWWAuthenticateHeader` the same way, emitting RFC 7235 wire form.
- [ ] 3.3 Add tests for `specs/http-framework/http-authentication-headers` Requirement 1: valid
      credentials, colon in the secret, empty secret, empty identifier, no colon, invalid base64,
      a `Bearer` header, and an absent header.
- [ ] 3.4 Add tests for Requirement 2: the exact `Bearer` wire form, order preservation, quoting
      and escaping, and a scheme with no parameters emitting the bare scheme.
- [ ] 3.5 Confirm the secret is exposed in a form the caller can overwrite in place, and that a
      test demonstrates clearing it.

## 4. openam-http — method dispatch

- [ ] 4.1 Expose, within the annotations package, whether an `AnnotatedMethod` resolved a real
      handler, so the allowed-method set can be computed. `findMethod` returns a placeholder
      rather than `null`, so the verb map's key set must not be used for this.
- [ ] 4.2 Add the `HEAD` entry to the verb map, delegating to the resolved `GET` handler and
      clearing the entity from the returned response, per design D4. Blocked by 1.3.
- [ ] 4.3 Move all `405` generation into `Endpoints.from` per design D3: check whether the
      requested method is served before invoking, and build the response there with status,
      `Allow` and body. Leave `AnnotatedMethod.invoke`'s null-method branch as a defensive guard.
- [ ] 4.4 Add tests for `specs/http-framework/annotated-endpoints` Requirement 1: declared method
      invoked, undeclared method rejected, `X-HTTP-Method-Override` on `POST` honoured.
- [ ] 4.5 Add tests for Requirement 2: `HEAD` on an endpoint declaring `GET` returns the `GET`
      status and handler-set headers with no body; `HEAD` on an endpoint without `GET` returns
      `405`; a failing `GET` reports the same status under `HEAD` with no body. Assert **no**
      particular `Content-Length` — the spec forbids it.
- [ ] 4.6 Add tests for Requirement 3 that would fail if `Allow` were derived from the verb map's
      key set: a `POST`-only endpoint advertises exactly `POST`, a `GET`-only endpoint advertises
      `GET` and `HEAD`, and a `GET`+`POST` endpoint advertises `GET`, `HEAD` and `POST`.
- [ ] 4.7 Add tests for Requirement 4: both `405` paths report code `405` and produce the same
      body shape.

## 5. Regression coverage for the existing CHF surface

- [ ] 5.1 Add regression tests for `/json/authenticate` confirming `POST` is unchanged, `HEAD`
      still returns `405` because only `@Post` is declared, and the `405` now carries `Allow: POST`.
- [ ] 5.2 Add regression tests for `ApiService` and `ApiDocsService` confirming `HEAD` now returns
      the `GET` status with no body, and that `GET` is unchanged.
- [ ] 5.3 Diff every `405` body against the 1.4 baseline and confirm each difference is one the
      specs require. Any other difference is a defect.
- [ ] 5.4 If 1.5 found a consumer depending on the `code` field of a `405` body, coordinate or
      document the break before this lands.

## 6. Release and integration

- [ ] 6.1 Land tasks 2 and 3 as two separate commons commits, each with its own tests, per
      design D5.
- [ ] 6.2 Land task 4 as a single `openam-http` commit. It does not depend on tasks 2, 3 or 6.1
      and may land first.
- [ ] 6.3 Release commons and record the version. Resolve the design's open question — whether
      any other Open Identity Platform product wants the `Form` fix in the same release.
- [ ] 6.4 Bump the commons version OpenAM inherits, and confirm the full reactor builds with
      `-am` so no stale same-version SNAPSHOT is resolved from `~/.m2`.
- [ ] 6.5 Run `openspec validate fix-chf-framework-gaps --strict` and confirm every spec scenario
      has a corresponding test.
