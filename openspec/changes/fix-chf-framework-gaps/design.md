## Context

See `proposal.md` — Why. Requirements are in `specs/http-framework/`; this document covers only
how they are met.

Three facts about the existing code shape the approach:

1. `ContentTypeHeader.valueOf(Message)` already parses a `Content-Type` header into a media type
   with `charset`, `boundary` and other parameters split off. `Entity` uses it internally. The
   form-parsing defect exists because `Form.fromRequestEntity` compares the raw header string
   instead of reaching for it.
2. `AnnotatedMethod.findMethod` never returns `null`. When a class declares no handler for a
   verb it returns a placeholder whose `method` field is `null`. So the key set of the verb map
   in `Endpoints.from` is **not** the set of methods an endpoint serves — every endpoint maps all
   four verbs. Anything deriving `Allow` from that key set would advertise `GET, POST, PUT,
   DELETE` for every endpoint in the product.
3. `HeaderFactory.HEADER_NAMES` and `HeaderFactory.FACTORIES` are closed, hand-maintained static
   registries with a size-consistency check between them. Registering a header type there changes
   how *every* CHF consumer stores and retrieves that header, in this product and in others that
   share the artifact.

## Goals / Non-Goals

**Goals:**

- Meet the three capability specs with changes confined to `Form`, the `header/` package, and
  `Endpoints`/`AnnotatedMethod`.
- Keep the commons changes additive for consumers outside OpenAM, since the artifact is shared.
- Produce exactly one code path per observable behaviour, so the two `405` bodies cannot drift
  apart again.

**Non-Goals:**

- Any change to routing, realm resolution, audit, or endpoint code. Nothing moves off Restlet
  in this change.
- Reworking `Request.getForm()`'s merge semantics. Its leniency is now specified, not incidental.
- Making `HEAD` report an accurate `Content-Length`. Specified as unconstrained; see the spec for
  the reasoning.

## Decisions

### D1 — Fix the media-type comparison by reusing `ContentTypeHeader`, not by string surgery

`Form.fromRequestEntity` compares `ContentTypeHeader.valueOf(request).getType()` against
`application/x-www-form-urlencoded`, case-insensitively.

*Alternative rejected:* splitting the raw header on `;` and trimming. It works, but it
reimplements parsing that already exists two packages away and would drift from it — the
existing parser handles quoted parameter values and whitespace that a naive split does not.

### D2 — New headers ship as `valueOf` factories, not as registry entries

`AuthorizationHeader` and `WWWAuthenticateHeader` follow the `Header` base class and expose
static `valueOf(Message)` / `valueOf(String)` factories, exactly as `ContentTypeHeader` does.
They are **not** added to `HeaderFactory.HEADER_NAMES` or `FACTORIES`.

*Why:* registration is not additive. It changes what `headers.get("Authorization")` returns for
every consumer of the shared artifact, and routes malformed values through a factory that may
raise `MalformedHeaderException` where a generic string was previously stored without complaint.
`Entity` already demonstrates that `valueOf` gives full ergonomics with none of that reach.

*Alternative rejected:* registering them for symmetry with the other typed headers. Symmetry is
not worth a behaviour change in products we are not touching. Registration remains available
later if a consumer needs `headers.get(AuthorizationHeader.class)`.

### D3 — All `405` responses originate in one place

`Endpoints.from` gains the allowed-method set, computed from which `AnnotatedMethod` instances
resolved a real method — which requires exposing that state within the package, since
`findMethod` hides it behind a placeholder (see Context 2). `Endpoints.from` then checks whether
the requested method is served *before* invoking, and builds every `405` itself: correct status,
`Allow` header, and one body shape.

This satisfies the consistent-body requirement **by construction** rather than by copying the
body-building code into a second location. `AnnotatedMethod.invoke`'s null-method branch becomes
unreachable and is kept only as a defensive guard.

*Alternative rejected:* passing the allowed set down into `AnnotatedMethod` so it can attach
`Allow` to its own `405`. That leaves two response-building sites, which is how the two bodies
diverged in the first place.

### D4 — `HEAD` is a wrapper over the resolved `@Get`, registered as a fifth verb

The verb map gains a `HEAD` entry only when a `GET` handler resolved. It delegates to the same
`AnnotatedMethod` and clears the entity from the returned response, leaving status and headers
as the handler set them.

Consequence to be checked rather than assumed: a `HEAD` request now **executes the `@Get` handler
body**. `GET` is required to be safe, but "required" is not "audited" — see Risks.

### D5 — The commons half and the in-tree half are separate commits

Two commits in `commons` (the `Form` fix; the two header classes), each with its own tests, then
a commons release and a version bump. One commit in `openam-http` for D3 and D4, which depends on
neither and can land first.

## Risks / Trade-offs

- **The live `Endpoints.from` surface changes behaviour.** It is six production classes.
  `405`s gain `Allow` everywhere, and unmapped-verb `405` bodies stop reporting `501`. `HEAD`
  changes only where a `GET` handler exists: `AuthenticationServiceV1`/`V2` declare only `@Post`,
  so `HEAD /json/authenticate` stays `405`. → Regression coverage for the existing CHF surface is
  a required deliverable of this change, not of the migration. Consumers that parse `405` bodies
  — XUI, the console, any SDK — must be enumerated before the change lands.

- **`HEAD` now runs `GET` handler bodies.** Any `GET` handler with a side effect (a counter, a
  session touch, a log-once) would begin firing on `HEAD`. Today that is `ApiService` and
  `ApiDocsService`, both documentation endpoints, so the exposure is small — but the audit must
  also cover a trap: `AnnotatedMethod.findMethod` falls back to matching a **public method merely
  named** `get`, `post`, `put` or `delete` when no annotation is present. A resource class with an
  unannotated `get()` is dispatched as the `GET` handler and would become `HEAD`-reachable.
  → Audit all six classes for both annotated and name-matched handlers, and record the result.

- **`Allow` derived from the wrong source would advertise all four verbs everywhere.** → D3 makes
  the allowed set explicit; a test asserting `Allow: POST` on a POST-only endpoint catches the
  mistake immediately.

- **Commons release lead time gates the `Form` fix.** → Sequence the commons commits first even
  though the `openam-http` commit is ready earlier; the in-tree work does not wait on them.

- **`HEAD` responses will carry `Content-Length: 0` where Restlet reported the true length.**
  Accepted and specified. → The spec forbids conformance tests asserting a value, so this cannot
  be "fixed" into a divergence later by someone reading a failing test.

## Migration Plan

1. `commons`: `Form.fromRequestEntity` media-type fix, with tests covering the parameterised,
   cased and non-form media types from the spec.
2. `commons`: `AuthorizationHeader` and `WWWAuthenticateHeader` with `valueOf` factories and tests.
3. Release `commons`; bump the version OpenAM inherits.
4. `openam-http`: D3 and D4, with tests for `HEAD`, `Allow` and the unified `405` body, plus the
   `@Get` side-effect audit and regression coverage for `/json/authenticate`.

Step 4 does not depend on 1–3 and may land first.

**Rollback.** Step 4 is a single-module revert. Steps 1–3 roll back by pinning the previous
commons version; no OpenAM code depends on the new commons behaviour until
`neutralize-oauth2-request` consumes it.

## Open Questions

- Which commons version number carries this, and whether any other Open Identity Platform product
  wants the `Form` fix in the same release. Answerable at release time; changes no requirement,
  no approach, and no task.
