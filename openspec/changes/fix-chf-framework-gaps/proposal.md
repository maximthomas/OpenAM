## Why

Migrating OpenAM's 22 Restlet-served routes onto CHF means CHF must cover what Restlet
covered. In four places it does not, and each gap changes **observable HTTP behaviour** —
a form body that silently stops parsing, a `405` where Restlet returned `200`, a `405`
whose JSON body claims `501`, and challenge headers with no typed support at all.

These are not migration details. They are defects in framework code that Open Identity
Platform maintains (`commons/http-framework` and the in-tree `openam-http`), and the
Restlet implementation that currently masks them is deleted at the end of the migration —
so the divergences would ship as silent regressions with no oracle left to catch them.
Fixing them first, with their own tests and their own commits, keeps framework behaviour
out of the migration's blame surface and unblocks every endpoint change that follows.

## What Changes

**`commons` — `org.openidentityplatform.commons.http-framework:core`**

- `Form.fromRequestEntity` compares the **full raw `Content-Type` header** against
  `"application/x-www-form-urlencoded"`, so `application/x-www-form-urlencoded; charset=UTF-8`
  is not recognised and the body is dropped. Restlet compares media types with parameters
  ignored and accepts it. Match on media type, ignoring parameters.
  A token request from such a client currently loses `grant_type`, `code` and `client_id`
  under CHF while working under Restlet.
- `Request.getForm()` — the convenient, discoverable entry point — merges query parameters
  and entity parameters into one `Form` with no way to tell which side a value came from.
  OAuth2 requires that distinction (`OAuth2Request.getParameter` gives query priority over
  body; RFC 6749 §2.3.1 forbids credentials in the query string). No new API is needed:
  `Form.fromRequestQuery(Request)` and `Form.fromRequestEntity(Request)` are already public
  and give exactly the two halves. The requirement is that callers needing the distinction
  use them, and that `fromRequestEntity` be correct — see the media-type defect above, which
  matters more once it is the only entity-parsing path in use.
- `Request.getForm()` swallows the `IOException` from entity parsing and returns an empty
  form, converting a parse failure into a silently wrong answer. Surface the failure.
- No typed `Authorization` or `WWW-Authenticate` header support exists. Restlet's
  `ChallengeResponse`/`ChallengeRequest` back OAuth2 client authentication and Bearer error
  responses, whose exact quoting and parameter order are observable contract. Add both.

**`openam-http` — in-tree, `org.forgerock.openam.http.annotations`**

- `Endpoints.from` maps only `DELETE`/`GET`/`POST`/`PUT`, so `HEAD` falls through to `405`.
  Restlet's `ServerResource` answers `HEAD` by invoking the `GET` method and dropping the
  entity (RFC 9110 §9.3.2). Dispatch `HEAD` to `@Get` and return no body.
- `405` responses carry no `Allow` header. RFC 9110 §15.5.6 requires one listing the
  resource's supported methods.
- **Two different `405` paths produce two different bodies**, and one contradicts its own
  status line: `Endpoints.java:66` sets status `405` but writes a `NotSupportedException`
  entity whose `code` field is `501` (`ResourceException.NOT_SUPPORTED = 501`), while
  `AnnotatedMethod.java:72` writes a correct `405` body. Unify them on the correct one.

Out of scope, deliberately: `Entity.getString()` falls back to ISO-8859-1 per RFC 2616 §3.7.1,
a default RFC 7231 removed. Percent-encoded form bodies are unaffected because `%XX` is ASCII
and `Uris.formDecodeParameterNameOrValue` re-decodes as UTF-8; only literal non-ASCII bytes in
a charset-less body are mangled. Changing a documented default across all CHF consumers is a
larger blast radius than the defect warrants. Recorded, not fixed.

## Capabilities

### New Capabilities

- `http-framework/request-form-parsing`: how request parameters are read from the query
  string and from an `application/x-www-form-urlencoded` entity — media-type matching,
  origin distinction between query and entity, and failure behaviour on unparseable bodies.
- `http-framework/annotated-endpoints`: HTTP method dispatch for annotated endpoint POJOs —
  which verbs are served, `HEAD` semantics, and the status line, `Allow` header and body of
  a `405` response.
- `http-framework/http-authentication-headers`: parsing `Authorization` credentials and
  emitting `WWW-Authenticate` challenges, including the wire form of each.

### Modified Capabilities

None — `openspec/specs/` is currently empty; this change introduces the first specs.

## Impact

**Code.** `commons/http-framework/core` (`Form`, `Request`, `header/`) and in-tree
`openam-http` (`Endpoints`, `AnnotatedMethod`). No OpenAM endpoint moves and no route
changes; this change is behaviour-only in the substrate.

**Blast radius beyond the migration — this is the main risk.** The `openam-http` changes
affect every endpoint already built on `Endpoints.from`, not just future ones:

- `openam-core-rest` — `AuthenticationServiceV1` and `V2`, i.e. **`/json/authenticate`**
- `openam-rest/Routers.java` — the generic `/json/*` route builder (3 call sites)

The surface is six production classes. `HEAD` changes only where a `GET` handler exists, which
narrows the impact considerably: `AuthenticationServiceV1` and `V2` declare only `@Post`, so
`HEAD /json/authenticate` stays `405` and merely gains `Allow: POST`. Only `ApiService` and
`ApiDocsService` — the API documentation endpoints — begin answering `HEAD`. Every endpoint's
`405` bodies change shape where they previously reported `501`.

Regression coverage for the existing CHF surface is required, independent of anything
Restlet-related.

**Dependencies and sequencing.** `commons` ships as a released artifact and `openam-http/pom.xml`
declares it without a version (inherited `dependencyManagement`), so the commons fixes need a
commons release and a version bump before OpenAM can consume them. That lead time is the reason
this change goes first. The `openam-http` fixes have no such constraint and can land immediately.

The two halves should land as separate commits with separate tests for this reason, even though
they are planned as one change.

**Downstream changes.** `neutralize-oauth2-request` depends on the `fromRequestEntity`
media-type fix and on `Authorization` header support for its CHF-side implementation; it can
begin against Restlet before those land. `decouple-oauth2-errors-from-restlet` is independent
of this change.
