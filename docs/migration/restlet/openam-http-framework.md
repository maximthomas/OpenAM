# openam-http framework fixes (F1–F4) — prerequisite to phase 3c-2

Execution plan for four defects in **`openam-http`'s annotation-driven endpoint framework**
(`org.forgerock.openam.http.annotations`), fixed **before** [phase-3c-2-error-layer.md](phase-3c-2-error-layer.md)
because 3c-2's design depends on the outcome. Parent tracker: [plan.md](plan.md); reusable CHF patterns:
[chf-patterns.md](chf-patterns.md); test layers: [docs/test-infrastructure.md](../../test-infrastructure.md).
Written 2026-07-21; branch `features/restlet-migration`. All facts verified against the tree on 2026-07-21.

## Context

Phase 3c-2's research turned up three framework defects and, per the plan's own instincts, designed **around**
all three: a filter that synthesises bodies the framework should have written, a "handlers must catch
everything" rule, and a value type whose central design constraint was *"a thrown exception is swallowed into a
bodiless 500"*. A fourth (**F4**) surfaced only once the ownership question was asked properly — it had been
filed under commons and written off.

**That framing was wrong, and it was wrong for a reason worth writing down: `openam-http` is ours and it is
in-tree.** `Endpoints`, `AnnotatedMethod` and `@ExceptionHandler` live at
`openam-http/src/main/java/org/forgerock/openam/http/annotations/` — not in a vendored dependency. Fixing them
is an ordinary commit in this repository. **Decided 2026-07-21: fix the framework, then build 3c-2 on the fixed
framework.**

> **The cost boundary that decides what is in scope here.** `openam-http` is in-tree ⇒ cheap. Commons
> `http-framework` (`Entity`, `ContentTypeHeader`, `Status` — artifact
> `org.openidentityplatform.commons.http-framework:core:3.1.1`) is also ours but ships as a released artifact,
> so changing it costs a release cycle and a version decision here — a well-trodden path, not a wall
> ([framework-ownership.md](../../framework-ownership.md#upstreaming-to-commons)). **F1–F4 are all in-tree.**
>
> **Re-classified 2026-07-21 (F4).** An earlier draft filed the ISO-8859-1 body trap wholly under commons and
> declared it out of scope. That was half right.
> [3c-1 finding 3](phase-3c-1-renderer.md#3--content-type-texthtml-charsetutf-8-is-implicit-today--and-chfs-default-is-iso-8859-1)
> describes **two** paths into it, and only one is commons':
> - a **`String`-returning `Endpoints.from` handler** → `ResponseCreator.apply:171` →
>   `new Response(OK).setEntity(content)` with no `Content-Type`, **because this module never sets one** —
>   in-tree, and now **F4**;
> - a caller invoking `Entity.setString` directly with no `Content-Type` — genuinely commons, and the one
>   item here worth an upstream fix plus release. It blocks nothing: the `getBytes(UTF_8)` + explicit-header
>   recipe stays correct either way.

**Outcome:** handler methods may `throw`, and the framework turns the throw into a response — either through
the endpoint's own `@ExceptionHandler` method or through a well-formed CREST 500 — and a handler that returns
text gets the encoding it declared instead of silent ISO-8859-1. This is the mechanism
Restlet's `doCatch` provided and whose absence Phase 5 was otherwise going to hand-roll per endpoint.

## Scope & sizing (decided)

**Four fixes, ~150 LOC main, ~520 LOC test — and the package's first tests.**

- **`openam-http/src/main/java/org/forgerock/openam/http/annotations/`** — `AnnotatedMethod.java`,
  `Endpoints.java`, `ExceptionHandler.java`, `Produces.java` (read, not edited). Existing ForgeRock-origin files: keep the package and the CDDL
  header, add `Portions copyright 2026 3A Systems LLC.` (the `oauth2/restlet/ExceptionHandler.java:15`
  precedent). The `org.openidentityplatform.openam.*` + no-ForgeRock-copyright convention in
  [decisions.md](decisions.md) governs **new** classes; these are edits to existing ones.
- **No pom change** — testng, assertj, mockito and `commons.guice:test` are already test-scoped on
  `openam-http` (`openam-http/pom.xml:64-88`).
- **No new dependency direction.** `InternalServerErrorException` (CREST) is already imported by
  `Endpoints.java:30`.
- **Deletes nothing.**

## Key research findings

### 1. ⚠ The `annotations` package has **zero tests**

`openam-http/src/test` contains exactly four classes — `GuiceHandlerTest`, `HttpGuiceModuleTest`,
`HttpRouterProviderTest`, `OpenAMHttpApplicationTest`. **None of them touches `Endpoints` or
`AnnotatedMethod`.** Every behaviour described below is unguarded today.

⇒ **Characterize before changing** (3b's as-built lesson #2, which cost 3/4 failing assumptions when skipped).
Step 1 of the execution order writes tests that pin the framework as it is *now* — including the parts F1–F4
will change — so that the diff in behaviour is visible in the test diff rather than inferred.

### 2. F1 — a handler that throws yields **500 with an empty body**

`AnnotatedMethod.java:83-94`, both catch branches:

```java
} catch (IllegalAccessException e) {              // :86-89
    DEBUG.warning("Could not invoke method: ", e);
    return newResultPromise(new Response(Status.INTERNAL_SERVER_ERROR)
            .setCause(new IllegalStateException("Cannot access the annotated method: " + method.getName(), e)));
} catch (InvocationTargetException e) {           // :90-94
    DEBUG.warning("Could not invoke method: ", e);
    return newResultPromise(new Response(Status.INTERNAL_SERVER_ERROR)
            .setCause(new IllegalStateException("Exception from invocation should be handled by promise", e)));
}
```

**No `setEntity`.** The client gets a bodiless 500. Two consequences already documented elsewhere:

- [chf-patterns.md](chf-patterns.md) §2's claim that an uncaught `Throwable` yields a CREST
  `InternalServerErrorException` map is **only** true for throwables escaping `AnnotatedMethod.invoke` itself
  and reaching `Endpoints.java:73-78`.
- Because `Entity.setJson` is what writes `Content-Type` (bytecode-verified), this response has **no
  `Content-Type` header at all** — which is why `XacmlXmlErrorFilter` passes it through unrewritten (its
  `catch (IOException) → return response`) and why 3c-2's filter needed a carefully ordered empty-entity rule.

**It is live today, not hypothetical:** `ApiService.java:84` declares
`public Response handle(@Contextual Request request) throws URISyntaxException, MalformedHeaderException`.

### 3. F2 — `@ExceptionHandler` is a declaration and nothing else

`ExceptionHandler.java:19-24` in full:

```java
/**
 * Mark a method that handles exceptions thrown by a service method and turns them into a response.
 * @since 13.0.0
 */
public @interface ExceptionHandler {
}
```

- **No `@Retention`** ⇒ defaults to `RetentionPolicy.CLASS` ⇒ **invisible to reflection**. Even a correctly
  annotated method could not be found at runtime.
- **No `@Target`** ⇒ applicable anywhere.
- **Zero usages** — grep-confirmed 2026-07-21 across the whole tree; the only hit is its own declaration.
- Neither `Endpoints` nor `AnnotatedMethod` ever looks for it.

So the framework advertises exactly the feature Phase 5 needs and does not implement it. The javadoc even
states the intended contract precisely.

### 4. F3 — a `Promise` return type wires up and then detonates

`AnnotatedMethod.checkMethod:138-150` accepts three return shapes; `Promise` takes the first branch:

```java
if (Promise.class.equals(method.getReturnType())) {
    resourceCreator = new PromisedResponseCreator();
```

and `PromisedResponseCreator.apply:200-203` is:

```java
@Override
public Promise<Response, NeverThrowsException> apply(Object o) {
    throw new UnsupportedOperationException("to be implemented");
}
```

The failure is **deferred to request time**: `Endpoints.from` succeeds, the route mounts, and the endpoint
throws on its first request. Contrast `ResponseCreator.forType:192`, which throws
`IllegalArgumentException("Unsupported response type: …")` at **wiring** time — the framework already has the
better convention and this path does not follow it.

`Promise<Response, NeverThrowsException>` is the native CHF `Handler` return type; Phase 5's token and
authorize handlers will want it (token exchange, LDAP round-trips).

### 5. F4 — `@Produces` is live-but-ignored, and that is why `String` returns are ISO-8859-1

`Produces.java:28-31` is **correctly formed** — unlike `@ExceptionHandler` it has both meta-annotations:

```java
@Target(ElementType.METHOD)
@Retention(RetentionPolicy.RUNTIME)
public @interface Produces {
```

…and it is **never read**. Grep, 2026-07-21: zero references to `Produces`/`Consumes` in `AnnotatedMethod` or
`Endpoints`, and **zero imports of `org.forgerock.openam.http.annotations.Produces` anywhere in the tree**
(every `@Produces` hit in the repo is `jakarta.ws.rs.Produces`, a different annotation on JAX-RS resources).
So the module declares "the content type of the response", and then never sets a content type.

That is exactly the missing input for the `String`-return trap. `ResponseCreator.apply:171`:

```java
return newResultPromise(new Response(content == null ? Status.NO_CONTENT : Status.OK).setEntity(content));
```

`setEntity(String)` → `Entity.setString` → `getBytes(cs(null))` → **ISO-8859-1**, with no `Content-Type` on
the response at all ([3c-1 finding 3](phase-3c-1-renderer.md#3--content-type-texthtml-charsetutf-8-is-implicit-today--and-chfs-default-is-iso-8859-1)).
`chf-patterns.md` §2's standing advice — *"Phase 5a/5b handlers must return `Response`"* — is a **workaround
for this**, and it is a rule every future endpoint author has to know and remember.

⇒ The commons-side `Entity.setString` default is a real defect for direct callers and worth an upstream fix,
but **this module never gave it a chance**: it owns a `@Produces` annotation designed to say what the content
type is. Fixing it here removes the trap for every `Endpoints.from` endpoint, in-tree, today.

### 6. Blast radius — every consumer of the annotations package

`Endpoints.from` call sites (grep, 2026-07-21):

| Consumer | Endpoint surface |
|---|---|
| `Routers.java:1037,1048,1059` (openam-rest) | every `service`-mode route |
| `CoreRestAuthenticationGuiceModule.java:76-77` | **`/json/authenticate`** v1 + v2 |
| `XacmlHttpRouteProvider.java:104` | `/xacml/policies` (Phase 2) |

Annotated handler classes: `AuthenticationServiceV1`/`V2`, `ApiService`, `ApiDocsService`,
`XacmlServiceHandler`.

⇒ F1 changes a response body on **`/json/authenticate`** and **`/xacml`** — on the bug path only, but really.
See [D-F1](#d-f1--f1s-body-shape-crest-matching-endpointss-own-catch) and Verification.

## Work items

### F1 — a thrown exception gets a body

Restructure `AnnotatedMethod.invoke` so that **everything** after the null-method check is inside one try, and
every failure routes through a single private `handleException(Context, Request, Throwable)`:

```java
Promise<Response, NeverThrowsException> invoke(Context context, Request request) {
    if (method == null) { … unchanged 405 … }
    try {
        Object[] args = new Object[numberOfParameters];
        if (requestParameter > -1) { args[requestParameter] = request; }
        for (ContextParameter parameter : contextParameters) {
            args[parameter.index] = parameter.getContext(context);      // was OUTSIDE the try
        }
        return responseAdapter.apply(method.invoke(requestHandler, args));
    } catch (InvocationTargetException e) {
        return handleException(context, request, e.getCause());          // unwrap — the handler's own throw
    } catch (Throwable t) {
        return handleException(context, request, t);
    }
}
```

Two deliberate changes beyond adding a body:

- **`parameter.getContext(context)` moves inside the try.** Today a missing context throws *before* the try and
  escapes to `Endpoints.java:73`, so identical failures produce different bodies depending on which line threw.
  One entry point, one shape.
- **`catch (Throwable)`** replaces `catch (IllegalAccessException)`, which also covers `responseAdapter.apply`
  failures. `Endpoints.java:71-78`'s outer catch **stays** as a last-resort net (it still guards
  `methods.get`/`getMethod`), but should now be unreachable from handler code.

`handleException` without F2 is: log at `DEBUG.warning`, then

```java
Response response = new Response(Status.INTERNAL_SERVER_ERROR);
response.setEntity(new InternalServerErrorException(t).toJsonValue().getObject());
response.setCause(t);                                   // keep the cause — it is free and aids debugging
return newResultPromise(response);
```

### F2 — make `@ExceptionHandler` real

**The annotation**, corrected to what its javadoc always claimed:

```java
@Retention(RetentionPolicy.RUNTIME)
@Target(ElementType.METHOD)
public @interface ExceptionHandler {
}
```

**Method shape** — deliberately the *same* shape as the verb methods, reusing `checkMethod`'s existing
reflection machinery rather than inventing a second convention:

- exactly **one** non-`@Contextual` parameter, whose type is assignable to `Throwable` — the exception;
- optionally `@Contextual Context` and/or `@Contextual Request` parameters, resolved by the existing
  `ContextParameter` code;
- return type from the same set as verb methods — `Response`, `Promise<Response, NeverThrowsException>`
  (F3), `String`, `byte[]`, `Void`, `JsonValue` — through the same `resourceCreator` dispatch.

```java
@ExceptionHandler
public Response onOAuth2Error(OAuth2Exception e, @Contextual Request request) { … }
```

**Discovery and matching:**

- Scanned **once**, in `Endpoints.from(Object)`, alongside the four `findMethod` calls — never per request.
  The resolved table is passed into each `AnnotatedMethod`.
- Dispatch picks the **most specific assignable** parameter type for the thrown exception. Assignability, not
  identity — the same rule as 3c-2's `NEVER_REDIRECT`, and for the same reason (`InvalidClientAuthZHeaderException`
  extends `InvalidClientException`; `OAuth2ProviderNotFoundException` extends `NotFoundException`).
- **Ambiguity is a wiring-time error.** Two `@ExceptionHandler` methods with types neither of which is a
  subtype of the other, both matching, cannot be ordered ⇒ throw `IllegalArgumentException` from
  `Endpoints.from`, matching `ResponseCreator.forType:192`'s convention (finding 4). Detect what is
  detectable statically (duplicate parameter types) at wiring time; detect the genuinely ambiguous pair at
  dispatch time and fail the request as a 500 rather than guessing.
- **No match ⇒ F1's default 500.** An endpoint annotating only `OAuth2Exception` keeps sane behaviour for a
  stray `NullPointerException`.

**Recursion guard, non-negotiable:** if the `@ExceptionHandler` method *itself* throws, log both throwables and
return F1's default 500. **Never re-enter dispatch.** An error mapper that faults on its own error path is how
a 500 becomes a stack overflow.

### F3 — implement the `Promise` return

```java
@Override
public Promise<Response, NeverThrowsException> apply(Object o) {
    return o == null ? newResultPromise(new Response(Status.NO_CONTENT))
                     : (Promise<Response, NeverThrowsException>) o;
}
```

…plus the **wiring-time** check that `checkMethod` should have had. Erasure hides the type arguments from
`method.getReturnType()`, so validate `method.getGenericReturnType()`: require
`Promise<Response, NeverThrowsException>` exactly, and throw
`IllegalArgumentException("Unsupported response type: …")` otherwise. Without it, a handler declaring
`Promise<Response, ResourceException>` compiles, mounts, and fails with a `ClassCastException` at request time
— trading one deferred detonation for another.

The `null` case mirrors `ResponseCreator.apply:171`'s `content == null → NO_CONTENT`.

### F4 — honour `@Produces`, and encode text bodies explicitly

In `checkMethod`, read `@Produces` off the method (falling back to a default per return type) and hand it to
`ResponseCreator`, which then:

```java
String contentType = producesValue != null ? producesValue : defaultFor(returnType);  // text/plain; charset=UTF-8
response.getHeaders().put(ContentTypeHeader.NAME, contentType);
response.setEntity(content instanceof String
        ? ((String) content).getBytes(charsetOf(contentType))       // never the cs(null) fallback
        : content);
```

- **`String` returns**: `Content-Type` set, body encoded with the charset that header actually declares —
  the same header-then-`getBytes` discipline `chf-patterns.md` §6 mandates for hand-built responses.
- **Default when `@Produces` is absent**: `text/plain; charset=UTF-8`. Today the answer is "no header at all,
  ISO-8859-1 bytes", so any explicit default is an improvement; UTF-8 matches the rest of the stack, and
  `@Produces("text/html; charset=UTF-8")` is available when a handler means HTML.
- **`JsonValue`/POJO returns are untouched** — `setJson` already writes
  `application/json; charset=UTF-8` and would clobber anything set first. If `@Produces` is present *and*
  disagrees with `application/json`, that is a wiring-time `IllegalArgumentException`: better to reject the
  contradiction than to let `setJson` silently win.
- **`byte[]`/`Void` returns**: honour `@Produces` if present, otherwise leave the response alone (no charset
  question arises).

`Consumes.java` is left alone. It is equally unread, but request-side negotiation has no consumer asking for
it and inventing one is not this commit's job — noted in the as-built as a known dead annotation.

## Decisions

<a id="d-f1--f1s-body-shape-crest-matching-endpointss-own-catch"></a>
### D-F1 — F1's body shape: **CREST**, matching `Endpoints`'s own catch

`new InternalServerErrorException(t).toJsonValue().getObject()` — byte-identical to what
`Endpoints.java:76` already produces for the sibling path, so the framework emits **one** 500 shape instead of
two. It also means `XacmlXmlErrorFilter` and 3c-2's `OAuth2ErrorFilter` already know how to rewrite it, with
no new discrimination rule.

*Disclosure note:* `ResourceException.toJsonValue()` emits `{code, reason, message}`, and `message` is
`t.getMessage()`. That is unchanged exposure, not new — `Endpoints:76` has always done it for the outer path,
and `setIncludeCause` stays **false**, so no stack trace reaches the client.

<a id="d-f2--the-annotation-is-fixed-not-replaced"></a>
### D-F2 — Fix the annotation rather than invent a new one

`@ExceptionHandler` is unused (finding 3), so there is no compatibility argument either way; the choice is
about where the concept lives. Fixing it keeps one framework with one documented convention, and its javadoc
already describes the intended semantics exactly. A new annotation in
`org.openidentityplatform.openam.*` would leave a broken lookalike in the same package for the next reader to
find — [3c-2](phase-3c-2-error-layer.md)'s finding 7 already flagged it for deletion in Phase 8, which would
have thrown away a working name.

<a id="d-f3--restlets-docatch-shape-is-restored-deliberately"></a>
### D-F3 — Restoring `doCatch`'s shape is the point, not a regression

Phase 3c-2 argued that CHF handlers must **return** errors, never throw, and made `OAuth2Error` a value type
"because a thrown exception is swallowed into a bodiless 500". With F1+F2 that premise is gone. Handlers may
throw the **existing** `OAuth2Exception` hierarchy — no new throwable type, and no re-import of the
`OAuth2RestletException` ctor trap, because the exceptions being thrown are the ones the core already throws.

**`OAuth2Error` survives unchanged as a value type.** It is what the `@ExceptionHandler` method *builds* on its
way to a `Response`; it was never the thing that needed throwing. 3c-2 loses a constraint, not a class.

<a id="d-f4--no-behaviour-flag"></a>
### D-F4 — No opt-in flag

F1 changes a response body for `/json/authenticate` and `/xacml` on the uncaught-exception path. A flag was
considered and rejected: the current behaviour is a bodiless 500 that no client can act on, the new behaviour
is the shape the sibling code path already emits, and a flag would mean shipping the defect indefinitely
behind a switch nobody sets. The characterization tests (finding 1) make the change visible in review, which
is the control that matters.

## Tests

### A. Characterization first — `EndpointsTest` / `AnnotatedMethodTest`

`openam-http/src/test/java/org/forgerock/openam/http/annotations/`. **Written and committed against unmodified
code**, pinning today's behaviour including the parts F1–F3 change. TestNG + AssertJ, no Guice
(`Endpoints.from(Object)` takes a plain instance), no container:

```java
Handler h = Endpoints.from(new TestHandler());
Response r = h.handle(new RootContext(), new Request().setMethod("GET").setUri("/"))
              .getOrThrowUninterruptibly();
```

Rows, all currently unguarded:

- verb dispatch for `GET`/`POST`/`PUT`/`DELETE`; `X-HTTP-Method-Override` on POST (`Endpoints:111-118`).
- **the two distinct 405 bodies** — unmapped verb (`HEAD`/`OPTIONS`/`PATCH`) → `Endpoints:66-67` →
  `code: 501`; mapped verb with no annotated method → `AnnotatedMethod:71-75` → `code: 405`.
  `findMethod:120` never returns null, which is what makes both reachable.
- every supported return type: `Response`, `String`, `byte[]`, `Void`, `JsonValue`, and `null → NO_CONTENT`.
- unsupported return type → `IllegalArgumentException` at `Endpoints.from`, **not** at request time.
- **the F1 baseline: a throwing handler yields 500, empty entity, `getCause() != null`, no `Content-Type`.**
  This row is deleted-and-replaced by F1's row — that diff *is* the change under review.
- `@Contextual Context` / `Request` injection, and a missing context today escaping to `Endpoints:73-78`.

### B. The fixes

- **F1** — throwing handler → 500 with `{code: 500, reason, message}`, `Content-Type: application/json`,
  cause still set. Checked *and* unchecked throwables. A handler whose `@Contextual` context is missing now
  produces the **same** shape (the moved `getContext` call).
- **F2** — matched handler wins; **most-specific** wins when two could match; unmatched throwable falls back
  to F1's 500; `@Contextual` params inject into the exception handler; every supported return type works from
  an exception handler; **the exception handler itself throwing yields F1's 500 and does not recurse**
  (assert exactly one dispatch via a counter). Also: the annotation is `RUNTIME`-retained —
  `assertThat(ExceptionHandler.class.getAnnotation(Retention.class).value()).isEqualTo(RUNTIME)`, the one
  assertion that fails if someone drops the meta-annotation and silently re-inerts the feature.
- **F4** — a `String`-returning handler with a **non-ASCII** body round-trips as UTF-8 and carries a
  `Content-Type` (⚠ an ASCII fixture passes under the bug — this is 3c-1's R-3c.4 in the framework, and the
  test must use a non-ASCII value to mean anything); `@Produces("text/html; charset=UTF-8")` is honoured;
  `@Produces` contradicting a `JsonValue` return → `IllegalArgumentException` at `Endpoints.from`.
- **F3** — a `Promise`-returning handler works end to end; `Promise<Response, SomeOtherException>` →
  `IllegalArgumentException` **at `Endpoints.from`**; a `Promise` handler that throws synchronously routes to
  F2/F1.

### C. Consumer regression — the existing suites are the guard

No new ITs. `XacmlRouterIT` (openam-entitlements) already drives `Endpoints.from` through a real route and
asserts the 405 path; the authn suites cover `/json/authenticate`. They must stay green, and where F1 changes
what they observe, the change is inspected rather than accommodated.

### Considered and rejected

- **An e2e leg** — nothing here is reachable by an OAuth2 e2e request, and the consumer endpoints
  (`/json/authenticate`, `/xacml`) already have coverage at the right layer.
- **A compatibility flag** — [D-F4](#d-f4--no-behaviour-flag).
- **Fixing `Entity.setString`'s ISO-8859-1 fallback here** — that call lives in commons `http-framework`
  (tier 2). **F4 removes the `Endpoints.from` route into it**, which is the only path this migration touches;
  the direct-caller defect remains real for other consumers and is worth an upstream fix plus release
  ([framework-ownership.md](../../framework-ownership.md#upstreaming-to-commons)) — **filed, not blocking**,
  since `getBytes(UTF_8)` + an explicit header is correct under either version.

## Verification

1. `mvn -o -pl openam-http test` — the package's first tests; record the new baseline (openam-http has
   **no** prior annotations coverage, so this number starts from whatever the four existing suites report).
2. `mvn -o -pl openam-http install -DskipTests` → `mvn -o -pl openam-rest,openam-core-rest,openam-entitlements test`
   — the three consumers from finding 5. **`openam-entitlements` must stay green including `XacmlRouterIT`**;
   run `verify`, not `test`, or the IT is skipped ([test-infrastructure.md](../../test-infrastructure.md)'s
   failsafe trap).
3. `mvn install -DskipTests` (whole reactor). **Doclint is fatal** (`-Xdoclint:all,-missing` +
   `failOnWarnings`, commit `3c45ff8d53`) and this commit adds javadoc to a framework class.
4. Grep gate: `grep -rn "to be implemented" openam-http/src/main` → **0**.
5. CI: `build-maven`'s 9 legs run `verify`.

## Effect on phase 3c-2

3c-2 is **not** invalidated — it loses a constraint and two workarounds:

| 3c-2 item | Effect |
|---|---|
| `OAuth2Error` as a value type | **unchanged** — it is what the `@ExceptionHandler` builds ([D-F3](#d-f3--restlets-docatch-shape-is-restored-deliberately)) |
| R-3c.9 "`OAuth2Error` re-grows a `Throwable`" | **retired** — handlers throw the existing `OAuth2Exception`s; nothing needs a new throwable |
| `OAuth2ErrorFilter` rule 1 (synthesize on empty entity) | **deleted** — F1 guarantees a body |
| R-3c.14 (filter rule ordering) | **retired** with rule 1 |
| `OAuth2ErrorFilter` rules 2–5 | **kept** — the framework's own 405/501 CREST bodies still need [D4](phase-3c-2-error-layer.md#d4--error-shape-unification-fix)'s unification |
| `OAuth2ErrorRouteCompositionIT` | **kept, and more valuable** — it now proves the fixed framework composes as believed |
| chf-patterns §2 "handlers must catch everything" | demoted from requirement to style preference |
| chf-patterns §2 "handlers must return `Response`, never `String`" | demoted likewise — **F4** makes a `String` return safe. Returning `Response` stays the house style for anything that needs a status or headers |
| Phase 5b's per-endpoint catch blocks | collapse into one `@ExceptionHandler` per handler class |

## Risks

| # | Risk | Detail | Mitigation |
|---|---|---|---|
| **R-F.1** | **F1 regresses a consumer that depends on the empty body** | `/json/authenticate` and `/xacml` see a body where there was none. A client asserting `content-length: 0` on a 500 would break — but so would any client relying on an unhandled server bug | Characterization tests first (finding 1); consumer suites in Verification step 2; the path is by definition an unhandled exception |
| **R-F.2** | **`@ExceptionHandler` dispatch becomes a second routing system** | Type-based dispatch invites scope creep — ordering, inheritance, per-verb overrides, wildcards | Deliberately minimal: one exception parameter, most-specific-assignable, no ordering annotations. Anything more is a later decision with its own plan |
| **R-F.3** | **The exception handler faults on the error path** | An `@ExceptionHandler` that throws could recurse or mask the original failure | Hard recursion guard (work item F2); test asserts exactly one dispatch and that **both** throwables are logged |
| **R-F.4** | **The `RUNTIME` retention is silently dropped again** | The feature re-inerts with no test failure — exactly how it got into this state | Explicit meta-annotation assertion (Tests §B), not a behavioural test |
| **R-F.6** | **F4 changes an existing endpoint's `Content-Type`** | Any current `String`-returning handler starts sending `text/plain; charset=UTF-8` where it sent no header. A client sniffing the body could behave differently | Enumerate `String`-returning handlers in the characterization pass and check each; `@Produces` gives any of them an explicit opt-out |
| **R-F.7** | **F4's charset fix is asserted with ASCII fixtures** | Every template and most test data in this repo is ASCII, and ISO-8859-1 and UTF-8 agree on ASCII — so the test passes with the bug intact | Mandate a non-ASCII body in the F4 tests, as [3c-1 R-3c.4](phase-3c-1-renderer.md#risks-extends-planmds-register) had to |
| **R-F.5** | **Phase 5 over-adopts `throw`** | Handlers throwing for ordinary control flow (consent required, redirects) rather than for errors | 5b guidance: throw for *errors*; `ResourceOwnerConsentRequired` stays a returned response, as it is a control-flow signal, not an error ([3c-2 finding 5](phase-3c-2-error-layer.md#5-the-oauth2exception-hierarchy--status--error-name-phase-5-reference)) |

## Execution order

1. **`EndpointsTest` + `AnnotatedMethodTest` against unmodified code** (Tests §A). Commit them first, green.
   The package has no tests; this is the only step that establishes what the framework actually does.
2. **F3** — smallest and fully independent: implement `PromisedResponseCreator`, add the generic-return check.
3. **F1** — restructure `invoke`, move `getContext` inside the try, add the CREST body.
4. **F2** — retention/target on the annotation, discovery in `Endpoints.from`, dispatch + recursion guard in
   `handleException`.
4b. **F4** — read `@Produces` in `checkMethod`, set the header and encode explicitly in `ResponseCreator`.
   Independent of F1/F2; ordered last because its blast radius (R-F.6) wants the characterization suite
   complete first.
5. Verification steps 1–5, including the consumer suites and `XacmlRouterIT` under `verify`.
6. Correct [chf-patterns.md](chf-patterns.md) **§2** to describe the fixed framework (one 500 shape;
   `@ExceptionHandler` live; `Promise` returns supported), and revise
   [phase-3c-2-error-layer.md](phase-3c-2-error-layer.md) per the table above.
7. Record an **As-built** section here, then resume 3c-2.
