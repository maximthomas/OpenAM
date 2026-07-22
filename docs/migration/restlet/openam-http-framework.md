# openam-http framework fixes (F1–F4) — prerequisite to phase 3c-2

Execution plan for four defects in **`openam-http`'s annotation-driven endpoint framework**
(`org.forgerock.openam.http.annotations`), fixed **before** [phase-3c-2-error-layer.md](phase-3c-2-error-layer.md)
because 3c-2's design depends on the outcome. Parent tracker: [plan.md](plan.md); reusable CHF patterns:
[chf-patterns.md](chf-patterns.md); test layers: [docs/test-infrastructure.md](../../test-infrastructure.md).
Written 2026-07-21; branch `features/restlet-migration`. All facts verified against the tree on 2026-07-21.

> **Execution schedule added 2026-07-22.** Scope confirmed: **all four fixes in one phase**, in the order
> below, landing as six commits ([Commit sequence](#commit-sequence)). [D-F1](#d-f1--f1s-body-shape-crest-matching-endpointss-own-catch)
> confirmed as written — the 500 body carries the throwable's own message. Findings 7–11 were added in the
> same pass, re-verified against the tree and against the commons sources (`../commons`, i.e. the
> [OpenIdentityPlatform/commons](https://github.com/OpenIdentityPlatform/commons) checkout — **use that repo
> for CHF source analysis, not decompiled `~/.m2` jars**). Two of them change work items: finding 8 simplifies
> F4, finding 10 empties R-F.6's blast radius.

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

### 7. F1's CREST body is self-describing — `setEntity(Map)` writes the `Content-Type`

`Response.setEntity(Object)` → `MessageImpl.setEntity0:77-87`: a `String` goes to `setString`, a `byte[]` to
`setBytes`, **anything else to `setJson`** — and `Entity.setJson:403-406` puts
`Content-Type: application/json; charset=UTF-8` on the message before writing the bytes. So F1's
`setEntity(new InternalServerErrorException(t).toJsonValue().getObject())` (a `LinkedHashMap`) gets a correct
`Content-Type` for free, with no extra header code. That is also **why the pre-fix 500 has no `Content-Type`
at all** — it never calls `setEntity` (finding 2).

### 8. F4 needs no manual `getBytes` — `Entity` already reads the header (⇒ work item simplified)

`Entity.cs(null):466-473` resolves the charset in this order: explicit argument → **the message's own
`Content-Type` charset** (`ContentTypeHeader.valueOf(message).getCharset()`) → ISO-8859-1. So setting the
header *before* `setEntity(String)` is sufficient; `setString`'s `getBytes(cs(null))` then picks up the
declared charset. The `((String) content).getBytes(charsetOf(contentType))` in F4's original sketch is
redundant — [the work item is rewritten accordingly](#f4--honour-produces-and-encode-text-bodies-explicitly).

⚠ `ContentTypeHeader.getCharset():150` is `Charset.forName(charset)`, which throws
`UnsupportedCharsetException`/`IllegalCharsetNameException` for a bad name. A typo'd
`@Produces("text/plain; charset=utf8x")` would therefore detonate at *request* time inside `setString` —
exactly the deferred-failure pattern findings 4 and 8 exist to stop. **Validate the `@Produces` value once at
wiring time** and rethrow as `IllegalArgumentException` from `Endpoints.from`.

### 9. `toJsonValue()` HTML-escapes `message`

`ResourceException.toJsonValue():600-618` builds a `LinkedHashMap` of `{code, reason, message}` and passes the
message through `HtmlEscapers.htmlEscaper()`; `detail` appears only when non-null and `cause` only when
`includeCause` is true (**default false** — no stack trace reaches the client, as
[D-F1](#d-f1--f1s-body-shape-crest-matching-endpointss-own-catch) states). `message` itself is
`ResourceException.message(code, message, cause):424-431` — the explicit message, else the cause's message,
else the reason phrase.

⇒ **F1 tests asserting a message containing `<`, `>` or `&` must expect the escaped form.**

### 10. Every mounted annotated handler returns `Response` (⇒ R-F.6's blast radius is empty)

Return types of all five classes from finding 6, checked 2026-07-22:

| Class | Annotated method | Return |
|---|---|---|
| `AuthenticationServiceV1` (`.../authn/http/`) | `@Post authenticate` | `Response` |
| `AuthenticationServiceV2` | inherits V1's `@Post` | `Response` |
| `ApiService:84` | `@Get handle` | `Response` (declares `throws` — finding 2) |
| `ApiDocsService:136` | `@Get handle` | `Response` (route commented out, `CoreRestRouteProvider:166`) |
| `XacmlServiceHandler:126,158` | `@Get`/`@Post` | `Response` |

**No in-tree handler returns `String`, `byte[]`, `Void` or `JsonValue`.** So F4 changes nothing observable
today — it removes the trap for future handlers (Phase 5a/5b) rather than altering a live response.
[R-F.6](#risks) is downgraded to "no in-tree consumer".

### 11. Build gates: checkstyle is inert here, doclint is fatal

`openam-http/pom.xml:31-33` sets `checkstyleFailOnError=true`, but the root pom declares
`maven-checkstyle-plugin` **only under `<reporting>`** (`pom.xml:2466-2468`) and has no parent pom, so nothing
binds checkstyle to the build. It is **not** a gate.

Doclint **is**: `pom.xml:140` `-Xdoclint:all,-missing` with `<failOnWarnings>true</failOnWarnings>`
(`pom.xml:1958-1959`). Every javadoc these commits add must be well-formed with complete
`@param`/`@return`/`@throws`.

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

The null-method early return **must stay before** the try: the sentinel `findMethod:120` returns has
`contextParameters == null`.

Two deliberate changes beyond adding a body:

- **`parameter.getContext(context)` moves inside the try.** Today a missing context throws *before* the try and
  escapes to `Endpoints.java:73`, so identical failures produce different bodies depending on which line threw.
  One entry point, one shape.
- **`catch (Throwable)`** replaces `catch (IllegalAccessException)`, which also covers `responseAdapter.apply`
  failures. `Endpoints.java:71-78`'s outer catch **stays** as a last-resort net (it still guards
  `methods.get`/`getMethod`), but should now be unreachable from handler code.

**What is actually observable — narrower than the restructure looks** (added 2026-07-22; state this in review,
because a reviewer reading the diff will over-estimate the change):

- The two bullets above are **body-shape neutral**. Both failures already escape to `Endpoints.java:73-78`,
  which builds the *identical* `new InternalServerErrorException(t).toJsonValue()` map. Only the log line
  moves — `DEBUG.error("Endpoints :: …")` → `DEBUG.warning`.
- **The one observable change is the `InvocationTargetException` path**: a handler that throws goes from a
  bodiless 500 with no `Content-Type` to a CREST 500 with `application/json; charset=UTF-8` (finding 7). That
  is precisely what F1 exists to do, and precisely the row the characterization suite deletes-and-replaces.
- The response's `cause` changes from the wrapping
  `IllegalStateException("Exception from invocation should be handled by promise", e)` to the **unwrapped**
  original. Internal only — `Response.getCause()` is never serialised.

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
  The resolved table is passed into each `AnnotatedMethod`: `findMethod(obj, Get.class, table)`.
- **Where the table lives** (decided 2026-07-22): a **package-private static nested class of
  `AnnotatedMethod`**, holding `{Class<? extends Throwable> type, AnnotatedMethod target}` entries. It needs
  package-private access to `checkMethod`, so it cannot move to `org.openidentityplatform.openam.*`; making it
  a nested class rather than a new top-level file sidesteps the new-class convention in
  [decisions.md](decisions.md) entirely (that convention governs new *classes*; this is an edit to an existing
  ForgeRock-origin file). Build each entry with a sibling of `checkMethod` that also records the
  exception-parameter index; add an `int exceptionParameter` field and an
  `invokeExceptionHandler(Context, Request, Throwable)` entry point that **never** re-enters `handleException`.
- Dispatch picks the **most specific assignable** parameter type for the thrown exception. Assignability, not
  identity — the same rule as 3c-2's `NEVER_REDIRECT`, and for the same reason (`InvalidClientAuthZHeaderException`
  extends `InvalidClientException`; `OAuth2ProviderNotFoundException` extends `NotFoundException`).
- **Ambiguity: statically detectable ⇒ wiring-time error; the rest ⇒ 500 at dispatch.** Two
  `@ExceptionHandler` methods declaring the **same** exception type cannot be ordered and are detectable from
  the class alone ⇒ throw `IllegalArgumentException` from `Endpoints.from`, matching
  `ResponseCreator.forType:192`'s convention (finding 4). A pair that is merely *potentially* ambiguous —
  types neither of which is a subtype of the other, but which some future thrown class implements both of
  (reachable when one is an interface) — is not knowable at wiring time; detect it at dispatch, log it, and
  fall through to F1's 500 rather than guessing.
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

<a id="f4--honour-produces-and-encode-text-bodies-explicitly"></a>
### F4 — honour `@Produces`, and encode text bodies explicitly

In `checkMethod`, read `@Produces` off the method (falling back to a default per return type) and hand it to
`ResponseCreator`, which then sets the header **before** the entity:

```java
String contentType = producesValue != null ? producesValue : defaultFor(returnType);  // text/plain; charset=UTF-8
response.getHeaders().put(ContentTypeHeader.NAME, contentType);
response.setEntity(content);   // Entity.cs(null) now resolves the charset from that header — finding 8
```

> **Simplified 2026-07-22 (finding 8).** An earlier draft encoded by hand —
> `((String) content).getBytes(charsetOf(contentType))`. Unnecessary: `Entity.cs(null):466-473` already
> consults the message's own `Content-Type` before falling back to ISO-8859-1, so header-first plus a plain
> `setEntity` is correct and has one fewer place to get the charset wrong. **Header order is still
> load-bearing** — set the entity first and `cs(null)` sees no header and returns ISO-8859-1.

- **`String` returns**: `Content-Type` set, body encoded with the charset that header actually declares —
  the same header-then-entity discipline `chf-patterns.md` §6 mandates for hand-built responses.
- **Default when `@Produces` is absent — `String` returns only**: `text/plain; charset=UTF-8`. Today the
  answer is "no header at all, ISO-8859-1 bytes", so any explicit default is an improvement; UTF-8 matches the
  rest of the stack, and `@Produces("text/html; charset=UTF-8")` is available when a handler means HTML. The
  default does **not** extend to `byte[]`/`Void`/`JsonValue` (see the two bullets below).
- **Skip the header entirely when `content == null`.** `ResponseCreator.apply:171` turns a null return into
  `NO_CONTENT` with a null entity — including from a `String`-returning method. Stamping
  `Content-Type: text/plain` onto a bodiless 204 would be a new (small) wrong. Set the header only on the
  `Status.OK` branch.
- **`JsonValue`/POJO returns are untouched** — `setJson` already writes
  `application/json; charset=UTF-8` and would clobber anything set first. If `@Produces` is present *and*
  disagrees with `application/json`, that is a wiring-time `IllegalArgumentException`: better to reject the
  contradiction than to let `setJson` silently win.
- **`byte[]`/`Void` returns**: honour `@Produces` if present, otherwise leave the response alone (no charset
  question arises).
- **Validate the `@Produces` value at wiring time** (finding 8): parse it with `ContentTypeHeader.valueOf(v)`
  and call `getCharset()` once inside `checkMethod`, rethrowing `UnsupportedCharsetException` /
  `IllegalCharsetNameException` as `IllegalArgumentException`. A typo'd charset then fails at `Endpoints.from`
  like every other wiring error, instead of detonating on the first request.

`Consumes.java` is left alone. It is equally unread, but request-side negotiation has no consumer asking for
it and inventing one is not this commit's job — noted in the as-built as a known dead annotation.

## Decisions

<a id="d-f1--f1s-body-shape-crest-matching-endpointss-own-catch"></a>
### D-F1 — F1's body shape: **CREST**, matching `Endpoints`'s own catch

`new InternalServerErrorException(t).toJsonValue().getObject()` — byte-identical to what
`Endpoints.java:76` already produces for the sibling path, so the framework emits **one** 500 shape instead of
two. It also means `XacmlXmlErrorFilter` and 3c-2's `OAuth2ErrorFilter` already know how to rewrite it, with
no new discrimination rule.

*Disclosure note, corrected 2026-07-22:* `ResourceException.toJsonValue()` emits `{code, reason, message}`,
where `message` is `t.getMessage()` when non-null, else the reason phrase (finding 9). An earlier draft called
this "unchanged exposure, not new". **That is only true of the outer path** — `Endpoints:76` has always emitted
it for throwables escaping `AnnotatedMethod.invoke`, but the `InvocationTargetException` path (a handler that
throws) emits *nothing* today, so F1 **is** new disclosure there. Confirmed and accepted 2026-07-22; tracked as
[R-F.1b](#risks). `setIncludeCause` stays **false**, so no stack trace reaches the client, and the message is
HTML-escaped on the way out (finding 9).

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
code**, pinning today's behaviour including the parts F1–F4 change. TestNG + AssertJ, no Guice
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
- **the name-based fallback** (`findMethod:110-119`): a method literally named `get`/`post`/`put`/`delete` is
  bound **even without an annotation**. Undocumented, and directly in the path of F2's `findMethod` refactor
  ([R-F.8](#risks)).
- every supported return type: `Response`, `String`, `byte[]`, `Void`, `JsonValue`, and `null → NO_CONTENT`.
- **`void` is not `Void`**: a `void`-returning method yields `void.class`, which `ResponseCreator.forType:182`
  does not match ⇒ `IllegalArgumentException("Unsupported response type: void")` at `Endpoints.from`, while a
  `Void`-returning method works. Pin both — F4 touches this dispatch.
- unsupported return type → `IllegalArgumentException` at `Endpoints.from`, **not** at request time.
- **the F1 baseline: a throwing handler yields 500, empty entity, `getCause() != null`, no `Content-Type`.**
  This row is deleted-and-replaced by F1's row — that diff *is* the change under review.
- **the F3 baseline**: a `Promise`-returning handler *mounts*, then throws `UnsupportedOperationException` at
  request time, escaping to `Endpoints:73-78` → CREST 500 (finding 4's deferred detonation, pinned).
- **the F4 baseline**: a `String`-returning handler with a **non-ASCII** body comes back ISO-8859-1-mangled
  with no `Content-Type`. ⚠ An ASCII fixture passes under the bug — see [R-F.7](#risks).
- `@Contextual Context` / `Request` injection, and a missing context today escaping to `Endpoints:73-78`.

### B. The fixes

- **F1** — throwing handler → 500 with `{code: 500, reason, message}`,
  `Content-Type: application/json; charset=UTF-8` (finding 7), cause still set. Checked *and* unchecked
  throwables. A handler whose `@Contextual` context is missing now produces the **same** shape (the moved
  `getContext` call). A message containing `<` or `&` comes back **HTML-escaped** (finding 9).
- **F2** — matched handler wins; **most-specific** wins when two could match; unmatched throwable falls back
  to F1's 500; `@Contextual` params inject into the exception handler; every supported return type works from
  an exception handler; **the exception handler itself throwing yields F1's 500 and does not recurse**
  (assert exactly one dispatch via a counter). Also: the annotation is `RUNTIME`-retained —
  `assertThat(ExceptionHandler.class.getAnnotation(Retention.class).value()).isEqualTo(RUNTIME)`, the one
  assertion that fails if someone drops the meta-annotation and silently re-inerts the feature.
- **F2** (cont.) — a genuinely **incomparable** pair (two handler types, neither a subtype of the other, both
  assignable from the thrown class — reachable when one is an interface) falls back to F1's 500 **and logs**.
- **F4** — a `String`-returning handler with a **non-ASCII** body round-trips as UTF-8 and carries a
  `Content-Type` (⚠ an ASCII fixture passes under the bug — this is 3c-1's R-3c.4 in the framework, and the
  test must use a non-ASCII value to mean anything); `@Produces("text/html; charset=UTF-8")` is honoured;
  `@Produces` contradicting a `JsonValue` return → `IllegalArgumentException` at `Endpoints.from`;
  `@Produces` naming an **unknown charset** → `IllegalArgumentException` at `Endpoints.from`, not at request
  time (finding 8).
- **F3** — a `Promise`-returning handler works end to end; `Promise<Response, SomeOtherException>` →
  `IllegalArgumentException` **at `Endpoints.from`**; a `Promise` handler that throws synchronously routes to
  F2/F1; a `null` promise → `NO_CONTENT`.

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
  since `getBytes(UTF_8)` + an explicit header is correct under either version. (That remains the recipe for
  **hand-built** responses, `chf-patterns.md` §6. F4 itself does not need it — finding 8.)

<a id="commit-sequence"></a>
## Commit sequence

Six commits, each independently green and shippable. This is the [execution order](#execution-order) below
expressed as the reviewable units.

| # | Commit | Contents |
|---|---|---|
| 1 | `test(openam-http): characterize the annotation endpoint framework` | Tests §A, **against unmodified main code** |
| 2 | `fix(openam-http): F3 — implement the Promise return type` | F3 work item + Tests §B's F3 rows |
| 3 | `fix(openam-http): F1 — a thrown handler exception gets a CREST body` | F1 work item; commit 1's F1 baseline row is **replaced, not accommodated** |
| 4 | `feat(openam-http): F2 — make @ExceptionHandler real` | F2 work item + Tests §B's F2 rows |
| 5 | `fix(openam-http): F4 — honour @Produces and encode text bodies explicitly` | F4 work item + Tests §B's F4 rows |
| 6 | `docs(restlet-migration): openam-http framework fixes as-built` | Execution-order steps 7–8 — `chf-patterns.md` §2 rewrite, `phase-3c-2-error-layer.md` revision, As-built section here |

Commit 1 is the only one that establishes what the framework *actually* does (finding 1); commits 2–5 each
show their behaviour change as a test diff. F4 is last for convenience only — [R-F.6](#risks)'s blast radius
turned out empty (finding 10), so nothing depends on the ordering.

## Verification

1. `mvn -o -pl openam-http test` — the package's first tests; record the new baseline (openam-http has
   **no** prior annotations coverage, so this number starts from whatever the four existing suites report).
2. `mvn -o -pl openam-http install -DskipTests` → `mvn -o -pl openam-rest,openam-core-rest,openam-entitlements verify`
   — the three consumers from finding 6. **`openam-entitlements` must stay green including `XacmlRouterIT`**
   (`openam-entitlements/src/test/java/org/forgerock/openam/xacml/v3/rest/XacmlRouterIT.java`); run `verify`,
   not `test`, or the IT is silently skipped ([test-infrastructure.md](../../test-infrastructure.md)'s
   failsafe trap).
3. `mvn install -DskipTests` (whole reactor). **Doclint is fatal** (finding 11: `-Xdoclint:all,-missing` +
   `failOnWarnings`, commit `3c45ff8d53`) and these commits add javadoc to framework classes. Checkstyle,
   despite `openam-http/pom.xml`'s `checkstyleFailOnError=true`, is **not** a gate (finding 11).
4. Grep gate: `grep -rn "to be implemented" openam-http/src/main` → **0**.
5. CI: `build-maven`'s 9 legs run `verify`.

> Build with `-am` if `.m2` may hold a same-version SNAPSHOT of a sibling module from another branch.

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

<a id="risks"></a>
## Risks

| # | Risk | Detail | Mitigation |
|---|---|---|---|
| **R-F.1** | **F1 regresses a consumer that depends on the empty body** | `/json/authenticate` and `/xacml` see a body where there was none. A client asserting `content-length: 0` on a 500 would break — but so would any client relying on an unhandled server bug | Characterization tests first (finding 1); consumer suites in Verification step 2; the path is by definition an unhandled exception |
| **R-F.1b** | **F1 is new disclosure on the `InvocationTargetException` path** | [D-F1](#d-f1--f1s-body-shape-crest-matching-endpointss-own-catch)'s "unchanged exposure" holds for the *outer* path (`Endpoints:76`) but **not** for a throwing handler, which today emits nothing. After F1 the throwable's message reaches the client — on `/json/authenticate`, a **pre-authentication** endpoint. Confirmed and accepted 2026-07-22 | `includeCause` stays false so no stack trace ships (finding 9); the message is HTML-escaped (finding 9); the as-built enumerates what the five mounted handlers (finding 10) can actually throw |
| **R-F.2** | **`@ExceptionHandler` dispatch becomes a second routing system** | Type-based dispatch invites scope creep — ordering, inheritance, per-verb overrides, wildcards | Deliberately minimal: one exception parameter, most-specific-assignable, no ordering annotations. Anything more is a later decision with its own plan |
| **R-F.3** | **The exception handler faults on the error path** | An `@ExceptionHandler` that throws could recurse or mask the original failure | Hard recursion guard (work item F2); test asserts exactly one dispatch and that **both** throwables are logged |
| **R-F.4** | **The `RUNTIME` retention is silently dropped again** | The feature re-inerts with no test failure — exactly how it got into this state | Explicit meta-annotation assertion (Tests §B), not a behavioural test |
| **R-F.6** | ~~**F4 changes an existing endpoint's `Content-Type`**~~ — **blast radius empty**, downgraded 2026-07-22 | All five mounted annotated handlers return `Response` (finding 10), so **no** in-tree endpoint takes the `ResponseCreator` path at all. F4 removes the trap for Phase 5a/5b handlers rather than changing a live response | Finding 10's enumeration is the check; `@Produces` remains the explicit opt-out for any future `String`-returning handler |
| **R-F.7** | **F4's charset fix is asserted with ASCII fixtures** | Every template and most test data in this repo is ASCII, and ISO-8859-1 and UTF-8 agree on ASCII — so the test passes with the bug intact | Mandate a non-ASCII body in the F4 tests, as [3c-1 R-3c.4](phase-3c-1-renderer.md#risks-extends-planmds-register) had to |
| **R-F.5** | **Phase 5 over-adopts `throw`** | Handlers throwing for ordinary control flow (consent required, redirects) rather than for errors | 5b guidance: throw for *errors*; `ResourceOwnerConsentRequired` stays a returned response, as it is a control-flow signal, not an error ([3c-2 finding 5](phase-3c-2-error-layer.md#5-the-oauth2exception-hierarchy--status--error-name-phase-5-reference)) |
| **R-F.8** | **F2's `findMethod` refactor silently drops the name-based fallback** | `findMethod:110-119` binds a method literally *named* `get`/`post`/`put`/`delete` even with no annotation. Undocumented, untested, and F2 changes that method's signature | Pinned by a Tests §A characterization row before F2 touches it |

<a id="execution-order"></a>
## Execution order

Renumbered 2026-07-22 (the earlier list had a `4b`); each of steps 1–5 is one row of the
[commit sequence](#commit-sequence).

1. **`EndpointsTest` + `AnnotatedMethodTest` against unmodified code** (Tests §A). Commit them first, green.
   The package has no tests; this is the only step that establishes what the framework actually does.
2. **F3** — smallest and fully independent: implement `PromisedResponseCreator`, add the generic-return check.
3. **F1** — restructure `invoke`, move `getContext` inside the try, add the CREST body.
4. **F2** — retention/target on the annotation, discovery in `Endpoints.from`, dispatch + recursion guard in
   `handleException`.
5. **F4** — read `@Produces` in `checkMethod`, set the header before the entity in `ResponseCreator`.
   Independent of F1/F2. Ordered last on the original blast-radius argument (R-F.6); finding 10 has since
   shown that radius to be **empty**, so the ordering is now only a convenience — do it last anyway so the
   characterization suite is complete, but it is no longer a constraint.
6. Verification steps 1–5, including the consumer suites and `XacmlRouterIT` under `verify`.
7. Correct [chf-patterns.md](chf-patterns.md) **§2** to describe the fixed framework (one 500 shape;
   `@ExceptionHandler` live; `Promise` returns supported), and revise
   [phase-3c-2-error-layer.md](phase-3c-2-error-layer.md) per the table above. ([plan.md](plan.md)'s tracker
   row and [decisions.md](decisions.md) were already updated to F1–F4 on 2026-07-22.)
8. Record an **As-built** section here, then resume 3c-2.
