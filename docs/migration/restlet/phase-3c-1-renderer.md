# Phase 3c-1 — FreeMarker template renderer (`FreemarkerTemplateRenderer`)

Detailed execution plan for **sub-phase 3c-1** of the Restlet → CHF migration. Parent tracker:
[plan.md](plan.md) (Phase 3); research & sizing: [phase-3-research.md](phase-3-research.md); reusable CHF
patterns: [chf-patterns.md](chf-patterns.md); predecessors: [phase-3a-oauth2request.md](phase-3a-oauth2request.md),
[phase-3b-collaborators.md](phase-3b-collaborators.md); successor: [phase-3c-2-error-layer.md](phase-3c-2-error-layer.md);
test layers: [docs/test-infrastructure.md](../../test-infrastructure.md). Written 2026-07-17; branch
`features/restlet-migration`. All facts below were verified against the tree and jar bytecode on 2026-07-17.

> **Reviewed 2026-07-17 (same day).** Claims re-verified against the tree, jar **sources** and by **executing**
> both renderers in one JVM. Corrections folded in, most-material first:
> 1. **§B's open unknown is resolved, and both its guesses were wrong.** `new org.restlet.Context()` **NPEs**;
>    `MultiTemplateLoader` does **not** fall through (an NPE is not an `IOException`); and the proposed
>    "ClassTemplateLoader-only Restlet leg" fallback is **rejected** — it would swap the oracle for a
>    reimplementation. Recipe: `new Component().getContext().createChildContext()`.
> 2. **The premise is proven**: all 10 templates render **byte-identical** between the real `TemplateFactory`
>    and this plan's `Configuration` (§B).
> 3. **New [D12](#d12--golden-data-models-are-derived-from-the-producers)** — golden data models are derived
>    from the producers. Three keys have counter-intuitive types (finding 8); guessing them throws on 4/10
>    templates, and a wrong-but-renderable model is the one error the parity leg cannot catch (R-3c.11).
> 4. **[D10](#d10)'s RETHROW rationale was wrong** — `DEBUG_HANDLER` *also* rethrows, so RETHROW is inert under
>    eager render-to-`String`. Eager rendering is the real fix; the RETHROW test was vacuous → config assert.
> 5. Finding 5's *"`new Configuration()` sets no default encoding"* is **false** (it sets `file.encoding`); the
>    conclusion survives, the mechanism is now stated correctly.
> 6. Smaller: empty-string `display` must resolve to `page`; §B needs a second scaffold for popup composition;
>    golden file I/O must pin UTF-8 (R-3c.12); WAP `text/html` contradiction resolved to **reproduce**;
>    `@Singleton`+`@Inject` no-arg ctor has no precedent in this module.

## Context

3a delivered the neutral `OAuth2Request`; 3b delivered the neutral collaborators. **3c is the first purely
additive sub-phase**: new classes in a new package, wired to **no route until Phase 5**. Nothing is observable
when it lands. Its whole value is that it *encodes a contract* — every decision below silently becomes
`/oauth2` behaviour at the 5d flip.

That inverts the usual guardrail. 3a/3b were protected by "the existing Restlet suite must stay green".
**3c has no such net**: no test anywhere asserts rendered HTML, charset, or popup composition
(`AuthorizeResourceTest:54` mocks `OAuth2Representation`). So 3c must **build its own oracle while Restlet is
still on the classpath to be one**. That is the organising idea of both 3c docs.

3c was split into two commits (decided 2026-07-17). **3c-1 (this doc) delivers the renderer**; 3c-2 delivers
the error layer and depends on it (the error factory's HTML branch renders `page/error.ftl`).

**Outcome:** one new class, `FreemarkerTemplateRenderer`, reproducing today's rendering byte-for-byte on
every shipping path, proven by a 3-way golden assert against the live Restlet renderer.

## Scope & sizing (decided)

**One new class + two test classes + 10 golden files.** ~150 LOC main, ~450 LOC test.

- **Package `org.openidentityplatform.openam.oauth2.http`** per [decisions.md](decisions.md) — CDDL header,
  `Copyright 2026 3A Systems LLC.`, **no `@since`**. This is the second subpackage under
  `org/openidentityplatform/openam/oauth2/` (after 3a/3b's `core/`). Note [plan.md](plan.md) says
  `org.forgerock.oauth2.http`; that predates the 2026-07-16 convention lock and is corrected by this commit.
- **No pom change.** FreeMarker **2.3.31** is already a *direct* compile dep of openam-oauth2
  (`openam-oauth2/pom.xml:106-109`; version from root `pom.xml:118`), and `restlet-ext-freemarker`'s
  transitive copy is explicitly excluded (`:134-144`). http-framework `core` 3.1.1, testng, mockito and
  assertj are already present too.
- **Deletes nothing.** `TemplateFactory` / `OAuth2Representation` die in Phase 5b, when their last callers
  are ported.
- **Does not touch the 10 templates** — they are the golden oracle (see [D8](#d8--template-bugs-defer-do-not-touch)).

## Key research findings (drove this plan)

### 1. The real migration target is `TemplateFactory`, not `OAuth2Representation`

`OAuth2Representation` **never constructs a `TemplateRepresentation`**. It delegates to
`org.forgerock.oauth2.restlet.TemplateFactory` (85 lines), which owns the FreeMarker `Configuration`.
`TemplateFactory:47-60` verbatim:

```java
config = new Configuration();
final TemplateLoader ctx = new ContextTemplateLoader(context, "clap:///");
final TemplateLoader ctl = new ClassTemplateLoader(TemplateFactory.class, "/");
final MultiTemplateLoader mtl = new MultiTemplateLoader(new TemplateLoader[]{ ctx, ctl });
config.setTemplateUpdateDelay(3600);                                        // SECONDS (deprecated)
config.setTemplateLoader(mtl);
config.setSetting(Configuration.CACHE_STORAGE_KEY, "strong:20, soft:250");
```

`getTemplateRepresentation(name)` (`:78-84`) → `new TemplateRepresentation(template, MediaType.TEXT_HTML)`,
or **`null`** on a miss. It is cached per Restlet `Context` under key `TemplateFactory.class.getName()`
(`OAuth2Representation:127-136`). **`DeviceCodeVerificationResource:282-291` carries a duplicate copy** of
that lookup — both copies die in 5b.

### 2. ⚠ The `clap:///` loader is dead code at runtime

`ContextTemplateLoader` resolves through the Restlet CLAP connector. The **only** `RIAP CLAP` declaration in
the repo is `openam-server-only/src/main/webapp/WEB-INF/web.xml:1051`, and it belongs to the **WebFinger**
servlet — not to `RestEndpointServlet`, which serves `/oauth2/*` (`web.xml:1127-1134`). With no client
connector registered, the CLAP branch never resolves, so **`ClassTemplateLoader(TemplateFactory.class, "/")`
is the sole effective loader** and reads `templates/...` straight from the openam-oauth2 jar.

⇒ Dropping `MultiTemplateLoader` + `ContextTemplateLoader` is **behaviour-preserving for `/oauth2/*`**, and it
removes the last reason the renderer would need a Restlet `Context`.

> **Confirmed empirically (2026-07-17), and the argument is stronger than the web.xml one.** Driving the real
> `TemplateFactory` twice in-process — once against a `Component` with **no** CLAP client (production's shape)
> and once with `Component.getClients().add(Protocol.CLAP)` — produces **byte-identical output**. So the CLAP
> leg is not merely unregistered: even when it *is* registered it resolves `clap:///templates/...` to the same
> classpath resource `ClassTemplateLoader` reads. Dropping it is behaviour-preserving **either way**, which
> does not depend on reading web.xml correctly.

### 3. ⚠ `Content-Type: text/html; charset=UTF-8` is implicit today — and CHF's default is ISO-8859-1

Restlet never sets the charset in OAuth2 code. `TemplateRepresentation(Template, MediaType)` →
`WriterRepresentation(MediaType)` → `CharacterRepresentation(MediaType)`, whose bytecode is:

```
invokespecial Representation."<init>":(MediaType)
getstatic  org/restlet/data/CharacterSet.UTF_8
invokevirtual setCharacterSet
```

So the wire result is `text/html; charset=UTF-8`, inherited, never written by us.

**CHF does the opposite.** [chf-patterns.md](chf-patterns.md) §6 said `setEntity(Object)` sends "anything not
`byte[]`" to `setJson`. **That is wrong** — `MessageImpl.setEntity0` has **four** branches (bytecode-verified):
`BranchingInputStream` → `setRawContentInputStream`; `byte[]` → `setBytes`; **`String` → `setString`**; else →
`setJson`. And `Entity.setString(v)` → `setBytes(v.getBytes(cs(null)))`, where `cs(null)` reads the message's
current `Content-Type` charset and **falls back to `ISO_8859_1`**. `setString` never touches `Content-Type`.

⇒ `response.setEntity(html)` before setting `Content-Type` **silently encodes the page as ISO-8859-1**,
mangling any non-ASCII in the data model (client names, localized scope text). **Mandated recipe** —
order-independent, no reliance on `cs()`:

```java
response.getHeaders().put(ContentTypeHeader.NAME, "text/html; charset=UTF-8");
response.setEntity(html.getBytes(StandardCharsets.UTF_8));   // byte[] → setBytes, Content-Type untouched
```

§6 is corrected by this commit — it is read by every later phase.

### 4. ⚠ `new Configuration()` pins `incompatibleImprovements` = 2.3.0, and bumping it is behaviour-changing

Bytecode-verified in freemarker 2.3.31:
- `Configuration()` → `this(DEFAULT_INCOMPATIBLE_IMPROVEMENTS)`, and the static initialiser assigns
  `DEFAULT_INCOMPATIBLE_IMPROVEMENTS = VERSION_2_3_0`. **Today's config is ii = 2.3.0.**
- `getDefaultObjectWrapper(Version)` branches at `VERSION_INT_2_3_21`: below → legacy
  `ObjectWrapper.DEFAULT_WRAPPER`; at/above → `DefaultObjectWrapperBuilder(version).build()`. **Bumping ii
  changes the ObjectWrapper** — i.e. how every data-model `Map`/`String`/bean is exposed to the templates.
- `getDefaultTemplateExceptionHandler(Version)` returns `DEBUG_HANDLER` **unconditionally** (`:1097-1099`) ⇒
  today the renderer writes **FreeMarker stack traces into the HTML response** on any render failure.
  ⚠ Note **`DEBUG_HANDLER` prints *and then rethrows*** (`TemplateExceptionHandler.java:88-96`: stack trace →
  `pw.flush(); // To commit the HTTP response` → `throw te`). The leak is therefore **not** caused by the
  handler swallowing the error — it is caused by Restlet **streaming** the template straight into the response
  entity, so the bytes are already on the wire when the throw happens. That distinction matters: see
  [D10](#d10).

⇒ Write `new Configuration(Configuration.VERSION_2_3_0)` — provably identical to today, no deprecation
warning, choice explicit. Bumping ii is a separate, golden-guarded change.

### 5. All 10 templates are pure ASCII — verified, not assumed

`file(1)` + a byte scan (`perl -ne '/[^\x00-\x7f]/'`) over all 10: **0 high bytes**. That is what makes
`setDefaultEncoding("UTF-8")` provably behaviour-neutral *today*, and it is why pinning it is worth doing:
it removes a **`file.encoding`-dependent** behaviour across the JDK 11–26 CI matrix (JEP 400 flipped the
platform default at JDK 18).

**Where the `file.encoding` dependence actually comes from** (corrected 2026-07-17 — an earlier draft said
"`new Configuration()` sets **no** default encoding", which is false and would mislead anyone re-deriving this):
`Configuration.java:583` initialises `defaultEncoding = getDefaultDefaultEncoding()` → `getJVMDefaultEncoding()`
→ `SecurityUtilities.getSystemProperty("file.encoding", "utf-8")` (`:2959-2965`). So today's config **does**
have a default encoding — the platform's. Observed live: FreeMarker's own cache key logs as
`("ru_RU", UTF-8, parsed)`, i.e. locale = `Locale.getDefault()`, encoding = `file.encoding`.

> ⚠ **`setDefaultEncoding` is not the whole story.** `getEncoding(Locale)` consults `localeToCharsetMap`
> **first** and only falls back to `defaultEncoding` when that map is empty (bytecode-verified). It is empty
> here **only because `loadBuiltInEncodingMap()` is never called** — not by the ctor, not by OpenAM. Anyone who
> later calls it (it maps e.g. `en` → `ISO-8859-1`) silently re-introduces locale-dependent template decoding
> that `setDefaultEncoding("UTF-8")` will **not** override. Do not call it.

No template uses `?new` / `?api` / `?eval` ⇒ `TemplateClassResolver.SAFER_RESOLVER` is a **no-op today** ⇒
free hardening. Precedent in this module: `RealmOAuth2ProviderSettings.java:969`.

**`wap/authorize.ftl` is WML, not HTML** (`XML 1.0 document text`: `<?xml?>` + `<!DOCTYPE wml>`), yet it is
served as `text/html` today like the rest. Reproduce; note it.

### 6. The popup bug is reachable — exactly one caller

`OAuth2Representation:79-92` hardcodes `"authorize.ftl"` at `:80`, **ignoring the `templateName` argument**:

```java
if (display != null && display.equalsIgnoreCase("popup")) {
    Representation popup = getRepresentation(context, displayType.getFolder(), "authorize.ftl", dataModel);
    dataModel.put("htmlCode", popup.getText());          // renders authorize.ftl to a String
    representation = getRepresentation(context, displayType.getFolder(), "popup.ftl", dataModel);
}
```

Four **external** callers of `getRepresentation` (7 call sites in total — `OAuth2Representation` also delegates
to its own package-private overload at `:80`, `:89`, `:91`):

| Caller | Template | `display=popup` effect |
|---|---|---|
| `ExceptionHandler:137` | `error.ftl` | none — calls the package-private 4-arg overload with display hardcoded `"page"` |
| `AuthorizeResource:131` | `authorize.ftl` | correct **by accident** (`:80` hardcodes the same name) |
| `DeviceCodeVerificationResource:197` | `authorize.ftl` | correct by accident |
| **`OpenIDConnectCheckSessionEndpoint:95`** | **`checkSession.ftl`** | **renders `popup/authorize.ftl`** — the latent bug |

### 7. Path resolution and display types

`OAuth2Representation:113`: `"templates/" + (display != null ? display : "page") + "/" + templateName`. The
`display != null` guard is dead — callers pass `displayType.getFolder()`, never null. `FormPostResponse.ftl`
**bypasses** the display folder entirely (`:181`: `"templates/FormPostResponse.ftl"`).

`OAuth2Constants.DisplayType` (openam-core, `:815-821`): `PAGE, POPUP, TOUCH, WAP`; `getFolder()` =
lowercase name. `OAuth2Representation:75` does `Enum.valueOf(DisplayType.class, display.toUpperCase())` —
**throws a raw `IllegalArgumentException`** on an unknown display, not a `ResourceException`.

### 8. Template inventory + data-model keys (verified by interpolation scan)

All under `openam-oauth2/src/main/resources/templates/`. These are the only `.ftl` files in the repo.

| Path | Data-model keys |
|---|---|
| `page/authorize.ftl` | `realm`, `ui_locales`/`locale`, `baseUrl`, `redirect_uri`, `scope`, `state`, `nonce`, `acr`, `csrf`, `display_description`, `response_type`, `client_id`, `target`, `display_name`, `user_name`, `user_code`, **`saveConsentEnabled`**, `display_scopes`, `display_claims` |
| `popup/authorize.ftl` | same **minus `saveConsentEnabled`** (the only functional diff vs `page/`) |
| `touch/authorize.ftl` | same minus `saveConsentEnabled`; **`:56` typo `isplayName:`** ([D8](#d8--template-bugs-defer-do-not-touch)) |
| `wap/authorize.ftl` | **WML.** `display_name`, `display_description`, **`display_scope`** (singular — *never populated*; producers emit `display_scopes`), `realm`, `redirect_uri`, `scope`, `state`, `nonce`, `acr`, `csrf`, `response_type`, `client_id`, `target` |
| `popup/popup.ftl` | **`htmlCode` only** |
| `page/error.ftl` | `error` (guards the `pageData` block), `realm`, `baseUrl`, `error_uri`, `error_description` |
| `page/checkSession.ftl` | `baseUrl`, `client_uri`, `valid_session`, `cookie_name` |
| `FormPostResponse.ftl` | `redirectUri?html`, `formValues` (`?keys` + `formValues[key]?html`) |
| `CodeVerificationForm.ftl` | `locale`, `errorCode`, `realm`, `baseUrl` |
| `CodeThanks.ftl` | `locale`, `baseUrl`, `realm`; **`:33` appends `/XUI` to realm** ([D8](#d8--template-bugs-defer-do-not-touch)) |

**⚠ Three keys have counter-intuitive types — the natural guess makes the template throw.** The table above
lists *keys*; the **types** are not inferable from the names, and every golden's data model must come from the
**real producer**, never from a plausible-looking invention ([D12](#d12--golden-data-models-are-derived-from-the-producers)):

| Key | Actual type | Producer | Template use |
|---|---|---|---|
| `display_scopes` | **`String`** — `JsonValue.toString()`, i.e. JSON *text* | `ConsentRequiredResource:139` (`scopes` is `json(array())`) | `page/authorize.ftl:60` `displayScopes: ${display_scopes}` — JSON injected raw into a JS array literal |
| `display_claims` | **`String`** — JSON text | `ConsentRequiredResource:152` | `page/authorize.ftl:61` |
| `valid_session` | **`String`** (`"true"`/`"false"`) | `OpenIDConnectCheckSessionEndpoint:116` `validSession.toString()` | `page/checkSession.ftl:56` `${valid_session?js_string}` |
| `saveConsentEnabled` | **`Boolean`** (a real `boolean`) | `AuthorizationService:205` | `page/authorize.ftl:59` `<#if saveConsentEnabled >` |

Passing a `List` for `display_scopes`/`display_claims` fails with *"Expected a string … but this has evaluated
to a sequence"*; passing a `Boolean` for `valid_session` fails with *"Can't convert boolean to string
automatically"* (`?js_string` needs a string, and ii = 2.3.0's `boolean_format` is the legacy
`true,false` default). **Verified by hitting all three during plan review** — they fail loudly, which is
survivable; the real hazard is the opposite one, a wrong-but-renderable model that bakes fiction into a golden
that R-3c.2 makes unfalsifiable after 5d.

**`error.ftl` requires `baseUrl` unconditionally.** `${realm?js_string}` and `${baseUrl?js_string}` sit inside
`<#if error??>`, but the final script tag dereferences `${baseUrl?html}` **outside** any guard. FreeMarker
treats a Java `null` as *missing* ⇒ `InvalidReferenceException`. Combined with finding 4's `DEBUG_HANDLER`,
a null `realm`/`baseUrl` today renders a **FreeMarker stack trace into the browser**. See
[3c-2's D9](phase-3c-2-error-layer.md#d9--null-realm--fix).

**Only `authorize.ftl` exists in all four display folders.** `error.ftl` and `checkSession.ftl` exist **only**
under `page/`. So `display=touch` + an error would resolve `templates/touch/error.ftl` → miss. It never fires
because `ExceptionHandler:137` hardcodes `"page"` — **preserve that hardcoding** (3c-2 does).

### 9. `Endpoints.from` handlers must return `Response` — a `String` return is the ISO-8859-1 trap

> **Superseded 2026-07-22 by [F1–F4](openam-http-framework.md#as-built).** A `Promise` return is implemented,
> and a `String` return now carries `text/plain; charset=UTF-8` (or whatever `@Produces` declares) and is
> encoded accordingly — the trap is gone, and "must return `Response`" is house style, not a rule. **3c-1's
> own conclusion is unaffected**: `toHtmlResponse` returns a `Response` because it sets `text/html` and a
> status, which is still the right shape. See [chf-patterns.md](chf-patterns.md) §2 for current behaviour;
> the text below is the framework as 3c-1 found it.

Verified in `AnnotatedMethod.checkMethod:138-152`. Supported return types: **`Response`** (`:141-147`),
`String` / `Void` / `byte[]` / `JsonValue` (`ResponseCreator.forType:182-191`). A **`Promise`** return hits
`PromisedResponseCreator.apply:202` → `throw new UnsupportedOperationException("to be implemented")` —
unimplemented despite the code appearing to support it. Any other type → `IllegalArgumentException("Unsupported
response type: …")` (`:192`), thrown at **`Endpoints.from` construction time** (route-provider wiring), not
per-request.

A `String`-returning method goes to `ResponseCreator.apply:171` →
`new Response(OK).setEntity(content)` → **finding 3's ISO-8859-1 path, with no `Content-Type`**.

⇒ **Phase 5a/5b handlers must return `Response`**, and this is exactly why `toHtmlResponse` returns one
rather than the renderer handing back a `String` for the handler to return. Recorded in
[chf-patterns.md](chf-patterns.md) §2 by this commit.

## Work items

### 1. `FreemarkerTemplateRenderer` (new, `org.openidentityplatform.openam.oauth2.http`)

**Configuration lifecycle.** Restlet cached it per Restlet `Context` (`OAuth2Representation:127-136`) — one
Context per application, so effectively a singleton. **CHF has no equivalent: `AttributesContext` is
per-request.** Hanging the `Configuration` there would rebuild the loader and blow the template cache on
**every request**. Do not do it; the javadoc must say so.

⇒ **`@Singleton` + `@Inject` no-arg constructor**, `Configuration` built once in the ctor. Guice JIT-binds it
(concrete class, `@Inject` ctor) ⇒ **no `OAuth2GuiceModule` change** ⇒ 3b's binding-guard concern does not
recur. Add a `@VisibleForTesting` ctor taking a `TemplateLoader` so tests can inject a `StringTemplateLoader`
for negative cases (and to prove [D5](#d5--popup-hardcoding-authorizeftl-fix) — see Tests §A).

- **Use `jakarta.inject.{Inject,Singleton}`** — the module's settled convention (83 `jakarta.inject.Inject` vs
  **0** `javax.inject.*`; the 2 `com.google.inject.Inject` are outliers).
- *Precedent note, corrected:* this is **not** "the same shape as 3b's verifiers" — `HeaderAccessTokenVerifier`
  is `@Singleton` + `@Inject` on an **arg-taking** ctor (`TokenStore`). openam-oauth2 has **no** existing
  `@Singleton` + `@Inject` *no-arg* ctor (the one `@Inject` no-arg ctor, `OAuth2AuditLogger:52`, is not
  `@Singleton`). The combination is still correct and JIT-binds fine — it is simply new here, so do not expect
  to find a template to copy.

```java
Configuration cfg = new Configuration(Configuration.VERSION_2_3_0);          // finding 4 — pin; a bump swaps the ObjectWrapper
cfg.setTemplateLoader(new ClassTemplateLoader(FreemarkerTemplateRenderer.class, "/"));  // finding 2 — clap:/// is dead
cfg.setDefaultEncoding("UTF-8");                                            // finding 5 — neutral today, kills file.encoding dependence
cfg.setTemplateUpdateDelayMilliseconds(3600_000L);                          // == Restlet's setTemplateUpdateDelay(3600) SECONDS
cfg.setSetting(Configuration.CACHE_STORAGE_KEY, "strong:20, soft:250");
cfg.setNewBuiltinClassResolver(TemplateClassResolver.SAFER_RESOLVER);       // finding 5 — no-op today
cfg.setTemplateExceptionHandler(TemplateExceptionHandler.RETHROW_HANDLER);  // finding 4 — was DEBUG_HANDLER
```

> **Unit trap:** `setTemplateUpdateDelay(int)` is **seconds** (deprecated); `setTemplateUpdateDelayMilliseconds(long)`
> is **milliseconds**. Restlet's `3600` = one hour. Writing `setTemplateUpdateDelayMilliseconds(3600)` would
> re-stat every template every 3.6 s.

**API:**

```java
public String render(String templatePath, Map<String, Object> dataModel);                        // "templates/page/error.ftl"
public String renderForDisplay(String display, String templateName, Map<String, Object> model);  // display resolution + popup composition
public static Response toHtmlResponse(Status status, String html);                               // finding 3 recipe
```

- `renderForDisplay` takes a **`String display`, not an `OAuth2Request`** — keeps the renderer free of *any*
  transport coupling and trivially unit-testable. The caller does `request.getParameter("display")`.
- Path resolution mirrors `OAuth2Representation:113`; `FormPostResponse.ftl` goes through the plain
  `render("templates/FormPostResponse.ftl", …)`, mirroring `:181`.
- ⚠ **`isEmpty(display) → PAGE` *before* `Enum.valueOf`** — `null` **and `""` both mean `page`**. This rule
  lives at `OAuth2Representation:72-76` (`Utils.isEmpty` = `s == null || s.isEmpty()`), **not** at `:113` — and
  `:113`'s own `display != null ? display : "page"` guard is dead, because the 4-arg overload only ever receives
  `displayType.getFolder()`. An implementer who mirrors `:113` alone and writes
  `Enum.valueOf(DisplayType.class, display.toUpperCase())` turns **`?display=`** (empty value — reachable in a
  real URL, `getParameter` returns `""`) from a rendered page into a 400. Reproduce the empty case as `page`.
- Popup composition: render `templates/popup/<templateName>` → String → `model.put("htmlCode", …)` → render
  `templates/popup/popup.ftl`. **`templateName` is passed through** — the [D5](#d5--popup-hardcoding-authorizeftl-fix) fix.
- Unknown display → `IllegalArgumentException`, verbatim ([D7](#d7--unknown-display--illegalargumentexception-reproduce)).
- **Template miss → throw**, not `null`. `TemplateFactory:83` returns null, which is what forces
  `OAuth2Representation:93-98` into its "check for null, throw `ResourceException`" dance. The new contract is
  *render or throw*.

## Decisions

<a id="d5--popup-hardcoding-authorizeftl-fix"></a>
### D5 — Popup hardcoding `authorize.ftl`: **fix**

`OAuth2Representation:80` ignores `templateName` (finding 6). Fix it: the live authorize flow is
**byte-identical** (the only shipping popup pair is `authorize.ftl` + `popup.ftl`), and nobody can depend on
receiving a consent page when they asked for a check-session iframe.

> ⚠ **Observable consequence.** After the fix, `checkSession?display=popup` resolves
> `templates/popup/checkSession.ftl`, which **does not exist** → template-not-found → error, where today it
> returns HTTP 200 with the wrong page. 3c-1's job is to stop the renderer lying. **Whether that case should
> error or fall back to `page/checkSession.ftl` is Phase 5b's call** when it ports `CheckSessionHandler`.
> Do **not** assert this case in the e2e lock.

<a id="d7--unknown-display--illegalargumentexception-reproduce"></a>
### D7 — Unknown `display` → `IllegalArgumentException`: **reproduce**

`AuthorizeResource:120`'s `catch (IllegalArgumentException)` depends on the **type** to produce
`invalid_request` (400). Defaulting to `PAGE` would turn `?display=bogus` from a 302-error into a rendered
consent page. Reproduce; Phase 5b must map IAE → `invalid_request`.

<a id="d8--template-bugs-defer-do-not-touch"></a>
### D8 — Template bugs: **defer, do not touch**

`touch/authorize.ftl:56` `isplayName:` (typo); `CodeThanks.ftl:33` appends `/XUI` to realm (differs from
`CodeVerificationForm.ftl`); `wap/authorize.ftl` guards on `display_scope` (singular) which no producer emits.

3c-1 does not own the templates. Both renderers render them identically, so they are **parity-neutral**. More
importantly, **editing them destroys the golden files' role as a Restlet oracle**. File as separate issues.

<a id="d12--golden-data-models-are-derived-from-the-producers"></a>
### D12 — Golden data models are **derived from the producers**, not invented (decided 2026-07-17)

Each golden's data model is built from the code that actually populates it today —
`ConsentRequiredResource.getDataModel` (`:139`, `:152`), `OpenIDConnectCheckSessionEndpoint:116`,
`AuthorizationService:205`, `ExceptionHandler:137`, `DeviceCodeVerificationResource` — with the **types**
recorded in finding 8, not with plausible-looking hand-written fixtures.

Why this is a decision and not a detail: a hand-authored model still proves `Restlet == CHF` (both legs get the
same model), so the parity leg cannot detect that the model is fictional. But the golden's **second** job is to
be the durable regression guard that outlives Restlet (§C, R-3c.2) — and a golden built from a data shape
production never emits is a guard against nothing, permanently, and **unfalsifiable after 5d**. The cost of
deriving is one read of each producer; the cost of inventing is discovered years later.

Three keys make this concrete rather than theoretical: `display_scopes`/`display_claims` are JSON **text**, and
`valid_session` is a **String** — see finding 8. Guessing the intuitive types makes 4 of the 10 templates
throw.

*Note:* Phase 5b re-ports `ConsentRequiredResource.getDataModel` for real (`AuthorizeHandler`). 3c-1 only reads
it to build fixtures — it does **not** port it, and must not be tempted to.

<a id="d10"></a>
### D10 — `RETHROW_HANDLER` + `SAFER_RESOLVER` + `setDefaultEncoding("UTF-8")` + pin `VERSION_2_3_0`

`SAFER_RESOLVER` and UTF-8 are **provably no-ops today** (finding 5) — pure hardening; UTF-8 additionally
removes a `file.encoding`-dependent behaviour across the JDK 11–26 matrix. `VERSION_2_3_0` **reproduces** today
exactly (finding 4); bumping ii changes the ObjectWrapper and is a separate, golden-guarded change.

**`RETHROW_HANDLER` — corrected rationale (2026-07-17).** An earlier draft credited RETHROW with *fixing* the
finding-4 information disclosure. **It does not, and cannot.** `DEBUG_HANDLER` already rethrows (finding 4), and
this renderer **renders eagerly to a `String` and only builds the `Response` on success** — so when a render
fails, the partial output (stack trace and all) is **discarded before any byte reaches a `Response`, whichever
handler is set**. RETHROW and DEBUG are *observationally identical* under this design.

⇒ **What actually fixes the disclosure is `render()` returning a `String`** — i.e. render-then-set-entity
instead of Restlet's stream-into-the-entity. That is an architectural property of the API in work item 1, not a
config flag, and it is why the fix is real even though the flag is inert.

⇒ **Keep `RETHROW_HANDLER` anyway**, for three reasons that are honest about its size: it is the correct
production setting; it skips pointless stack-trace formatting on the failure path; and it is the guard that
keeps the disclosure fixed **if anyone later makes the renderer stream** (the one change that would resurrect
finding 4). It is defence-in-depth, **not** the fix.

⚠ **Consequence for tests.** A test asserting "render failure throws instead of emitting a stack trace into the
body" **passes with `DEBUG_HANDLER` too** — it cannot fail if the `setTemplateExceptionHandler` line is
deleted, so it guards nothing. The only assertion that discriminates is on the `Configuration` itself; see
[Tests §A](#a-freemarkertemplaterenderertest-unit).

## Tests

### A. `FreemarkerTemplateRendererTest` (unit)

TestNG + AssertJ, per house style (`ChfOAuth2RequestTest`). No `RealmTestHelper` needed — the renderer never
touches `Realm`.

- Each display folder resolves (`page`/`popup`/`touch`/`wap` × `authorize.ftl`).
- Popup composition: `htmlCode` is injected and appears in the output; **`templateName` is honoured**
  ([D5](#d5--popup-hardcoding-authorizeftl-fix)). Needs the `@VisibleForTesting` `StringTemplateLoader` ctor —
  `popup/` ships only `authorize.ftl` + `popup.ftl`, so there is no *real* second template to prove
  pass-through with.
- Unknown display → `IllegalArgumentException` ([D7](#d7--unknown-display--illegalargumentexception-reproduce)).
- **`display` of `null` *and* `""` → `page`** (not IAE) — the `isEmpty` rule in work item 1. `?display=` is
  reachable, so this is a regression guard, not a curiosity.
- Template miss → throws (not `null`).
- `toHtmlResponse` sets `Content-Type: text/html; charset=UTF-8` **and the entity bytes are UTF-8** —
  asserted with a **non-ASCII data-model value** (e.g. a client name `Ünïcode`). **The templates are ASCII
  (finding 5), so an ASCII data model would pass even with the ISO-8859-1 bug** — this is R-3c.4 and the test
  must be written to catch it.
- Render failure **propagates** and **no partial output escapes** — assert the throw *and* that no `Response`
  is produced. Note this asserts the **eager-render** property (what actually fixes finding 4), and it passes
  under either exception handler.
- **`RETHROW_HANDLER` is pinned** — assert it on the `Configuration` directly:
  `assertThat(cfg.getTemplateExceptionHandler()).isSameAs(TemplateExceptionHandler.RETHROW_HANDLER)`.
  ⚠ This is the **only** assertion that fails if the `setTemplateExceptionHandler` line is deleted; a
  behavioural "does it throw?" test does not ([D10](#d10)). Same reasoning for the other three inert config
  pins — assert `VERSION_2_3_0` (via `cfg.getIncompatibleImprovements()`), the `SAFER_RESOLVER` and
  `"UTF-8"` defaults. They are no-ops **today**, so only a config assert can stop them silently regressing.

### B. `RestletRendererParityTest` — the oracle (**highest value**)

Drives **both** renderers in one JVM and asserts identical output. Possible only because Restlet is on the
classpath until 5d/8.

Why it outweighs everything else: **3b's own as-built lesson #2** — characterization tests written *before*
the strip "failed **3/4** against the unmodified code", because the author's belief about `handle(String)`'s
contract was wrong. Every parity claim in this document is, until executed, a *belief*. This test is the only
instrument that converts beliefs into facts mechanically.

Restlet-side scaffolding (in-process, no server, no HTTP connector):

```java
Component comp = new Component();                                // NOT `new Context()` — see below
TemplateFactory.newInstance(comp.getContext().createChildContext())
        .getTemplateRepresentation("templates/page/error.ftl")   // → TemplateRepresentation
        .setDataModel(model);                                    // then .getText() → String
```

> **✅ The §B unknown is RESOLVED (2026-07-17) — and the original answer was wrong in both directions.**
>
> **`new org.restlet.Context()` does not work.** It constructs fine and `TemplateFactory.newInstance` succeeds,
> but the first `getTemplateRepresentation` throws:
> ```
> NullPointerException: Cannot invoke "org.restlet.Restlet.handle(org.restlet.Request)"
>   because the return value of "org.restlet.Context.getClientDispatcher()" is null
> ```
> A bare `Context` has a **null `clientDispatcher`** (the field is returned unguarded, no lazy init), and
> `ContextTemplateLoader.findTemplateSource` calls `.handle()` on it.
>
> **`MultiTemplateLoader` does *not* fall through, contrary to this plan's original guess.** An NPE is not an
> `IOException`, so neither `MultiTemplateLoader` nor `TemplateRepresentation.getTemplate`'s `catch (IOException)`
> (which is what turns a miss into `null`) intercepts it. It propagates straight out.
>
> **The proposed fallback would have destroyed the oracle.** "Build the Restlet leg with a
> `ClassTemplateLoader`-only `Configuration`" means the Restlet leg no longer drives `TemplateFactory` at all —
> it drives a *reimplementation* of it, and `Restlet == golden` degenerates into "my hand-built config equals my
> new config", proving nothing about legacy behaviour. That is precisely the failure
> [chf-patterns §13](chf-patterns.md#13-the-3-way-golden-oracle-phase-3c--how-parity-survives-restlets-deletion)
> exists to prevent. **Do not take it.**
>
> **Use a `Component` context instead** (recipe above). `Component.getContext().createChildContext()` supplies a
> real client dispatcher with **no CLAP client registered** — which is exactly `RestEndpointServlet`'s shape
> (finding 2) — so `ContextTemplateLoader` returns `null` gracefully and `MultiTemplateLoader` falls through to
> `ClassTemplateLoader` as production does. **Verified: renders all 10 templates.**

**Popup composition needs a second scaffold — `TemplateFactory` alone cannot express it.** Composition lives in
`OAuth2Representation.getRepresentation(Context, OAuth2Request, String, Map)` (`:79-92`), not in
`TemplateFactory`, so the snippet above can only characterize *single-template* renders. Hand-composing
`htmlCode` in the test would again be asserting against a reimplementation. Drive the real object:

```java
OAuth2Representation rep = new OAuth2Representation(null);        // requestFactory is only used by
                                                                  // toRepresentation(), never by getRepresentation()
OAuth2Request req = mock(OAuth2Request.class);
given(req.getParameter("display")).willReturn("popup");
rep.getRepresentation(comp.getContext().createChildContext(), req, "authorize.ftl", model);  // → Representation
```

**✅ The premise is already proven (2026-07-17, plan review).** A throwaway harness ran exactly this comparison
— the real `TemplateFactory` (Component context) vs. the work-item-1 `Configuration` verbatim — over **all 10
templates**, with a non-ASCII data model and producer-accurate types:

```
IDENTICAL templates/page/authorize.ftl (2837)   IDENTICAL templates/page/error.ftl (1932)
IDENTICAL templates/popup/authorize.ftl (2789)  IDENTICAL templates/page/checkSession.ftl (2160)
IDENTICAL templates/touch/authorize.ftl (2788)  IDENTICAL templates/FormPostResponse.ftl (1366)
IDENTICAL templates/wap/authorize.ftl (2802)    IDENTICAL templates/CodeVerificationForm.ftl (1521)
IDENTICAL templates/popup/popup.ftl (1425)      IDENTICAL templates/CodeThanks.ftl (1503)
==== identical=10  different=0  errors=0 ====
```

So `VERSION_2_3_0` + `ClassTemplateLoader`-only + `UTF-8` + `SAFER_RESOLVER` + `RETHROW` is **byte-identical to
today on every shipping path**. This does **not** discharge §B — a throwaway probe is not a committed
regression guard, and it did not cover popup composition through `OAuth2Representation` — but it means the test
is expected to go green on first run, and **a red §B is now a genuine signal, not the routine cost of
discovery**. If it goes red, distrust the new code, not the plan.

**Honest limitation: this test dies in 5d/8.** It is a development-time instrument — which is exactly why it
must write down what it learns → §C.

### C. Golden files — **yes for HTML**

This establishes the repo's **first** golden-file infrastructure. Verified: no `*.golden`, no `expected/` dirs
anywhere; the nearest precedent is `openam-rest/src/test/java/org/forgerock/openam/rest/fluent/JsonUtils.java`'s
`assertJsonValue(JsonValue, resourcePath)` (comparing `toString()` against a classpath resource; duplicated in
openam-audit-core). [plan.md](plan.md) risk #14 already names golden render tests and Phase 5d already promises
them — **3c-1 is simply the last moment the oracle is alive to generate them truthfully**.
`openam-oauth2/src/test/resources/` currently holds only two groovy scripts, so this is a new subtree:
`openam-oauth2/src/test/resources/golden/<display>/<name>.html`.

10 templates × 1 data model each, **each model derived from that template's real producer**, never invented
([D12](#d12--golden-data-models-are-derived-from-the-producers)). The output is large and structural; there is
no readable way to assert it inline.

> ⚠ **Pin the golden files' own I/O charset to UTF-8 — explicitly, on both read and write.** Finding 5's
> `setDefaultEncoding("UTF-8")` pins how FreeMarker **reads `.ftl` templates**; it says nothing about how the
> *test* reads and writes `golden/*.html`. `new String(bytes)` / `Files.readString` / `FileWriter` without an
> explicit `Charset` resolve against `file.encoding`, which is exactly the JDK 11–26 × 3-OS variable this phase
> is trying to eliminate (JEP 400 flipped it at 18). Left unpinned, the goldens are stable on the author's
> machine and flap on CI — and R-3c.4 deliberately puts **non-ASCII in the data model**, so the golden bytes
> *are* non-ASCII and this bites for real. Use `Files.readString(path, UTF_8)` / `Files.write(path,
> s.getBytes(UTF_8))` (or read the classpath resource through an explicit `InputStreamReader(in, UTF_8)`).

**Design — fuse B and C into one 3-way assert.** `RestletRendererParityTest` reads the golden and asserts
**Restlet == golden == CHF**:
- **Today:** maximal confidence — the golden is *proven* to be Restlet's real output, and CHF is proven to
  match it.
- **Post-5d:** delete the Restlet leg; it degrades gracefully to `golden == CHF` — a durable regression guard
  that still encodes Restlet's truth after Restlet is gone.
- The 5d/8 deletion is then a **mechanical one-line removal**, not a test rewrite.

This is the answer to "how does parity survive Restlet's deletion", and it costs one extra assert. Provide a
`-Dgolden.regenerate=true` mode for the initial generation. **Never regenerate a golden after 5d** without
re-deriving it from git history (R-3c.2).

### Considered and rejected

- **An e2e leg for 3c-1** — the renderer is unrouted; no HTTP request can reach it. The HTML contract rows
  (`Content-Type`) are locked by [3c-2's e2e spec](phase-3c-2-error-layer.md#e-e2e-error-contract-lock),
  which is where the error page becomes observable.
- **A Guice binding guard** (3b's `OAuth2GuiceModuleTest` pattern) — **not applicable**: 3c-1 adds no
  bindings (the renderer JIT-binds). openam-oauth2 has no `commons.guice:test` dep and stays off.
- **Fixing the template bugs** — [D8](#d8--template-bugs-defer-do-not-touch).

## Verification

1. `mvn -o -pl openam-oauth2 install -DskipTests` → `mvn -o -pl openam-oauth2,openam-uma test`.
   **Baseline (3b as-built): openam-oauth2 716, openam-uma 192**, 0 failures/errors/skips. 3c-1 is additive ⇒
   openam-uma must stay **exactly 192**; openam-oauth2 grows by the two new suites.
2. `mvn install -DskipTests` (whole reactor). 3c-1 adds no cross-module signature changes, but **doclint is
   fatal** (`-Xdoclint:all,-missing` + `failOnWarnings`, commit `3c45ff8d53`), and a new class with javadoc is
   exactly where a dangling `{@link}` lands. Non-negotiable.
3. Grep gates:
   - `grep -rn "org.restlet" openam-oauth2/src/main/java/org/openidentityplatform/openam/oauth2/http/ --include=*.java` → **0**
     (the new package must be Restlet-free; the parity *test* legitimately imports Restlet).
   - `grep -rn "setEntity(" openam-oauth2/src/main/java/org/openidentityplatform/openam/oauth2/http/` → no
     `setEntity(<String>)` on an HTML path; every HTML body goes through `getBytes(UTF_8)` (finding 3).
4. **No route flip ⇒ no behaviour change expected anywhere.** No e2e for this commit.
5. CI (`.github/workflows/build.yml`): `build-maven` runs 9 legs (ubuntu × JDK 11/17/21/25/26, macOS × 11/26,
   windows × 11/26) on the `features/**` push. The UTF-8 pin (finding 5) is precisely what makes the goldens
   stable across that matrix.

## Parity checklist

| Item | Verdict | Guard |
|---|---|---|
| Rendered HTML byte-identical, all 10 templates | reproduce | **golden 3-way** (§B+§C) |
| `Content-Type: text/html; charset=UTF-8` | reproduce (was implicit) | renderer test asserts header **and UTF-8 bytes with a non-ASCII model value** |
| FreeMarker ii = 2.3.0 | reproduce ([D10](#d10)) | `VERSION_2_3_0` pinned with a comment naming the ObjectWrapper branch; goldens |
| `templates/{display}/{name}.ftl` resolution | reproduce | renderer test per display folder |
| `FormPostResponse.ftl` bypasses the display folder | reproduce | renderer test |
| Popup composition (`htmlCode` → `popup.ftl`) | reproduce | parity test |
| Popup ignores `templateName` | **fix** ([D5](#d5--popup-hardcoding-authorizeftl-fix)) | renderer test; checkSession consequence recorded for 5b |
| Unknown `display` → IAE | reproduce ([D7](#d7--unknown-display--illegalargumentexception-reproduce)) | renderer test |
| Template miss → `null` | **fix → throw** | renderer test |
| `wap/authorize.ftl` is WML, but served as `text/html` | **reproduce** (decided 2026-07-17) | `toHtmlResponse` gives it `text/html; charset=UTF-8` like every other page; goldens pin the body. **Revisit in 5b** |
| Template typos (`isplayName`, `/XUI`, `display_scope`) | **defer** ([D8](#d8--template-bugs-defer-do-not-touch)) | goldens pin current output |
| `clap:///` loader | **drop** (dead) | finding 2; goldens prove equivalence |
| DEBUG_HANDLER stack traces into HTML | **fix — via eager render-to-`String`**, *not* via RETHROW ([D10](#d10)) | renderer test asserts throw **and** that no partial `Response` escapes |
| `RETHROW_HANDLER` pinned (inert today; guards a future streaming refactor) | hardening ([D10](#d10)) | **config assert** — `getTemplateExceptionHandler()` is `RETHROW_HANDLER`; a behavioural test cannot catch its removal |
| `SAFER_RESOLVER`, `setDefaultEncoding("UTF-8")` | **fix** (no-ops today) | finding 5; goldens |
| Per-request `Configuration` | **must not happen** | `@Singleton` + ctor-built; javadoc names the trap |

## Execution order

1. ~~**Resolve the §B unknown**~~ — **done during plan review (2026-07-17)**. Answer: `new Context()` NPEs;
   use `new Component().getContext().createChildContext()`; `MultiTemplateLoader` does **not** fall through on
   an NPE; the "ClassTemplateLoader-only Restlet leg" fallback is rejected as oracle-destroying. See §B.
2. **Read the producers first** ([D12](#d12--golden-data-models-are-derived-from-the-producers)) — build the 10
   data models from `ConsentRequiredResource.getDataModel`, `OpenIDConnectCheckSessionEndpoint:116`,
   `AuthorizationService:205`, `ExceptionHandler:137`, `DeviceCodeVerificationResource`. Mind the three
   counter-intuitive types in finding 8. Getting this wrong is the one error the parity leg **cannot** detect.
3. **`RestletRendererParityTest`, Restlet leg only** — drive `TemplateFactory` and **write the goldens**
   (`-Dgolden.regenerate=true`, UTF-8 pinned on golden I/O per §C). ***Before any new main code exists.*** This
   is 3b's as-built #2 lesson applied: characterize first, and let the oracle correct you. Commit the goldens.
4. `FreemarkerTemplateRenderer` + `FreemarkerTemplateRendererTest`.
5. **Close `RestletRendererParityTest`'s CHF leg** → the 3-way assert goes green (or tells you something true).
   Expected green on first run — the premise was proven during review (§B) — so **red means the code is wrong**.
6. `mvn -o -pl openam-oauth2 install -DskipTests` → `test` → whole-reactor build → grep gates.
7. ~~Correct [chf-patterns.md](chf-patterns.md) §6/§2 and add §13~~ — **done during 3c planning**; §2, §6 and
   §13 already carry their corrections and inline `Corrected 2026-07-17` notes. Plan review added the
   Component-context recipe to §13. Nothing left here.
8. Update [plan.md](plan.md) (3c → 3c-1/3c-2 rows; package correction) and [decisions.md](decisions.md)
   (D5). Record an **As-built** section here (3a/3b convention), then start
   [phase-3c-2-error-layer.md](phase-3c-2-error-layer.md).

Steps 3 and 5 are the spine: **the oracle exists before the code, and the code is measured against it.**

## Risks (extends [plan.md](plan.md)'s register)

| # | Risk | Detail | Mitigation |
|---|---|---|---|
| **R-3c.1** | **Build-ahead has no live guard** (R-3.4 realised) | The renderer is unrouted; no existing test asserts HTML/charset/popup. A wrong contract is invisible until 5d | The golden 3-way (§B+§C) *is* the guard. [phase-3-research.md](phase-3-research.md) R-3.4 proposed "consider a `phase-3-golden/` capture step" — **this is that step, executed** |
| **R-3c.2** | **The oracle expires** | `RestletRendererParityTest` dies in 5d/8; a golden regenerated after that is unfalsifiable | Goldens generated **only** while the Restlet leg lives; post-5d the test degrades to `golden == CHF` by deleting one assert. Never regenerate after 5d without re-deriving from git history |
| **R-3c.3** | **chf-patterns §2/§6 are wrong** and every later phase reads them | Findings 3 and 9. 3d/4/5 will build filters and set entities on these premises | Fix both sections in this commit (step 6). Highest-leverage doc change in the phase |
| **R-3c.4** | **Silent ISO-8859-1 HTML** | `setEntity(String)` without a prior `Content-Type` mangles non-ASCII (finding 3). All templates are ASCII, so **unit tests with ASCII data models will not catch it** | Mandate `getBytes(UTF_8)`; renderer test asserts bytes with a **non-ASCII data-model value** (not a non-ASCII template) |
| **R-3c.7** | **FreeMarker ii bump smuggled in** | `new Configuration(VERSION_2_3_31)` looks like a harmless modernisation; it changes the ObjectWrapper (finding 4) | `VERSION_2_3_0` pinned **with a comment naming the ObjectWrapper branch**; **the config assert in `FreemarkerTemplateRendererTest` is the only guard**. ⚠ **Corrected as-built:** this row previously said "goldens would catch it" — **they do not**. Verified by mutation: bumping ii to `VERSION_2_3_31` leaves **all 11 goldens byte-identical**, because the ObjectWrapper swap is only observable for data models that exercise it (beans, arrays, `?api`) and every producer-derived model is a plain `Map` of `String`/`Boolean`/`Map`. See [as-built #2](#as-built) |
| **R-3c.10** | **Per-request `Configuration`** | Hanging it on `AttributesContext` (per-request) rebuilds the loader and voids the template cache every request | `@Singleton` + ctor-built `Configuration`; the trap is called out in the javadoc |
| **R-3c.11** | **Fictional golden data models** — the one error the parity leg *cannot* catch | Both legs get the **same** model, so `Restlet == CHF` passes even when the model is a shape production never emits. The golden then guards nothing in its post-5d regression role, and R-3c.2 makes that unfalsifiable. Three keys invite it: `display_scopes`/`display_claims` are JSON **text**, `valid_session` is a **String** (finding 8) | [D12](#d12--golden-data-models-are-derived-from-the-producers): derive every model from its producer; types recorded in finding 8; execution step 2 does this **before** the goldens are written |
| **R-3c.12** | **Goldens flap on CI via unpinned file I/O** | Finding 5 pins how FreeMarker *reads templates*, not how the test reads/writes `golden/*.html`. Default-charset I/O resolves against `file.encoding` — the exact JDK 11–26 × 3-OS variable this phase eliminates — and R-3c.4 puts non-ASCII **in the goldens** | Explicit `UTF_8` on golden read **and** write (§C). **As-built: load-bearing, not theoretical — 6 of the 11 goldens really are non-ASCII** |

<a id="as-built"></a>

## As-built (3c-1 delivered — 2026-07-17)

Delivered as planned — **one** new main class, wired to no route, so `/oauth2` still renders through
Restlet and nothing is observable. Gates: openam-oauth2 **743** tests (3b baseline 716; **+27** = 11
parity + 16 renderer), openam-uma **192** unchanged (additive, as required), whole-reactor
`mvn install -DskipTests` BUILD SUCCESS, `javadoc:javadoc` clean under `-Xdoclint:all,-missing` +
`failOnWarnings`, all grep gates 0. **The parity leg was green on first run**, exactly as §B predicted —
so the premise held and no discovery cost was paid at this step.

Six deviations and discoveries worth recording.

1. **Eleven goldens, not ten.** §C said "10 templates × 1 data model each"; §B separately noted that popup
   composition needs its own scaffold. Composition is a distinct output no single-template golden can
   express, so it became an 11th golden (`golden/composed/popup-authorize.html`) — the Restlet leg drives
   the real `OAuth2Representation`, the CHF leg drives `renderForDisplay`. It asks for `authorize.ftl`
   deliberately: that is the one template name where [D5](#d5--popup-hardcoding-authorizeftl-fix) is a
   no-op (the legacy hardcode names the same file), so a genuine 3-way assert holds. The D5 divergence is
   proven separately against a synthetic `StringTemplateLoader` pair.

2. **⚠ R-3c.7's stated guard was wrong: the goldens do *not* catch a FreeMarker ii bump.** The risk table
   credited "goldens would catch it". Mutation-tested against the delivered code: bumping
   `VERSION_2_3_0` → `VERSION_2_3_31` leaves **all 11 goldens byte-identical** and the parity suite fully
   green. The ObjectWrapper swap (finding 4) is only observable for data models that exercise it — beans,
   arrays, `?api` — and every producer-derived model here is a plain `Map` of `String`/`Boolean`/`Map`.
   **The `Configuration` assert is the sole guard**, which is precisely the argument
   [D10](#d10) already made for `RETHROW_HANDLER` — it generalises to *every* inert config pin, and the
   plan applied it to only one of them. Row corrected above.

3. **⚠ R-3c.4's `byte[]`-vs-`String` choice is unobservable by any test, under correct ordering.**
   Mutation-tested: weakening `setEntity(html.getBytes(UTF_8))` to `setEntity(html)` while the
   `Content-Type` is still set **first** keeps every test green — necessarily, because `Entity.setString`
   then reads `charset=UTF-8` off the header and emits byte-for-byte the same result. The tests do catch
   the two shapes that matter (verified): setting the entity **before** the header, and dropping the
   header entirely. So the `byte[]` form is defence-in-depth against a future reordering and is guarded by
   **the grep gate, not by a test** — the plan's verification step 3 is load-bearing and must not be
   retired on the belief that a test covers it. Recorded in the test javadoc.

4. **The render error contract is checked: `throws IOException, TemplateException`.** The plan mandated
   "render or throw" but left checked-vs-unchecked open, and its API sketch implied unchecked. Checked was
   chosen: it forces 3c-2 and 5b to handle failure at compile time, which directly mitigates
   [chf-patterns](chf-patterns.md) §2's trap (a thrown exception inside `Endpoints.from` becomes an
   *empty* 500). It also yields a coherent split — unchecked `IllegalArgumentException` = the client's
   fault (`?display=bogus` → 5b maps to `invalid_request`/400); checked = our fault (missing or broken
   template) → 500. Costs no new class, and leaking FreeMarker types from a class named
   `FreemarkerTemplateRenderer` is mild.

5. **D12 was vindicated concretely — three facts a hand-written fixture would have got wrong.** All three
   were discovered *by the oracle*, not by reasoning: (a) `JsonValue.toString()` emits **spaced** JSON
   (`[ { "name": "..." } ]`), so a hand-copied compact string would have baked a lie into the golden;
   (b) `?js_string` escapes `/` as `\/`, so `realm` renders `"\/"`; (c) those compound in
   `CodeThanks.ftl:33`'s `/XUI` bug to produce the genuinely mangled `realm : "\//XUI"`, now pinned. The
   fixtures build `display_scopes`/`display_claims` by running the producer's own `JsonValue` calls —
   including `ConsentRequiredResource:119,123`'s add-then-put ordering, which relies on `getObject()`
   returning the live map — rather than by transcribing expected text.

6. **The non-ASCII marker had to go in `user_name`, not `display_name`.** R-3c.4 wants non-ASCII in the
   data model, but `ConsentRequiredResource:88-89` pushes `display_name`/`display_description` through
   `ESAPI.encoder().encodeForHTML`, which folds any high character back to an ASCII entity and would have
   silently defeated the byte assertions. `user_name` (`:91`) is stored raw and `?js_string` does not
   touch non-ASCII, so it survives to the bytes. The fixtures carry ESAPI's *output* for the encoded keys
   (`"Demo &amp; Co"`), which is what production actually emits. Net: **6 of 11 goldens are non-ASCII**,
   making R-3c.12's UTF-8 pinning genuinely tested rather than decorative.

*Minor:* a package-private `@VisibleForTesting Configuration configuration()` accessor was added — per
#2 it is the only guard for four inert pins, so the test needs the object itself.
`org.forgerock.util.annotations.VisibleForTesting` was chosen over Guava's (repo-wide 44 vs 10; both are
on this module's classpath).
