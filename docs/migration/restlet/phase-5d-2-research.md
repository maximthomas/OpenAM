# Phase 5d-2 research — what the deletion actually touches

Measured against the tree at `83f465452b` (2026-08-06), the commit that carries the 5d-1 soak fix.
Everything below was read from source; the point of writing it down is that **5d-2 should not have to
read that source again**. The spec that consumes this is [phase-5d-2.md](phase-5d-2.md).

Where a finding contradicts [§ Handed to 5d-2](phase-5d-1-asbuilt.md#handed-to-5d-2) or
[inventory §12](inventory.md#12-deletion-checklist-final-state), the contradiction is called out —
those lists were written before the /oauth2 flip and two of their five traps are now wrong.

---

<a id="1"></a>
## 1 — WebFinger is the blocker, and it is why 5d-2a exists

`WebFinger` and `OpenIDConnectDiscovery` are **phase 6**, not 5d-2. But between them they import
twelve classes that 5d-2 exists to delete:

| Importer | What it drags in |
|---|---|
| `WebFinger:20,24,25,28,29` | `RestletBodyAuditor.noBodyAuditor`, `GuicedRestlet`, `OAuth2StatusService`, `OAuth2AccessAuditFilter`, `RestletRealmRouter` |
| `OpenIDConnectDiscovery:25,26,31` | `ExceptionHandler`, `OAuth2RestletException`, `ServletUtils` |
| transitively | `OAuth2AbstractAccessAuditFilter` (base of `OAuth2AccessAuditFilter`), `AbstractRestletAccessAuditFilter` (its base, openam-rest), `JacksonRepresentationFactory` (`ExceptionHandler:24`), `RestletUtils` (`GuicedRestlet`) |

So a 5d-2 that runs before phase 6 cannot empty a single one of the three Restlet packages, and the
`grep org.restlet == 0` gate is unreachable. **Decision (2026-08-06): port WebFinger first, as
5d-2a.** It is cheap — 239 lines across three classes, one `@Get`, one route — and
[plan.md's phase 6 row](plan.md#phase-status) records that the endpoint has been **500 on every
request** since before the migration began, with `e2e/oauth2/webfinger-test.spec.mjs` already written
against the contract it *ought* to serve.

### What the port has to reproduce

`WebFinger:69-84` is an `Application` whose `createInboundRoot` is a `RestletRealmRouter` with one
attachment, `/webfinger` → `OpenIDConnectDiscovery`, wrapped in
`OAuth2AccessAuditFilter(…, noBodyAuditor(), noBodyAuditor())`. The `Application` also sets
`OAuth2StatusService` and a default media type of `application/json` (`:58-60`).

`OpenIDConnectDiscovery:71-90` is the whole endpoint:

```java
OAuth2Request request = requestFactory.create(getRequest());
String resource = request.getParameter("resource");
String rel      = request.getParameter("rel");
String realm    = request.getParameter("realm");
String deploymentUrl = baseUrlProviderFactory.get(realm).getRootURL(ServletUtils.getRequest(getRequest()));
Map<String,Object> response = providerDiscovery.discover(resource, rel, deploymentUrl, request);
return new JsonRepresentation(response);           // OAuth2Exception -> OAuth2RestletException
```

`providerDiscovery` (`OpenIDConnectProviderDiscovery`) is already transport-free. The **only** reason
it 500s today is `ServletUtils.getRequest(...)`: web.xml mounts the application on **upstream**
`org.restlet.ext.servlet.ServerServlet` (`web.xml:1048`), not OpenAM's jakarta port, so
`ServletUtils` does not recognise the call, returns `null`, and `getRootURL(null)` NPEs. A CHF
handler reads the servlet request off `AttributesContext` and the defect cannot recur.

### Routing facts

- `/.well-known/*` (`web.xml:1093-1095`) is the **only** mapping the `WebFinger` servlet has, and
  after 5d-1c it is the **only** Restlet servlet mapping left in the WAR — `ForgeRockRest`
  (`web.xml:1143-1146`) is a declaration with no mappings at all.
- Nothing else in `web.xml` mentions `.well-known`. `/oauth2/.well-known/openid-configuration` is a
  different path, already served by `OAuth2HttpRouteProvider:196`.
- The CHF servlet uses `routing-base=context_path`, so a provider keyed
  `newHttpRoute(STARTS_WITH, ".well-known")` is the exact equivalent — same lever every other phase used.

<a id="1-review"></a>
### Review of 5d-2a, 2026-08-06 — four corrections and six confirmations

Measured while reviewing the sub-phase. **Correct the claims above where they conflict.**

**Correction 1 — the endpoint is not broken end to end; only the success path is.**
`OpenIDConnectDiscovery:98-100` overrides `doCatch` to `ExceptionHandler.handle(Throwable, Response)`,
the **two-arg** overload at `ExceptionHandler:147-157`. It renders
`jacksonRepresentationFactory.create(exception.asMap())` and takes the status off the exception — no
`getRootURL`, so no NPE. A missing `resource` returns a **live, working 400** today; so do the bad-`rel`
400 and the unknown-user 404. Only the JRD path NPEs. The four-arg overload at `:82-135` is the one
that renders `error.ftl` and *would* NPE on `getRootURL(ServletUtils.getRequest(request))` — it is
reached only from the Restlet `OAuth2Filter`, which never wrapped this application. `webfinger-test.spec.mjs`'s
header comment states the broader claim and is wrong; 5d-2a-ii fixes it.

**Correction 2 — `@ExceptionHandler` dispatch is polymorphic, not exact-type.** `AnnotatedMethod:69`
keys the map by declared type, which reads like exact-match, but `mostSpecificExceptionHandler`
(`:195-202`) selects by `candidate.isInstance(t)` and keeps the most specific. So one
`@ExceptionHandler(OAuth2Exception)` catches every subclass. This matters beyond 5d-2a: it is why
`AbstractOAuth2HttpJsonEndpoint.onError` has been catching `BadRequestException` and friends since
5a-2, and it removes the only reason 5d-2a might have needed a CHF change.

**Correction 3 — `HEAD` is already handled.** `Endpoints:70-72` maps `HEAD` to the `GET` method
(`methods.put("HEAD", methods.get("GET"))`), with a comment citing RFC 7231 §4.3.2. Restlet answered
`HEAD` through `@Get` and CHF now does the same. No divergence, no openam-http work.

**Correction 4 — the audit filter belongs *inside* the realm layer.** `WebFinger:76` wraps the audited
restlet in the `attach(...)` *under* its `RestletRealmRouter`, and `OAuth2HttpRouteProvider.endpoint()`
does the identical thing (`chainOf(handler, auditFilter)` inside `endpointRouter`, itself behind
`RealmContextFilter`). An audit filter hoisted above the realm filter publishes events with no realm.

**Confirmed, so nobody re-checks:**

1. **The deletion is clean.** `grep -rn "WebFinger\|OpenIDConnectDiscovery"` across `*.java` / `*.xml` /
   `*.properties` finds only the two classes themselves, their mutual reference, `web.xml:1047,1053,1093`,
   and prose in `openam-documentation`. **No Guice binding, no `META-INF/services` entry.**
2. **`web.xml`'s only `org.restlet` references are five lines, all inside the WebFinger servlet block**
   (`:1048, 1053, 1058, 1064` plus the class name). Deleting that block makes criterion 10's
   `grep -c org.restlet web.xml` → 0 achievable in 5d-2a-ii alone.
3. **Realm plumbing survives the port unchanged.** `ChfOAuth2Request:392-397` seeds
   `OAuth2Constants.Custom.REALM` / `REALM_OBJECT` from `RealmContext`, and `getParameter` checks
   attributes before query (`:63-69`) — so `getParameter("realm")` yields the resolved realm path, as
   `RestletRealmRouter.doHandle` did via request attributes. `RealmContextFilter:211` applies the
   `?realm=` override, matching `RestletRealmRouter.getRealmFromQueryString`. Both Restlet spellings
   keep working and `/realms/{realm}` comes free.
4. **`OpenIDConnectProvider.isUserValid` is not a `RestletRealmRouter` constant reader** — it imports
   `OAuth2Constants.Params.REALM` (`:20`). All the `REALM`-family constants are the string `"realm"` /
   `"realmObject"`, so [§5](#5)'s list of six readers stands; this is not a seventh.
5. **`BaseURLProvider.getRootURL(HttpServletRequest)` (`:77`) declares no checked exception** — only
   `getRealmURL` throws `InvalidBaseUrlException`. The handler needs no try/catch around it, just the
   null-guard.
6. **The no-match shape is `OAuth2StatusService:17-23`** — `{"error": status.getReasonPhrase(),
   "error_description": status.getDescription()}`. That is the incumbent for `/.well-known/nonsense`,
   bare `/.well-known/`, and an unresolvable realm segment (`RestletRealmRouter` throws
   `ResourceException(404, "Realm \"x\" not found")`). `OAuth2NotFoundHandler` answers
   `{"error":"not_found","error_description":"Not Found"}` — hence divergence row 34.
7. **`OAuth2Error.of(OAuth2Exception)` (`OAuth2Error:189-206`) maps `statusCode`/`error`/`message`
   exactly as `OAuth2RestletException.asMap()` (`:163-176`) does**, so the three working error paths
   should port byte-identically. That is what makes them parity targets rather than divergences.

---

<a id="2"></a>
## 2 — The deletion inventory, module by module

Counts are files, measured. "Clean" = the file is already Restlet-free.

### openam-oauth2 — main (51 files import `org.restlet`)

**`org.forgerock.oauth2.restlet` — 23 of its 24 files die**, plus 1 of the 3 in its `resources`
sub-package. Everything except the clean ones below:
`AccessTokenFlowFinder`, `AuthorizeEndpointFilter`, `AuthorizeRequestHook`, `AuthorizeResource`,
`ConsentRequiredResource`, `DeviceCodeResource`, `DeviceCodeVerificationResource`, `ErrorResource`,
`ExceptionHandler`, `GuicedRestlet`, `OAuth2Filter`, `OAuth2FlowFinder`, `OAuth2Representation`,
`OAuth2RestletException`, `OAuth2StatusService`, `RefreshTokenResource`, `RestletConstants`,
`TemplateFactory`, `TokenEndpointFilter`, `TokenEndpointResource`, `TokenIntrospectionResource`,
`TokenRequestHook`, `ValidationServerResource`, plus
`resources/ResourceSetRegistrationExceptionFilter`.

**Three classes are stranded in Restlet packages and must survive** — they import no Restlet at all
and are live on the CHF path. They need to *move*, not die:
`oauth2/restlet/OpenAMClientAuthenticationFailureFactory`,
`oauth2/restlet/resources/ResourceSetDescriptionValidator`,
`oauth2/restlet/resources/ResourceSetRegistrationHook`. This confirms and extends
[5c finding 8](phase-5c-research.md#8--the-restlet-resources-package-is-not-deletable-at-5d-2), which
named only the two in `resources`.

**`org.forgerock.openidconnect.restlet` — 9 of 10 die**, plus `WebFinger`/`OpenIDConnectDiscovery` at
5d-2a: `ConnectClientRegistration`, `EndSession`, `IdTokenInfo`,
`OpenIDConnectCheckSessionEndpoint`, `OpenIDConnectConfiguration`, `OpenIDConnectJWKEndpoint`,
`UserInfo`. **`LoginHintHook` survives** — it implements four interfaces
(`LoginHintHook:42`), two Restlet (`AuthorizeRequestHook`, `TokenRequestHook`) and two CHF
(`ChfTokenRequestHook`, `ChfAuthorizeRequestHook`). Each hook point exists twice, once per transport:
`beforeAuthorizeHandling` at `:54` (Restlet) / `:110` (CHF), `afterAuthorizeSuccess` at `:73` / `:132`,
`afterTokenHandling` at `:90` / `:99`. Strip the Restlet three, move the class out of a `.restlet`
package.

**Elsewhere in openam-oauth2:** `openam/oauth2/AccessTokenProtectionFilter`,
`openam/oauth2/resources/ResourceSetRegistrationEndpoint`, `openam/oauth2/rest/OAuth2RouterProvider`,
`openam/oauth2/rest/TokenRevocationResource`, `oauth2/core/RestletOAuth2Request`, and the three
Restlet audit filters `openam/rest/audit/{OAuth2AbstractAccessAuditFilter, OAuth2AccessAuditFilter,
UMAAccessAuditFilter}`. Total pure-Restlet main source in openam-oauth2: **~5,380 lines**.

**Edited, not deleted:** `oauth2/core/OAuth2Request` (the deprecated `getRequest()` at `:54-62`),
`oauth2/core/OAuth2RequestFactory` (`:34` import, `:75` the `RestletOAuth2Request` branch),
`oauth2/core/ResourceOwnerAuthenticator` ([§4](#4)), `oauth2/core/ResourceOwnerSessionValidator`
(`:94,382` — `Reference` used only to build a login URI), `openam/oauth2/StatefulTokenStore`
(`:88` — `Status.*.getCode()` constants at `:729,740,760,767,777`),
`openam/oauth2/OAuthProblemException` ([§3](#3)), `openam/oauth2/rest/TokenResource`
(`:108` — **the import is unused**, no `org.restlet.Request` reference in the body), and both Guice
modules.

### openam-oauth2 — test (16 files)

Delete with their subjects: `oauth2/restlet/AuthorizeResourceTest`,
`openidconnect/restlet/LoginHintHookTest` (rewrite for the CHF halves),
`oauth2/core/RestletOAuth2RequestTest`, `openam/oauth2/resources/ResourceSetRegistrationEndpointTest`.
Edit: `oauth2/core/OAuth2RequestFactoryTest`, `oauth2/core/ResourceOwnerSessionValidatorTest`,
`openam/oauth2/OpenAMClientRegistrationStoreTest` (`:198` stubs `getRequest()`),
`openam/oauth2/StatefulTokenStoreTest`,
`oauth2/restlet/OpenAMClientAuthenticationFailureFactoryTest` (moves with its subject).
The five parity tests are [§6](#6).

### openam-rest — 8 main + 3 test, **all now-dead**

Main: `RestEndpointServlet`, `service/RestletServiceServlet`, `service/ServiceEndpointApplication`,
`service/OAuth2ServiceEndpointApplication`, `service/RestStatusService`,
`service/JSONRestStatusService`, `audit/AbstractRestletAccessAuditFilter`,
`audit/RestletBodyAuditor`; plus the Restlet branch of `RealmRoutingFactory` ([§5](#5)).
Test: `RestEndpointServletTest`, `service/RestletServiceServletTest`,
`service/JSONRestStatusServiceTest`, `audit/AbstractRestletAccessAuditFilterTest`.

After these go **openam-rest imports no Restlet at all** and can drop its `openam-restlet`
dependency (`openam-rest/pom.xml:60`) — provided `RestRealmValidator` moves ([§7](#7)).

### The rest

| Module | File | Fate |
|---|---|---|
| openam-oauth2-saml2 | `oauth2/saml2/restlet/Saml2BearerServerResource` | delete — dead code, nothing routes it. Drops both restlet deps at `pom.xml:63,68` |
| openam-uma | `UmaProviderSettingsFactory:36,80`, `UmaUrisFactory:36,87` | edit — `RestletRealmRouter` **constants only** ([§5](#5)). No `org.restlet` type is used; the `import org.restlet.Request` on each is vestigial |
| openam-core-rest | `AuthenticationServiceV1` | edit — unused import + a javadoc reference |
| openam-core-rest | `SmsRealmProvider:25` | edit — **a real use**: `HeaderConstants.HEADER_IF_NONE_MATCH`. Inline the literal `"If-None-Match"`. The module has no restlet pom dep; it resolves transitively |
| openam-federation/OpenFM | `DefaultWsFedAuthenticator` | edit — unused imports only |
| openam-http-client | `RestletHttpClient` + 2 beans | **phase 7.** Untouched by 5d-2 |
| openam-restlet | 15 files | **phase 8.** Untouched except the two in [§5](#5)/[§7](#7) |

---

<a id="3"></a>
## 3 — `OAuthProblemException`: unchecked today, and nothing catches it

`OAuthProblemException:30` extends **`org.restlet.resource.ResourceException`**, which extends
`RuntimeException`. It is thrown from fifteen sites in live CHF-served code:

| File | Sites | Enclosing method |
|---|---|---|
| `StatefulTokenStore` | `:729,740,760,767,777` | incl. `public void deleteAuthorizationCode(...)` (`:748`) — a `TokenStore` interface method with no `throws` |
| `OpenAMClientRegistration` | `:695,734,775,793,890` | four private `by*Key/JWKs` helpers, plus `private String getAttribute(String)` at `:884` — **23 call sites**, feeding the `ClientRegistration` (15 methods) and `OpenIdConnectClientRegistration` (8 methods) interfaces |
| `RealmOAuth2ProviderSettings` | `:132` | `private void addServiceListener()` (`:120`) |
| `OAuth2ProviderSettingsFactory` | `:91` | `private void addServiceListener()` (`:79`) |
| `UmaSettingsImpl` (openam-uma) | `:82` | `private void addServiceListener()` (`:70`) |
| `OpenIdConnectToken` | `:385` | `private Jwt createJwt()` (`:379`) |
| `Utils` | `:128` | returns, does not throw |

**Three facts that decide the refactor:**

1. **Nothing anywhere in the tree catches `OAuthProblemException`** — `grep "catch (OAuthProblemException"`
   is empty. It reaches the framework as an unchecked throw and gets `openam-http`'s
   [F1](openam-http-framework.md) 500 body.
2. **Its only `getStatus()` callers are Restlet classes 5d-2 deletes** — `ExceptionHandler:113`,
   `OAuth2Filter:64,69`. After the deletion `getStatus()` (`:255`) and the `Status` import are dead.
3. **`OAuth2Exception:26` extends `Exception` — it is checked.** Folding `OAuthProblemException` into
   that hierarchy makes it checked and forces `throws` onto both ClientRegistration interfaces,
   `TokenStore`, and every caller of those; and the three `addServiceListener()` sites are
   construction-time code no `@ExceptionHandler` can ever reach.

**Decision (2026-08-06): the bridge.** `OAuthProblemException extends RuntimeException`, keeping name,
package and constructors; delete `getStatus()` and the two Restlet imports. Then add one
`@ExceptionHandler onProblem(OAuthProblemException)` to each of `AbstractOAuth2HttpJsonEndpoint` and
`AbstractOAuth2HttpBrowserEndpoint`, rendering through the existing
`OAuth2Error.of(int statusCode, String error, String description)` (`OAuth2Error:217`) and
`OAuth2ErrorResponseFactory` — both already injected on `AbstractOAuth2HttpEndpoint:43-45`. Same wire
bytes as folding it in, no interface signature changes anywhere.

⚠ **This is a behaviour change and needs its own oracle.** Today these paths answer a framework CREST
500; after the bridge they answer OAuth2-shaped JSON. The producer that must be measured is the
**current post-flip CHF stack**, which 5d-2 itself destroys — so the capture is a pre-change step of
the sub-phase that makes the change, exactly as 5-E was for the flip.

⚠ **`@ExceptionHandler` dispatch is by exact type, not by hierarchy walk** — `AnnotatedMethod:69`
holds a `Map<Class<? extends Throwable>, AnnotatedMethod>` and `:251` rejects a duplicate key. So
registering `OAuthProblemException` cannot collide with the existing `OAuth2Exception` and
`IllegalArgumentException` handlers, and UMA's `onError(Throwable)`
(`AbstractUmaHttpEndpoint:35-36`) is unaffected.

---

<a id="4"></a>
## 4 — `ResourceOwnerAuthenticator` throws a raw Restlet `ResourceException`

`ResourceOwnerAuthenticator:127,145,150` throw `new ResourceException(Status.SERVER_ERROR_INTERNAL, …)`
— Restlet's, unchecked. This is the **password grant** path, live under CHF since 5d-1c and reachable
only through `/access_token` with `grant_type=password`. As with `OAuthProblemException`, nothing
catches it; it becomes a framework 500.

It is the same class the soak fixed for realms (`d52496710e`), so its coverage is the
`e2e/oauth2/realms-test.spec.mjs` row 10 the soak added. Replacing the throw changes a live error
path and therefore needs the same pre/post capture as [§3](#3) — treat the two as one measurement.

---

<a id="5"></a>
## 5 — `RestletRealmRouter`'s constants are load-bearing on the CHF path

⚠ **This corrects [trap 5](phase-5d-1-asbuilt.md#handed-to-5d-2) in both directions.**

`org.forgerock.openam.rest.service.RestletRealmRouter` (openam-restlet) defines three constants at
`:44-46` — `REALM = "realm"`, `REALM_OBJECT = "realmObject"`, `REALM_URL = "realmUrl"` — and **six
live CHF-path files read them**, none of which is a Restlet consumer:

| Reader | Line | Constant |
|---|---|---|
| `OAuth2UrisFactory` (openam-oauth2) | `:69` | `REALM_OBJECT` |
| `OAuth2RealmResolver` (openam-oauth2) | `:51` | `REALM` |
| `UmaUrisFactory` (openam-uma) | `:87` | `REALM_OBJECT` |
| `UmaProviderSettingsFactory` (openam-uma) | `:80` | `REALM` |
| `RealmRoutingFactory` (openam-rest) | `:21-22`, used `:248-263` | both |
| `UmaUrisFactoryTest` (openam-uma, test) | — | `REALM_OBJECT` |

`REALM_URL` has exactly one reader, `RestletOAuth2Request:158`, and dies with it.

**The neutral home already exists.** `OAuth2Constants.Custom.REALM` and `.REALM_OBJECT`
(`openam-core/.../OAuth2Constants.java:784,791`; the enclosing nested class is `Custom`, declared at
`:729` — **not** `Params`) are the same string values, and the latter's javadoc
says in as many words that *"Phase 8 of the Restlet removal migrates those readers onto this constant
and deletes the duplicate."* 5d-2 should do it instead of phase 8 — it is five main files plus one
test, and it is what makes openam-uma and openam-rest Restlet-free.

**And the trap's other half is now wrong too.** Trap 5 says `RealmRoutingFactory`'s private inner
`RestletRealmRouter` (`:232-290`) "must survive 5d-2 — other Restlet consumers still call it." Its
only entry point is the `createRouter(org.restlet.routing.Router)` overload at `:116`, and that
overload has exactly **two** callers today: `OAuth2RouterProvider:96` (deleted by 5d-2) and
`WebFinger:70`'s `new RestletRealmRouter()` — the openam-restlet class, not this one. Once 5d-2a
ports WebFinger and 5d-2b deletes `OAuth2RouterProvider`, **both** `RestletRealmRouter`s are dead and
5d-2 can delete both. The trap's real content survives: *never delete by simple name* — the two are
different classes in different modules and only one of them is the outer `/oauth2` router.

---

<a id="6"></a>
## 6 — The five parity tests, and why they must be frozen before the delete

Each runs real Restlet code as one leg of a comparison, so each stops compiling with the stack:

| Test | Lines | Restlet leg |
|---|---|---|
| `RestletErrorParityTest` | 266 | `ExceptionHandler`, `OAuth2Representation`, `OAuth2RestletException`, `AuthenticatorUtils` |
| `RestletRendererParityTest` | 197 | `OAuth2Representation`, `TemplateFactory`, `TemplateRepresentation`, `Component` |
| `RestletContentTypeParityTest` | 184 | `MediaType`, `ContentType`, the representation classes |
| `RestletAuditParityTest` | 144 | `RestletBodyAuditor`, `JacksonRepresentation` |
| `RestletAcceptLanguageParityTest` | 141 | `ClientInfo`, `Language`, `Preference`, `PreferenceReader` |

**Decision (2026-08-06): convert to golden-literal pins, do not delete.** The Restlet leg is removed
and the bytes it currently produces are inlined as literal expectations, so the test keeps failing on
a CHF regression after the producer is gone. This is [risk #19](plan.md#risk-register-behavioral-compatibility)'s
"degrade to `golden == CHF`" made explicit rather than accepted.

⚠ **Ordering constraint:** the literals must be *captured by running the tests*, in a commit where
Restlet still compiles. A hand-written expectation is a guess, and guessing here silently rewrites
the oracle these five files exist to preserve.

---

<a id="7"></a>
## 7 — `RestRealmValidator`, and what phase 8 is left with

`org.forgerock.openam.rest.router.RestRealmValidator` lives in **openam-restlet** and imports no
Restlet. Its live consumer is CHF's `RealmContextFilter:60,76,79,283`; `RestRouterIT`,
`RealmContextFilterTest` and `OAuth2RouterIT` mock it. [inventory §12](inventory.md#12-deletion-checklist-final-state)
already flags "relocate → openam-rest first".

Four poms depend on openam-restlet: root, openam-oauth2 (`:172`), openam-rest (`:60`), openam-uma
(`:34`). After 5d-2's deletions, the [§5](#5) constants migration and this relocation, **no module
outside openam-restlet itself references it**, and `openam-http-client`'s `RestletHttpClient` (phase
7) is the only remaining `org.restlet` consumer in the tree — it uses the vendored fork directly, not
openam-restlet.

That makes the 5d-2 exit gate exactly checkable:

```
grep -rn "org.restlet" --include="*.java" . | grep -v "^./docs" \
  | grep -v "^./openam-restlet/" | grep -v "^./openam-http-client/"      # -> 0
```

and leaves phase 8 as a mechanical module + pom deletion once phase 7 lands.

---

<a id="8"></a>
## 8 — State of the branch at planning time

- `HEAD` = `83f465452b`, tree clean, and the branch **is** pushed — to `upstream`
  (`git@github.com:maximthomas/OpenAM.git`), whose `refs/heads/features/restlet-migration` matches
  `HEAD` exactly. There is no `origin/features/restlet-migration`; the earlier read that the soak fix
  was unpushed was wrong.
- CI run **`31105613611`** is `in_progress` on `83f465452b` — the first run that covers the soak fix
  `d52496710e`. [plan.md's 5d-2 row](plan.md#phase-status) makes this run the precondition for
  starting the deletion; it is not a task, only a gate to read before 5d-2b's first `git rm`.
- The previous green run, `31031060622`, is on `bccbc9c4d9` — the flip, without the fix.
