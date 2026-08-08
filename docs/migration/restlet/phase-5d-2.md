# Phase 5d-2 — the deletion: removing the Restlet `/oauth2` stack

Written 2026-08-06 against `83f465452b`. **5d-2a landed 2026-08-08** ([as-built](phase-5d-2-asbuilt.md)).
**The tail was re-planned 2026-08-08** against the tree as it stands after the master merge
`a8c13e07ec` — six sub-phases instead of three, plus four corrections to the research that sized the
original split. The measurements behind the re-plan are [research §11](phase-5d-2-research.md#11);
the per-file inventory is [research §2](phase-5d-2-research.md#2), **as amended by §11**.

## Context

5d-1c moved `/oauth2` onto CHF and left the Restlet stack dormant behind a one-line revert; 5d-2a then
ported `/.well-known/webfinger` and took the WAR's last Restlet servlet mapping with it. What is left
is deletion, which is cheap to write and dangerous to verify: nothing that is deleted can fail a test,
so the evidence has to come from what *stays* green. Two parts of the tail are not deletion at all —
the parity-oracle freeze (5d-2b-i) and the `OAuthProblemException` bridge (5d-2d-i) — and those are
where the risk lives.

⚠ **The revert lever dies at 5d-2b-ii.** From that commit `/oauth2` cannot be put back on Restlet by
reverting one line. CI run `31105613611` on `83f465452b` is green and is the gate on the first
`git rm` ([criterion 11](#criteria-5d-2b-i)).

## Scope & sizing — the tail, split six ways

The original three-way split put ~200k of implementation into 5d-2b alone. It was sized against
research §2, which under-counted the Restlet-legged tests (nine, not five) and called openam-uma
"constants only" when it has two real `org.restlet.Request` overloads. Each row below is one
shippable green commit inside the 150k budget, ordered by what must compile after it.

| Sub-phase | Scope | Live-path risk |
|---|---|---|
| ✅ **5d-2a-i** | WebFinger `/.well-known` → CHF, left dormant | none — [as-built](phase-5d-2-asbuilt.md#as-built-5d-2a-i--recorded-2026-08-08) |
| ✅ **5d-2a-ii** | The flip; `WebFinger` + `OpenIDConnectDiscovery` deleted; web.xml's last `org.restlet` gone | landed — [as-built](phase-5d-2-asbuilt.md#as-built-5d-2a-ii--recorded-2026-08-08) |
| **5d-2b-i** | Freeze the oracles: five byte-parity tests → golden literals ([D4](#d4)); four transport-input tests → Restlet leg dropped ([D9](#d9)). **No main source** | none — test-only |
| **5d-2b-ii** | Delete the two Restlet endpoint packages + seven elsewhere + `Saml2BearerServerResource`; both Guice unbinds; the four class moves + `LoginHintHook` strip; the `ForgeRockRest` declaration. **Reaches openam-uma** — 4 of the move's 20 import sites are there ([D3](#d3)) | low — dormant code, but Guice + four moves |
| **5d-2b-iii** | Delete `RestletOAuth2Request` and the transport de-plumb it forces — `OAuth2Request`, `OAuth2RequestFactory`, **openam-uma's two overloads**, the javadoc links ([D10](#d10)) | low — but it crosses into openam-uma and changes two injected constructors |
| **5d-2c** | Delete the openam-rest Restlet layer + `RealmRoutingFactory`'s Restlet branch, which is callerless after 5d-2b-ii | none — nothing references it |
| **5d-2d-i** | **The behaviour change:** `OAuthProblemException` bridge ([D5](#d5)) + `ResourceOwnerAuthenticator` ([D6](#d6)), with its own pre/post capture | **yes — the only deliberate behaviour change in the phase** |
| **5d-2d-ii** | The mechanical de-leak: realm constants, both `RestletRealmRouter`s, `RestRealmValidator` relocation, vestigial imports, pom sweep, exit gates | none — compile-level only |

**Why the seams fall where they do.** 5d-2b-ii/iii split at the endpoint-vs-transport boundary:
`RestletOAuth2Request` compiles standalone once the endpoints are gone, so it can survive one commit.
Both touch openam-uma, but at very different depths — b-ii rewrites four import lines, b-iii changes
two `@Inject` constructor signatures, and only the second can fail at Guice graph construction
([R-5d2.6](#risk-register)). Keeping them apart means the boot failure, if it comes, has one candidate
cause. 5d-2d-i/ii split the one behaviour change away from the sweep, so a bad capture reverts without
losing the de-leak.

**Not in scope: [row 37](phase-5d-2-asbuilt.md#row-37)**, the bodyless 500 on a bare trailing slash.
It is an `openam-http` router defect we own, it predates the migration, and `/json/`, `/oauth2/` and
`/uma/` share it — so it is neither caused by nor blocking this phase. Decided 2026-08-08 to keep it a
separate follow-up rather than mix a live-behaviour change into commits whose value is being trivially
revertible. Tracked in [decisions.md](decisions.md#chf-cleanup-backlog).

---

## Design decisions

<a id="d1"></a><a id="d2"></a>
### D1 / D2 — WebFinger on CHF, and the `/.well-known` contract *(5d-2a, landed)*

`WebFingerHandler` is an ordinary CHF JSON endpoint on its own `WellKnownHttpRouteProvider`, with the
chain copied from `OAuth2HttpRouteProvider.get()` — `OAuth2ErrorFilter` outside, audit *inside* the
realm layer, `OAuth2NotFoundHandler` as the default route, `.well-known` and `webfinger` added to
`invalidRealmNames`.

The incumbent contract was captured before the port and re-captured after; **both files are oracle
record and neither is deletable**:

- [`artefacts/well-known-probes-pre-flip.md`](artefacts/well-known-probes-pre-flip.md) — 19 probes,
  Restlet, unrepeatable. Fourteen of them returned one byte-identical 500
  (md5 `dd82fa5d59a42118454371b094ddfa6a`): `getRootURL(null)` NPE'd *before* `discover(...)` ran, so
  the endpoint's validation contract had never once executed in this deployment.
- [`artefacts/well-known-probes-post-flip.md`](artefacts/well-known-probes-post-flip.md) — the same 19
  on CHF, repeatable via `e2e/tools/well-known-probes.sh`. Eighteen land on divergence rows 33–36; the
  nineteenth found [row 37](phase-5d-2-asbuilt.md#row-37). The control row
  (`/oauth2/.well-known/openid-configuration`, md5 `74c2c745fbbdc2c4bdd52cbe748d83ed`) is unchanged,
  which is what proves the router built with our provider.

Full design rationale and the four corrections the capture forced are in the
[as-built](phase-5d-2-asbuilt.md) and [research §1](phase-5d-2-research.md#1); the execution steps are
in git.

<a id="d3"></a>
### D3 — four classes move package; they do not die

`OpenAMClientAuthenticationFailureFactory`, `resources/ResourceSetDescriptionValidator` and
`resources/ResourceSetRegistrationHook` import no Restlet and are live. They move to
`org.openidentityplatform.openam.oauth2.http` (the first) and
`org.openidentityplatform.openam.oauth2.resources` (the other two), per the
[new-class convention](decisions.md#locked-decisions). `ResourceSetRegistrationHook` is a Guice
`Multibinder` set element (`OAuth2GuiceModule:253`) and `ResourceSetDescriptionValidator` is injected
into UMA — both bindings are by type, so the move is a rename plus imports, but **the Cargo boot is
what proves it**, not the compiler.

`LoginHintHook` moves the same way, minus its three Restlet-signature methods (`:54, :73, :90`) and
the two Restlet `Multibinder` blocks that bind them (`OAuth2GuiceModule:228-234`). Its three CHF
overloads (`:99, :110, :132`) and their two bindings (`:236-242`) stay; the class then implements
`ChfTokenRequestHook` and `ChfAuthorizeRequestHook` only.

⚠ **Two corrections, 2026-08-08.**

- `OpenAMClientAuthenticationFailureFactoryTest` **does** import Restlet (`:31-33`, three
  `org.restlet.Request` rows at `:113,124,133`) even though its subject does not. It is therefore a
  [D9](#d9) case, handled at 5d-2b-i, and only then moves with its subject at 5d-2b-ii.
- **The move is 20 import rewrites across two modules, not four file renames**
  ([research §11.7](phase-5d-2-research.md#117)). Four of them are **openam-uma main and test**
  (`UmaGuiceModule:44`, `UmaResourceSetRegistrationHook:31`, `ResourceSetResource:73`,
  `ResourceSetResourceTest:49`), so 5d-2b-ii builds and boots openam-uma too. Four more are the ITs
  criterion 16 governs — which is why that criterion permits an import line and nothing else.

<a id="d4"></a>
### D4 — the five byte-parity oracles are frozen by *running* them, in their own commit

`RestletErrorParityTest`, `RestletRendererParityTest`, `RestletContentTypeParityTest`,
`RestletAuditParityTest` and `RestletAcceptLanguageParityTest` compute their expected values by
executing real Restlet code ([research §6](phase-5d-2-research.md#6)). 5d-2b-i runs them, captures the
Restlet leg's actual output, and inlines those bytes as literal expectations — while the stack still
compiles. Hand-writing an expectation instead of capturing it silently rewrites the oracle these files
exist to preserve, and no later test can detect that.

Each is data-provider driven and asserts `chf == restletLeg(input)`; the freeze adds an expected-value
column to the provider and deletes the leg. Each has a CHF-only sibling that already covers the
behaviour (`HttpBodyAuditorTest`, `OAuth2ErrorResponseFactoryTest`, `FreemarkerTemplateRendererTest`),
so what the freeze preserves is the **cross-check**, not the only coverage — which is precisely why a
mistyped literal would be invisible.

⚠ `RestletAuditParityTest`'s leg is `openam-rest`'s `RestletBodyAuditor`, deleted at **5d-2c**, not
5d-2b. It is frozen at 5d-2b-i regardless, and the ordering holds either way.

<a id="d9"></a>
### D9 — the four transport-input tests lose their Restlet leg; they are not frozen

Decided 2026-08-08. Four more tests drive a live `RestletOAuth2Request` and die with it — research §6
did not name them ([research §11](phase-5d-2-research.md#11)):

| Test | Restlet rows | What the leg asserts |
|---|---|---|
| `QueryParameterAccessTokenVerifierTest` | 5 | token read from a Restlet query string |
| `HeaderAccessTokenVerifierTest` | 7 | token read from a Restlet `ChallengeResponse` / raw header |
| `FormBodyAccessTokenVerifierTest` | 6 | token read from a Restlet form entity |
| `OpenAMClientAuthenticationFailureFactoryTest` | 3 | challenge decision for a Restlet request |

**They get the opposite treatment to [D4](#d4): drop the Restlet rows, keep the CHF rows.** The five
D4 tests assert *output bytes the CHF stack must keep producing*, so a frozen literal keeps guarding a
live producer. These four assert *how a deleted transport parsed input* — after 5d-2b-iii no code can
produce that input, so a frozen literal would pin nothing and guard nothing. Freezing them is
[R-5d2.3](#risk-register)'s failure mode written deliberately: a rubber stamp that reads as coverage.

Deleting the files outright was rejected — the three verifiers are phase-3b collaborators still on the
hot path, and their CHF rows are live coverage.

**21 declared test methods disappear.** That number is the checkable bar for
[criterion 13](#criteria-5d-2b-i): the surefire delta must equal it, or be explained by a data
provider, and nothing else may move.

<a id="d10"></a>
### D10 — the transport de-plumb rides with `RestletOAuth2Request`, not with 5d-2d

Decided 2026-08-08, correcting the original file lists. `RestletOAuth2Request` cannot be deleted
alone: five main files reference it, and the first draft assigned two of them to 5d-2d, which would
have left the tree un-compilable for three sub-phases.

| File | Module | Reference | Fate at 5d-2b-iii |
|---|---|---|---|
| `OAuth2RequestFactory:75` | openam-oauth2 | `new RestletOAuth2Request(...)` branch | branch + `:34,:29,:35` imports go; the `JacksonRepresentationFactory` ctor param goes |
| `OAuth2Request:35,54-62` | openam-oauth2 | `import org.restlet.Request`; the deprecated `getRequest()` | method + import deleted |
| `UmaProviderSettingsFactory:75-77` | **openam-uma** | package-private `get(org.restlet.Request)` | overload + ctor param + two imports go |
| `UmaUrisFactory:82-84` | **openam-uma** | package-private `get(org.restlet.Request)` | overload + ctor param + two imports go |
| `ChfOAuth2Request:241` | openam-oauth2 | `{@link ...RestletOAuth2Request#getEndpointPath()}` | reworded |

⚠ **Two of these are Guice-visible.** Both openam-uma factories are `@Inject` constructors, and
dropping the `JacksonRepresentationFactory` parameter changes the graph. `UmaRouterIT`,
`UmaUrisFactoryTest`, `OAuth2RouterIT:244` and `WellKnownRouterIT:194` all construct these by hand and
must lose the mock argument — so [criterion 18](#criteria-5d-2b-iii) is "arity, and nothing else".

⚠ **Doclint is `all,-missing`** (`pom.xml:140`), so a `{@link}` at a deleted class fails the javadoc
build, not merely the IDE. `ChfOAuth2Request:241` is the one that bites; `ChfOAuth2RequestTest:278,353`
use `{@code}` and are safe.

<a id="d5"></a>
### D5 — `OAuthProblemException` gets a bridge, not a new supertype

Decided 2026-08-06 after measuring the ripple ([research §3](phase-5d-2-research.md#3)):
`OAuth2Exception` is **checked**, so folding `OAuthProblemException` into that hierarchy would force
`throws` onto both ClientRegistration interfaces, `TokenStore`, and every caller — and three of the
throw sites are in `addServiceListener()`, construction-time code no handler can reach.

Instead: `OAuthProblemException extends RuntimeException` (same name, package and constructors;
`getStatus()` and both Restlet imports deleted), plus one
`@ExceptionHandler public Response onProblem(OAuthProblemException e, @Contextual Context ctx, @Contextual Request request)`
on **each** of `AbstractOAuth2HttpJsonEndpoint` and `AbstractOAuth2HttpBrowserEndpoint`, rendering
through `OAuth2Error.of(int, String, String)` (`OAuth2Error:217`) and the already-injected
`OAuth2ErrorResponseFactory`. Identical wire bytes to folding it in; zero signature changes.

⚠ **Corrected 2026-08-08 — research §3's reason was wrong, its conclusion survives.** §3 warned that
`@ExceptionHandler` dispatch is "by exact type, not a hierarchy walk", and concluded from that that
UMA's `onError(Throwable)` is unaffected. Dispatch is in fact **polymorphic, most-specific-wins** —
`AnnotatedMethod:197-202` is `candidate.isInstance(t) && (match == null || match.isAssignableFrom(candidate))`.
Registration is what is keyed by exact type (`:69,:251`), which is what stops a duplicate-key collision.
Re-derived from the code, the conclusion still holds, for two different reasons:

- **UMA is unaffected because it already catches it.** `AbstractUmaHttpEndpoint:35-36` declares
  `onError(Throwable)`, and `OAuthProblemException` is *already* a `RuntimeException` today (via
  Restlet's `ResourceException`). It reaches that handler before the change and after it, and
  `UmaErrorResponseFactory:47-50` branches only on `UmaException` / `OAuth2Exception`, so it lands in
  the same default arm either way. **No UMA behaviour change.**
- **The OAuth2 bases have no wider handler to lose to.** The JSON base declares `OAuth2Exception`
  only; the browser base declares `OAuth2Exception` and `IllegalArgumentException`. Neither is a
  supertype of `OAuthProblemException`, so today it escapes to `openam-http`'s
  [F1](openam-http-framework.md) 500 — exactly as D5 assumed — and after the change the new handler is
  the most specific match.

Declaring it on both siblings and not on the shared base mirrors `AbstractOAuth2HttpEndpoint`'s own
javadoc: the two shapes differ (JSON body vs redirect/HTML page), and the framework discovers
`@ExceptionHandler` on inherited methods, so one declaration per sibling covers every subclass.

<a id="d6"></a>
### D6 — `ResourceOwnerAuthenticator`'s raw `ResourceException` is replaced in the same commit

`ResourceOwnerAuthenticator:127,145,150` throw Restlet's unchecked `ResourceException` on the
password-grant path ([research §4](phase-5d-2-research.md#4)). Replace with `OAuthProblemException`
so D5's bridge covers it and the answer is an OAuth2 `server_error` rather than a framework 500. It is
the same class the soak fixed, and `e2e/oauth2/realms-test.spec.mjs` row 10 is its only e2e coverage —
extend that spec rather than inventing a new one.

<a id="d7"></a>
### D7 — the realm constants migrate now, and both `RestletRealmRouter`s die

Six live CHF-path files read `RestletRealmRouter.REALM` / `.REALM_OBJECT`, and the neutral constants
`OAuth2Constants.Custom.REALM` / `.REALM_OBJECT` (`:784,791`) already hold the identical literals with
a javadoc promising this migration ([research §5](phase-5d-2-research.md#5)). Repoint all six —
`OAuth2UrisFactory:33`, `OAuth2RealmResolver:23`, `UmaUrisFactory:36`, `UmaProviderSettingsFactory:36`,
`RealmRoutingFactory:21-22`, `UmaUrisFactoryTest` — and delete the duplicate. `REALM_URL`'s only
reader dies with `RestletOAuth2Request` at 5d-2b-iii.

⚠ **Both classes named `RestletRealmRouter` are deletable, and the
[trap that says otherwise](phase-5d-1-asbuilt.md#handed-to-5d-2) is out of date.** Its premise was that
other Restlet consumers still call `RealmRoutingFactory.createRouter(org.restlet.routing.Router)`;
after 5d-2a ported WebFinger and 5d-2b-ii deletes `OAuth2RouterProvider`, that overload has no callers
at all — so the inner router goes at **5d-2c** with the rest of openam-rest's Restlet layer, and the
openam-restlet class at 5d-2d-ii. The trap's *operational* content stands: they are different classes
in different modules, so never delete by simple name.

<a id="d8"></a>
### D8 — 5d-2 finishes what phase 8 needs, so phase 8 stays mechanical

`RestRealmValidator` (openam-restlet, Restlet-free) is used by CHF's `RealmContextFilter` and is the
last thing standing between phase 8 and a module delete. It relocates to openam-rest
`org.forgerock.openam.rest.router`.

⚠ **Corrected 2026-08-08 — it has three times the consumers research §7 counted.** §7 named
`RealmContextFilter` plus three mocks. The full list is eleven imports across five modules:

| Module | Files |
|---|---|
| openam-rest | `RealmContextFilter:60` (main), `RestRouterIT:92`, `RealmContextFilterTest:59` |
| **openam-sts/openam-publish-sts** | `STSPublishServiceHttpRouteProvider:39`, `SoapSTSPublishServiceRequestHandler:48`, `RestSTSPublishServiceRequestHandler:48`, `STSPublishModule:27` — **all main source** |
| openam-oauth2 | `OAuth2RouterIT:88`, `WellKnownRouterIT:60` |
| openam-uma | `UmaRouterIT:81` |
| **openam-entitlements** | `XacmlRouterIT:62` |

`openam-publish-sts/pom.xml:51` already depends on openam-rest, so the relocation needs no new
dependency — only eleven import rewrites. **openam-sts and openam-entitlements are modules the
inventory never listed**, and both are in the criterion-22 exit gate's blast radius.

After 5d-2, `openam-oauth2`, `openam-uma`, `openam-rest` and `openam-oauth2-saml2` are all
Restlet-free and drop their restlet + openam-restlet dependencies. The only `org.restlet` left in the
tree is `openam-http-client` (phase 7) and the `openam-restlet` module itself (phase 8).

---

## New / modified / deleted

Per-file lists are [research §2](phase-5d-2-research.md#2) as amended by
[§11](phase-5d-2-research.md#11) — this is the shape, not a duplicate of it.

**5d-2b-i** — modified, tests only: the five D4 parity tests (leg → literal) and the four D9 tests
(leg deleted). No main source, no `git rm`.

**5d-2b-ii** — deleted: 23 of `org.forgerock.oauth2.restlet`'s 24 files +
`resources/ResourceSetRegistrationExceptionFilter`; 7 of `org.forgerock.openidconnect.restlet`'s 8;
`AccessTokenProtectionFilter`, `ResourceSetRegistrationEndpoint`, `OAuth2RouterProvider`,
`TokenRevocationResource`, the three Restlet audit filters; `Saml2BearerServerResource`; and the tests
of all of them (`AuthorizeResourceTest`, `ResourceSetRegistrationEndpointTest`). Moved: the four
classes of [D3](#d3), with `LoginHintHookTest` rewritten for the CHF halves. Modified:
`OAuth2GuiceModule` (the `RSR_ENDPOINT` `@Provides`, the `wrap` import, the two Restlet multibinders),
`OAuth2RestGuiceModule` (the `@Named("OAuth2Router")` binding; the `Config<TokenStore>` binding stays),
`web.xml` (the `ForgeRockRest` declaration at `:1119-1120`), `openam-oauth2-saml2/pom.xml`, and the
**20 import sites of the D3 move — four of them in openam-uma**
([research §11.7](phase-5d-2-research.md#117)).

**5d-2b-iii** — deleted: `RestletOAuth2Request` + `RestletOAuth2RequestTest`. Modified: the five files
of [D10](#d10), plus `ResourceOwnerSessionValidatorTest:80`, `OAuth2RequestFactoryTest`,
`OpenAMClientRegistrationStoreTest:198`, and the four ITs that mock the dropped ctor argument.

**5d-2c** — deleted: 8 openam-rest main classes (`RestEndpointServlet`, `service/RestletServiceServlet`,
`service/ServiceEndpointApplication`, `service/OAuth2ServiceEndpointApplication`,
`service/RestStatusService`, `service/JSONRestStatusService`, `audit/AbstractRestletAccessAuditFilter`,
`audit/RestletBodyAuditor`) + 4 tests, and `RealmRoutingFactory`'s Restlet `createRouter` overload
(`:116`) and private inner `RestletRealmRouter` (`:232-290`). Modified: `openam-rest/pom.xml`.

**5d-2d-i** — modified: `OAuthProblemException`, `AbstractOAuth2HttpJsonEndpoint`,
`AbstractOAuth2HttpBrowserEndpoint` + both tests, `ResourceOwnerAuthenticator`,
`e2e/oauth2/realms-test.spec.mjs`.

**5d-2d-ii** — modified: the six realm-constant readers ([D7](#d7)), `StatefulTokenStore:88`
(`Status.*.getCode()` at `:729,740,760,767,777` → literals), `TokenResource:108` (unused import),
`ResourceOwnerSessionValidator:94,382`, `SmsRealmProvider:25` (inline `"If-None-Match"`),
`AuthenticationServiceV1`, `DefaultWsFedAuthenticator`, **`PolicyResourceTest:55,82`
(openam-entitlements — an `org.restlet.resource.Resource` auto-import in a `ResultHandler<>`, found
2026-08-08 and in no earlier list)**, and the eleven `RestRealmValidator` imports of [D8](#d8). Moved:
`RestRealmValidator`. Deleted: `RestletRealmRouter` (openam-restlet) + its test,
`OAuth2Constants.Custom.RSR_ENDPOINT` (dead after 5d-2b-ii). Poms: openam-oauth2, openam-rest,
openam-uma, root.

---

## Verification criteria

Numbered so the as-built can cite them. **1–10 are unchanged from the original spec** — the as-built
cites them for 5d-2a — and 11 onward were renumbered for the six-way split on 2026-08-08.

### The standing bar — every sub-phase

1. `mvn -q -am -pl <touched modules> verify` green, with the surefire/failsafe **counts** recorded — a
   deletion phase can turn a suite green by removing the tests that failed, and only the count catches
   that. Baseline after 5d-2a-ii: **surefire 1309 / failsafe 70** on `-am -pl openam-oauth2`.
2. `mvn install -DskipTests` from the root, then a **Cargo boot** — the Guice graph is what class moves,
   unbinds and dropped constructor parameters actually threaten, and it is the only thing that proves it.
3. Full `npx playwright test` on a container rebuilt from that commit. Baseline after 5d-2a-ii:
   **159 declared, 158 passed / 1 skipped / 0 failed**. Only 5d-2d-i moves the declared count on
   purpose (**+n**, D6's password-grant rows). Any other movement is an accidentally deleted row and
   must be justified in the as-built.
4. `git diff --stat` reviewed against this doc's file lists — an unlisted file in a deletion commit is
   either a missed dependency or scope creep.

### 5–10 — discharged by 5d-2a

Recorded in the [as-built](phase-5d-2-asbuilt.md). Criterion 7 (dormancy, byte for byte) and
criterion 8 (every probe lands on a divergence row) carried the weight; both are green.

<a id="criteria-5d-2b-i"></a>
### 5d-2b-i — freeze the oracles

11. **CI run `31105613611` (or its successor on this SHA) green** before this commit. It is the last
    point at which the Restlet oracle the soak fix was diagnosed against still exists.
12. Each of the five D4 tests still asserts non-trivial byte-level values after the freeze, each
    literal was **captured by running the test** (never hand-written), and each is **mutation-checked**
    against the CHF side: perturb the CHF producer, confirm red, restore. A frozen oracle that cannot
    go red is [R-5d2.3](#risk-register) realised.
13. The surefire delta is **exactly the 21 D9 rows**, or the excess is explained by a data provider.
    Every surviving CHF row of the four D9 tests still runs.

### 5d-2b-ii — the endpoint deletion

14. Criterion 2 carries this sub-phase. The four class moves and both Guice unbinds fail at graph
    construction, not at compile — a green `verify` proves nothing here.
15. Before each `git rm`, `grep` the doomed simple names across `*.xml`, `*.properties` and
    `META-INF/` — not only across `*.java` ([R-5d2.2](#risk-register)).
16. `OAuth2RouterIT`, `UmaRouterIT`, `WellKnownRouterIT` and the five composition ITs green, and
    changed **in import lines only** — `OAuth2RouterIT:69-70` and `ResourceSetRouteCompositionIT:55-56`
    import two of the classes [D3](#d3) moves, so "unchanged" is not achievable here; the bar is that
    no assertion, binding or fixture moves. They exercise the CHF stack only, so a red one means the
    deletion took something live, and a *substantively* edited one means it did not.

<a id="criteria-5d-2b-iii"></a>
### 5d-2b-iii — the transport de-plumb

17. `grep -rn "org.restlet" --include="*.java" openam-uma/` → **0**. ⚠ **No pom change here**:
    openam-uma declares no direct restlet artifact — it resolves `org.restlet.Request` transitively
    through `openam-restlet` (`pom.xml:32-35`), and that dependency must survive until 5d-2d-ii,
    because `UmaUrisFactory:36` / `UmaProviderSettingsFactory:36` still import `RestletRealmRouter`
    ([D7](#d7)) and `UmaRouterIT:81` still imports `RestRealmValidator` ([D8](#d8)). The pom map is
    [research §11.8](phase-5d-2-research.md#118).
18. The four ITs of [D10](#d10) change **in constructor arity only** — one dropped mock argument each,
    no assertion touched. Any other edit to an IT in this commit is a regression being papered over.
19. `mvn javadoc:javadoc -pl openam-oauth2,openam-uma` green — doclint is `all,-missing`, so the
    `{@link}` rewrites are load-bearing and no other criterion catches them.

### 5d-2c — the openam-rest layer

20. `grep -rn "org.restlet" --include="*.java" openam-rest/` → **0**.

### 5d-2d-i — the behaviour change

21. **The pre/post capture.** Drive each reachable `OAuthProblemException` path and the password-grant
    failure path against the container built from the *previous* commit, record status + headers +
    body into `artefacts/`, then re-run after. Every difference must match divergence row 31 or 32; an
    unmatched one is a regression, per [the table's rule](plan.md#expected-divergences-at-the-flip).
22. **No new 302 anywhere in that capture** ([R-5d2.5](#risk-register)), plus an explicit assertion in
    the browser base's test that an `OAuthProblemException` renders rather than redirects.

### 5d-2d-ii — the sweep and the exit

23. The exit gate, exactly:
    ```
    grep -rn "org.restlet" --include="*.java" . | grep -v "^./docs" \
      | grep -v "^./openam-restlet/" | grep -v "^./openam-http-client/"     # -> 0
    grep -rln restlet --include=pom.xml . | grep -vE "openam-restlet|openam-http-client|transform-jakarta|^pom.xml"   # -> 0
    ```
24. CI green on the push — 9 legs, as [5d-1 criterion 16](phase-5d-1.md#verification-criteria)
    enumerates them.

⚠ **What "green" is not.** Four of the six sub-phases delete dormant code, so a green suite proves
little more than "the build still builds". The criteria that carry weight are **12** (the frozen
oracles), **14** (Guice), **16** and **18** (the ITs, unchanged), **21** (the only measured behaviour
change) and **1**'s row *counts* throughout.

---

## Integration testing

Same three layers as 5d-1, per [test-infrastructure.md](../../test-infrastructure.md).

1. **Layer 2 — no new IT this phase.** `WellKnownRouterIT` was 5d-2a's; the eight surviving ITs
   (`OAuth2RouterIT`, `UmaRouterIT`, `WellKnownRouterIT`, `RestRouterIT`, `XacmlRouterIT` and the
   composition ITs) become the *regression instrument*, which is why criteria 16 and 18 forbid editing
   them beyond constructor arity. 5d-2b/c delete code no IT covers; 5d-2d-i's change is covered by
   extending existing suites.
2. **Layer 3 — Cargo boot on every sub-phase** (criterion 2). The phase's highest-value guard: 5d-2b-ii
   moves four classes and unbinds two Guice modules, and 5d-2b-iii changes two `@Inject` constructor
   signatures in openam-uma. All of those fail at graph construction, not at compile.
3. **Layer 4 — the full e2e suite on every sub-phase**, plus 5d-2d-i's targeted capture (criterion 21).
   `realms-test.spec.mjs` gains rows for D6's password-grant path.

Deliberately **not** repeated: the soak's load probe. It proved concurrent body re-reading under the
CHF handlers, and no sub-phase here changes a body-reading path. If 5d-2d-i's capture shows anything
unexpected on `/access_token`, re-run `e2e/tools/oauth2-load.mjs` before continuing.

---

<a id="risk-register"></a>
## Risk register

- **R-5d2.1 — the revert lever is gone.** From 5d-2b-ii, `/oauth2` cannot be put back on Restlet by
  reverting one line; recovery means reverting the whole sub-phase. **Guard:** criterion 11, and
  keeping each sub-phase a single revertible commit.
- **R-5d2.2 — a "dead" class is not dead.** The deletion lists come from static imports; a class
  reached only by reflection, a `META-INF/services` entry or a Guice string binding would not appear.
  **Guard:** criteria 14–15.
- **R-5d2.3 — the frozen oracle is frozen wrong.** A mistyped literal in D4 turns five regression
  guards into five rubber stamps, permanently and undetectably. **Guard:** D4's capture-by-running and
  criterion 12's mutation check. [D9](#d9) exists because freezing the wrong four tests would have
  manufactured this risk rather than guarded it.
- **R-5d2.5 — D5 widens an error into a redirect.** The browser base's error path can *redirect* when
  a `redirect_uri` is in play. An `OAuthProblemException` from deep inside the token store must not
  become a redirect carrying an unvalidated URI. **Guard:** the bridge builds through
  `OAuth2Error`/`OAuth2ErrorResponseFactory`, whose `NEVER_REDIRECT` list (`OAuth2Error:75`) is the
  existing mechanism for exactly this; criterion 22.
- **R-5d2.6 — the openam-uma constructor change is invisible until boot.** *(new, 2026-08-08)*
  Dropping `JacksonRepresentationFactory` from two `@Inject` constructors compiles cleanly and passes
  every unit test that constructs them by hand. Only Guice sees it. **Guard:** criterion 2 on
  5d-2b-iii specifically, and criterion 18's arity check on the four ITs.
- **R-5d2.7 — the exit gate reaches modules nobody planned for.** *(new, 2026-08-08)* `openam-sts` and
  `openam-entitlements` carry `RestRealmValidator` and `org.restlet` imports and appear in no earlier
  inventory ([D8](#d8)). A sub-phase that builds only its own modules will not see them. **Guard:**
  criterion 23 is a whole-tree grep, and 5d-2d-ii's `verify` must include both modules.
- ✅ **R-5d2.4 — `/.well-known` serves more than webfinger somewhere. Discharged by measurement,
  2026-08-06** ([D2](#d2)).
- ✅ **Discharged before the phase started:** WebFinger's twelve-class hold on the deletion
  ([research §1](phase-5d-2-research.md#1)), the checked-exception ripple
  ([research §3](phase-5d-2-research.md#3)), and the two stale traps
  ([research §5](phase-5d-2-research.md#5), [§2](phase-5d-2-research.md#2)).

---

## Divergence rows this phase adds to [plan.md](plan.md#expected-divergences-at-the-flip)

Rows **33–37 landed with 5d-2a** and are recorded in
[plan.md](plan.md#expected-divergences-at-the-flip) and the
[as-built](phase-5d-2-asbuilt.md#criterion-8--where-the-nineteen-probes-landed). Rows 31–32 are still
owed, by 5d-2d-i. **Their incumbent is the post-flip CHF stack**, not Restlet — Restlet stopped serving
`/oauth2` at 5d-1c.

| # | What differs | Before | After | Why |
|---|---|---|---|---|
| 31 | Errors raised as `OAuthProblemException` — token-store failures, client-registration attribute reads, id_token signing | framework CREST 500 `{code,reason,message}` | OAuth2 `{error,error_description}` with the exception's own status | [D5](#d5). Same unifying argument as [row 8](plan.md#expected-divergences-at-the-flip): one error shape across `/oauth2` is the whole point of `OAuth2ErrorFilter` |
| 32 | Password-grant internal failures (`ResourceOwnerAuthenticator`) | framework CREST 500 | OAuth2 `{"error":"server_error"}` | [D6](#d6). Restlet's own answer here was never a CREST body either; the raw `ResourceException` was an artefact of the transport, not a contract |

**No divergence row is expected from 5d-2b, 5d-2b-iii or 5d-2c.** All three delete code that no
request reaches. If criterion 3's e2e count or criterion 21's capture moves in one of them, that is a
finding, not a row.

---

## Checklist

**5d-2b-i — freeze the oracles.** Test-only; no `git rm`.

1. Read CI `31105613611`. Not green ⇒ stop and fix before anything else (criterion 11).
2. Run the five D4 tests with the Restlet leg's output dumped; inline the captured bytes as literal
   expectations in each data provider; delete the leg and its imports.
3. Mutation-check each of the five: perturb the CHF producer, confirm red, restore (criterion 12).
4. Delete the 21 D9 rows and their Restlet imports from the four tests of [D9](#d9); keep every CHF row.
5. Criteria 1–4, 11–13.

**5d-2b-ii — the endpoint deletion.**

6. Move the four surviving classes out of the `.restlet` packages ([D3](#d3)); strip `LoginHintHook`'s
   three Restlet methods; rewrite `LoginHintHookTest` for the CHF halves.
7. `grep` every doomed simple name across `*.xml` / `*.properties` / `META-INF/` (criterion 15).
8. Delete the two Restlet packages, the seven elsewhere classes and `Saml2BearerServerResource`; unbind
   in both Guice modules; drop the `ForgeRockRest` declaration and `openam-oauth2-saml2`'s restlet deps.
9. Criteria 1–4, 14–16.

**5d-2b-iii — the transport de-plumb.**

10. Delete `RestletOAuth2Request` + its test; apply the five [D10](#d10) edits, including openam-uma's
    two overloads and both constructor parameters.
11. Fix the four ITs' arity and the `{@link}` at `ChfOAuth2Request:241`.
12. Criteria 1–4, 17–19.

**5d-2c — the openam-rest layer.**

13. Delete the 8 main + 4 test classes and `RealmRoutingFactory`'s Restlet overload and inner router;
    drop openam-rest's restlet + openam-restlet deps.
14. Criteria 1–4, 20.

**5d-2d-i — the behaviour change.**

15. Capture the "before" against the previous commit's container (criterion 21).
16. `OAuthProblemException` → `RuntimeException`; add the two `@ExceptionHandler` bridges + tests
    including R-5d2.5's no-redirect assertion.
17. `ResourceOwnerAuthenticator`; extend `realms-test.spec.mjs`.
18. Capture the "after"; classify every difference against row 31 or 32. Criteria 1–4, 21–22.

**5d-2d-ii — the sweep and the exit.**

19. Realm constants ([D7](#d7)); delete both `RestletRealmRouter`s.
20. Relocate `RestRealmValidator` and rewrite all eleven imports ([D8](#d8)) — **openam-sts and
    openam-entitlements included**.
21. The vestigial imports: `StatefulTokenStore`, `TokenResource`, `ResourceOwnerSessionValidator`,
    `SmsRealmProvider`, `AuthenticationServiceV1`, `DefaultWsFedAuthenticator`, `PolicyResourceTest`.
22. Pom sweep; criteria 1–4, 23–24; write the as-built.
23. Update [plan.md](plan.md) — phase status, rows 31–32, and phase 7/8's now-reduced scope.
