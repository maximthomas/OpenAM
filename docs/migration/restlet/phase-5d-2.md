# Phase 5d-2 — the deletion: removing the Restlet `/oauth2` stack

Written 2026-08-06 against `83f465452b`; **5d-2a reviewed against the source the same day**, which
re-split it and corrected four things ([research §1 review](phase-5d-2-research.md#1-review)).
Background facts — the exact file inventory, the coupling that decides the split, and the traps this
doc corrects — are in [phase-5d-2-research.md](phase-5d-2-research.md). **Read that once; do not
re-read the source it already measured.**

## Context

5d-1c moved `/oauth2` onto CHF and left the Restlet stack dormant behind a one-line revert. The soak
([criterion 17](phase-5d-1-asbuilt.md#criterion-17--the-soak--recorded-2026-08-06)) found and fixed
one regression, and the branch has since been pushed; CI run `31105613611` on `83f465452b` is the
first that covers the fix. **That run must be green before the first `git rm`** — after it, the
Restlet oracle the fix was diagnosed against no longer exists.

This phase is mostly deletion, which is cheap to write and dangerous to verify: nothing that is
deleted can fail a test, so the evidence has to come from what *stays* green. Two parts of it are not
deletion at all — the WebFinger port (5d-2a) and the `OAuthProblemException` bridge (5d-2d) — and
those are where the risk actually lives.

## Scope & sizing — split four ways, five commits

The whole phase is ~5,400 lines of main source plus ~20 test files across six modules. Each row below
is a shippable green commit under the 150k implementation budget, and each is ordered by what must
compile after it. 5d-2a is two commits for the reason 5d-1 was: **build the route dormant, then flip
it**, so a routing surprise costs one `web.xml` hunk rather than the handler.

| Sub-phase | Scope | Live-path risk |
|---|---|---|
| **5d-2a-i** | WebFinger `/.well-known` → CHF, **left dormant**: handler, route provider, unit test, IT. `/.well-known/*` still maps to the Restlet servlet. **Pulled forward from phase 6** — [research §1](phase-5d-2-research.md#1) | none — the route is registered but unreachable |
| **5d-2a-ii** | The flip: move the `/.well-known/*` mapping to `OpenAM`, delete `WebFinger` + `OpenIDConnectDiscovery`, rewrite the e2e spec | yes — a route flips |
| **5d-2b** | Freeze the parity oracles, then delete the openam-oauth2 Restlet stack + Guice unbinds + `ForgeRockRest` + `Saml2BearerServerResource` | low — dormant code, but Guice + 3 class moves |
| **5d-2c** | Delete the now-dead openam-rest Restlet layer (servlets, applications, status services, audit base, body auditor) + tests | none — nothing references it after 5d-2b |
| **5d-2d** | The core de-leak: `OAuthProblemException` bridge, `ResourceOwnerAuthenticator`, realm constants, `RestRealmValidator` relocation, vestigial imports, pom sweep, exit gates | **yes — the only deliberate behaviour change in the phase** |

⚠ **Why WebFinger comes first and is not deferred.** `WebFinger` + `OpenIDConnectDiscovery` import
twelve classes 5d-2 exists to delete ([research §1](phase-5d-2-research.md#1)). Run 5d-2 before the
port and none of the three Restlet packages can be emptied, the exit gate is unreachable, and phase 6
makes a second pass over the same files. The port is 239 lines and it fixes a lookup that has
**500ed on every success since before this migration started** — the error paths still work, which is
why [D2](#d2) treats most of the endpoint as a parity target rather than a rewrite.

---

## Design decisions

<a id="d1"></a>
### D1 — `WebFingerHandler` is an ordinary CHF JSON endpoint, on its own route provider

`WellKnownHttpRouteProvider` (openam-oauth2, `org.openidentityplatform.openam.oauth2.http`) —
`newHttpRoute(STARTS_WITH, ".well-known")`, appended to the module's existing `META-INF/services`
file.

**The chain is copied from `OAuth2HttpRouteProvider.get()`, not re-derived** (decided 2026-08-06):

```
OAuth2ErrorFilter
 └ Router root
    ├ STARTS_WITH REALM_ROUTE → chainOf(realmRoutingFactory.createRouter(root),
    │                                   realmRoutingFactory.createHostnameFilter())
    └ default                 → chainOf(endpointRouter, realmContextFilter)
                                  ├ EQUALS "webfinger" → chainOf(Endpoints.from(WebFingerHandler.class),
                                  │                              auditFilter(noBodyAuditor(), noBodyAuditor()))
                                  └ default            → OAuth2NotFoundHandler
```

Three things in that shape were wrong in this doc's first draft and are load-bearing:

- **Audit is inside the realm layer, not outside it.** `OAuth2HttpRouteProvider.endpoint()` builds
  `chainOf(handler, auditFilter)` *within* `endpointRouter`, which sits behind `RealmContextFilter` —
  and that is what `WebFinger:76` did too, wrapping the audited restlet *inside* its
  `RestletRealmRouter`. Hoisting audit outside the realm filter would publish every webfinger access
  event with no realm on it.
- **`OAuth2ErrorFilter` wraps the whole route.** Without it a bad `?realm=` surfaces as the CREST
  `{code,reason,message}` body, which is neither the Restlet incumbent nor the shape the rest of the
  migrated surface emits. It is idempotent, so adding it costs nothing on the success path.
- **`invalidRealmNames` gains `.well-known` and `webfinger`.** Realm resolution greedily consumes
  leading path segments, so a realm named `webfinger` would shadow the endpoint. Every other provider
  registers its own segments (`OAuth2HttpRouteProvider:104-107`); relying on the OAuth2 provider
  having already added `.well-known` is a coupling this route should not have.

`WebFingerHandler extends AbstractOAuth2HttpJsonEndpoint`, one `@Get` reproducing
`OpenIDConnectDiscovery:74-85`:

```java
@Get
public Response discover(@Contextual Context ctx, @Contextual Request request) throws OAuth2Exception {
    OAuth2Request o2 = requestFactory.create(ctx, request);
    HttpServletRequest servletRequest = o2.getHttpServletRequest();   // ChfContexts, via ChfOAuth2Request
    if (servletRequest == null) {
        throw new ServerException("Cannot determine the deployment URL: no servlet request on the context");
    }
    String realm = o2.getParameter(REALM);
    String deploymentUrl = baseUrlProviderFactory.get(realm).getRootURL(servletRequest);
    return new Response(Status.valueOf(200)).setEntity(providerDiscovery.discover(
            o2.<String>getParameter("resource"), o2.<String>getParameter("rel"), deploymentUrl, o2));
}
```

Four facts make that a faithful port rather than a rewrite, all verified in the tree:

- `o2.getHttpServletRequest()` is the idiom the migrated handlers already use
  (`ConsentPageRenderer:161`, `DeviceCodeVerificationHandler:277`); it resolves through `ChfContexts`,
  so the `ServletUtils` defect cannot recur. The explicit null-guard is the point of the fix — an
  unreachable branch that names the failure instead of NPE-ing is exactly what
  `OAuth2UrisFactory:85-98` does.
- `o2.getParameter(REALM)` returns the `RealmContext` realm (`ChfOAuth2Request:392-397`), and
  `RealmContextFilter:211` already applies the `?realm=` override — so both spellings Restlet honoured
  (`RestletRealmRouter:doHandle`, URI subrealm and query override) keep working, plus the
  `/realms/{realm}` form for free.
- `discover(...)` throws `BadRequestException` / `NotFoundException`, both `OAuth2Exception`
  subclasses. `@ExceptionHandler` dispatch is **polymorphic** — `AnnotatedMethod:195-202` picks the
  most specific handler by `isInstance` — so `AbstractOAuth2HttpJsonEndpoint.onError` catches them
  with no new handler and no CHF change. (An earlier note in this migration claimed exact-type
  dispatch; that is wrong, and [research §1](phase-5d-2-research.md#1) now records it.)
- `HEAD` needs nothing: `Endpoints:70-72` already maps it to the `GET` method.

`OpenIDConnectProviderDiscovery` is transport-free and is not touched.

**`STARTS_WITH`, not `EQUALS`** (plan.md's phase 6 bullet says `EQUALS`): the provider owns the whole
`.well-known` segment because the servlet mapping does, and an unmatched child must answer from our
default route rather than fall through to a container 404. Set `OAuth2NotFoundHandler` as the default
route, as `OAuth2HttpRouteProvider:210` does.

<a id="d2"></a>
### D2 — the `.well-known` contract is captured before the port, and most of it is a parity target

⚠ **Correction to this doc's first draft, and to `webfinger-test.spec.mjs`'s header: the endpoint is
not wholly broken. Only the success path is.** `OpenIDConnectDiscovery:98-100` overrides `doCatch` to
`ExceptionHandler.handle(Throwable, Response)` — the **two-arg** overload (`ExceptionHandler:147-157`),
which renders `jacksonRepresentationFactory.create(exception.asMap())` and sets the exception's own
status. It never calls `getRootURL`, so it cannot hit the NPE. A missing `resource` returns a **live,
working 400** today. The four-arg overload that renders `error.ftl` and *would* NPE is only reached
from the Restlet `OAuth2Filter`, which never wrapped this application.

So the capture is the arbiter for real contracts, not a record of 500s. Against the running
pre-change container, capture status + headers + body bytes into
`docs/migration/restlet/artefacts/`, alongside the 5d-1 captures:

| Probe | Expected incumbent | After the port |
|---|---|---|
| `?resource=acct:demo@example.com&rel=<issuer>` | **500** — `getRootURL(null)` NPEs | **200 JRD** — the fix (row 33) |
| `?rel=<issuer>` (no `resource`) | 400, `{"error":"invalid_request",…}` | **parity target** |
| `?resource=…` (no `rel`), and a wrong `rel` | 400 | **parity target** |
| `?resource=acct:nobody@…&rel=<issuer>` | 404 (`NotFoundException`) | **parity target** |
| `?resource=…&rel=…&realm=/bogus` | realm failure, shape unknown | capture decides |
| `/.well-known/nonsense`, `/.well-known/` bare | 404 via `OAuth2StatusService` | shape moves — row 34 |
| a realm-spelled path, `HEAD`, `POST` | — | capture decides |

`OAuth2Error.of(e)` (`OAuth2Error:189-206`) maps `statusCode`/`error`/`message` exactly as
`OAuth2RestletException.asMap()` (`:163-176`) does, so the four parity targets should come out
byte-identical. Any that do not are a divergence row with a written reason, not an acceptable drift —
the same rule [the divergence table](plan.md#expected-divergences-at-the-flip) applies everywhere else.

<a id="d3"></a>
### D3 — three Restlet-free classes move package; they do not die

`OpenAMClientAuthenticationFailureFactory` (+ its test),
`resources/ResourceSetDescriptionValidator` and `resources/ResourceSetRegistrationHook` import no
Restlet and are live. They move to `org.openidentityplatform.openam.oauth2.http` (the first) and
`org.openidentityplatform.openam.oauth2.resources` (the other two), per the
[new-class convention](decisions.md#locked-decisions). `ResourceSetRegistrationHook` is a Guice `Multibinder`
set element (`OAuth2GuiceModule:253`) and `ResourceSetDescriptionValidator` is injected into UMA —
both bindings are by type, so the move is a rename plus imports, but **the Cargo boot is what proves
it**, not the compiler.

`LoginHintHook` moves the same way, minus its three Restlet-signature methods (`:54, :73, :90` —
the `(OAuth2Request, Request, Response)` overloads) and the two Restlet `Multibinder` blocks that
bind them (`OAuth2GuiceModule:228-234`). Its three CHF overloads (`:99, :110, :132`) and their two
bindings (`:236-242`) stay exactly as they are; the class then implements `ChfTokenRequestHook` and
`ChfAuthorizeRequestHook` only.

<a id="d4"></a>
### D4 — the parity oracles are frozen by *running* them, in their own commit

The five `Restlet*ParityTest`s compute their expected values by executing real Restlet code
([research §6](phase-5d-2-research.md#6)). 5d-2b's **first** commit runs them, captures the Restlet
leg's actual output, and inlines those bytes as literal expectations — while the stack still
compiles. The deletion commit follows. Hand-writing an expectation instead of capturing it silently
rewrites the oracle these files exist to preserve, and no later test can detect that.

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

Declaring it on both siblings and not on the shared base is deliberate and mirrors
`AbstractOAuth2HttpEndpoint`'s own javadoc: the two shapes differ (JSON body vs redirect/HTML page),
and the framework discovers `@ExceptionHandler` on inherited methods, so one declaration per sibling
covers every subclass. `AnnotatedMethod:69,251` keys handlers by **exact type** and rejects
duplicates, so this cannot collide with the existing `OAuth2Exception` handler.

<a id="d6"></a>
### D6 — `ResourceOwnerAuthenticator`'s raw `ResourceException` is replaced in the same commit

`ResourceOwnerAuthenticator:127,145,150` throw Restlet's unchecked `ResourceException` on the
password-grant path ([research §4](phase-5d-2-research.md#4)). Replace with `OAuthProblemException`
so D5's bridge covers it and the answer is an OAuth2 `server_error` rather than a framework 500. It
is the same class the soak fixed, and `e2e/oauth2/realms-test.spec.mjs` row 10 is its only e2e
coverage — extend that spec rather than inventing a new one.

<a id="d7"></a>
### D7 — the realm constants migrate now, and both `RestletRealmRouter`s die

Six live CHF-path files read `RestletRealmRouter.REALM` / `.REALM_OBJECT`, and the neutral constants
`OAuth2Constants.Custom.REALM` / `.REALM_OBJECT` (`:784,791`) already hold the identical literals
with a javadoc promising this migration ([research §5](phase-5d-2-research.md#5)). Repoint all six —
`OAuth2UrisFactory:69`, `OAuth2RealmResolver:51`, `UmaUrisFactory:87`,
`UmaProviderSettingsFactory:80`, `RealmRoutingFactory:21-22`, `UmaUrisFactoryTest` — and delete the
duplicate. `REALM_URL`'s only reader dies with `RestletOAuth2Request`.

⚠ **Both classes named `RestletRealmRouter` are deletable at 5d-2, and the
[trap that says otherwise](phase-5d-1-asbuilt.md#handed-to-5d-2) is out of date** — its premise was
that other Restlet consumers still call `RealmRoutingFactory.createRouter(org.restlet.routing.Router)`.
After 5d-2a ports WebFinger and 5d-2b deletes `OAuth2RouterProvider`, that overload has no callers at
all. The trap's *operational* content stands: they are different classes in different modules, so
never delete by simple name.

<a id="d8"></a>
### D8 — 5d-2 finishes what phase 8 needs, so phase 8 stays mechanical

`RestRealmValidator` (openam-restlet, Restlet-free) is used by CHF's `RealmContextFilter`. Relocating
it to openam-rest `org.forgerock.openam.rest.router` is the last thing standing between phase 8 and a
module delete, and it costs one move plus three test imports. Do it here.

After 5d-2, `openam-oauth2`, `openam-uma`, `openam-rest` and `openam-oauth2-saml2` are all
Restlet-free and drop their restlet + openam-restlet dependencies. The only `org.restlet` left in the
tree is `openam-http-client` (phase 7) and the `openam-restlet` module itself (phase 8).

---

## New / modified / deleted

Full per-file lists are in [research §2](phase-5d-2-research.md#2) — this is the shape, not a
duplicate of it.

**5d-2a-i** — new: `WebFingerHandler`, `WellKnownHttpRouteProvider`, `WebFingerHandlerTest`,
`WellKnownRouterIT`. Modified: `META-INF/services/org.forgerock.openam.http.HttpRouteProvider`
(one line appended). Nothing else — `/.well-known/*` still maps to the Restlet servlet, so the route
is registered and unreachable.

**5d-2a-ii** — modified: `web.xml` (delete the `WebFinger` servlet block `:1046-1068` — four
`org.restlet` references, the WAR's last — and move the `/.well-known/*` mapping `:1092-1095` to
`OpenAM`), `e2e/oauth2/webfinger-test.spec.mjs`. Deleted: `WebFinger`, `OpenIDConnectDiscovery`.
**Nothing else references either class** — no Guice binding, no `META-INF/services` entry, no
`*.properties`; `web.xml:1053` and their own mutual reference are the whole of it (verified
2026-08-06). The one-hunk revert is the `<servlet-mapping>` move.

**5d-2b** — modified: the five parity tests (D4), `OAuth2GuiceModule`, `OAuth2RestGuiceModule`,
`web.xml` (`ForgeRockRest` declaration), `openam-oauth2-saml2/pom.xml`. Moved: the four classes of
D3. Deleted: 23 of `org.forgerock.oauth2.restlet`'s 24 files + `resources/ResourceSetRegistrationExceptionFilter`,
the 7 of `org.forgerock.openidconnect.restlet` that 5d-2a did not already take,
`AccessTokenProtectionFilter`, `ResourceSetRegistrationEndpoint`, `OAuth2RouterProvider`,
`TokenRevocationResource`, `RestletOAuth2Request`, the three Restlet audit filters,
`Saml2BearerServerResource`, and their tests.

**5d-2c** — deleted: 8 openam-rest main classes + 4 tests. Modified: `openam-rest/pom.xml`.

**5d-2d** — modified: `OAuthProblemException`, the two endpoint bases, `ResourceOwnerAuthenticator`,
`ResourceOwnerSessionValidator`, `StatefulTokenStore`, `OAuth2Request`, `OAuth2RequestFactory`,
`TokenResource`, `RealmRoutingFactory`, the six realm-constant readers, `SmsRealmProvider`,
`AuthenticationServiceV1`, `DefaultWsFedAuthenticator`, four poms. Moved: `RestRealmValidator`.
Deleted: `RestletRealmRouter` (openam-restlet) + its test, `RealmRoutingFactory`'s Restlet overload
and inner router.

---

## Verification criteria

Numbered so the as-built can cite them.

**Every sub-phase (the standing bar):**

1. `mvn -q -am -pl <touched modules> verify` green, with the surefire/failsafe **counts** recorded —
   a deletion phase can turn a suite green by removing the tests that failed, and only the count
   catches that. Compare against 5d-1b's recorded baseline.
2. `mvn install -DskipTests` from the root, then a **Cargo boot** — the Guice graph is what class
   moves and unbinds actually threaten, and it is the only thing that proves it.
3. Full `npx playwright test` on a container rebuilt from that commit. The baseline is the soak's
   post-fix figure — **153 declared, 152 passed / 1 skipped / 0 failed**
   ([record](phase-5d-1-asbuilt.md#criterion-17--the-soak--recorded-2026-08-06)). Two sub-phases move
   the declared count on purpose: 5d-2a-ii (−1 for the deleted "records the current live response"
   500 row, +n for the D2 parity rows — criterion 9) and 5d-2d **+n** (D6's password-grant rows). Any
   *other* movement is an accidentally deleted row and must be justified in the as-built.
4. `git diff --stat` reviewed against this doc's file lists — an unlisted file in a deletion commit
   is either a missed dependency or scope creep.

**5d-2a-i (dormant build):**

5. The D2 pre-port capture exists in `artefacts/` **before** this commit — it is taken against the
   container built from the *previous* commit, and 5d-2a-ii destroys the oracle.
6. `WellKnownRouterIT` pins the route table, the realm spellings and the default route, and is
   **mutation-checked**: break the URI template, confirm it goes red. It must also assert the two
   things the chain shape exists for — that an audit event carries the resolved realm, and that a bad
   `?realm=` comes back `{error,error_description}` rather than `{code,reason,message}` ([D1](#d1)).
7. The route is genuinely dormant: on a container built from this commit, `/.well-known/webfinger`
   still answers exactly what the D2 capture recorded, byte for byte. If it changed, the servlet
   mapping is not where this doc says it is.

**5d-2a-ii (the flip):**

8. Every D2 parity target reproduced byte-for-byte against the capture; each miss carries a
   divergence row and a reason. The success row is the fix (row 33), the 404 shapes are row 34.
9. `webfinger-test.spec.mjs` — the `test.fail()` annotation removed and the row genuinely passing
   (Playwright reports "expected to fail but passed" if it is left on), the "records the current live
   response" 500 row deleted as the spec's own header comment instructs, and the header comment's
   claim that the endpoint is wholly broken corrected ([D2](#d2)). New rows for the parity targets the
   capture confirmed.
10. No Restlet servlet mapping remains in `web.xml` — `grep -c "org.restlet" web.xml` → 0. This is the
    WAR's last one; after it, `ForgeRockRest` is a declaration with no mappings.

**5d-2b:**

11. **CI run `31105613611` (or its successor on this SHA) green** before the first `git rm`.
12. The five parity tests still assert non-trivial byte-level values after D4's freeze, and each is
    mutation-checked against the CHF side.
13. `OAuth2RouterIT` + the five composition ITs unchanged and green — they exercise the CHF stack
    only, so a red one means the deletion took something live.

**5d-2c:**

14. `grep -rn "org.restlet" --include="*.java" openam-rest/` → 0.

**5d-2d:**

15. **The D5/D6 pre/post capture.** Drive each reachable `OAuthProblemException` path and the
    password-grant failure path against the container built from the *previous* commit, record
    status + headers + body, then re-run after. Every difference must match divergence row 31 or 32;
    an unmatched one is a regression, per [the table's rule](plan.md#expected-divergences-at-the-flip).
16. The exit gate, exactly:
    ```
    grep -rn "org.restlet" --include="*.java" . | grep -v "^./docs" \
      | grep -v "^./openam-restlet/" | grep -v "^./openam-http-client/"     # -> 0
    grep -rln restlet --include=pom.xml . | grep -vE "openam-restlet|openam-http-client|transform-jakarta|^pom.xml"   # -> 0
    ```
17. CI green on the push — 9 legs, as [5d-1 criterion 16](phase-5d-1.md#verification-criteria)
    enumerates them.

⚠ **What "green" is not, again.** Three of the four sub-phases delete dormant code, so a green suite
proves little more than "the build still builds". The criteria that carry actual weight are 2 (Guice),
3 (the row **count**), 8 (the `/.well-known` parity targets), 12 (the frozen oracles) and 15 (the only
measured behaviour change in the tail).

---

## Integration testing

Same three layers as 5d-1, per [test-infrastructure.md](../../test-infrastructure.md):

1. **Layer 2** — `WellKnownRouterIT` (new, 5d-2a-i) joins `OAuth2RouterIT`, `UmaRouterIT` and the five
   composition ITs. It is the only new IT this phase needs: 5d-2b/c delete code that no IT covers,
   and 5d-2d's change is covered by extending existing suites rather than adding one.
2. **Layer 3** — Cargo boot on every sub-phase (criterion 2). This is the phase's highest-value guard
   because Guice unbinds and package moves fail at graph construction, not at compile.
3. **Layer 4** — the full e2e suite on every sub-phase, plus the two targeted captures (D2, criterion
   15). `realms-test.spec.mjs` gains rows for D6's password-grant path; `webfinger-test.spec.mjs` is
   rewritten by 5d-2a.

Deliberately **not** repeated: the soak's load probe. It proved concurrent body re-reading under the
CHF handlers, and no sub-phase here changes a body-reading path. If 5d-2d's capture shows anything
unexpected on `/access_token`, re-run `e2e/tools/oauth2-load.mjs` before continuing.

---

## Risk register

- **R-5d2.1 — the revert lever is gone.** From 5d-2b's first commit, `/oauth2` cannot be put back on
  Restlet by reverting one line; recovery means reverting the whole sub-phase. **Guard:** criterion 11,
  and keeping each sub-phase a single revertible commit.
- **R-5d2.2 — a "dead" class is not dead.** The deletion lists come from static imports; a class
  reached only by reflection, a `META-INF/services` entry or a Guice string binding would not appear.
  **Guard:** criterion 2 (Cargo boot) plus criterion 4 (diff review); `grep` the deleted simple names
  across `*.xml`, `*.properties` and `META-INF/` before each `git rm`, not only across `*.java`.
- **R-5d2.3 — the frozen oracle is frozen wrong.** A mistyped literal in D4 turns five regression
  guards into five rubber stamps, permanently and undetectably. **Guard:** D4's capture-by-running,
  and criterion 12's mutation check.
- **R-5d2.4 — `/.well-known` serves more than webfinger somewhere.** The WAR maps the whole segment
  to one Restlet servlet; a deployment or a plugin could rely on a path we do not route.
  **Guard:** D1's `OAuth2NotFoundHandler` default route makes the failure a clean 404 rather than a
  container error, and D2's capture records what the incumbent answered for unrouted children.
- **R-5d2.5 — D5 widens an error into a redirect.** The browser base's error path can *redirect* when
  a `redirect_uri` is in play. An `OAuthProblemException` from deep inside the token store must not
  become a redirect carrying an unvalidated URI. **Guard:** the bridge builds through
  `OAuth2Error`/`OAuth2ErrorResponseFactory`, whose `NEVER_REDIRECT` list (`OAuth2Error:75`) is the
  existing mechanism for exactly this; assert it in the browser base's test, and check criterion 15's
  capture for any new 302.
- ✅ **Discharged before the phase started:** WebFinger's twelve-class hold on the deletion
  ([research §1](phase-5d-2-research.md#1)), the checked-exception ripple
  ([research §3](phase-5d-2-research.md#3)), and the two stale traps
  ([research §5](phase-5d-2-research.md#5), [§2](phase-5d-2-research.md#2)).

---

## Divergence rows this phase adds to [plan.md](plan.md#expected-divergences-at-the-flip)

Numbering continues from row 30. **The incumbent for rows 31–32 is the post-flip CHF stack**, not
Restlet — Restlet stopped serving `/oauth2` at 5d-1c. Rows 33–34 are the exception: `/.well-known` is
still Restlet-served until 5d-2a-ii, so their incumbent is Restlet.

| # | What differs | Before | After | Why |
|---|---|---|---|---|
| 31 | Errors raised as `OAuthProblemException` — token-store failures, client-registration attribute reads, id_token signing | framework CREST 500 `{code,reason,message}` | OAuth2 `{error,error_description}` with the exception's own status | [D5](#d5). Same unifying argument as [row 8](plan.md#expected-divergences-at-the-flip): one error shape across `/oauth2` is the whole point of `OAuth2ErrorFilter` |
| 32 | Password-grant internal failures (`ResourceOwnerAuthenticator`) | framework CREST 500 | OAuth2 `{"error":"server_error"}` | [D6](#d6). Restlet's own answer here was never a CREST body either; the raw `ResourceException` was an artefact of the transport, not a contract |
| 33 | `/.well-known/webfinger`, **success path only** | **500**, `{"error":"Internal Server Error"}` — `ServletUtils` returns null under the upstream `ServerServlet` and `getRootURL(null)` NPEs | 200 JRD naming the issuer | [D1](#d1)/[D2](#d2). A pre-existing defect fixed by construction; `webfinger-test.spec.mjs` already asserts the target |
| 34 | `/.well-known` **no-match** — unrouted children, bare `/.well-known/`, an unresolvable realm segment | `OAuth2StatusService` (`:17-23`): `{"error":"<reason phrase>","error_description":"<description>"}`, e.g. `{"error":"Not Found",…}` | `OAuth2NotFoundHandler`: `{"error":"not_found","error_description":"Not Found"}` | [D1](#d1). The status service is one of the twelve classes 5d-2b deletes, so this shape cannot survive. `not_found` is the RFC-6749-style code the rest of the migrated surface already emits |

Row 33 is the phase's one intentional user-visible fix. Row 34 is a no-match shape; 31 and 32 are
shape changes on paths that only ever produced 5xx. ⚠ **The webfinger 400s and 404s are deliberately
not on this list** — they work today ([D2](#d2)) and criterion 8 requires them byte-identical. If the
capture shows one moving, it becomes row 35 with a written reason, not a shrug.

---

## Checklist

**5d-2a-i — build the route, leave it dormant.** Each step ends where the next can start from a green
tree; steps 3–5 are the only ones that write main source.

1. Read CI `31105613611`. Not green ⇒ stop and fix before anything else.
2. **Capture the oracle** ([D2](#d2)) — build a container from `HEAD`, drive the ten probes in D2's
   table, write status + headers + raw bytes to `artefacts/`. This is the one step that cannot be
   redone later: 5d-2a-ii destroys the endpoint it measures. Record what the four parity targets
   actually answer, and note anything the table guessed wrong.
3. `WebFingerHandler` — the `@Get` of [D1](#d1), plus `WebFingerHandlerTest` covering the success
   JRD, the null-servlet-request guard, and one row per exception `discover(...)` throws (proving the
   polymorphic `@ExceptionHandler` reaches them). Unit-test-only; no wiring yet.
4. `WellKnownHttpRouteProvider` — the chain of [D1](#d1) verbatim, including `OAuth2ErrorFilter`, the
   audit filter *inside* the realm layer, `OAuth2NotFoundHandler` as default route, and the
   `invalidRealmNames` registration. Append it to `META-INF/services/…HttpRouteProvider`.
5. `WellKnownRouterIT`, modelled on `OAuth2RouterIT` (534 lines; this one is far smaller — one
   endpoint). Rows: `webfinger` matches; `/realms/{realm}/webfinger` and the subrealm spelling both
   resolve; an unrouted child hits `OAuth2NotFoundHandler`; the audit event carries the realm; a bad
   `?realm=` comes back OAuth2-shaped. Then **mutation-check it** — break the URI template, confirm
   red, restore.
6. Criteria 1–7. Criterion 7 is the one specific to this step: the endpoint must still answer exactly
   what step 2 captured, because nothing has been flipped yet.

**5d-2a-ii — the flip.** One commit, one-hunk revert.

7. `web.xml`: delete the `WebFinger` servlet block, move the `/.well-known/*` mapping to `OpenAM`.
8. Delete `WebFinger` and `OpenIDConnectDiscovery`.
9. Rewrite `webfinger-test.spec.mjs`: drop `test.fail()`, delete the 500-pinning row, correct the
   header comment ([D2](#d2)), add rows for the parity targets step 2 confirmed.
10. Re-run the D2 probes against the new container and **diff against the capture**. Every difference
    is row 33, row 34, or a bug.
11. Criteria 1–4, 8–10.

**5d-2b**
12. Run the five parity tests, capture the Restlet-leg values, inline them ([D4](#d4)) — **own commit**.
13. Move the four surviving classes out of the `.restlet` packages ([D3](#d3)); strip `LoginHintHook`.
14. `grep` every doomed simple name across `*.xml` / `*.properties` / `META-INF/` (R-5d2.2).
15. Delete the openam-oauth2 Restlet stack + `Saml2BearerServerResource`; unbind in both Guice
    modules; drop the `ForgeRockRest` declaration.
16. Criteria 1–4, 11–13.

**5d-2c**
17. Delete the openam-rest Restlet layer + its four tests; drop `openam-rest`'s restlet deps.
18. Criteria 1–4, 14.

**5d-2d**
19. Capture the D5/D6 "before" against the previous commit's container (criterion 15).
20. `OAuthProblemException` → `RuntimeException`; add the two `@ExceptionHandler` bridges + tests
    incl. R-5d2.5's no-redirect assertion.
21. `ResourceOwnerAuthenticator`; extend `realms-test.spec.mjs`.
22. The remaining core de-leak: `OAuth2Request`/factory, `StatefulTokenStore`,
    `ResourceOwnerSessionValidator`, `TokenResource`, the vestigial imports.
23. Realm constants ([D7](#d7)); delete both `RestletRealmRouter`s and the `RealmRoutingFactory`
    Restlet branch.
24. Relocate `RestRealmValidator` ([D8](#d8)); pom sweep.
25. Criteria 1–4, 15–17; capture the "after"; write the as-built.
26. Update [plan.md](plan.md) — phase status, rows 31–34, and phase 6/8's now-reduced scope.
