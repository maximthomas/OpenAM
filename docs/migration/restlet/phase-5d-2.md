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
**500ed on every request since before this migration started** — success and error paths alike, as the
[pre-flip capture](artefacts/well-known-probes-pre-flip.md) measured on 2026-08-06.

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
### D2 — the `.well-known` contract is captured before the port, and it is a 500 almost everywhere

✅ **Captured 2026-08-06 — [`artefacts/well-known-probes-pre-flip.md`](artefacts/well-known-probes-pre-flip.md),
19 probes against `openam-e2e:soakfix` with the deployed jar checksummed.** Re-run it with
`e2e/tools/well-known-probes.sh`.

⚠ **The measurement refuted this doc's own correction. The endpoint *is* wholly broken, and
`webfinger-test.spec.mjs`'s header comment was right all along.** An earlier draft claimed only the
success path 500s, reasoning from `OpenIDConnectDiscovery:98-100`'s `doCatch` override to the two-arg
`ExceptionHandler.handle(Throwable, Response)` (`ExceptionHandler:147-157`), which renders
`exception.asMap()` and sets the exception's own status. That mechanism is real but never fires here,
because of one line of ordering at `OpenIDConnectDiscovery:79-83`:

```java
final String deploymentUrl =
        baseUrlProviderFactory.get(realm).getRootURL(ServletUtils.getRequest(getRequest()));   // NPEs here
final Map<String, Object> response = providerDiscovery.discover(resource, rel, deploymentUrl, request);
```

`getRootURL(null)` throws **before** `discover(...)` is ever called, so the `BadRequestException` /
`NotFoundException` that would have produced the 400s and the 404 are unreachable. What reaches
`doCatch` is a `NullPointerException`, not an `OAuth2Exception`, and it renders as the generic 500.
**That validation contract has never once executed in this deployment.** Per
[the oracle rule](INDEX.md#the-oracle-record), the measurement replaces the prediction:

| Probe | **Measured incumbent** | After the port |
|---|---|---|
| `?resource=acct:demo@example.com&rel=<issuer>` (± `realm=/`) | **500**, `{"error":"Internal Server Error",…}`, 149 B | **200 JRD** — the fix (row 33) |
| `?rel=<issuer>` (no `resource`); `?resource=…` (no `rel`); a wrong `rel`; no params at all | **500 — the same 149 bytes.** Not a parity target; the 400 never ran | 400 `{"error":"bad_request",…}` — row 33 |
| `?resource=acct:nobody@…&rel=<issuer>` | **500 — the same 149 bytes** | 404 `{"error":"not_found",…}` — row 33 |
| `?resource=…&rel=…&realm=/bogus` | **404**, `{"error":"Not Found","error_description":"Realm \"/bogus\" not found"}` | 400 via `RealmContextFilter` + `OAuth2ErrorFilter` — **row 35** |
| `/.well-known/nonsense`, `/a/b/c`, `/webfinger/extra`, a realm-spelled path | **500 — the same 149 bytes.** Restlet's single `attach("/webfinger",…)` matches far more than its literal path | 404 `OAuth2NotFoundHandler` — row 34 |
| `/.well-known` and `/.well-known/` bare | **404 via `OAuth2StatusService`**, 102 B — the only two paths that reach it | 404 `OAuth2NotFoundHandler` — row 34 |
| `HEAD` on the success URL | **500 `text/html`, 717 B** — Restlet's HTML status page, a third shape | as the success row (`Endpoints:70-72` maps HEAD→GET) — row 33 |
| `POST` on the success URL | **500 — the same 149 bytes** | 405 + `Allow` — **row 36** |
| `/.well-known/openid-configuration` at the **context root** | **500 — the same 149 bytes.** The real document is `/oauth2/.well-known/openid-configuration` (200, CHF-served, unaffected) | 404 `OAuth2NotFoundHandler` — row 34 |

**There are no parity targets.** Fourteen of the nineteen probes return one byte-identical 500
(md5 `dd82fa5d59a42118454371b094ddfa6a`). Nothing under `/.well-known/*` currently returns a value
worth reproducing, so every post-port answer is an improvement to be justified, not a contract to
match. The one thing the capture still arbitrates is that the **control** row — `/oauth2/.well-known/
openid-configuration`, md5 `74c2c745fbbdc2c4bdd52cbe748d83ed` — must not move.

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

8. Re-run `e2e/tools/well-known-probes.sh` and diff against
   [the pre-flip capture](artefacts/well-known-probes-pre-flip.md). **There are no parity targets to
   reproduce** — the capture found one byte-identical 500 on fourteen of nineteen probes ([D2](#d2)) —
   so the bar is the inverse: **every one of the nineteen probes must land on a divergence row 33–36
   with a written reason, and the control row (`/oauth2/.well-known/openid-configuration`,
   md5 `74c2c745…`) must be unchanged.** An answer matching no row is a bug.
9. `webfinger-test.spec.mjs` — the `test.fail()` annotation removed and the row genuinely passing
   (Playwright reports "expected to fail but passed" if it is left on), and the "records the current
   live response" 500 row deleted as the spec's own header comment instructs. ⚠ **Its header comment's
   claim that the endpoint is wholly broken is correct and must be kept** — an earlier draft of
   [D2](#d2) called for "correcting" it, and the capture showed the header right and the draft wrong.
   New rows for the 400/404 paths, which the port makes reachable for the first time.
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
- ✅ **R-5d2.4 — `/.well-known` serves more than webfinger somewhere. Discharged by measurement,
  2026-08-06.** The capture drove every unrouted-child spelling plus the context-root
  `/openid-configuration`, and **all of them answer the same 149-byte 500**
  ([D2](#d2)). Nothing real is served from the segment, so there is nothing to lose. D1's
  `OAuth2NotFoundHandler` default route still stands, and now turns those 500s into clean 404s (row 34).
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
| 33 | `/.well-known/webfinger`, **every routed request** — the success JRD *and* the missing-`resource`, missing/wrong-`rel` and unknown-user paths | **500**, `{"error":"Internal Server Error"}`, 149 B — `ServletUtils` returns null under the upstream `ServerServlet` and `getRootURL(null)` NPEs *before* `discover(...)` runs | 200 JRD naming the issuer; 400 `bad_request`; 404 `not_found` | [D1](#d1)/[D2](#d2). A pre-existing defect fixed by construction. ⚠ **Widened 2026-08-06 by the capture**: the draft scoped this to the success path, believing the 400s/404 were live contracts. They are not — the NPE precedes them, so all four answers are the same 500 today and all four move |
| 34 | `/.well-known` **no-match** — unrouted children (`/nonsense`, `/a/b/c`, `/webfinger/extra`), a realm-spelled path, context-root `/openid-configuration`, and bare `/.well-known`(`/`) | **500** (149 B) for everything with a path element — Restlet's single `attach("/webfinger",…)` matches far more than its literal path; **404 `OAuth2StatusService`** (`:17-23`, 102 B) for the two bare spellings only | `OAuth2NotFoundHandler`: `{"error":"not_found","error_description":"Not Found"}` | [D1](#d1). `EQUALS "webfinger"` is strict where Restlet's attach was loose, so this is a **narrowing** as well as a reshape. The status service is one of the twelve classes 5d-2b deletes, so its shape cannot survive either way |
| 35 | `/.well-known/webfinger?realm=<unresolvable>` | **404**, `{"error":"Not Found","error_description":"Realm \"/bogus\" not found"}` — `RestletRealmRouter` rejects before dispatch | 400, OAuth2-shaped, via `RealmContextFilter` + `OAuth2ErrorFilter` | [D1](#d1). `RealmContextFilter` never 404s a bad realm — it is a `BadRequestException` ([chf-patterns §23](chf-patterns.md#23-route-provider-mechanics--when-handlers-are-built-and-what-a-no-match-answers-phase-5d-1)). Accepting the status move buys one realm-error shape across the whole migrated surface; preserving the 404 would make `/.well-known` the only route that disagrees |
| 36 | `POST /.well-known/webfinger` | **500** (149 B) — the NPE again; Restlet dispatched `POST` into the `@Get` resource | 405 with an `Allow` header | [D1](#d1). `Endpoints` refuses an unmapped method; WebFinger is a read endpoint and RFC 7033 defines `GET` only |

Row 33 is the phase's one intentional user-visible fix. Rows 34–36 are shapes on paths that only ever
produced a 500 or a framework 404; 31 and 32 are shape changes on paths that only ever produced 5xx.
⚠ **Rows 33–36 were rewritten on 2026-08-06** from the
[pre-flip capture](artefacts/well-known-probes-pre-flip.md), which refuted the draft's claim that the
webfinger 400s and 404s were live contracts held out of this table as parity targets. They were never
reachable. Criterion 8 is now the inverse test: every probe must land on a row here.

---

## Checklist

**5d-2a-i — build the route, leave it dormant.** Each step ends where the next can start from a green
tree; steps 3–5 are the only ones that write main source.

1. ✅ Read CI `31105613611`. Not green ⇒ stop and fix before anything else. *(Green, all 10 jobs,
   2026-08-06.)*
2. ✅ **Capture the oracle** ([D2](#d2)) — 19 probes via `e2e/tools/well-known-probes.sh` into
   [`artefacts/well-known-probes-pre-flip.md`](artefacts/well-known-probes-pre-flip.md), 2026-08-06.
   This is the one step that cannot be redone later: 5d-2a-ii destroys the endpoint it measures.
   It refuted D2's parity-target premise; [D2](#d2), criteria 8–9, R-5d2.4 and rows 33–36 were
   rewritten from it.
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
9. Rewrite `webfinger-test.spec.mjs`: drop `test.fail()`, delete the 500-pinning row, **keep the
   header comment's "broken today" claim — the capture proved it right** ([D2](#d2)) — and add rows
   for the 400/404 paths the port makes reachable for the first time.
10. Re-run `e2e/tools/well-known-probes.sh` against the new container and **diff against the capture**.
    Every difference is row 33, 34, 35, 36, or a bug.
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
26. Update [plan.md](plan.md) — phase status, rows 31–36, and phase 6/8's now-reduced scope.
