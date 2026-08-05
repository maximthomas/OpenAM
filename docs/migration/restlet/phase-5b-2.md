# Phase 5b-2 — `/device/user`, `/connect/checkSession`, `/connect/endSession` → CHF: Detailed Plan

Execution plan for **step 5b-2** of [Phase 5](phase-5-oauth2.md) of the Restlet → CHF migration — the three
remaining browser-facing `/oauth2` endpoints. Parent tracker: [plan.md](plan.md); umbrella:
[phase-5-oauth2.md](phase-5-oauth2.md); the step this one builds on: [phase-5b-1.md](phase-5b-1.md) (the
`AbstractOAuth2HttpEndpoint`/`…Browser`/`…Json` hierarchy, `ConsentPageRenderer`, `OAuth2ContentTypes`,
`OAuth2NoCacheFilter`); build-ahead infra it consumes: [phase-3c-1-renderer.md](phase-3c-1-renderer.md),
[phase-3c-2-error-layer.md](phase-3c-2-error-layer.md); decisions: [decisions.md](decisions.md); reusable CHF
patterns: [chf-patterns.md](chf-patterns.md); test layers: [../../test-infrastructure.md](../../test-infrastructure.md).
Written 2026-07-28; branch `features/restlet-migration`. **All facts below were verified against the tree on
2026-07-28** — file and line references are to that state.

> **Naming.** [plan.md](plan.md)'s phase table calls this step **5b-2**. This doc splits it into **5-E3** (a
> test-only live-oracle gate), **5b-2a** (the two JSON-error endpoints) and **5b-2b** (the device flow) — the
> same reviewability/risk-isolation split 5a-2 and 5b-1 used.

## Context

The umbrella describes these three as "near-mechanical relative to `AuthorizeHandler`", and by volume they are:
`DeviceCodeVerificationResource` 302 L, `OpenIDConnectCheckSessionEndpoint` 119 L, `EndSession` 156 L against
`AuthorizeResource`'s ~600 L. But the umbrella's one-line framing —
*"Extend `AbstractOAuth2HttpBrowserEndpoint` (from 5b-1). All three are near-mechanical"* — **is wrong about
the most load-bearing thing in the step**: only **one** of the three is a browser endpoint. See
[finding 1](phase-5b-2-research.md#1--only-one-of-the-three-is-a-browser-endpoint-the-doccatch-arity-decides).

Two further things make this step less mechanical than the sizing suggests:

- the device flow reaches the consent page through a **different data path** than `/authorize` does, and
  `ConsentPageRenderer` as shipped in 5b-1 **cannot serve it correctly** ([finding 2](phase-5b-2-research.md#2--consentpagerenderer-phase-1-is-realm-only-and-that-silently-breaks-the-device-consent-page));
- there is **no §E contract lock** for any of the three, and three of this doc's decisions are gated on
  observations that can only be made while Restlet still serves `/oauth2`
  ([finding 6](phase-5b-2-research.md#6--no-e-lock-covers-these-three--what-e2e-already-records-and-what-it-does-not)).

Build-ahead as usual: **nothing is routed** until 5d-1.

> **Convention.** New classes: `org.openidentityplatform.openam.oauth2.http` (OAuth2) /
> `org.openidentityplatform.openam.openidconnect.http` (OIDC), CDDL header, `Copyright 2026 3A Systems LLC.`,
> **no `@since`** ([decisions.md](decisions.md)). Classes modified in place keep their header and gain a
> `Portions copyright 2026 3A Systems LLC.` line — except our own 2026 classes, which carry no `Portions` line.

## Scope & sizing — split three ways

| Step | Scope | New / changed | Risk |
|---|---|---|---|
| **5-E3** | **The live-Restlet contract lock for all three endpoints.** ~14 rows added to the existing `e2e/oauth2/oidc-test.spec.mjs` (`OIDC session endpoints`) and `e2e/oauth2/oauth2-endpoints-test.spec.mjs` (`OAuth2 device flow`) describes, written **by observation**. Test-only, no main code. Gates D5, D7, D8 | e2e specs only (0 main) | **High** — unrecoverable after 5d-1 |
| **5b-2a** | **The two JSON-error endpoints**: `EndSessionHandler`, `CheckSessionHandler`. Both extend `AbstractOAuth2HttpJsonEndpoint` unchanged; each wraps its own client-reachable unchecked throw (D7). Carries the `OAuth2ErrorFilter` 405 one-liner (D10) | 2 new + 1 filter one-liner + 3 tests | **Med** |
| **5b-2b** | **The device flow**: `DeviceCodeVerificationHandler` + the `ConsentPageRenderer` phase-1 correction (D2) it forces | 1 new + 1 modified + 2 tests + 1 IT | **High** |

**Total new main classes: 3.** Plus one behavioural correction to a 5b-1 class (`ConsentPageRenderer`) and one
additive mapper on a 5a class (`AbstractOAuth2HttpJsonEndpoint`).

Order: **5-E3 → 5b-2a → 5b-2b**. 5-E3 first for the same reason 5-E2 was first in 5b-1: three of the decisions
below are *settled by* what it records, and the [CONTINUE-bug lesson](phase-5b-1-research.md#2--the-continue-bug-makes-authorizes-filter-validation-unpredictable--record-it-do-not-derive-it)
is that predicting this provider's error surface is unreliable. 5b-2a before 5b-2b because it is the smaller
and its `RuntimeException` mapper is a base-class edit the device handler also inherits.

---

## Design decisions

<a id="d1"></a>
### D1 — base class per endpoint, from the `doCatch` arity (finding 1)

```
AbstractOAuth2HttpEndpoint
├── AbstractOAuth2HttpJsonEndpoint    ← EndSessionHandler, CheckSessionHandler
└── AbstractOAuth2HttpBrowserEndpoint ← DeviceCodeVerificationHandler
```

Not negotiable and not a style choice: it is the difference between a JSON error body and an HTML page on every
error these endpoints produce. **The `@ExceptionHandler` methods on both bases must not be overridden**
(annotations are dropped on overrides — the trap both base javadocs already warn about).

<a id="d2"></a>
### D2 — `ConsentPageRenderer` phase 1 reads the same enumerated keys from the attributes

Change `dataModel`'s phase 1 from "copy `realm`" to "copy each of the enumerated keys that is present as an
attribute", keeping phase 2 (query overlay, `getQueryParameter` only) and phase 3 (derived, strictly last)
exactly as they are:

```java
// 1. Request attributes. On /authorize this is just the realm the RealmContext seeded; on the device
//    flow it is the whole device-code record, which is the ONLY source those keys have there.
for (String key : MODEL_KEYS) {                    // MODEL_KEYS == today's QUERY_KEYS
    Object value = o2.getAttribute(key);
    if (value != null) {
        data.put(key, value);
    }
}
// 2. Query overlay -- query wins.  (unchanged)
// 3. Derived keys, strictly last.  (unchanged)
```

Behaviour-neutral for `/authorize` (`ChfOAuth2Request.attributes()` seeds only `realm`, `realmObject` and URI
template variables — and `realmObject` is not in the list), and it is what makes the device consent page render
the same keys Restlet rendered. Guarded by a new `ConsentPageRendererTest` case that seeds device-code-shaped
attributes and asserts all seven keys survive.

*Alternative rejected:* have the device handler pre-copy attributes into the query. That mutates the request
URI (`setQueryParameter` writes through to it — `ChfOAuth2Request:324-334`), which would corrupt the consent
form's `target` and leak the device code's stored values into a page the user posts back.

<a id="d3"></a>
### D3 — seed the device code onto the `OAuth2Request` attributes, not into a local map

`o2.setAttribute(key, value)` per finding 3, including the `clientID` → `client_id` rename and the `scope`
join. Attributes are the first source `getParameter` consults, so this reproduces Restlet's effect on every
downstream collaborator in one place. Extracted as a package-private method so the test can assert the mapping
without a full flow.

<a id="d4"></a>
### D4 — the two device pages render by literal path; only the consent page is display-scoped

`renderer.render("templates/CodeVerificationForm.ftl", model)` / `"templates/CodeThanks.ftl"`, never
`renderForDisplay` (finding 4). Their model is exactly `{errorCode?, baseUrl, locale, realm}` with `errorCode`
**omitted** (not null-valued) when absent, so `<#if errorCode??>` behaves as it does today — Restlet put a null
into a `Map<String,String>`, which FreeMarker treats as missing; CHF should not put the key at all. `locale`
is `OAuth2Utils.joinStatic(o2.getAcceptedLanguages(), " ")` (the 5b-1a accessor); `baseUrl` is
`baseURLProviderFactory.get(o2.getParameter("realm")).getRootURL(o2.getHttpServletRequest())`.

<a id="d5"></a>
### D5 — `?display=` on check-session: keep display resolution, let a missing template be a 400 (**gated on 5-E3 row 7**)

`OpenIDConnectCheckSessionEndpoint` goes through the display-scoped renderer, so `CheckSessionHandler` uses
`renderForDisplay(display, "checkSession.ftl", model)`. Since `checkSession.ftl` exists only under `page/`:

| `?display=` | Restlet today | CHF after the 3c-1 D5 fix |
|---|---|---|
| absent / `page` | `page/checkSession.ftl` | identical |
| `popup` | renders the **hardcoded** `popup/authorize.ftl` with the check-session model — which reads `${display_name}`/`${display_scopes}` unguarded and therefore **throws**, surfacing as `ResourceException(400, "Server can not serve …")` → 400 JSON | `popup/checkSession.ftl` not found → `TemplateNotFoundException` (an `IOException`) |
| `touch` / `wap` | template missing → `TemplateFactory` returns null → `getRepresentation` throws `ResourceException(400, …)` → 400 JSON | `TemplateNotFoundException` |
| unknown | `Enum.valueOf` → `IllegalArgumentException` → 400 `server_error` JSON | `IllegalArgumentException` |

⇒ **Decision: one `try` around the render, mapping both `IOException` and `IllegalArgumentException` to
`ServerException` — 400 `server_error` JSON** (D7's second row). Every case above stays a 400 with a JSON body,
which is what live Restlet does for all of them; the only movement is in the `error_description` text.
**5-E3 row 7 must confirm the 400s before this lands**; if the oracle shows any of them succeeding, revisit (a
`page/` fallback is the alternative, and it would then be the parity-preserving choice).

This is the decision [3c-1's `renderForDisplay` javadoc](phase-3c-1-renderer.md) and
**[decisions.md D5](decisions.md)** both explicitly deferred to "Phase 5b's call". Update *both* to point here.

<a id="d6"></a>
### D6 — mount `CheckSessionHandler` on the ordinary route; the JSP keeps the bare path by itself

No web.xml change, no conditional routing, no special-casing (finding 5). `router.attach("connect/checkSession", …)`
in `OAuth2HttpRouteProvider` at 5d-1 is both correct and sufficient: the exact JSP mapping wins on
`/oauth2/connect/checkSession`, and the handler serves the realm-prefixed variants — which is precisely today's
split. **Do not delete the JSP or its mapping at 5d-2** ([R-5.7](phase-5-oauth2.md), locked).

<a id="d7"></a>
### D7 — wrap the **client-reachable** unchecked throws at their source; no base-class mapper (**revised at review; confirmed and extended by 5-E3, 2026-07-28**)

~~Three~~ **Four** unchecked throws in this step are reachable from client input, and each is wrapped where it
is raised so it leaves the handler as a checked `ServerException` — which the JSON base already maps to **400
`server_error`**, byte-identical to Restlet's `toOAuth2RestletException` fallback. All four are now pinned on
the live wire ([As-built](phase-5b-2-asbuilt.md#as-built-5-e3--recorded-2026-07-28) rows 6d, 7 and 10):

| Where | Trigger | Wrap |
|---|---|---|
| `EndSessionHandler` | malformed `id_token_hint` → `JwtReconstruction.reconstructJwt` (finding 10) | `catch (RuntimeException e) { throw new ServerException(e); }` around the reconstruction |
| `CheckSessionHandler` | `?display=bogus` → `Enum.valueOf` `IllegalArgumentException` (D5) | around the `renderForDisplay` call, together with its `IOException` |
| `CheckSessionHandler` | id_token with **no `aud` claim** → NPE in `CheckSession.getClientSessionURI` (finding 13) | around the `getClientSessionURI`/`getValidSession` pair |
| `CheckSessionHandler` | **any** valid id_token when the client's `clientSessionURI` is **unset** → `NoSuchElementException` from `set.iterator().next()` in `OpenAMClientRegistration.getClientSessionURI:426-434` (**added by 5-E3**) | the same wrap as the row above — it is the same call |

⚠ The fourth row is the one to take seriously, because it is not an edge case: the admin API leaves
`com.forgerock.openam.oauth2provider.clientSessionURI` **empty on every client it creates**, and
`getClientSessionURI()` has no emptiness guard. So on a default-configured deployment, check-session **400s on
its own happy path** the moment an RP actually supplies an `id_token` — the endpoint's entire reason for
existing. 5-E3 only got a 200 out of row 6c after the fixture set the attribute explicitly. This does not
change the port (the same wrap covers it), but the separate null-guard ticket in checklist step 9 must cover
**the empty set as well as the null registration**, or it fixes the rarer half of the bug.

⚠ **Explicitly *not* a `@ExceptionHandler` on `AbstractOAuth2HttpJsonEndpoint`.** An earlier draft of this plan
proposed exactly that, and it contradicts locked **[D3](decisions.md)**: *"the uncaught-bug path keeps CHF's
500; Restlet's 400 is not reproduced […] reproducing 400 would mean a filter that downgrades a 500 —
permanently masking server bugs from monitoring."* A blanket mapper cannot tell a malformed JWT from a null
dereference in a collaborator, so it would restore parity on three paths by hiding every future one. Wrapping
at the source keeps the distinction the migration already decided to keep, and it touches **none** of the five
committed 5a handlers — so there is no base-class edit, no regression gate on their suites, and nothing new for
the 5d-1 diff notes.

The third row is a **pre-existing product bug**, not a migration artifact: `getClientSessionURI:111-115` guards
`clientRegistration != null` for the validity check and then dereferences it unconditionally, and
`getClientRegistration` returns null exactly when the JWT carries no audience. Reproduced here (400
`server_error`, as today); **fixing the guard is its own commit with its own test and release note** — the same
treatment `ServerException`'s hardcoded 400 got under [D2](decisions.md), and the same reason the
`touch/authorize.ftl` typo and the unverified `id_token_hint` signature are reproduced rather than corrected
inside a parity migration.

*Alternative rejected:* leave all three to the framework's 500. It converts three client-controlled inputs into
server errors, which is a monitoring regression in the opposite direction and a worse wire contract than the
one being replaced.

<a id="d8"></a>
### D8 — the endSession 302 composes through `RedirectUris` (**gated on 5-E3 row 8**)

```java
Map<String, String> params = isEmpty(state) ? Map.of() : Map.of("state", state);
return redirectTo(RedirectUris.compose(redirectUri, params, UrlLocation.QUERY));
```

`RedirectUris.compose(…, QUERY)` **appends**, which is what `Reference.addQueryParameter` did; the
percent-encoding parity between the two was proven and closed at 3c-2 ([plan.md](plan.md) risk #3). The
documented empty-params divergence — an empty map leaves the target untouched — is **the desired behaviour
here**, matching Restlet's `if (state != null && !state.isEmpty())` guard exactly.

The one thing observation must settle is whether `new Reference(uri).toString()` **normalises** a redirect URI
that already carries a query or a fragment, where `RedirectUris` emits it verbatim. 5-E3 row 8 registers a
`post_logout_redirect_uri` with an existing query string and records the exact `Location`. If they differ,
record it as an expected 5d-1 divergence rather than bending `RedirectUris`, whose contract is shared with
`/authorize`.

Status is **302** (`MODE_CLIENT_FOUND`); the no-redirect path returns **204 with no entity**, which on CHF is
`new Response(Status.NO_CONTENT)` — matching the already-recorded e2e row.

<a id="d9"></a>
### D9 — handler shapes

```java
// org.openidentityplatform.openam.oauth2.http
public class DeviceCodeVerificationHandler extends AbstractOAuth2HttpBrowserEndpoint {
    @Get  public Response userCodeForm(@Contextual Context ctx, @Contextual Request request) throws OAuth2Exception
    @Post public Response verify(@Contextual Context ctx, @Contextual Request request) throws OAuth2Exception
}

// org.openidentityplatform.openam.openidconnect.http
public class CheckSessionHandler extends AbstractOAuth2HttpJsonEndpoint {
    @Get  public Response checkSession(@Contextual Context ctx, @Contextual Request request) throws OAuth2Exception
    @Post public Response checkSessionPost(@Contextual Context ctx, @Contextual Request request) throws OAuth2Exception
}

public class EndSessionHandler extends AbstractOAuth2HttpJsonEndpoint {
    @Get  public Response endSession(@Contextual Context ctx, @Contextual Request request) throws OAuth2Exception
}
```

`CheckSessionHandler` keeps **both** verbs (`OpenIDConnectCheckSessionEndpoint` has `@Get` and `@Post`, both
delegating to the same body). `EndSessionHandler` is GET-only, as today. `DeviceCodeVerificationHandler`'s two
verbs delegate to one private method, mirroring `userCodeForm()` → `verify(null)`; the GET renders the bare
form when `user_code` is absent.

<a id="d10"></a>
### D10 — `OAuth2ErrorFilter` maps a rewritten **405** to `method_not_allowed` (**decided at review, 2026-07-28**)

```java
case 405:
    return "method_not_allowed";   // parity with AuthorizeEndpointFilter/TokenEndpointFilter
```

`errorFor` currently sends every rewritten 4xx except 401/403 to `invalid_request` through its `default` branch,
so at the flip a wrong verb answers `invalid_request` where live Restlet answered **`method_not_allowed`** —
recorded twice already, by [5-E](plan.md) for `GET /access_token` and [5-E2 row 7](phase-5b-1.md#d8) for
`PUT /authorize`.

> ⚠ **Cite the subclasses, not the base.** `OAuth2Filter.validateMethod` is **abstract** (`OAuth2Filter.java:88`)
> and emits nothing. The literal comes from `AuthorizeEndpointFilter.validateMethod:54` (`"Required Method: GET
> or POST found: "`) and `TokenEndpointFilter.validateMethod:54` (`"Required Method: POST found: "`) — the two
> concrete subclasses, and the reason the parity claim covers exactly two routes. An earlier draft of this
> decision and of the filter's own javadoc cited the abstract base, which sends a reader chasing the route-scope
> question to an empty declaration.

> **Corrected by 5-E3 row 11 (2026-07-28).** The original draft of this paragraph went on: *"5b-2 would have
> added three more endpoints to that list, which is what turned a tolerated one-off into a pattern worth
> closing."* **That is false.** None of this step's three endpoints emits `method_not_allowed` today — none is
> wrapped by `OAuth2Filter`, so a wrong verb gets the framework's **CREST** `{code, reason, message}` body
> (see the [As-built](phase-5b-2-asbuilt.md#as-built-5-e3--recorded-2026-07-28)). D10 therefore rests on **two** endpoints,
> `/authorize` and `/access_token`, not five. It still stands — the caveat below anticipated exactly this
> outcome — but the "pattern" argument does not, and the decision should be read as the narrow parity fix it
> is.

One line, in **our own** code, no framework change. It **narrows but does not delete**
[expected divergence #3](plan.md#expected-divergences-at-the-flip): the `error` field — the one clients dispatch
on — becomes identical, while `error_description` still differs (the framework's `"Method Not Allowed"` against
Restlet's `"Required Method: GET or POST found: PUT"`). Update that row rather than removing it.

⚠ Two things to be honest about. `method_not_allowed` is **not** an RFC 6749 error code, and `errorFor`'s
javadoc argues for RFC-specific codes — but Restlet emitted the non-standard value, and this is a parity
migration, so the incumbent wins. And the mapping also applies to endpoints where a wrong verb produced a
**CREST** body under Restlet rather than an OAuth2 one (everything the `OAuth2Filter` did not wrap, including
all three of this step's); those diverge either way, and `method_not_allowed` is no further from a CREST 405
than `invalid_request` was. **5-E3 row 11 records what each of the three actually sends** — if any of them
turns out to emit `method_not_allowed` today, this decision gets *better*, not worse.

Lands in **5b-2a**, with a new `OAuth2ErrorFilterTest` case and a re-run of `AuthorizeRouteCompositionIT`
(whose D8 row asserts the current `invalid_request` body and must be updated in the same commit).

> **As-built 2026-07-28 — the blast radius is 4 test rows across 2 ITs, not 1.** Gate 6 predicted "exactly one
> intentional edit"; the real set is `AuthorizeRouteCompositionIT`'s two rows (the stand-in handler *and*
> `theRealHandlerAnswersPutWithTheFrameworks405`) plus `OAuth2ErrorRouteCompositionIT`'s
> `aMappedVerbWithNoAnnotatedMethod…` and `anUnmappedVerb…`, the latter pair proving one `case` covers **both**
> framework 405 paths — `AnnotatedMethod`'s own and `Endpoints`' fallback — because `errorFor` keys off the wire
> status, not the body's `code`. **The gate still passes on its substance**: every moved row is a 405 assertion,
> nothing at 400/401/403/404/500/503 moved. The plan simply recalled one of the two ITs.
>
> Also corrected: gate 6 and R-5b2.9 call `OAuth2ErrorFilter`
> "composed on already-committed routes" / "a live-bound path". It is **not bound to any route yet** —
> `new OAuth2ErrorFilter()` appears in three test files and nowhere else, and `openam-oauth2` has no
> `OAuth2HttpRouteProvider` (only the two `/frrest` providers). Build-ahead holds: D10 cannot reach a client
> until 5d-1 mounts the filter, which also means **no test here proves the value on a real wire** — only the
> 5d-1 e2e re-run will.

---

