# Restlet → CHF: the shape of the work

Big-picture map for removing the Restlet framework from OpenAM in favour of CHF
(`org.openidentityplatform.commons.http-framework`). Individual changes under
`openspec/changes/` are the executable units; this file is the thing to read first, and the
thing to correct when a stage turns out differently than planned.

All counts below were derived from the tree on **2026-08-08**, branch
`features/openspec-restlet-migration`. See [Provenance](#provenance) for what is verified and
what is inherited.

---

## The premise

Four decisions are locked and are not reopened by individual changes.

**CHF defects get fixed in CHF.** We maintain `../commons`. Where CHF cannot yet do something
Restlet did, the fix goes into the framework, not into a workaround in OpenAM. This is what
stage ① exists for.

**Neutralise before migrating.** The OAuth2 core stops depending on *any* HTTP framework type
before any endpoint moves. It sees neither `org.restlet.*` nor `org.forgerock.http.*`. This is
stage ③, and it is what unblocks ④–⑦ in parallel.

**Clean-sheet under OpenSpec.** The 85-commit `features/restlet-migration` branch is reference
and oracle only — a source of verified findings and of answers to "what did Restlet actually
do here", not a source of commits to cherry-pick.

**Contracts get written down before the layer under them is swapped.** A facade that resolves
parameters in a subtly different order passes every existing test and breaks a client. Specs
capture protocol-visible behaviour (RFC 6749/6750/7235/7523) that today exists only as the
body of one class.

---

## What Restlet is here today

105 main-source `.java` files import `org.restlet`, across nine modules:

| Module | Files | What they are |
|---|---:|---|
| `openam-oauth2` | 65 | OAuth2/OIDC endpoints, the core classes that unwrap to Restlet, routing, audit |
| `openam-restlet` | 13 | **Ours.** `RestletRealmRouter`, version routing, `JacksonRepresentationFactory`, and a vendored jakarta port of Restlet's servlet extension |
| `openam-uma` | 10 | UMA endpoints, router, audit, exception handler |
| `openam-rest` | 10 | The `ServiceEndpointApplication` family, status services, `RealmRoutingFactory`, Restlet audit filters |
| `openam-entitlements` | 3 | `XacmlService`, `XacmlRouterProvider`, `EntitlementRestGuiceModule` |
| `openam-oauth2-saml2` | 1 | `Saml2BearerServerResource` |
| `openam-http-client` | 1 | `RestletHttpClient` — **outbound**, exposed to customer scripts |
| `openam-core-rest` | 1 | `AuthenticationServiceV1` |
| `openam-federation/OpenFM` | 1 | `DefaultWsFedAuthenticator` |

Plus the build surface: `openam-restlet/pom.xml` and six poms under
`transform-jakarta/restlet-parent-jakarta/` (parent + `restlet`, `restlet-ext-servlet`,
`restlet-ext-xml`, `restlet-ext-json`, `restlet-ext-jackson`) — the jakarta-transformed fork we
publish ourselves.

Two of those modules are worth calling out because they are not endpoints and do not follow the
inbound story: `openam-http-client` is an **outbound** HTTP client (stage ⑧), and the last two
single-file entries are stragglers with no stage assigned yet — see [Open threads](#open-threads).

---

## The cutover lever

Inbound Restlet traffic enters through exactly **four servlet mappings across two servlets**, in
`openam-server-only/src/main/webapp/WEB-INF/web.xml`:

```
  <servlet-name>ForgeRockRest</servlet-name>          → /xacml/*
  org.forgerock.openam.rest.RestEndpointServlet       → /oauth2/*
                                                      → /uma/*

  <servlet-name>WebFinger</servlet-name>              → /.well-known/*
  org.restlet.ext.servlet.ServerServlet
    hosting org.forgerock.openidconnect.restlet.WebFinger
```

CHF is already mounted alongside them:

```
  <servlet-name>OpenAM</servlet-name>                 → /json/*
  org.forgerock.http.servlet.HttpFrameworkServlet     → /frrest/oauth2/*
    application-loader = guice                        → /rest-sts/*
    routing-base       = context_path                 → /sts-publish/*
                                                      → /sts-tokengen/*
```

So each area moves by **registering an `HttpRouteProvider` for its leading path segment and
moving that one `<url-pattern>` from `ForgeRockRest` to `OpenAM`**. The SPI is in-tree
(`org.forgerock.openam.http.HttpRouteProvider`) with five existing `META-INF/services`
registrations — `openam-rest`, `openam-oauth2`, and the three STS modules — so the pattern is
proven, not speculative.

That is also the rollback: one line of XML, reverted.

Three details the lever does not show:

- **`/xacml` is already half CHF.** `RestEndpointServlet` wraps it in a *private*
  `HttpFrameworkServlet` so the CAF authentication filter can run, then hands off to Restlet
  through an inner `RestletHandler`. Migrating `/xacml` replaces that leaf handler; it does not
  introduce CHF. But the CAF filter must survive the move to the shared `OpenAM` servlet.
- **Two exact-match mappings shadow `/oauth2/*`**: `/oauth2/registerClient.jsp` and
  `/oauth2/connect/checkSession` are JSP servlets and win over the prefix mapping. They are not
  Restlet and do not move.
- **`ForgeRockRest` dies when its last mapping leaves.** `RestEndpointServlet` exists only to
  fan `/xacml`, `/oauth2` and `/uma` out to three `RestletServiceServlet` instances. Emptying it
  is the real completion criterion for the inbound work.

---

## Stages

| # | Change | Scope | State |
|---|---|---|---|
| ① | `fix-chf-framework-gaps` | Fix CHF in `../commons` where it cannot yet do what Restlet did | planned, 31 tasks |
| ② | `decouple-oauth2-errors-from-restlet` | `OAuthProblemException` and friends off Restlet types | planned, 29 tasks |
| ③ | `neutralize-oauth2-request` | `OAuth2Request` becomes framework-agnostic; `getRequest()` deleted | planned, 38 tasks |
| ④ | `migrate-xacml-endpoint-to-chf` | `/xacml/policies` — the canary | scaffolded |
| ⑤ | `migrate-uma-endpoints-to-chf` | `/uma/*` — 3 routes | scaffolded |
| ⑥ | `migrate-oauth2-endpoints-to-chf` | `/oauth2/*` — 15 endpoints; **needs splitting** | scaffolded |
| ⑦ | `migrate-discovery-endpoints-to-chf` | `/.well-known/*` — WebFinger + OIDC discovery | scaffolded |
| ⑧ | *(unscaffolded)* | Outbound `RestletHttpClient` → `java.net.http` | not started |
| ⑨ | *(unscaffolded)* | Delete `openam-restlet` + the jakarta fork poms | not started |

```
   ┌───────────────────────┐        ┌───────────────────────────┐
   │ ① fix-chf-framework-  │        │ ② decouple-oauth2-errors- │
   │    gaps               │        │    from-restlet           │
   │   (substrate)         │        └─────────────┬─────────────┘
   └───────────┬───────────┘                      │
               │                    ┌─────────────▼─────────────┐
               │                    │ ③ neutralize-oauth2-      │
               │                    │    request                │
               │                    │  core stops demanding a   │
               │                    │  Restlet request          │
               │                    └─────────────┬─────────────┘
               │                                  │
               └──────────────┬───────────────────┘
                              │
        ┌───────────┬─────────┴─────────┬──────────────┐
        ▼           ▼                   ▼              ▼
      ④ xacml     ⑤ uma              ⑥ oauth2       ⑦ discovery
      (canary)                       (split me)     (shares ⑥'s code)
        └───────────┴─────────┬─────────┴──────────────┘
                              │
   ⑧ outbound client ─────────┤   (independent of the inbound track,
     (any time)               │    can land whenever)
                              ▼
                    ⑨ delete openam-restlet
                      + transform-jakarta poms
```

### ① `fix-chf-framework-gaps`

The substrate. Everything CHF must be able to do before an endpoint can rely on it. Lands in
`../commons`, not here. Not a hard prerequisite for ② or ③ — ③ ships a Restlet adapter and
takes the CHF dependency only when its CHF adapter is written — but it gates ④ onward.

### ② `decouple-oauth2-errors-from-restlet`

`OAuthProblemException` carries a Restlet `Request`; error rendering reaches for Restlet status
types. Ends with the class deleted and its throw sites retargeted to typed `OAuth2Exception`
subclasses. Placed before ③ because it removes seven `Request.getCurrent()` thread-local
lookups and makes `OAuth2Utils`'s Restlet half dead code — which is what lets ③ delete that
half outright instead of porting it.

Ships one wire-visible correction: a missing OAuth2 resource reported through
`/json/users/{user}/oauth2/applications` currently returns `500`; it becomes `404`.

### ③ `neutralize-oauth2-request`

The keystone. 130 main-source files reference `OAuth2Request`; only 18 reach through it for the
raw `org.restlet.Request`. The abstraction is already 86% honoured — it has a hole in it, and
the hole is what keeps Restlet in the OAuth2 core.

`OAuth2Request` becomes abstract over twelve primitives with the protocol behaviour implemented
once above the adapter seam; `RestletOAuth2Request` is the only adapter this stage ships;
`getRequest()` is deleted. Two wire-visible corrections ride along: duplicate parameters get
rejected in the body as well as the query, and combining HTTP Basic with a client assertion
reports `invalid_request` rather than `invalid_client`.

Everything from ④ on is blocked behind this. An endpoint cannot serve CHF traffic while the
services it calls demand a Restlet request.

### ④ `migrate-xacml-endpoint-to-chf` — the canary

One route (`/policies`, attached by `XacmlRouterProvider`), one resource (`XacmlService`, 331
lines, nine Restlet imports). Small enough to prove the whole pattern end to end and cheap
enough to throw away if the pattern is wrong.

It is a good canary for two reasons beyond size. First, it is the one path already running
through an `HttpFrameworkServlet`, so it tests the *route provider + mapping move* in isolation
rather than testing CHF for the first time. Second, `XacmlService` uses
`OutputRepresentation` (streaming the policy export) and `Disposition` (the
`Content-Disposition` attachment header) — response-body shapes, not parameters or status
codes. That is the first real test of whether CHF's `Response`/`Entity` model covers Restlet's
representation model, and exactly the kind of gap the standing decision says we fix in
`../commons`.

### ⑤ `migrate-uma-endpoints-to-chf`

Three `router.attach()` calls: `/permission_request`, `/authz_request`,
`/.well-known/uma-configuration`. Carries the UMA audit filter and `UmaExceptionHandler` with
it. Several UMA endpoints are misfiled outside `*.restlet` packages
(`AuthorizationRequestEndpoint`, `PermissionRequestEndpoint`,
`UmaWellKnownConfigurationEndpoint`) — they are endpoints regardless of package and belong here.

### ⑥ `migrate-oauth2-endpoints-to-chf` — needs splitting

`OAuth2RouterProvider` makes 18 `attach()` calls: one realm-recursion route, and 17 endpoint
attaches of which `/resource_set` accounts for three — **15 distinct endpoints**. That is not
one reviewable change. The first thing its proposal must decide is the split, and the likely
outcome is that this change is replaced by three or four.

The natural seams, from the endpoint shapes rather than from convenience:

- **JSON endpoints** — `/access_token`, `/tokeninfo`, `/introspect`, `/idtokeninfo`,
  `/connect/register`, `/userinfo`, `/connect/jwk_uri`, `/token/revoke`, `/device/code`,
  `/.well-known/openid-configuration`. Uniform error contract, no redirects, no HTML.
- **Browser endpoints** — `/authorize`, `/device/user`, `/connect/endSession`,
  `/connect/checkSession`. Redirects, consent pages, templates. `/authorize` alone is the
  largest single resource in the set.
- **`/resource_set`** — three attaches onto one endpoint, and it is UMA-adjacent.

The reference branch used exactly this JSON/browser split and needed two abstract exception-
handler bases rather than one, which is corroborating evidence that the seam is real.

Two known parity-preserved security debts sit in this stage and should be reproduced, recorded
and deferred rather than silently fixed during a framework move: an unverified `id_token_hint`
signature on `/connect/endSession`, and a `301` (permanent) redirect to login on an
unauthenticated `/authorize`.

### ⑦ `migrate-discovery-endpoints-to-chf`

Separable at the servlet level — WebFinger has its own `ServerServlet` and its own
`/.well-known/*` mapping, and internally attaches one route, `/webfinger`, to
`OpenIDConnectDiscovery`.

Separable at the *code* level is unconfirmed. `OpenIDConnectDiscovery` lives in
`openam-oauth2` and depends on the same request factory and provider settings as ⑥'s
endpoints; on the reference branch, WebFinger and discovery imported twelve of the classes the
OAuth2 stage deleted, which forced them to be absorbed into it. **Verify this against the
current tree before writing ⑦'s proposal** — if the coupling still holds, ⑦ merges into ⑥'s
final split rather than standing alone.

### ⑧ Outbound `RestletHttpClient` (unscaffolded)

The only outbound use of Restlet: `openam-http-client`'s `RestletHttpClient`, targeted at
`java.net.http`.

Independent of the entire inbound track — it can land at any point — but it is the stage with
the widest external blast radius, because it is **public API for customer scripts**.
`JavaScriptHttpClient` and `GroovyHttpClient` in `openam-scripting` both extend it and are
bound into the scripting sandbox; the scripted authentication module holds one too. Changing
its shape changes what deployed customer scripts compile against. That needs an explicit
compatibility decision, not an incidental one.

### ⑨ Delete `openam-restlet` and the fork (unscaffolded)

The terminal stage. `openam-restlet` is 16 Java files we own: `RestletRealmRouter` (whose
`REALM_URL` attribute ③'s endpoint-type derivation depends on), version routing,
`JacksonRepresentationFactory`, and a vendored jakarta port of Restlet's servlet extension
(`ServerServlet`, `ServletCall`, `ServletWarClient` and friends). With it go
`openam-restlet/pom.xml` and the six `transform-jakarta/restlet-parent-jakarta` poms, and
`RestEndpointServlet` and the `ServiceEndpointApplication` family in `openam-rest`.

Deleting the fork removes a published artifact from our build. That is the only stage with an
external release consequence beyond ⑧'s API question.

---

## Open threads

- **⑥'s split.** Decide before writing its proposal, not during. Likely three changes.
- **⑦'s independence.** Verify the WebFinger/discovery code coupling to ⑥ on the current tree.
  If it holds, fold ⑦ in.
- **Stragglers with no stage.** `openam-core-rest/AuthenticationServiceV1`,
  `openam-federation/OpenFM/DefaultWsFedAuthenticator`, and
  `openam-oauth2-saml2/Saml2BearerServerResource`. The last is a Restlet `ServerResource` and
  plausibly belongs with ⑥'s token endpoint; the first two are unclassified. All three must
  land somewhere before ⑨ can compile.
- **Templates.** Restlet's `TemplateRepresentation` has no CHF analogue. `/authorize`'s consent
  page and the device-user page depend on it. This wants an agreed seam with the
  Click→FreeMarker migration rather than two independent answers.
- **Audit filters.** `AbstractRestletAccessAuditFilter`, `RestletBodyAuditor`, and the OAuth2
  and UMA subclasses are Restlet-typed at their signatures
  (`getUserIdForAccessAttempt(Request)`). They cut across ④–⑦ and may deserve their own change
  ahead of them.
- **Whether contract specs are captured up-front or per-area.** ③ writes
  `oauth2/request-parameters`; ② writes `oauth2/error-responses`. The endpoint stages each have
  a protocol contract too. Deciding once is cheaper than deciding four times.

---

## Provenance

Verified by inspection of the working tree on 2026-08-08, branch
`features/openspec-restlet-migration`: the import counts and module table; the four servlet
mappings and the two CHF/Restlet servlet definitions in `web.xml`; the `HttpRouteProvider` SPI
registrations; `RestEndpointServlet`'s CAF-wrapped `/xacml` path; the route counts for the
XACML, UMA and OAuth2 routers; `XacmlService`'s size and Restlet imports; `openam-restlet`'s
file list; the `RestletHttpClient` call sites; and the WebFinger servlet definition.

Inherited from the `features/restlet-migration` reference branch and **not** re-verified here:
the twelve-class coupling between WebFinger/discovery and the OAuth2 endpoint set; the
two-exception-handler-bases finding; the two deferred security debts. Each is flagged at the
point of use above. Treat them as leads to confirm, not as facts.

The 130-referencing / 18-unwrapping split for `OAuth2Request` comes from
`changes/neutralize-oauth2-request/proposal.md`, where it is derived in full.
