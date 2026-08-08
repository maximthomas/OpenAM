# Phase 5d-1 — the flip: `/oauth2` → CHF: as-built

What actually landed, and **every value measured against live Restlet**. This file is the durable record: the Restlet oracle dies at 5d-1c and these numbers cannot be re-derived afterwards. Spec: [phase-5d-1.md](phase-5d-1.md).

---

<a id="as-built-5-e5--recorded-2026-08-04"></a>
## As-built — 5-E5, recorded 2026-08-04 (test-only)

Captured against a live container built from this tree: `openam-e2e:5e5` (the repo
`openam-distribution/openam-distribution-docker/Dockerfile` with its three `#COPY` lines uncommented, exactly
CI's `build-docker` sed) over a full `mvn install -DskipTests` of the working tree, plus
`openidentityplatform/opendj:latest` on the `test-openam` network, configured with CI's `conf.file`. Restlet
still serves `/oauth2`: `web.xml:1143-1146` is unchanged and no CHF `HttpRouteProvider` claims those paths.

Provenance was checked by **md5 of the deployed jar**, not the banner (5-E4's lesson):
`WEB-INF/lib/openam-oauth2-16.2.0-SNAPSHOT.jar` = `d03a404db1a56057c4eb1a12529717d3` = this working tree's
`openam-oauth2/target/openam-oauth2-16.2.0-SNAPSHOT.jar`. (`openam-restlet` likewise.)

**Deliverables — e2e only, zero main-source lines:**

| File | Change |
|---|---|
| `e2e/oauth2/oauth2-test.spec.mjs` | new describe `/oauth2 routing contract lock (5-E5, live Restlet)` — **14 rows**, plus a `node:http` raw client for the three things Playwright cannot express (a `Host` that does not match the connection, path bytes a normalising client would rewrite, and `PROPFIND`/`PATCH`), and a sub-realm fixture created through `/json/global-config/realms` and deleted in `afterAll`. ⚠ The realm's resource id is **base64url of the realm PATH** (`/e2e5e5realm` → `L2UyZTVlNXJlYWxt`), not its name — a `DELETE …/realms/%2Fe2e5e5realm` answers 400 |

`npx playwright test oauth2 uma`, **one pass on a freshly recreated container**: **113 passed** (1.4 min) —
99 + 14, with `oauth2-test` going **23 → 37** and `oauth2-endpoints` 43, `oidc` 20, `webfinger` 2, `uma` 11 all
unchanged. No existing row edited, no fixture changed.

### The recorded rows

| # | Request | Recorded |
|---|---|---|
| 13 | `/oauth2/tokeninfo/`, `/oauth2/Tokeninfo`, `/oauth2/TOKENINFO`, `/oauth2//tokeninfo` | **404**, and the **router** 404 — `{"code":404,"reason":"Not Found","message":"The server has not found anything matching the request URI"}`. Two-segment endpoints answer the **realm** 404 instead: `/oauth2/connect/jwk_uri/` → `…"message":"No mapping organization found for organization identifier: /connect"`, `/oauth2/.well-known/openid-configuration/` → `…: /.well-known`, `/oauth2/Connect/jwk_uri` → `…: /Connect`. Routing is **case-sensitive**. `/oauth2/resource_set/` still answers (401 `invalid_token`) — it is the one endpoint attached three times. ⇒ **[D1](phase-5d-1.md#d1)'s flat `EQUALS` table stands**; no endpoint needs [D2](phase-5d-1.md#d2)'s nested shape |
| 1 | `?realm=/`, `?realm=%2F` on `/tokeninfo`; `?realm=<sub>` on `/.well-known/openid-configuration`; `?realm=bogus` on an unrouted path | **200** for both spellings of root. The override really **switches** realm: `?realm=e2e5e5realm` → **404** `{"error":"not_found","error_description":"No OpenID Connect provider for realm /e2e5e5realm"}`, and `?realm=/e2e5e5realm` is identical (the leading slash is optional). ⚠ On a path that matched **no** endpoint the override is **not applied at all** — `/oauth2/nosuchendpoint?realm=bogus` is the plain router 404, not a realm error, which is `RestletRealmRouter:86`'s `next != delegateRoute` guard on the wire |
| 2 | `?realm=bogus` on `/tokeninfo` and on `POST /access_token` | **404** `{"code":404,"reason":"Not Found","message":"No mapping organization found for organization identifier: bogus"}`, identical for both, and with **no `Cache-Control`/`Pragma`** even on `/access_token` — the realm layer answers above the `OAuth2Filter`. ⇒ divergence row 16's **status** is confirmed (404 here, 400 on CHF); its **body** is corrected, see [correction 3](#5-e5-correction-3) |
| 3 | `/oauth2/<sub>/tokeninfo`, `/oauth2/<sub>/.well-known/openid-configuration`, and the same with `?realm=/` | The legacy style **resolves, and resolves to the sub-realm**: the discovery document answers **404** `No OpenID Connect provider for realm /e2e5e5realm`, while `/tokeninfo` under the same prefix answers **200**. `?realm=/` on top of a legacy prefix **replaces** it — 200, `issuer` = the root issuer |
| 4 | `/oauth2/realms/root/tokeninfo`, `/realms/bogus/tokeninfo`, **flat `/realms/<sub>/…`**, nested `/realms/root/realms/<sub>/…` | root → **200**; bogus → **404** `…"message":"No mapping organization found for organization identifier: /bogus"` (note the **leading slash**, where row 2's is bare); ⚠ **flat `/realms/<sub>/…` is SERVED, in the sub-realm** — 404 `No OpenID Connect provider for realm /e2e5e5realm`, the endpoint's own answer — and the nested spelling is identical. ⇒ [correction 1](#5-e5-correction-1) |
| 5 | `HEAD` on `/tokeninfo`, `/.well-known/openid-configuration`, `/connect/jwk_uri`, `/authorize`, `/access_token` | The first three: **200**, the `GET`'s exact `Content-Type` (`application/json` on `/tokeninfo`, `application/json;charset=UTF-8` on the other two), `/tokeninfo`'s `no-cache, no-store` intact, and **no `Content-Length`** on any of them (as 5-E4 row 15 recorded for `resource_set` — so [finding 7](phase-5d-1-research.md#7--content-length-on-a-head-is-tomcats-decision)'s Restlet half is answered; what *Tomcat* does behind CHF is still 5d-1c's to measure). ⚠ `/authorize` and `/access_token`: **405**. A `HEAD` carrying a complete, authenticated, valid authorization request is a 405 while the byte-identical `GET` is a **302 with an issued code**. ⇒ [correction 2](#5-e5-correction-2). ⚠ Also: a `HEAD` that ends in an **error** status sends `text/html;charset=utf-8` **with** a `Content-Length` (401 → 721 B, 404 → 714 B, 405 → 726 B, 400 → 796 B) instead of the `application/json` body its `GET` sends |
| 6 | `PROPFIND` / `PUT` on `/tokeninfo` and `/connect/jwk_uri`; `PROPFIND` on `/access_token` and `/authorize` | Two producers, two shapes. The **resource**: 405 + **`Allow: GET`** + the CREST body `{"code":405,"reason":"Method Not Allowed","message":"The method specified in the request is not allowed for the resource identified by the request URI"}`, no cache headers. The **endpoint filter**: 405 + `{"error":"method_not_allowed","error_description":"Required Method: POST found: PROPFIND"}` (`/authorize`: `"Required Method: GET or POST found: PROPFIND"`) + `no-store`/`no-cache` and **no `Allow` at all**. ⇒ [D4](phase-5d-1.md#d4)'s `Allow` list is **per endpoint** — `GET` here, not `resource_set`'s four |
| 7 | `PATCH` on `/tokeninfo` (with and without a token), `/connect/jwk_uri`, `/access_token` | ⚠ **`PATCH` runs the resource's `@Get` first and only then 405s.** With a valid token: 405 + `Allow: GET` + the CREST body — **carrying `Cache-Control: no-cache, no-store`, which only `ValidationServerResource.validate()` sets**. Without a token: **401 `invalid_token`** — the `@Get`'s own error, no 405 at all. A `PUT` on the same URL is a 405 with **no** cache headers, i.e. it does not run the `@Get`. On the method-filtered endpoints the filter refuses first: `{"error":"method_not_allowed","error_description":"Required Method: POST found: PATCH"}`. ⇒ [correction 4](#5-e5-correction-4) |
| 8 | `?_api`, `?_crestapi` | **Ignored**. `/connect/jwk_uri?_api` and `?_crestapi` are **byte-identical** to the plain `GET` (asserted as a body comparison, not a status); `/tokeninfo?_api` with a token is a normal 200 |
| 9 | `OPTIONS /oauth2/authorize` with and without an `Origin`; `OPTIONS /tokeninfo` | **405** `{"error":"method_not_allowed","error_description":"Required Method: GET or POST found: OPTIONS"}`, and **not one `Access-Control-*` header** in either case — the `web.xml` `CORSFilter` is unconfigured on this deployment and contributes nothing. On an endpoint with no method filter, `OPTIONS` is the same CREST 405 + `Allow: GET` as any other unmapped verb: Restlet does **not** answer `OPTIONS` automatically |
| 10 | `X-HTTP-Method-Override` and `?method=` | ⚠ Three answers, not two. **(a)** the header on a **POST** is **honoured** — `POST /access_token` + `X-HTTP-Method-Override: GET` → 405 `Required Method: POST found: GET` (the same request without it → 200 + a token), and `POST /tokeninfo` + override `GET` → **200**. **(b)** the header on a **non-POST** is *also* honoured — `GET /tokeninfo` + override `PUT` → **405**. **(c)** Restlet's own `?method=` query tunnel is live, **POST-only** — `POST /access_token?method=GET` → 405 `…found: GET`, while `GET /tokeninfo?method=PUT` → **200**. ⇒ [D11](phase-5d-1.md#d11) settles, [correction 5](#5-e5-correction-5) |
| 11 | `/oauth2/nosuchendpoint`, `/oauth2/authorize/extra`, `/oauth2/connect/nosuch`, `/oauth2/realms/root/nosuch` | All **404 `application/json`**, from **two** producers by segment count: one element below `/oauth2` → the **router** 404; two → the **realm** 404 naming the first (`/authorize`, `/connect`). `/realms/root/nosuch` is a router 404 — the realm route consumed both leading elements |
| 12 | `GET /oauth2/`, `GET /oauth2`, `/oauth2/realms`, `/oauth2/realms/root` | **404**, the router's, for all four. The bare prefix is where `/{subrealm}` has nothing to bind |
| 14 | An unknown `Host` on `/oauth2/tokeninfo`, `/oauth2/realms/root/tokeninfo` and `/oauth2/.well-known/openid-configuration` | ⚠ **500** for **all three** — `{"code":500,"reason":"Internal Server Error","message":"No mapping organization found for organization identifier: not-a-real-host.invalid"}`. The realm-prefixed form does **not** work today. An IP-literal `Host` behaves the same; `Host:` without a port works. ⇒ [correction 6](#5-e5-correction-6), and divergence row 17 is rewritten |

<a id="5-e5-the-one-mechanism"></a>
### One mechanism explains rows 4, 13 and 14

`Router.doHandle` runs **before** the matched route's template is parsed, so `RestletRealmRouter.doHandle`
never sees the attributes the *current* route will set — only what an earlier pass left behind. Everything
surprising above follows from that:

- **row 13 / row 11.** One unmatched element is consumed by `/{subrealm}` (`MODE_STARTS_WITH`), leaving an
  **empty** remaining URI that matches no route at all on the recursive pass — so `doHandle` never runs again
  and Restlet's own router 404 surfaces. With **two** elements the recursion re-enters with a non-empty URI,
  `subrealm` is set from the first pass, and the realm lookup fails instead. ⇒
  [finding 8](phase-5d-1-research.md#8--an-unrouted-oauth2-path-is-a-bodiless-404-on-chf) is right about the mechanism and wrong
  about the reach: it predicted a realm 404 for `/oauth2/tokeninfo/`, which is a **router** 404.
- **row 4.** `realmId` is set by the `/realms/{realmId}` template, i.e. after the outer `doHandle` has already
  resolved the host and stored `REALM_OBJECT` — so the inner router's "root or an existing `REALM_OBJECT`"
  guard is *always* satisfied and a flat `realms/<non-root>` resolves.
- **row 14.** The same ordering means `doHandle:75-78`'s `realmId` short-circuit **cannot fire on the first
  pass**, so `getRealmFromServerName` runs on every request, whatever the URL style.

And the wire message of every realm failure is the **cause's**, not the router's:
`RestStatusService.toRepresentation:42-52` renders `status.getThrowable().getMessage()` whenever a throwable is
present, so `RestletRealmRouter:102-104`'s `"Realm \"" + x + "\" not found"` — which
[finding 15](phase-5d-1-research.md#15--the-realm-layer-has-its-own-404-and-400-and-they-are-crest-shaped) quotes for rows a and d —
is a `Status` *description* that never reaches a client.

### Six corrections to this plan

<a id="5-e5-correction-1"></a>
**1. A flat `/oauth2/realms/<non-root>/…` works on Restlet too.** [The 5-E5 brief](phase-5d-1-asbuilt.md#as-built-5-e5--recorded-2026-08-04)'s row 4
predicted a Restlet 404 and a CHF **capability gain** worth recording. There is no gain and no divergence —
both stacks serve it, in the sub-realm. Had it gone unmeasured, the byte diff would have read as a regression
in reverse.

<a id="5-e5-correction-2"></a>
**2. ⚠ `HEAD /oauth2/authorize` does *not* run the authorization flow.**
[Finding 6](phase-5d-1-research.md#6--head-after-the-fix-lands-on-code-paths-that-are-already-correct) states that it "runs the real
authorization flow — including … on success, a 302 with an issued code. Restlet did precisely the same". It
does not: `AuthorizeEndpointFilter.validateMethod` accepts `GET` and `POST` only, and Restlet's `HEAD` → `GET`
rewrite happens at **annotation lookup**, *inside* the resource and *below* that filter — so the filter sees a
`HEAD` and answers 405. Measured with a complete, authenticated, valid request: `HEAD` → **405**, the
byte-identical `GET` → **302 with a code**. `/access_token` is a 405 on both verbs, so only `/authorize` moves.
⇒ [D4](phase-5d-1.md#d4) is updated: `Endpoints.from` still maps `HEAD` → `@Get`, and `AuthorizeHandler` must refuse `HEAD`
explicitly so the incumbent 405 survives. ⚠ **The guard is 5d-1b's, not 5d-1a's** (decided 2026-08-05, see the
[5d-1a as-built](#as-built-5d-1a--recorded-2026-08-05)): `AuthorizeHandler` is migration code in
`openam-oauth2`, and 5d-1a's whole premise is a framework-only commit. Nothing is on the wire in between —
`AuthorizeHandler` is not routed until 5d-1c — so the reassignment costs no coverage, and `OAuth2RouterIT` is
where `HEAD /authorize` → 405 gets pinned.

<a id="5-e5-correction-3"></a>
**3. The realm 404's message is `No mapping organization found for organization identifier: X`.**
[Finding 15](phase-5d-1-research.md#15--the-realm-layer-has-its-own-404-and-400-and-they-are-crest-shaped) rows a and d quote
`Realm "bogus" not found` for the Restlet side, and [D5](phase-5d-1.md#d5) builds a near-byte-parity argument for divergence
row 15 on it (*"even the `error_description` is byte-identical to Restlet's `message`"*). It is not: see
[the mechanism above](#5-e5-the-one-mechanism). The identifier is spelled **`bogus`** for a `?realm=` override
and **`/bogus`** for `realms/<bogus>`. `case 404 → not_found` is still right — it keeps `/oauth2`'s 404
vocabulary consistent — but it buys **consistency only**, not parity, and D5's parity sentence is struck.

<a id="5-e5-correction-4"></a>
**4. `PATCH` is wider than `resource_set`, and it has a side effect.** [D4](phase-5d-1.md#d4) scopes divergence row 14 to
`resource_set` because it is the only ported endpoint with a `@Put`. That is true of the *200*, but Restlet
runs the resource's `@Get` for **every** `PATCH` before looking for a handler — so on a `@Get`-only endpoint
the `@Get`'s errors are what reach the wire (`PATCH /oauth2/tokeninfo` without a token is a **401**, not a
405) and its side effects happen (the 405 carries `/tokeninfo`'s own cache directives). On CHF, `PATCH` is an
unmapped verb everywhere: a flat 405 that runs nothing. Divergence row 14 is widened rather than re-scoped.

<a id="5-e5-correction-5"></a>
**5. [D11](phase-5d-1.md#d11) settles — and splits.** Restlet **honours** `X-HTTP-Method-Override`, so its first branch
applies and there is nothing to do for the POST case. But `Endpoints.getMethod:119-126` gates the rewrite on
`"POST".equals(method)`, and Restlet does not, and Restlet additionally honours the `?method=` **query** tunnel
on a POST, which CHF has no equivalent for. Two new divergences, both changing a **405 into a 200**:
`GET …?…` + `X-HTTP-Method-Override: PUT`, and `POST /oauth2/access_token?method=GET` — the second of which
starts **issuing tokens** for a request that is refused today. Neither is a reason to change `Endpoints`
(the header is shared with `/json`, and the query tunnel is a Restlet service nothing else implements), so both
are recorded.

<a id="5-e5-correction-6"></a>
**6. ⚠ An unknown `Host` does not work on either URL style today.**
[Finding 16](phase-5d-1-research.md#16--the-flip-adds-host-validation-to-oauth2-that-restlet-never-did) predicted
`/oauth2/realms/root/…` **works** under an unrecognised `Host` and would start 400ing — *"the only row here
that can break a deployment that works today"*. Measured, it is a **500**, exactly like the bare-path form.
⇒ divergence row 17 becomes **500 → 400 on both styles**: a better answer to a request that already fails, not
a working integration breaking. [R-5d1.9](phase-5d-1.md#risk-register-extends-phase-5-oauth2s) keeps its release-note line
(the *status* still changes, and the FQDN-map test is genuinely new) but is no longer the step's most dangerous
row. The `FQDNValidationFilter` redirect on `/oauth2/authorize` is unaffected either way.

### Divergence rows this gate hands to 5d-1c

Added to [plan.md](plan.md#expected-divergences-at-the-flip) with measured bytes **in 5d-1c's commit**, not now:

⚠ **These are draft numbers, and four of the six moved when 5d-1c measured the flip** (mapping added
2026-08-08 — the numbers below were never reconciled with the final table, and in this doc set a divergence
row number *is* the contract, so an unmapped draft number is a live cross-reference hazard). The rows are kept
under their draft numbers as the record of what was predicted; **cite the landed number, never these**:

| Draft | Landed as | Note |
|---|---|---|
| 16 | **16** | unchanged |
| 17 | **17** | unchanged |
| 18 | **23** | an erroring `HEAD`. Draft 18's "no `Content-Length`" CHF half was **inverted** by measurement — see [row 22](plan.md#expected-divergences-at-the-flip) and the [5d-1a finding](#5d-1a-content-length) |
| 19 | **nothing — it is parity, not divergence** | the guard landed in 5d-1b (`AuthorizeHandler:106,276`), so `HEAD /oauth2/authorize` is **405 on both stacks**. Its absence from rows 14–30 is the correct outcome, not an omission |
| 20 | **30** | both method tunnels. ⚠ The draft's CHF column *predicted* the 200s; 5d-1c measured that `?method=GET` **issues a real access token**, which is the table's one **widening** |
| 14 *(widened)* | **21** | the `/tokeninfo` unmapped-verb behaviour became its **own** row. Final **row 14 is a different subject** — `PATCH /oauth2/resource_set/{rsid}` — so a reader following "row 14 (widened)" into plan.md lands on the wrong row |

| # | What differs | Restlet (measured 2026-08-04) | CHF (expected) |
|---|---|---|---|
| 16 | `?realm=<bogus>` | **404** `{"code":404,…,"message":"No mapping organization found for organization identifier: bogus"}`, no cache headers | **400** `{"error":"invalid_request","error_description":"Invalid realm, bogus"}` |
| 17 *(rewritten)* | an unknown request `Host`, **both** URL styles | **500** `{"code":500,…,"message":"No mapping organization found for organization identifier: <host>"}` | **400** — `HostnameFilter:123-131` / `RealmContextFilter:229-231` |
| 18 | `HEAD` on an endpoint whose answer is an **error** | the JSON body and `Content-Type` are replaced by `text/html;charset=utf-8` **plus** a `Content-Length` (401 → 721 B, 404 → 714 B, 405 → 726 B, 400 → 796 B) | the `GET`'s `Content-Type`, no `Content-Length`. Not a prediction: the same probe against a CHF path (`HEAD /openam/json/nosuchthing`) answers **501 `application/json;charset=UTF-8`**, no length, no HTML — so the substitution is the Restlet stack's, and it goes away with it |
| 19 | `HEAD /oauth2/authorize` | **405** | **405**, *provided* [correction 2](#5-e5-correction-2)'s guard lands in **5d-1b** (reassigned from 5d-1a 2026-08-05 — it is `openam-oauth2` code); without it, a 302 **issuing an authorization code** |
| 20 | the method tunnel beyond `POST` + header | `GET …` + `X-HTTP-Method-Override: PUT` → **405**; `POST /access_token?method=GET` → **405** | **200** for both — the override is ignored on a non-POST, and `?method=` is not implemented |
| 14 *(widened)* | `PATCH` on a `@Get`-only endpoint | the `@Get` runs first: **401** `invalid_token` on `/tokeninfo` with no token; 405 + `Allow: GET` + `Cache-Control: no-cache, no-store` with one | **405**, nothing run |

---

<a id="as-built-5d-1a--recorded-2026-08-05"></a>
## As-built — 5d-1a, recorded 2026-08-05 (`openam-http` only)

The framework half of [D4](phase-5d-1.md#d4), landed as its own commit per the F1–F4 precedent — written up in the
[F1–F4 house style as **F5**](openam-http-framework.md#f5), which is where the reusable half of this belongs.
**Zero migration-source lines**: no `openam-oauth2`, no `openam-uma`, no route provider.

**Deliverables:**

| File | Change |
|---|---|
| `openam-http/.../annotations/Endpoints.java` | `methods.put("HEAD", methods.get("GET"))`; `allowHeader(...)` computed once at construction; `withAllow(...)` stamping every 405 that leaves the handler (both producers, idempotent) |
| `openam-http/.../annotations/AnnotatedMethod.java` | package-private `isSupported()` — `method != null`, the sentinel test |
| `openam-http/.../annotations/EndpointsTest.java` | **8** new rows (the plan asked for six; `handlersOwnAllowIsNotOverwritten` and `allowCoversMethodsMatchedByNameRatherThanAnnotation` were added because each is the only guard on a documented design point) |
| `decisions.md`, `openam-http-framework.md` | the `HEAD` backlog entry closed, an `Allow` entry added already-closed, the F5 section |

**59 lines of main code.** Verification, all green:

| Criterion | Recorded |
|---|---|
| 3 — `mvn -o -pl openam-http test` | **81** (baseline 73, grew only). Mutation-checked: removing the `HEAD` put reddens 1 row, disabling the `Allow` stamp reddens 5 |
| 4a — every other `Endpoints.from` consumer | `openam-rest` **275**, `openam-entitlements` **580**, `openam-core-rest` **414**, `openam-oauth2` **1281**, `openam-uma` **196** — unchanged. ⚠ **Surefire only.** These are `mvn … test`, so the failsafe suites were never re-run — and `openam-oauth2`'s had **two red rows** until 5d-1b found them ([the 5d-1a casualties](#5d-1b-the-two-5d-1a-casualties)) |
| 4b — the live `HEAD` smoke | below |
| 5 — `mvn -o install -DskipTests` whole reactor | SUCCESS, 33:49, doclint clean |

<a id="the-live-smoke--openam-e2e5d1a"></a>
### The live smoke — `openam-e2e:5d1a`

IDP container only (no SP: none of the four URLs needs it), built and configured exactly as
[test-infrastructure.md](../../test-infrastructure.md#running-layer-4-locally-against-a-war-built-from-your-tree)
prescribes. Provenance by md5 of the **deployed** jar, not the banner:
`WEB-INF/lib/openam-http-16.2.0-SNAPSHOT.jar` = `ad5d9f49e03ccc94a64c14c7d69871a8` = this tree's.

| Endpoint | `GET` | `HEAD` | Verdict |
|---|---|---|---|
| `/json/api` (`@Get`) | **200**, 12011 B | **200**, same headers, same `Content-Length` | ✅ [finding 6](phase-5d-1-research.md#6--head-after-the-fix-lands-on-code-paths-that-are-already-correct)'s "descriptor computed and discarded", confirmed |
| `/xacml/policies` (`@Get`, the **export**) | **200** `application/xacml+xml; version=3.0`, 392 B of real `<ns2:PolicySet>` | **200**, byte-identical header set | ✅ the expensive row: it really does serialise the realm's policies and drop them |
| `/uma/.well-known/uma-configuration` (`@Get`) | **404** `{"error":"not_found","error_description":"No OpenID Connect provider for realm /"}` — the endpoint's own answer on a container with no OIDC provider configured, **not** a routing failure | **404**, identical | ✅ `HEAD` tracks `GET` whatever `GET` says |
| `/json/authenticate` (`@Post` only) | — | **405 `Allow: POST`** | ✅ the row that would have mattered: authentication is still not reachable by `HEAD`, and it now advertises why |

And `Allow` on live 405s, per endpoint as [5-E5 row 6](#the-recorded-rows) demands:
`PROPFIND /xacml/policies` → **`Allow: GET, POST`**; `PROPFIND /uma/.well-known/uma-configuration` →
**`Allow: GET`** — the same single-verb shape Restlet gives `/oauth2/tokeninfo`.
(`PROPFIND /json/api` is a **403**: the authz module refuses above dispatch, so no 405 is produced at all.)

Control: `HEAD /oauth2/tokeninfo` on the same container still answers Restlet's **401 + `text/html;charset=utf-8`
+ `Content-Length: 721`**, reproducing [5-E5 row 5](#the-recorded-rows) exactly — the container is a faithful
replica and `/oauth2` is untouched by this commit.

<a id="5d-1a-content-length"></a>
### ⚠ [Finding 7](phase-5d-1-research.md#7--content-length-on-a-head-is-tomcats-decision) is answered early, and the answer is a divergence

The finding says `Content-Length` on a `HEAD` is Tomcat's decision and *"only a live container answers"* it, and
schedules the measurement for 5d-1c. This smoke measured it four times, because every URL above is already CHF:

**Tomcat behind CHF sends the `GET`'s `Content-Length` on a `HEAD`** — 232, 392, 82 and 12011 B, each equal to
its own `GET`'s. `HttpFrameworkServlet.writeResponse:371-386` never sets the header (verified this session: it
copies headers and streams `copyRawContentTo`), so this is the connector computing the length from the bytes
written and then suppressing the body.

Restlet sends **none** ([5-E4 row 15](phase-5c-asbuilt.md#as-built-5-e4--recorded-2026-07-29),
[5-E5 row 5](#the-recorded-rows)). ⇒ a **new divergence row for 5d-1c**, drafted below, and one the flip's
header diff *will* show — unlike [D4](phase-5d-1.md#d4)'s three, which a body byte-diff cannot see.

| # | What differs | Restlet (measured) | CHF (measured 2026-08-05, pre-flip, on `/json` `/xacml` `/uma`) |
|---|---|---|---|
| 21 *(draft — **landed as [row 22](plan.md#expected-divergences-at-the-flip)**)* | `Content-Length` on a successful `HEAD` | **absent** | **present**, equal to the `GET`'s |

⚠ **Draft number, corrected 2026-08-08.** Final row 21 is a different subject (the `/tokeninfo` unmapped-verb
behaviour); this one landed as **row 22**. Same hazard, and same fix, as the
[5-E5 draft table](#divergence-rows-this-gate-hands-to-5d-1c) above.

Nothing to fix: RFC 7231 §3.3.2 explicitly permits — and §4.3.2 encourages — a `HEAD` to carry the
`Content-Length` its `GET` would have sent. It is the *better* answer; it is simply not the incumbent's.

### Two things found and deliberately not fixed here

- ⚠ **`/json/api` 500s when the request carries no `Accept-Language`.** The body is
  `Cannot invoke "…AcceptLanguageHeader.getLocales()" because the return value of
  "…Headers.get(java.lang.Class)" is null` — `Headers.get(Class)` returns null for an absent header and
  `ApiService` dereferences it. **Pre-existing and unrelated to F5**: it is on the `GET` path, which this
  commit does not touch, and `HEAD` reproduces it identically (500 → 500). Sending `Accept-Language: en` gives
  200 on both verbs. Found only because the smoke drove `/json/api` with curl, which sends no such header —
  every browser and the e2e suite do. Filed to the [CHF cleanup backlog](decisions.md#chf-cleanup-backlog);
  fixing it in this commit would have widened a framework-verb change into an unrelated endpoint fix.
- **`AuthorizeHandler`'s `HEAD` guard** ([correction 2](#5-e5-correction-2)) moved to **5d-1b** — it is
  `openam-oauth2` code and 5d-1a is framework-only. Nothing is exposed in between: `AuthorizeHandler` is not
  routed until 5d-1c.

---

<a id="as-built-5d-1b--recorded-2026-08-05"></a>
## As-built — 5d-1b, recorded 2026-08-05 (the provider, still unflipped)

The composition step: everything 5a–5c built is now wired and registered, and **`/oauth2` is still served by
Restlet**. `web.xml:1143-1146` is untouched — the only difference between this commit and the flip is 5d-1c's
one line.

**Deliverables:**

| File | Change |
|---|---|
| `…/oauth2/http/OAuth2HttpRouteProvider.java` | **new**, ~250 lines with javadoc — [D1](phase-5d-1.md#d1), [D2](phase-5d-1.md#d2), [D3](phase-5d-1.md#d3), [D7](phase-5d-1.md#d7). Every route carries the `OAuth2RouterProvider` line it copies as a trailing comment |
| `…/oauth2/http/OAuth2NotFoundHandler.java` | **new**, 19 lines of body — [D5](phase-5d-1.md#d5). Dependency-free by design: a default route with no collaborators cannot widen [finding 3](phase-5d-1-research.md#3--the-provider-instantiates-all-15-handlers-when-the-router-is-built-and-that-router-is-the-whole-chf-servlets)'s Guice blast radius |
| `…/oauth2/http/AuthorizeHandler.java` | the `HEAD` guard ([correction 2](#5-e5-correction-2)) + the class javadoc's "no verb check" sentence, which is no longer true |
| `…/oauth2/http/OAuth2ErrorFilter.java` | `case 404: return "not_found";`, the `default:` comment that named 404, and the "one exception to RFC-first reasoning" paragraph, now naming two |
| `META-INF/services/org.forgerock.openam.http.HttpRouteProvider` | the provider appended. The file ended **without** a trailing newline; `printf '\n…\n' >>` and a byte check afterwards |
| `…/test/…/oauth2/http/OAuth2RouterIT.java` | **new** — [D9](phase-5d-1.md#d9). 17 probe rows + [D7](phase-5d-1.md#d7) + 6 deep rows = **24** |
| `…/test/…/oauth2/http/OAuth2NotFoundHandlerTest.java` | **new**, 3 rows |
| `…/test/…/oauth2/http/AuthorizeHandlerTest.java` | 2 rows for the `HEAD` guard (48 → 50) |
| `…/test/…/oauth2/http/OAuth2ErrorFilterTest.java` | the `statusToError` pin at `:114` — 404 is now `not_found` |
| `…/test/…/oauth2/http/ResourceSetRouteCompositionIT.java` | row 9's new body + the re-expressed counterfactual; the inline nested router gains D5's default route; **and** the `Allow` assertion (below) |
| `…/test/…/oauth2/http/OAuth2ErrorRouteCompositionIT.java` | ⚠ **not in the plan's table** — see [the two 5d-1a casualties](#5d-1b-the-two-5d-1a-casualties) |
| `openam-oauth2/pom.xml` | ⚠ **not in the plan's table** — `org.openidentityplatform.commons.guice:test` (test scope). `OAuth2RouterIT` drives the real provider, whose `Endpoints.from(Class)` resolves through `InjectorHolder`, so it needs `GuiceTestCase`. The same declaration `openam-uma` carries for `UmaRouterIT` |
| `…/test/java/org/forgerock/openam/http/HttpRouteAccessor.java`, `…/test/java/org/forgerock/guice/core/GuiceModuleLoaderAccessor.java` | ⚠ **not in the plan's table** — copied verbatim from `openam-uma`'s test tree (third copy of each). Both expose package-private framework state a provider-driven IT cannot otherwise reach |

**Verification — criteria 6-11, all green:**

| Criterion | Recorded |
|---|---|
| 6 — `mvn -o -pl openam-oauth2 test` | **1286** surefire (baseline 1281; +3 `OAuth2NotFoundHandlerTest`, +2 `AuthorizeHandlerTest`) |
| 7 — `mvn -o -pl openam-oauth2 verify` | **62** failsafe (baseline 38; +24 `OAuth2RouterIT`) |
| 8 — `grep -rn "org.restlet\|getCurrent()"` over the two new main files | **0** |
| 9 — `mvn -o install -pl openam-oauth2,openam-oauth2-saml2,openam-uma,openam-rest -am -DskipTests` | SUCCESS, 9:27 |
| 10 — **Cargo boot** (`mvn -o -pl openam-server verify -P integration-test`) | SUCCESS, 3 tests, 364.8 s. Verified **non-vacuously**: see below |
| 11 — **the full e2e suite** on `openam-e2e:5d1b` | **131 passed, 1 skipped, 0 failed** (132 declared) |

<a id="5d-1b-criterion-10-is-not-vacuous"></a>
### Criterion 10 proves what it claims — checked, not assumed

A Cargo boot that never loaded the provider would pass exactly as green. What was checked on the booted WAR:
`OAuth2HttpRouteProvider.class`, `OAuth2NotFoundHandler.class`, `AuthorizeHandler.class`,
`OAuth2ErrorFilter.class` and `META-INF/services/org.forgerock.openam.http.HttpRouteProvider` each **md5-match
the working tree's**. (The *jar* md5 differs — the WAR assembly repacks it — so the comparison has to be
per-entry, not per-archive. Worth knowing before the next step repeats this check.)

⇒ **R-5d1.1 discharged**: the production Guice graph constructs all 15 handlers eagerly, and the router that
also serves `/json`, `/xacml`, `/uma` and `/rest-sts` builds.

### Criterion 11 — the full suite, one pass, fresh containers

`openam-e2e:5d1b`, built by CI's `build-docker` recipe (the three `#COPY` lines uncommented by the same sed,
a minimal hard-linked context) over a single `mvn -o install -DskipTests -am -pl openam-server,…ssoadmintools,…ssoconfiguratortools`
so all three artifacts share one provenance. IDP **and** SP, both on that image, configured with `build.yml`'s
`conf.file` verbatim. Deployed-jar md5 `fd650b8b2f440cdc265759cd7621b1f2` = the working tree's.

| Surface | Rows | Result |
|---|---|---|
| `/oauth2` — `oauth2-endpoints` 43, `oauth2-test` 37 (incl. 5-E5's 14), `oidc` 20, `webfinger` 2 | 102 | all pass, **still Restlet** |
| `/uma` | 11 | pass |
| `/xacml` | 15 | pass |
| `/xui` | 3 | 2 pass, 1 skipped |
| `/saml` | 1 | pass |
| `/json` | — | exercised by every spec's login |

Two marks that are **not** failures, resolved by reading rather than by assuming:

- `webfinger-test.spec.mjs:59` renders `✘` but is counted **passed**: it carries `test.fail(true, "Pre-existing
  defect: ServletUtils.getRequest returns null under the upstream ServerServlet…")`, to be removed when phase 6
  fixes it. The list reporter marks an expected failure with the same glyph as a real one;
- `xui-httponly.spec.mjs:208` is skipped by a `cookieHttpOnly` mode gate.

⚠ **Two false starts, recorded so the next step does not repeat them.** The first full run reported *130 passed,
1 failed* — the failure was `saml`, whose `bootstrap.sh` does `docker exec … openam-sp` against an SP container
that had not been started. Standing the SP up was not enough: `bootstrap.sh` is **not idempotent**, and the
first run had already created the `MYSAML` circle of trust on the IDP before failing, so `create-cot` exited
**127** under `set -e` on the retry. Both containers had to be recreated. That is the same rule
[5c's gate notes](phase-5c-asbuilt.md#run-this-gate-against-a-fresh-container) state for resource-set leakage, and it
applies to the SAML fixture too: **a second run against a used container is not a measurement.**

<a id="5d-1b-the-two-5d-1a-casualties"></a>
### ⚠ 5d-1a left this module's failsafe suite red, and its as-built records it green

Found by running `mvn -o -pl openam-oauth2 verify` — which **5d-1a never did**. Its criteria 3 and 4 are
`mvn … test`, and `*IT.java` is bound to failsafe, so two composition ITs asserting framework verb behaviour
were never re-run after the `HEAD`/`Allow` change landed. Both were broken by it:

| Row | Was | Now |
|---|---|---|
| `ResourceSetRouteCompositionIT:295` | asserted `Allow` is **absent** — and its own comment said *"closing it is a 5d-1 handoff item, and this line is what will fail when it is"* | asserts the four-verb **set**. `Endpoints.allowHeader` emits `DELETE, GET, POST, PUT`; Restlet sent the same four in a different order ([5-E4 row 11](phase-5c-asbuilt.md#as-built-5-e4--recorded-2026-07-29)), and the e2e row asserts a set too |
| `OAuth2ErrorRouteCompositionIT:152` | used **`HEAD`** as its example of *"a verb that is not in the framework's map at all"* — 5d-1a mapped it, so on a `@Get`-only endpoint it now serves | uses **`PATCH`**, the verb that producer still answers ([divergence row 14](phase-5d-1.md#divergence-rows-this-step-adds-to-planmd)) |

Both are faithful repairs of each row's stated intent. ⇒ **the [5d-1a as-built](#as-built-5d-1a--recorded-2026-08-05)'s
criterion table should read "surefire only"**, and any future framework commit must run `verify` on every
consumer it names, not `test`.

### Two design choices the plan left open

- **the `HEAD` refusal's body** is the framework's own unsupported-verb answer — `{"error":"method_not_allowed",
  "error_description":"Method Not Allowed"}`, identical to what `PUT`/`DELETE` already get on this endpoint —
  rather than Restlet's `"Required Method: GET or POST found: HEAD"`. [D8](phase-5b-1.md) already accepted the
  framework's phrasing for those two verbs, and on a `HEAD` no body reaches the wire, so reproducing Restlet's
  string would buy an unobservable parity at the cost of one endpoint answering two different 405s;
- **the guard reads the *effective* method**, not the request line. `Endpoints.getMethod:119-126` rewrites a
  `POST` carrying `X-HTTP-Method-Override`, so `POST /oauth2/authorize` + `X-HTTP-Method-Override: HEAD` reaches
  the `@Get`. Restlet refuses that too ([5-E5 row 10a](#the-recorded-rows) — its tunnel rewrites above the
  endpoint filter), so guarding on the raw verb alone would have left the refusal bypassable by one header on
  the endpoint that issues codes.

### Mutation checks

Every guard whose value is "it fails when someone gets this wrong" was reddened deliberately and restored:

| Mutation | Reddens |
|---|---|
| `"tokeninfo"` → `"tokeninf0"` in the provider | exactly that probe row (404, not 405) — R-5d1.3 |
| `noCache(...)` added to the `tokeninfo` route | `theNoCacheFilterIsOnTwoRoutesAndNoOthers` **and** the `HEAD` header row — R-5d1.4 |
| `USERNAME` dropped from `access_token`'s `formAuditor` | exactly `theAccessTokenAuditDetailIsExactlyTheConfiguredFieldList` — R-5d1.3 |
| `isHead`'s raw-verb branch disabled | row 1 only |
| `isHead`'s override branch disabled | row 2 only — the two branches are independently load-bearing |

### What `OAuth2RouterIT` deliberately does not cover

[D9](phase-5d-1.md#d9) lists four deep rows not written, three of them by decision: `/access_token` bad-secret 401 +
`WWW-Authenticate`, `/authorize` unauthenticated 301, and `/authorize`'s 302 fragment-vs-query. All three are
pinned at handler-plus-chain level by `AuthorizeRouteCompositionIT`, and the provider adds nothing to those
paths but the audit wrap and the no-cache filter — both of which *are* pinned here. The fourth, *"the three
error shapes coexisting in one run"*, **is** covered: the probe table shows 14 routes answering
`method_not_allowed` from the root filter and 3 `resource_set` routes answering `unsupported_method_type` from
the nested one, in a single run.

---

<a id="the-pre-flip-audit-capture--recorded-2026-08-05"></a>
## The pre-flip audit capture — recorded 2026-08-05

[D8](phase-5d-1.md#d8)'s pre-flip half, taken early: it has to happen on a live-Restlet `/oauth2`, and the
5d-1b soak containers were still up. Checklist step 14 of **5d-1c**, done ahead of the flip.

| | |
|---|---|
| Artefact | `docs/migration/restlet/artefacts/d8-audit-pre-flip.csv` (8 rows + a provenance header) |
| Tool | `e2e/tools/d8-audit-capture.mjs` (md5 in the artefact header), fixtures from `e2e/common/oauth2-fixtures.mjs` unchanged |
| Normaliser | `e2e/tools/d8-audit-diff.py` |
| Container | `openam-idp` on `openam-e2e:5d1b` — the same image 5d-1b's criterion 11 measured |
| Commit | `ca7bed61159250149599c4f402d3eae7f0764004` (5d-1b) |
| Statuses | `1:200 2:401 3:302 4:302 5:200 6:200 7:201 8:405` — all eight as expected, bar D8's predicted 301 |

⚠ **Corrected 2026-08-05, after the flip.** Rows 3 and 4's `302` was read here as an unauthenticated login
redirect. It is not: the probe sends no `redirect_uri`, the request fails validation, and Restlet redirected
the *error* back to the client's registered `redirect_uri`. Post-flip both rows are a **400**, because
[D7](phase-5d-1.md#d7) makes exactly that failure non-redirecting. The audit diff is therefore D7 working as
designed, not a regression — and row 4 being authenticated (it carries the demo user's `id`) never mattered.

**The capture is validated in both directions.** Two captures of the same unchanged container normalise to
byte-identical output, so a non-empty post-flip diff is a real difference and not run-to-run noise; and
mutating a `reason` string in the artefact still shows up in the diff, so the normaliser is not simply
hiding everything. Both checks were run, not assumed.

**Four of D8's assumptions were wrong** — the corrected procedure is now in [D8](phase-5d-1.md#d8) itself.
Briefly: the audit handler is already enabled (nothing to turn on), but `csvBuffering.bufferingEnabled` must
be turned **off** or the extraction silently captures someone else's traffic; the auditor detail is at
`request.detail`/`response.detail`, not `http.request.detail`; `AM-ACCESS-ATTEMPT` is blacklisted by default
so there are 8 rows and not 16; and the probe's `/authorize` is a **302**, not a 301 — an error redirect, as
corrected above, not the login redirect this originally called it.

**What the artefact already proves, pre-flip.** The audit matrix
([finding 2](phase-5d-1-research.md#2--the-route-table-is-18-attachments-and-7-distinct-auditor-pairs-lift-both-verbatim))
is directly readable in the response details, which is the strongest available check that the copy in
`OAuth2HttpRouteProvider` is the same contract Restlet is serving today:

| Row | Endpoint | `response.detail` | Matches table row |
|---|---|---|---|
| 1 | `/access_token` | `{"scope":"uma_protection","token_type":"Bearer"}` | 3 — `jsonAuditor(SCOPE, TOKEN_TYPE)` |
| 5 | `/tokeninfo` | `{"scope":["uma_protection"],"token_type":"Bearer"}` | 4 — `jsonAuditor(SCOPE, TOKEN_TYPE)` |
| 6 | `/introspect` | `{"scope":…,"token_type":"access_token","client_id":"d8_probe","active":true}` | 5 — `jsonAuditor(SCOPE, TOKEN_TYPE, CLIENT_ID, USERNAME, ACTIVE)`; `USERNAME` is absent because a `client_credentials` token has no resource owner |
| 7 | `/resource_set` | `{"_id":"…"}` | 12–14 — `jsonAuditor("_id")` |
| 3, 4 | `/authorize` | *(none)* | 2 — `noBodyAuditor()` on both sides |

**The two strings the flip is expected to change**, pinned exactly:

| Row | Now (Restlet `getDescription()`) | Expected after the flip (`getReasonPhrase()`) |
|---|---|---|
| 2 — bad-secret token, 401 | `{"reason":"The request requires user authentication"}` | `{"reason":"Unauthorized"}` |
| 8 — `PROPFIND /oauth2/tokeninfo`, 405 | `{"reason":"The method specified in the request is not allowed for the resource identified by the request URI"}` | `{"reason":"Method Not Allowed"}` |

⚠ **The `:-1` port does not reproduce.** [Risk #13](plan.md#risk-register-behavioral-compatibility) allows for
`http.request.path` carrying `:-1` ([backlog](decisions.md#chf-cleanup-backlog)); every pre-flip row shows
`http://openam.example.org:8080/…`. So a `:-1` appearing post-flip is a **regression**, not the known issue —
this artefact is what removes that excuse.

**Left on the container by this capture** (both harmless, both recreated identically by a re-run): an OAuth2
client `d8_probe`, and the audit service's `csvBuffering.bufferingEnabled` set to `false`.

---

<a id="as-built-5d-1c--recorded-2026-08-05"></a>
## As-built — 5d-1c, recorded 2026-08-05 (the flip)

`/oauth2/*` now resolves to the CHF `OpenAM` servlet. The change itself is four lines of `web.xml`; everything
else below is what measuring it turned up.

### The commit shape — two commits, not one

[D6](phase-5d-1.md#d6) requires the flip to be one revertible commit and says any fix it demands lands *on top*.
That sentence assumed a flip already pushed and soaking. Here the fixes were known **before** the flip existed,
and the e2e rows they move are re-pinned in the flip commit — so putting them on top would leave the flip
commit itself red under `git bisect`. They go **underneath** instead:

| | Commit | Contents | Green? |
|---|---|---|---|
| A | the parity fixes | five source changes + their unit/IT rows, all in `openam-oauth2`; plus the oracle-extractor fix | yes — the CHF routes have been registered since 5d-1b but are not yet *served*, so nothing on the wire moves |
| B | **5d-1c** | the one `web.xml` mapping move, the licensed e2e re-pins, the docs, the post-flip artefacts | yes |

`git revert` of **B** still restores Restlet on `/oauth2` with the CHF stack built and dormant — the
[cutover lever](decisions.md#cutover-lever) unchanged. Reverting B does **not** revert A, which is correct: A
is inert while Restlet serves.

### Criteria 12–13 — the byte-diff

| | |
|---|---|
| Image | `openam-e2e:5d1c-v5`, built from this working tree; `/oauth2/*` → `OpenAM` asserted **inside the WAR** before baking, and the deployed `openam-oauth2` jar md5 matched the local build |
| Environment | full teardown + rebuild via `recreate-e2e-env.sh` — both OpenAM containers recreated, never reused |
| Suite | **131 passed, 1 skipped, 0 failed** (132 declared), one pass on fresh fixtures |
| Artefacts | [`artefacts/e2e-transcript-post-flip.txt`](artefacts/e2e-transcript-post-flip.txt), [`artefacts/e2e-oracle-post-flip.txt`](artefacts/e2e-oracle-post-flip.txt) (211 rows, against 217 pre-flip) |
| Oracle diff | 99 rows byte-identical, 118 pre-only, 112 post-only |

**Every unmatched difference resolved to a divergence row.** Rows 14–30 in
[plan.md](plan.md#expected-divergences-at-the-flip) are the result; all are measured on both stacks, and the
directions are 13 shape-only, 3 narrowing (14, 21, 26) and **1 widening** (30 — the method tunnels, where
`POST /access_token?method=GET` now issues a real token). Row 30 is the one that wants a release-note line.

⚠ **A green suite is not a green surface.** Playwright aborts a test at its first failing assertion, so an
early divergence hides every later one in the same row. Three of the fixes below were found only because a
row that had already gone red was re-run after the earlier failure was fixed.

### Criterion 14 — the audit smoke

Post-flip capture on the shipped image: [`artefacts/d8-audit-post-flip.csv`](artefacts/d8-audit-post-flip.csv),
8 rows. Field-for-field identical to the pre-flip capture apart from run-specific values (event ids,
timestamps, ports, token and resource-set ids, durations) and the **two strings the pre-flip capture pinned as
expected to change** — both changed exactly as predicted, `getDescription()` → `getReasonPhrase()`.

Two statuses differ from D8's own prediction and are recorded, not fatal: rows 3 and 4 (`/authorize`) were
**302** pre-flip and are **400** post-flip. The 302 was never a login redirect — it was the `invalid_request`
error redirect back to `redirect_uri`; [D7](phase-5d-1.md#d7) makes that failure a non-redirecting 400 on
purpose, so this is D7 working, not a regression. No `:-1` port appears in any row.

### Criterion 15 — the Cargo boot

`mvn -o -pl openam-server verify -P integration-test` against the flipped WAR: **the instance starts**
(`OpenAM instance started, context=/test-am`) and the suite is green — `Tests run: 3, Failures: 0, Errors: 0,
Skipped: 0`, BUILD SUCCESS. The WAR that booted is the one the e2e image was baked from, so the mapping move
is exercised by both the container and the in-reactor boot.

### Criterion 16 — CI, nine legs — recorded 2026-08-06

| | |
|---|---|
| Run | [`31031060622`](https://github.com/maximthomas/OpenAM/actions/runs/31031060622), workflow `Build`, event `push` |
| Head SHA | `bccbc9c4d95933ffefdddcf70bac66e6b7c5fef5` — **the SHA the branch still carries**, checked against `git rev-parse HEAD` rather than against the SHA the commit reported when it was written |
| Window | 2026-08-05 17:39:46 → 18:28:10 UTC (48m24s) |
| Result | `success`, **9** `build-maven` legs — exactly the matrix the criterion names (`build.yml:27-34`): ubuntu × 11/17/21/25/26 plus macOS and windows on 11 and 26. `build-docker` (`needs: build-maven`) is green as well — a tenth signal the criterion did not ask for |

**One leg was read, not just its badge** — ubuntu/JDK 17, job `92391594843`:

- `-P integration-test` **reaches the command line**. The ubuntu-only step writes `MAVEN_PROFILE_FLAG` to
  `$GITHUB_OUTPUT` and the build step interpolates
  `${{ steps.maven-profile-flag.outputs.MAVEN_PROFILE_FLAG }}` (`build.yml:52-61`), so the Cargo boot really is
  an ubuntu signal and not a flag dropped between two steps. The literal appears in the log.
- `openam-oauth2`: surefire **1305**, failsafe **63**, both 0 failures — so `OAuth2RouterIT` ran in CI on the
  flipped commit, on all nine legs (its frames appear in the log, from the rows that log an expected error).
  Against 5d-1b's baselines (1286 / 62) that is +19 / +1, and commit A is the only source of test rows in
  between: `git diff --stat ca7bed6115 HEAD -- openam-oauth2/src/test` is 7 files, +299/-20, one of them the
  new `ResourceSetRouteCompositionIT` rows.
- `openam-server` under the integration profile: `OpenAM instance started, context=/test-am` three times,
  `Tests run: 3, Failures: 0, Errors: 0, Skipped: 0`, 246.2 s. `BUILD SUCCESS` at 18:03:40.

### Five parity fixes the flip demanded (commit A)

Each was a real wire difference the pre-flip capture did not license, so each was fixed rather than recorded:

1. **Unauthored `server_error` descriptions leaked internals.** `OAuth2Error.asMap` now masks them to Restlet's
   own generic sentence. The discriminator is exact rather than heuristic: `ServerException(Throwable)` is the
   wrap-any-bug path and its description *is* the throwable's message, while `ServerException(String)` is
   authored. Masking lives in `asMap()` (the wire), not `getDescription()` (the log), so the detail survives
   for operators. The authored `precondition_failed (512) - …` family and [D7](phase-5d-1.md#d7)'s
   `invalid_request` are deliberately untouched.
2. **`CheckSessionHandler` display errors.** `?display=popup|touch|wap` now answers Restlet's own
   `Bad Request (400) - Server can not serve the content of authorization page`, and `?display=<unknown>` the
   generic mask — reproducing `OAuth2Representation`'s two branches and restoring byte parity on all four
   measured spellings.
3. **`CheckSessionHandler` client-driven runtime failures.** The catch was an enumeration of exception types
   and found a new one on every measurement (`NullPointerException`, `NoSuchElementException`,
   `UnsupportedOperationException`, `JwtRuntimeException`) because the set is the transitive closure of what the
   store and the JWT parser may throw. Replaced with `catch (RuntimeException)` scoped to the single call that
   parses the client's own `id_token`. The other three collaborator calls sit outside it and keep CHF's 500 for
   a genuine bug ([D3](phase-5c.md#d3)).
4. **`resource_set` thrown errors carried a charset.** The `PUT` 400 and `GET` 404 left through the base class's
   `@ExceptionHandler` → `setEntity(Map)` and went out `application/json;charset=UTF-8`, where 5-E4 row 14
   measured bare. Fixed by overriding `withErrorHeaders` on `ResourceSetRegistrationHandler` — the same
   `protected` hook `TokenEndpointHandler` and `AuthorizeHandler` already use. ⚠ **Not** in
   `ResourceSetErrorFilter`, which was the first attempt: by the time the filter sees them, a thrown error and
   the in-band duplicate-name 400 are both OAuth2-shaped 4xx JSON bodies with a charset, and **row 7's charset
   is measured Restlet parity**. Normalising there would have closed two divergences by opening a third.
5. **The oracle extractor lost ~6% of fixture suffixes.** `SUFFIX` required a digit to avoid eating English
   words, but the suffix is base-36, so about one name in 17 draws none — `cejdvhxu` did, and put a phantom
   5-E4 row 7 in the byte-diff. Anchoring a second rule on the closing quote of a quoted fixture name fixes it;
   re-extracting the committed pre-flip transcript with the fixed tool yields a **byte-identical body**, which
   is what keeps the two sides of the diff comparable.

### One divergence row withdrawn, and three comments that repeated it

⚠ [plan.md](plan.md#expected-divergences-at-the-flip) **row 11** — "every `Content-Type` that carries a charset
gains a space after the `;`" — is **false on the wire and is withdrawn**. commons
`ContentTypeHeader.getValues()` does render `"; charset="`, so a unit test reading the header back with
`getFirst` sees the spaced form; but that renderer only runs when something reads the header *as a
`ContentTypeHeader`*. `setJson` writes the literal constant, and that is what reaches the socket. The post-flip
capture contains **no spaced Content-Type at all** — 26 logged values across both stacks, every one of them
`application/json`, `application/json;charset=UTF-8` or `text/html;charset=UTF-8`. The rows row 11 predicted
would go red (5-E2 2/3/4, the 5-E3 device pages, 5-E4 row 7) are all green.

The same claim had been copied into `ResourceSetRegistrationHandler`'s duplicate-name branch, its
`JSON_TYPE` javadoc and `ResourceSetRegistrationHandlerTest`; all three are corrected in commit A.

### Answers to questions the plan left open

| Question | Answer |
|---|---|
| 5-E4 row 15 — `HEAD` `Content-Length` | CHF **sends** it; Restlet did not. Measured: `/tokeninfo` 213, `.well-known/openid-configuration` 1515, `connect/jwk_uri` 447, `resource_set` item 238. Inverted from [finding 7](phase-5d-1-research.md#7--content-length-on-a-head-is-tomcats-decision) |
| 5-E4 row 17 — the unrouted-path 404 | Collapses to one body ([D5](phase-5d-1.md#d5)); Restlet's per-segment sub-realm messages have no counterpart |
| `//tokeninfo` — could the empty segment now be consumed? | **No.** Measured 404. `RealmContextFilter`'s cleanup does not make the empty element routable |
| `PUT /tokeninfo` — did it take the `@Get`-first path like `PATCH`? | **No.** No cache directives on either stack; the `@Get`-first behaviour was PATCH-specific |
| `?_api` — fix or record? | **Record** (row 26). The filter is mounted application-wide and shared with `/json`, whose descriptor works; the only surgical alternative mutates a query `/authorize` echoes into `goto` |

<a id="criterion-17--the-soak--recorded-2026-08-06"></a>
### Criterion 17 — the soak — recorded 2026-08-06

Criterion 17's own condition — 13–16 recorded — was met by the paragraph above it. What it could not supply was
*repetition* and *coverage*: `build.yml:16-18` is push-triggered with no `schedule`, so an idle branch produces
no further signal, and [criterion 12's caveat](phase-5d-1.md#verification-criteria) says in as many words that a
green suite proves only the rows that exist. The soak was therefore run as repetition plus the three gaps that
caveat names, not as elapsed time.

**It found one regression, which the byte-diff had missed, and the same pass fixed it.**

#### What was run

| | |
|---|---|
| Repetition | **3** full-suite runs, each on a completely recreated environment (all four containers + the network, never reused): **151 passed / 1 skipped / 0 failed** of 152 declared, 75 s / 80 s / 65 s. A pre-change baseline run reproduced the recorded single pass exactly (131/1/0 of 132) |
| Flake | **none.** Sorting each run's rows and diffing gives byte-identical output across all three — 456 row executions, no row red in one and green in another. `2f16a47c0d`'s flake did not recur |
| Tripwire — CREST from `/authorize` | **clear** on every run and across 23,469 concurrent authorize calls. The only CREST bodies in any transcript are `/uma`'s, which `uma-test.spec.mjs` asserts on purpose. ⚠ A naive `grep -i authorize` false-matches **"Unauthorized"** |
| Tripwire — `:-1` in `http.request.path` | **clear**: 0 occurrences over **91,307** audit rows sampled after the load probe. The single `:80` origin is a portless `Host` on a raw 5-E5 request rendering the scheme default, which is the opposite of the failure mode |
| Load | 90,689 requests in 240 s at 377.8/s: 46,938 tokens all **distinct**, zero `state` cross-talk across 23,469 `/authorize` calls, zero 5xx. The `client_secret_post` half — where audit, client authentication **and** the handler all re-read one body ([risk #1](plan.md#risk-register-behavioral-compatibility)) — was exactly as clean as the `client_secret_basic` control |
| Provenance | image `openam-e2e:soak`; deployed `openam-oauth2` and `openam-http` jar md5s both equal to the local build; `/oauth2/*` → `OpenAM` asserted **inside the WAR** before baking |

#### The regression, and the fix

Confidential-client authentication at `/oauth2/access_token` **in a non-root realm** was broken on all three
**path** spellings — `401 invalid_client` where pre-flip Restlet issued a token — while `?realm=` kept working.
Measured A/B on one identical fixture against `openam-e2e:5d1b` (Restlet) and `openam-e2e:soak` (CHF). It
matched no divergence row, and by [that table's rule](plan.md#expected-divergences-at-the-flip) an unmatched
difference is a regression.

It was worse than a parity slip: the sub-realm's **own discovery document advertises the nested path spelling
as `token_endpoint`**, so a conformant OIDC client discovering a non-root realm was handed the one spelling
that could not authenticate — and `/authorize` worked on every spelling, so the failure surfaced only at the
code exchange, after the user had consented.

**Cause.** `AMLoginContext.processIndexType:1730-1746` cross-checks the `AuthContext` realm against
`AuthClientUtils.getDomainNameByRequest:1475-1502`, which resolves the realm from the **servlet request
attribute** `realm` first, then the query string, and only then falls back to `request.getServerName()`.
Restlet's realm router wrote that attribute on every request it routed
([`RestletRealmRouter:97`](../../../openam-restlet/src/main/java/org/forgerock/openam/rest/service/RestletRealmRouter.java));
CHF's realm layer publishes the realm on `RealmContext` instead. So a path-spelled realm fell through to the
host's realm — root — and the mismatch threw `AUTH_ERROR`. Adding a redundant `?realm=` to a failing request
made it succeed, which is what isolated the branch.

⚠ **An earlier reading of this — that Restlet's `getHttpServletRequest()` returned null and skipped the branch
— is wrong**, and is recorded because it is the plausible-looking answer: `ClientAuthenticator:150-151`
dereferences the servlet request one line before `lc.login`, so a null would have thrown, not issued a token.
`hreq` is non-null on both stacks; what changed is what is *on* it.

**Fix.** `ClientAuthenticator.authenticate` and `ResourceOwnerAuthenticator.authenticate` set
`ISAuthConstants.REALM_PARAM` on the servlet request to the realm they just built the `AuthContext` with —
the same value the Restlet router used to write, so it is a no-op on the Restlet path. Chosen over restoring
the write in `RealmContextFilter`, which is shared with `/json` and which
[divergence row 16](plan.md#expected-divergences-at-the-flip) explicitly declines to change. The attribute has
exactly **one** reader in the tree (`AuthClientUtils.getRealmFromAttribute:1511`), so the narrow fix is
complete, and the migration already had the same one-liner at `IdTokenInfoHandler:151`, ported from Restlet's
`IdTokenInfo:196`.

**`ResourceOwnerAuthenticator` had the identical defect and no measurement had caught it** — it is reached only
by the password grant, which no row exercised. That is why row 10 exists.

**Verified after the fix**, image `openam-e2e:soakfix`, deployed jar md5 = local build: two clean runs on
freshly recreated environments (151/1/0, the only red being an assertion of mine that was wrong, below), then
a third after correcting it: **152 passed / 1 skipped / 0 failed** of 153 declared.

⚠ **Two things the new row asserted wrongly, both corrected against the live oracle rather than by reasoning**
— and the second is the more useful: a wrong password is **400 `invalid_grant`**, not 401 (RFC 6749 §5.2 — a
bad *resource-owner* credential is a bad grant; 401 is for a bad *client* credential), and a **root-realm user
does get a token from the sub-realm's token endpoint**, measured **200 on Restlet as well**. That is parity
caused by the fixture — a realm created over REST has no identity store of its own, so its chain reaches the
directory root uses. It is **not** the row-7 property, which is about an SSO session and still holds.

#### What the soak added to the tree

| Path | Rows | Purpose |
|---|---|---|
| `e2e/oauth2/realms-test.spec.mjs` | 10 | non-root realms through all four spellings. **Rows 3 and 10 are the regression guard**, asserting the correct answer so they cannot be "fixed" by rewriting an expectation |
| `e2e/oauth2/display-test.spec.mjs` | 11 | `?display=` on `/authorize` and `/device/user` — closes the renderer half of [risk #19](plan.md#risk-register-behavioral-compatibility), which had stayed open since 3c-1 because 131 rows exercised exactly one display. Pins [T4](plan.md#post-migration-tickets--raised-by-the-port-deliberately-not-fixed-in-it), confirmed present on Restlet too |
| `e2e/tools/oauth2-load.mjs` | — | the load probe. A tool, not a spec: it must outlive Playwright's 180 s per-test timeout, and its exit code keys on correctness only, never latency |

A fixture discovery worth keeping, and the reason no earlier spec put a client in a sub-realm: a realm created
over REST has **no `AgentService` organization config**, so every write to `realm-config/agents/OAuth2Client/…`
answers `404 Parent service does not exist.` and `agents` is not in its `getCreatableTypes`. The only REST path
that creates it is `connect/register`, so the fixture bootstraps through one throwaway dynamic registration.

#### What the soak did not cover

Single container, so nothing about the multi-server leg. No production realm with its own identity store — the
fixture realm shares root's, which is what made the root-user row parity rather than isolation. No long
duration: this is repetition and coverage, not elapsed time under real traffic.

⚠ **CI had not seen the fix when this was written; it has now** (corrected 2026-08-08). The paragraph above
ended "the two source changes above, which are still uncommitted", and
[criterion 16](#criterion-16--ci-nine-legs--recorded-2026-08-06) does cover only the flip commit
(`bccbc9c4d9`, run `31031060622`). The two changes landed as **`d52496710e`**, and run **`31105613611`** on
**`83f465452b`** — a descendant — is green across all nine legs. That run is what
[5d-2 criterion 11](phase-5d-2.md#verification-criteria) names as the gate on the first `git rm`, so the
sentence being stale is load-bearing in both directions: it was the reason 5d-2 waited, and its closure is the
reason 5d-2b may proceed.

---

## Handed to 5d-2

Recorded here so the deletion step reads one list:

⚠ **Two of these six were overtaken by 5d-2's own research (marked in place, 2026-08-08). Read the correction
before acting on the trap** — [plan.md's 5d-2 row](plan.md#phase-status) flags the pair but does not say which,
and both are the kind of claim that is acted on by `git rm`.

1. **The Restlet hook interfaces** — `TokenRequestHook`, `AuthorizeRequestHook`, and `LoginHintHook`'s two
   Restlet methods ([finding 1](phase-5d-1-research.md#1--the-hook-re-sign-is-already-done)); the CHF halves stay.
   ⚠ **Corrected by [research §2](phase-5d-2-research.md#2): `LoginHintHook`'s Restlet methods are *three*, not
   two** — `beforeAuthorizeHandling:54`, `afterAuthorizeSuccess:73`, `afterTokenHandling:90`, each the
   `(OAuth2Request, Request, Response)` overload of a hook point that exists twice, once per transport. "Two"
   is the count of Restlet `Multibinder` blocks (`OAuth2GuiceModule:228-234`), not of methods. Stripping two
   and leaving the third would leave the class implementing a deleted interface — a compile break, so this one
   fails loudly rather than silently. The class also **moves** out of its `.restlet` package
   ([D3](phase-5d-2.md#d3)).
2. **`ForgeRockRest`** — after 5d-1c it is a declared servlet with **no mapping**
   ([finding 12](phase-5d-1-research.md#12--the-webxml-change-is-one-line-and-oauth2-is-forgerockrests-last-mapping)); delete the
   declaration with the stack.
3. **`OAuth2RouterProvider` + `OAuth2RestGuiceModule`'s `@Named("OAuth2Router")` + `OAuth2GuiceModule`'s
   `@Named(RSR_ENDPOINT)` `Restlet` provider** — the last references to the Restlet OAuth2 chain
   ([5c finding 15](phase-5c-research.md#15-5d-2-must-also-delete-the-guice-provider-not-just-the-classes)).
4. **`org.forgerock.oauth2.restlet.resources` is not wholly deletable** — two of its three classes are
   Restlet-free and used by openam-uma
   ([5c finding 8](phase-5c-research.md#8--the-restlet-resources-package-is-not-deletable-at-5d-2)).
5. ⚠ **Two classes are called `RestletRealmRouter`.** The deprecated
   `org.forgerock.openam.rest.service.RestletRealmRouter` (openam-restlet) is the outer `/oauth2` router
   (`OAuth2RouterProvider:95`) and goes with the stack; `RealmRoutingFactory`'s private inner class of the
   same name (`openam-rest`, `:232-290`) backs `createRouter(org.restlet.routing.Router)` and must **survive**
   5d-2 — it is `RealmRoutingFactory`'s Restlet overload, and other Restlet consumers still call it. Deleting
   by simple name would take the wrong one
   ([finding 15](phase-5d-1-research.md#15--the-realm-layer-has-its-own-404-and-400-and-they-are-crest-shaped)).
   ⚠ **Corrected by [research §5](phase-5d-2-research.md#5), in both directions: *both* classes die at 5d-2.**
   The "must survive" premise was that other Restlet consumers still call
   `RealmRoutingFactory.createRouter(org.restlet.routing.Router)`; after 5d-2a ported WebFinger and 5d-2b
   deletes `OAuth2RouterProvider`, that overload has **no callers at all**, and [D7](phase-5d-2.md#d7) removes
   it with the inner class. The trap's *operational* content stands and is the half worth keeping: they are
   different classes in different modules, so **never delete by simple name**.
6. **The golden/parity tests degrade to `golden == CHF`** when the Restlet leg goes
   ([risk #19](plan.md#risk-register-behavioral-compatibility)) — expected, and the reason 5d-2 waits for a
   green soak.
