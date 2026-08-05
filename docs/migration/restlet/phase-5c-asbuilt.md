# Phase 5c — `/oauth2/resource_set` → CHF: as-built

What actually landed, and **every value measured against live Restlet**. This file is the durable record: the Restlet oracle dies at 5d-1c and these numbers cannot be re-derived afterwards. Spec: [phase-5c.md](phase-5c.md).

---

<a id="as-built-s3"></a>
#### As built — S3, 2026-07-29

The overload landed as D2 specified: `ErrorShape` nested in the filter, the three-argument constructor
delegating with `CREST`, `crestError` narrowed from `Exception` to `OAuth2Exception` (every call site already
passed one) so the `OAUTH2` branch can read `getStatusCode()`/`getError()`. 9 new rows, 18 in the class;
`openam-oauth2` **1226 surefire**, `openam-uma` **196**, both green.

⚠ **The 401's `error_description` was measured, not derived.** D2 prescribed `e.getMessage()` but no row had
ever pinned the string. Probed against the live container 2026-07-29:

```
POST /oauth2/resource_set  (no token, and again with a bogus token)
  401  Content-Type: application/json          <- bare, no charset
  {"error_description":"The access token provided is expired, revoked, malformed, or invalid for other reasons.","error":"invalid_token"}
  no WWW-Authenticate
```

Three things fell out of that probe:

- the value is `InvalidTokenException`'s constructor message, so D2's `getMessage()` is right;
- ⚠ Restlet emits `error_description` **first** — its `setExceptionResponse` uses a `HashMap`. `OAuth2Error.asMap`
  is a `LinkedHashMap` with `error` first. Key order in a JSON object is not a contract and the migration
  already decided this ([`OAuth2Error.asMap`'s javadoc](../../../openam-oauth2/src/main/java/org/openidentityplatform/openam/oauth2/http/OAuth2Error.java));
  noted only so a byte-diff at 5d-1 is not mistaken for a defect;
- the same probe confirmed the **bare** `Content-Type` on the 401, so the `OAUTH2` branch re-stamps it exactly
  as [S2](#as-built-s2) does — and confirmed [D5](phase-4-uma.md)'s no-challenge rule holds in this shape too.

Mutation-checked three ways — taking the status from `crestError`'s `code` instead of the exception turns
**1** row red (finding 14's path, and the natural implementation), defaulting the three-argument constructor
to `OAUTH2` turns **8** red including the dedicated additivity row, and dropping the bare-`Content-Type`
stamp turns **1**.

**The blast radius was gated for real, not by unit test alone.** This is the first 5c step whose class is on a
live route, so the WAR and an `openam-e2e:5c1` image were rebuilt from this tree and the suites re-run on a
fresh container: `npx playwright test oauth2 uma` in one pass = **94 passed**, unchanged, with
`uma-test.spec.mjs:152` green **without edit** — D2's own criterion for "the overload is additive". Probed
directly on the rebuilt container, the live `/uma` 401 is byte-identical to the pre-change probe
(`{"code":401,...}` under `application/json;charset=UTF-8`), and `resource_set`'s stays Restlet's until 5d-1.

<a id="as-built-s2"></a>
#### As built — S2, 2026-07-29

`ResourceSetErrorFilter` landed with D3's table unchanged, 16 unit rows, `openam-oauth2` **1217 surefire**
(was 1201). Two things the decision did not settle:

- ⚠ **The `Content-Type` must be re-stamped bare.** `Entity.setJson` writes
  `application/json; charset=UTF-8`, while 5-E4 row 14 measured **bare `application/json`** on 200, 201, 204,
  400, 401, 404, 405 and 412 — and the gate asserts it with `toBe`, not `toContain`
  (`oauth2-endpoints-test.spec.mjs:838`). One line after `setEntity` closes it.
  **Decided 2026-07-29: bare, scoped to this endpoint.** This **binds [D8](phase-5c.md#d8)** — 5c-2's handler must do the
  same on its own 200/201/204, or the endpoint contradicts itself. ⚠ The one exception is row 7's in-band
  duplicate-name 400, which really does send `;charset=UTF-8`.
  The migration-wide charset diff (`/tokeninfo`, `/authorize`) is **not** retired by this and stays flagged
  for 5d-1, as `oauth2-test.spec.mjs:493-496` and `oauth2-test.spec.mjs:741` already record. ⚠ Note that
  [plan.md](plan.md)'s 5a-2 paragraph reads as though the no-charset form were *reproduced*; it is not —
  the e2e comments are the accurate record.
- **The guard needs a body carrying `error` *and* `code` to be testable at all.** Every realistic
  already-shaped body lacks `code`, so the CREST clause alone spares it and the `containsKey("error")` clause
  is unreachable — a mutation that deletes it passes the whole suite. Kept anyway, matching
  `OAuth2ErrorFilter`, because this filter's output feeds another rewriting filter and idempotency should be
  structural rather than an accident of which keys today's producers use; one synthetic row now defends it.

Mutation-checked four ways — dropping the idempotency clause turns **1** row red (only after that row was
added), dropping the bare-`Content-Type` re-stamp **3**, letting the catch-all keep the incoming status **3**,
and dropping the empty-or-CREST guard **3**.

⚠ **One row added in review** (17 now): a **412 carrying the representation**. 5-E4 row 3b measured that a
losing `If-Match` on a `GET` answers 412 with the full body, so the shape [D6](phase-5c.md#d6)'s handler must produce is
one this filter has to *leave alone* — and it does, because the representation is neither CREST- nor
OAuth2-shaped, so the guard spares it before the 412 branch is reached. Nothing pinned that: a guard loosened
to "rewrite every 412" passed all 16 original rows, and the only thing that would have caught it was an IT
still unwritten at 5c-2 S6. With the row, that mutation turns **1** red and dropping the guard entirely turns
**5** (was 3 — the recount is the two rows added since).

#### As built — S1, 2026-07-29

`HttpConditions` landed with D6's signature unchanged (`of`/`hasIfMatch`/`matches`/`noneMatches`), ~50 lines,
21 unit rows. Three things the design note did not anticipate, all from disassembling the fork's parser
([chf-patterns §21b](chf-patterns.md#21b) has the full read-out — do **not** reopen the jar):

- ⚠ **The tag splitter is not quote-aware**, so a comma always ends an element and a tag name containing one
  can never match. Commons' `HeaderUtil.split` **is** quote-aware, so the obvious reuse is a behaviour
  change; mutation-checked, it turns two rows red.
- **`*` and `"*"` parse to the same tag** — but see the correction below: that is a fact about the *parser*
  and it does not license dropping the weak flag.
- **`If-Match: "` (a lone quote) makes Restlet throw** `StringIndexOutOfBoundsException` out of its reader —
  unmeasured, presumed a 500. Decided 2026-07-29: **drop it as invalid**, i.e. treat it as absent like any
  other garbage. A footnote, not a divergence row; reproducing a crash is not a contract.

Mutation-checked three ways — `hasIfMatch()` reporting presence instead of parse turns **7** rows red,
`noneMatches` honouring `*` turns **1**, quote-aware splitting turns **2**. `openam-oauth2` **1201 surefire**
(was 1180).

##### ⚠ Corrected in review, same day — two divergences, both from reading the parser and not the comparator

S1 disassembled `TagReader` → `Tag.parse` and stopped there. The rules that decide what a parsed list *means*
live in `Conditions.getStatus`, which was never opened, and all 21 rows passed over both holes:

1. **The wildcard is positional and strong-only.** `all = getMatch().get(0).equals(Tag.ALL)` — one test, on
   the first element, with weakness checked (`Tag.equals(Object)` is the 1-argument form). The helper asked
   "does the list contain `*`", so `If-Match: W/"stale", *` and `If-Match: W/*` both **applied an update
   Restlet answers 412 to** — the lost-update hole D6 exists to close, reintroduced in the class written to
   close it.
2. **`If-None-Match` compares weakness.** Its comparison passes `checkWeakness = GET || HEAD`, and those are
   the only verbs that reach it, so weakness always counts — while `If-Match`'s passes `false`. The endpoint's
   tag is weak, so `If-None-Match: "<name>"` must answer **200 with the body**; the helper answered a bodiless
   **304**. The class javadoc's "weakness is ignored", chf-patterns §21's bullet and the test row
   `ifNoneMatchIgnoresWeakness` all asserted the wrong half of an asymmetry nobody had looked for.

Neither divergence was measured at 5-E4 — no row sent `W/*`, a trailing `*`, or the strong form of the tag in
`If-None-Match` — so the oracle would not have caught them either. The bytecode is now recorded in
[chf-patterns §21b's comparator section](chf-patterns.md#21b-comparator).

Fixed by giving the helper Restlet's own two-field `Tag` (name + weak) instead of a name with `*` as a
sentinel: `matches` keeps the name-only comparison, `noneMatches` compares both fields, and each wildcard test
is `list.get(0)`. A `null`/unparseable current tag now yields `matched = all` as it does in Restlet, where it
previously threw `NullPointerException`. **27 rows** (was 21), mutation-checked twice more — restoring
"contains `*`, weakness ignored" turns **2** red, restoring the name-only `noneMatches` turns **1**.
`openam-oauth2` finishes the review at **1233 surefire**, 0 failures.

<a id="as-built-s4"></a>
#### As built — S4, 2026-07-29

`ResourceSetRegistrationHandler` landed with D8's four annotated methods, ~320 lines including javadoc, **32
unit rows**. `openam-oauth2` **1270 surefire** (was 1233), `openam-uma` **196** unchanged, javadoc clean,
`grep -c org.restlet` on the new class **0**, and the route gate finds the class named in no file but its own.

**The one structural departure from D8, and it is the whole shape of the class.** D8 (and D6) gave each verb
its own conditional rules. Rows 18–21, measured before a line was written, show Restlet running **one
verb-independent precondition gate**, so the handler has `preconditions(o2, request)` called first by
`@Post`, `@Put` and `@Delete` alike, and the `@Get` doing the same comparisons inline because its two
outcomes differ (a 304, and a 412 that *carries* the body). Three things fall out of that gate that no
per-verb version produces, and each is a mutation-checked row:

- a `POST` with a stale `If-Match` is a 412 and never reaches `store.create`;
- `If-None-Match` is evaluated on writes, where a match is a 412 — with `checkWeakness = false`, so the
  strong form of the weak tag matches on a `PUT` and not on a `GET`;
- the gate is entered only when a conditional header was **sent**. Not an optimisation: computing a tag
  unconditionally would read the addressed resource set on every request, and row 16's create-at-an-item-URL
  would 404 instead of creating.

**Three decisions the plan did not cover:**

- ⚠ **The body is parsed with `org.json` first, then Jackson over its re-serialisation** — Restlet's `toMap`
  verbatim. **Challenged at review, and the challenge is what produced row 22**: "why not just use Jackson?"
  is the obvious simplification, and the answer turned out to be much stronger than the error-message parity
  the decision was originally made for. `@Post createResourceSet(JsonRepresentation)` reaches
  `new JSONObject(<raw body>)` — `JsonConverter.toObject` wraps the representation and
  `JsonRepresentation.getJsonText()` returns its raw text, both read from the fork's bytecode — so the
  endpoint inherits **org.json's leniency**, measured: single-quoted strings, unquoted keys and a trailing
  comma all **create**. A Jackson port answers 400 to all three, switching off resource servers that work
  today, and the status a client sees (400 `bad_request`) is plausible enough that nobody would suspect the
  parser. In the other direction Jackson accepts duplicate keys last-one-wins where org.json **rejects**
  them. So the parser is a wire contract on at least five inputs, not just a message.
  Two smaller reasons remain: `JsonValueBuilder`'s wrapper throws an **unchecked** `JsonException`, which the
  runtime-exception guard would turn into row 9's `server_error` rather than 400 `bad_request`; and parsing
  from `Entity.getString()` yields a fresh map, which settles D8's "copy the parsed body" caution **by
  construction** (`getString()` brackets its read with `push()`/`pop()`, so it disturbs no other reader).
  ⇒ `org.json:json` is now a **declared** dependency of `openam-oauth2`; it arrived transitively through
  `openam-core` before, which is one dependency change away from breaking a wire contract.
  ⚠ Moving to a strict parser is defensible on its own merits, and is filed as **[T8](phase-5c.md#t8)** — to be done
  after 5d-1, deliberately, with its own divergence row and release note, rather than as an invisible side
  effect of a port.
- ⚠ **`ResourceSetLabelRegistration`'s three `updateLabelsFor*` methods were package-private** and visible to
  the Restlet endpoint only because it sits in the same package. Widened to `public` (the only main-source
  callers are that endpoint and this handler). A one-word change; the alternative was putting a
  migration-authored class in `org.forgerock.openam.oauth2.resources`, against the naming convention.
- **`guarded` logs the throwable it swallows.** The wire message is the engine's generic 500 sentence, so
  without the log the original exception would be lost entirely — Restlet's `ExceptionHandler` logged it too.

**Mutation-checked six ways**, each mutation being a plausible implementation rather than a random edit —
the first three are literally what D6/D8 prescribed:

| Mutation | Rows red |
|---|---|
| the runtime-exception guard no longer maps to 400 `server_error` | **2** |
| conditional evaluation restricted to `GET`/`PUT`/`DELETE` (D6's rule) | **1** |
| `If-None-Match` given to the `GET` path alone (D6's rule) | **2** |
| the tag hashed from the bare `store.read` rather than the read model ([finding 17](phase-5c-research.md#17--the-conditional-comparison-tag-comes-from-the-read-model-labels-and-all)) | **9** |
| the "was either header sent" guard dropped | **3** |
| the `labels` strip/re-add "tidied" away ([finding 18](phase-5c-research.md#18--the-extension-point-sees-a-description-without-labels-and-without-an-id)) | **1** |
| the body parsed with **Jackson only** instead of org.json-then-Jackson | **3** |

**Still open at the end of S4:** S5 (port `ResourceSetRegistrationEndpointTest`'s cases), S6
(`ResourceSetRouteCompositionIT`) and S7 (the full gates). The class is routed **nowhere** until 5d-1, so no
wire behaviour changed and the 99-row e2e gate is unaffected.

<a id="as-built-s5"></a>
#### As built — S5, 2026-07-29

**Four rows, not six.** The plan said "port `ResourceSetRegistrationEndpointTest`'s six cases"; diffing them
against S4's 32 rows first showed two already covered end to end (`shouldReadResourceSetDescription`,
`shouldDeleteResourceSetDescription`) and the other four covered only in part. So S5 added what the legacy
suite asserts and S4 did not, rather than re-asserting what was already held. **36 unit rows**,
`openam-oauth2` **1274 surefire** (was 1270), 0 failures.

| Legacy case | Already held by S4 | Added at S5 |
|---|---|---|
| `shouldCreateResourceSetDescription` | 201 body, hook, label registration, before/after ordering | the description handed to `store.create` — client and owner **from the token**, fields from the **validated** map |
| `shouldNotCreateExistingResourceSetDescription` | the in-band 400, its charset, `never().create` | the duplicate query's **shape**, and that the extension point is never entered |
| `shouldUpdateResourceSetDescription` | 200, the new tag, `store.update` called | the description handed to `store.update` — id/client/owner preserved, body applied |
| `shouldListResourceSetDescriptions` | the id array | the list query's **shape** |
| `shouldReadResourceSetDescription`, `shouldDeleteResourceSetDescription` | in full | — |

**The gap worth naming.** Both query rows exist because every other row stubs `store.query(any())`, which
makes the filter's *contents* unasserted — and both mutations there are silent data leaks rather than
failures: a duplicate check without `clientId`/`resourceOwnerId` lets one tenant's name block another's, and
a list query without `resourceOwnerId` returns **every owner's** resource sets to anyone holding a PAT for
the client. Likewise the create row: swapping `clientId` and `resourceOwnerId` in the constructor is two
same-shaped strings in the wrong order, invisible to all 32 earlier rows.

The query shape is read with `BaseQueryFilterVisitor` (the legacy suite's own tool) rather than by matching
`QueryFilter.toString()`: every visit method it does not override **throws**, so an `or`, a `not` or a
`startsWith` anywhere in the filter fails the row instead of being flattened into a passing map. That is
strictly stronger than legacy's `doesNotContain(" or ")` and shorter.

**Mutation-checked five ways**, all restored byte-identically afterwards:

| Mutation | Rows red |
|---|---|
| `clientId` and `resourceOwnerId` swapped on create | **1** |
| duplicate check by `name` alone | **1** |
| description built from the raw body, skipping the validator | **2** |
| list query drops `resourceOwnerId` | **1** |
| the update never applies the validated body | **2** |

**Two facts the rows pinned that no plan section had:**

- ⚠ **`ResourceSetDescription.update(Map)` replaces the description outright — it does not merge.** A `PUT`
  that omits a field *deletes* it. 5-E4 row 2a measured this for `labels` and read as a labels quirk; it is
  the general rule, and the S5 row now holds it on an ordinary field (`scopes`).
- **`org.json`'s `JSONObject` is `HashMap`-backed, so a request body's key order does not survive the parse.**
  Harmless on this endpoint — no response echoes the parsed body — and recorded as a row in [T8](phase-5c.md#t8),
  because Jackson *would* preserve it.

**Still open at the end of S5:** S6 (`ResourceSetRouteCompositionIT`) and S7 (the full gates). Still routed
nowhere; the 99-row e2e gate is still unaffected.

<a id="as-built-s6"></a>
#### As built — S6, 2026-07-29

`ResourceSetRouteCompositionIT` landed with **all 13 named rows**, mutation-checked on the three the plan
asked for (8, 10 and 13). The chain and the nested router are D9 verbatim, with one extra `STARTS_WITH
"oauth2"` parent standing in for the endpoint router the provider supplies at 5d-1; context stack is
`RootContext -> ClientContext -> RequestAuditContext -> AttributesContext -> RealmContext`.

**⚠ Row 4 as the plan specified it was wrong, and the measurement is why.** The plan says "`PATCH` yields
`unsupported_method_type`" — written before [5-E4 correction 1](#the-recorded-rows) measured Restlet routing
`PATCH` to the `@Put` method, where it 200s and really replaces the resource set. The row uses **`PROPFIND`**,
which row 11 did measure as a 405. A row written to the plan would have asserted a 405 the incumbent does not
produce, and — because `Endpoints.from` *does* 405 there — it would have **passed**, locking in a divergence
as if it were parity.

**Two things the rows now hold that were previously only prose:**

- **The vanishing `Allow` header is asserted, not remembered.** Restlet sent
  `Allow: POST, PUT, GET, DELETE` on that 405 and `Endpoints.from` sends nothing; row 4 asserts the header is
  **null** with a comment saying that line is what will fail when 5d-1 closes the gap. A handoff item that
  announces itself beats one that depends on someone rereading this document.
- **D9's filter placement is demonstrated by counterfactual.** Row 9 asserts the router's no-match 404 stays
  CREST — then builds the same router wrapped by `ResourceSetErrorFilter` and shows the identical 404 becoming
  a **500 `server_error`**. That is the bug the placement exists to avoid, executed rather than argued.

**⚠ Row 13 cannot replay the `GET`'s ETag.** The obvious way to write "take the tag from a `GET`, replay it as
`If-Match`" is self-consistent under exactly the mutation the row exists to catch: a handler that hashed the
bare `store.read` emits and expects the *same* wrong tag, so the round trip succeeds and the row passes. The
row therefore **computes** the expected tag from the read model (description + the two labels) and asserts the
`GET` returned that value. Verified: with the tag replayed the mutation stays green; with it computed the
mutation turns the row red.

| Mutation | Rows red |
|---|---|
| the three routes as **sibling `EQUALS`** matchers ([finding 12](phase-5c-research.md#12--the-trailing-slash-route-cannot-be-expressed-with-equals-in-chf)'s shape) | **1** (row 8) |
| the `OAUTH2` error shape takes the status the **call site** passed rather than the exception's | **1** (row 10) |
| the conditional tag hashes the bare `store.read`, labels never folded in | **1** (row 13) |

**Two in-process facts worth carrying forward:** `Entity.getJson()` hands back the very collection the handler
set — no serialization round-trip — so a list assertion must compare membership, not type; and
`-DskipTests=true` skips **failsafe as well as surefire**, so a `verify` run with it reports `BUILD SUCCESS`
having executed no IT at all (both recorded in [test-infrastructure.md](../../test-infrastructure.md)).

**Still open at the end of S6:** S7 only — the full gates and the commit.

<a id="as-built-s7"></a>
#### As built — S7 (the gates), 2026-07-30

All seven gates green, nothing rewritten to make them pass.

| Gate | Measured |
|---|---|
| `mvn -o install -DskipTests -am -pl openam-oauth2` | `BUILD SUCCESS` |
| `mvn -o -pl openam-oauth2 javadoc:javadoc` | `BUILD SUCCESS`, zero `.java` warnings |
| Restlet import gate, all five 5c main classes | **0** |
| Route gate | `ResourceSetRegistrationHandler` named in its own file only |
| `mvn -o -pl openam-oauth2 test` | **1274** (S5) |
| `mvn -o -pl openam-oauth2 verify` failsafe | **38**, 0 failures (S6) |
| `npx playwright test oauth2 uma`, one pass on `openam-e2e:5c2` | **99 passed** (15.9 s) |

**The e2e gate is a formality here and the reason is worth stating**, because it is the argument 5d-1 will *not*
be able to make. The whole 5c-2 main-source delta is wire-inert: `ResourceSetRegistrationHandler` is routed
nowhere, `HttpConditions` is referenced by that class and nothing else (grepped over `openam-*/src/main`), and
the only edit to a live class — `ResourceSetLabelRegistration` — widens three methods from package-private to
`public` and touches no logic. The image was still rebuilt from this tree rather than reusing `openam-e2e:5c1`,
because provenance is the point of the gate and 5c-1 set that precedent.

**Provenance, proved rather than asserted.** The 5-E4 as-built already warns that the container's banner
carries the *merge base*, not the classes. The check that does work: `docker cp` the deployed jar out and
checksum it against the module's own output — `openam-oauth2-16.2.0-SNAPSHOT.jar` was
`8d851c8c38efcfee7ec5610bea70aef2` in all three places (module `target/`, inside the WAR, and in
`openam-idp:/usr/local/tomcat/webapps/openam/WEB-INF/lib/`). ⚠ The image has **no `jar` and no `unzip`**, so
listing the archive in place is not an option. Both distribution zips were rebuilt too, not just the WAR:
`SSOAdminTools.zip` bundles `openam-oauth2`, so reusing the 07-29 zips would have put mixed provenance behind
the gate.

**⚠ The one-pass rule caught its author.** Having recorded it at 5-E4, I still ran `uma` a second time against
the same container to split the 99 into 88 + 11, and got the exact documented failure —
`warmUpResourceSetStore` → `resource-set store never became ready: 400 server_error`, with
`EntitlementException: Resource Type <id> does not exist in realm /` underneath. A third run degraded further
(45 passed, 2 failed, 52 not run). Nothing regressed: the same container and the same bytes had just passed all
99. Two small additions to what [that section](#run-this-gate-against-a-fresh-container) already says — the
exception also lands in `debug/Entitlement`, not only `debug/UmaProvider`; and the suite counts are **not
separable after the fact**, so if the per-suite split matters it has to be read from the one pass's own output
(don't `tail` it away, as I did) rather than re-measured.

<a id="s7-review-findings"></a>
##### Review of the finished change — four things the gates could not catch

All seven gates were green **before** this review, which is the point: none of the four is a test failure.
Two are wire-visible differences no single-stack test can see, one is a doc that contradicted the code 5d-1
will be written from, and one is an instruction that would have broken the build's dependency hygiene.

1. ⚠ **Every charset-bearing `Content-Type` gains a space on CHF — Phase-5-wide, and already shipped.**
   Restlet sends `application/json;charset=UTF-8` and `text/html;charset=UTF-8`; CHF sends both **with a space
   after the `;`**. The cause is not in any handler: commons `ContentTypeHeader.getValues()` builds
   `sb.append("; charset=")` unconditionally, so the header is **re-rendered** whatever a handler stamps.
   Now [divergence row 11](plan.md#expected-divergences-at-the-flip).

   ⚠ **My first attempt at this was wrong and the test caught it.** I read it as a 5c-2-only difference on the
   duplicate-name 400 and "fixed" it by stamping `application/json;charset=UTF-8` explicitly — the class
   already stamps `Content-Type` on every other status, so it looked like a one-line win over a divergence row.
   The unit row came back `expected "application/json;charset=UTF-8" but was "application/json; charset=UTF-8"`
   **with the new literal compiled in**, which is what sent me to `ContentTypeHeader` and turned a local
   cosmetic difference into a cross-cutting one. Reverted; the test now asserts what CHF really emits.

   The blast radius is wider than this endpoint: `FreemarkerTemplateRenderer` and **nine-plus committed
   unit/IT rows** pin the spaced form for the 5b-1 and 5b-2b browser endpoints today, while 5-E2 row 2 recorded
   Restlet's *"**no space** after the `;`"* at the time and no divergence row was ever written. So the affected
   oracles — 5-E2 rows 2/3/4, the 5-E3 device-page rows and 5-E4 row 7 — all go red at the flip on
   `Content-Type` alone. Fixing it means changing commons for one space that RFC 7231 §3.1.1.1 explicitly
   permits; recording it is the proportionate call.
2. **Response-body key order changes** — `createJsonResponse` copied into a `HashMap`, the port uses a
   `LinkedHashMap`. Semantically nothing (RFC 8259 §4), and *not* worth fixing: matching it would mean
   reproducing hash order on purpose. Recorded as [divergence row 13](plan.md#expected-divergences-at-the-flip),
   derived from the two sources and labelled as **not measured**.
3. ⚠ **[D3](phase-5c.md#d3)'s ordering diagram contradicted [D9](phase-5c.md#d9), on a line 5d-1 builds from.** It read
   `ResourceSetErrorFilter( audit( protect( … ) ) )` — audit *inside* the error filter — where D9's code block,
   the composition IT and S6's gate all have **audit outermost**. Not cosmetic:
   `AbstractHttpAccessAuditFilter.filter` audits the *response*, and `OAuth2HttpAccessAuditFilter` carries a
   response-body auditor, so the inner filter decides whether the audit record holds the OAuth2-shaped body the
   client got or the CREST body it never saw. D3 predates D9's revision and was simply left stale. Corrected,
   with the reason, so the next reader cannot pick the wrong one.
4. **[T8](phase-5c.md#t8) told its own implementer to delete a dependency five live classes need.** *"drop the
   `org.json:json` dependency … if nothing else needs it"* — `RealmOAuth2ProviderSettings`,
   `ClaimsParameterValidator`, `StatefulTokenStore`, `OpenAMScopeValidator` and `TokenRevocationResource` all
   import `org.json`, and none dies at 5d-2. Worse, removing the declaration would **not** fail the build —
   the module resolves `org.json` transitively through `openam-core` — so the mistake would have been silent
   and would have restored the exact fragility the `<dependency>` comment exists to prevent. Corrected in
   place.

**What this says about the gate set.** Items 1 and 2 are wire-visible differences that a full green build, 1274
unit rows, 38 ITs and 99 e2e rows passed over — because every one of those runs one stack or the other, never
both. A CHF test asserting `text/html; charset=UTF-8` and an e2e row asserting `text/html;charset=UTF-8` are
**both green today** and describe the same header; nothing in the gate set compares them. The only instrument
that catches this class before 5d-1 is reading the two sides together and asking what the *oracle* will say —
which is what the divergence table is for, and why finding row 11 four handlers late is the real lesson here.

**Second pass, 2026-07-30.** Re-reviewed after the four fixes, sweeping the surface the first pass had not read
end to end (`ResourceSetRouteCompositionIT`, the five new e2e rows, the `pom.xml`/`HttpConditions`/
`ResourceSetLabelRegistration` diffs) and re-checking every cross-reference the renumbering touched. Two defects,
both cosmetic and both in the new test sources: the IT's two `<a href>`s into this file climbed **eight** `..`
where the package needs **nine**, so both resolved to a non-existent `openam-oauth2/docs/…` (the two sibling
test classes in the same package get it right); and `ResourceSetRegistrationHandlerTest` imported `JsonValue`
without using it. Both fixed.

⚠ **The second one is a note on method, not on the import.** I had already written *"no unused imports"* into
this paragraph off a careful read-through of all five files — and it was wrong. `javac` does not warn on unused
imports and no gate in the set checks them, so the claim survived a green build twice. Checking it took one
shell loop over `import` lines; asserting it by eye took longer and got the wrong answer. Anything claimed in
an as-built that a five-line script can decide should be decided by the script.

Verified clean otherwise: anchors all resolve, divergence rows 11/12/13 agree everywhere they are cited,
[D3](phase-5c.md#d3)'s corrected diagram now matches [D9](phase-5c.md#d9) *and* the IT *and* the handler, and no widened or added API
lacks a caller **and** a test — `hasIfNoneMatch()` has both, and `matches(null)`, `noneMatches(null, ·)` and
`withEtag(…, null)` are exactly what makes the tag-less collection answer 5-E4 rows 19–21 the way Restlet does.

**Third pass, 2026-07-30.** Nothing further in 5c-2's own change: 36 + 13 test methods all carry an assertion or
a `verify`, no duplicate method names, no unused imports, and every markdown link and anchor in the four edited
docs resolves. What it did produce is a lesson about the sweeps themselves — see the `--` trap below.

⚠ **Seven pre-existing instances left alone.** Running each check over the whole tree rather than only 5c-2's
files found the same mistakes in already-committed code: `EndSessionHandlerTest:56` has the identical
off-by-one doc link (5b-2); `TokenRevocationHandler` / `TokenRevocationHandlerTest` carry an unused
`ClientRegistration` / `JsonValue` import (5a); and **four** citations — `plan.md` ×2, `phase-5b-2.md` ×2 —
point at `phase-5-oauth2.md#parity-preserved-security-debts--reproduce-now-fix-later`, whose heading has since
gained a trailing `(finding #7)`, so the live slug ends `-finding-7`. All seven are out of this commit's scope —
noted here rather than folded into unrelated phases' diffs. **Update 2026-07-30:** the four stale anchors were
fixed during [5d-1](phase-5d-1.md)'s review pass, whose own anchor sweep re-found them — the first sweep had
dismissed them as tool false positives, because it collapsed whitespace where GitHub emits one hyphen per
space, hiding every `—`-derived double-hyphen slug. The other three items stand. The sweeps themselves are the reusable part, in
[test-infrastructure.md](../../test-infrastructure.md#unused-imports-are-not-caught-by-any-gate).

⚠ **One of the three findings above was my own tooling, not the docs.** The first run of the anchor sweep
reported a *correct* link as broken, because the anchor began with `-` (GitHub slugs a `⚠`-prefixed heading to a
leading hyphen) and `grep -qxF "$anchor"` parsed it as options instead of a pattern. Two passes in a row have
now had a verification step be wrong in the same direction as the thing it was checking — first "no unused
imports" asserted by eye, then a sweep that mis-answered. The rule that falls out: **reproduce a sweep's failure
by hand once before editing anything**, and treat the checker as suspect until it has caught something real.

<a id="as-built-5-e4--recorded-2026-07-29"></a>
## As-built — 5-E4, recorded 2026-07-29 (test-only)

Captured against a live container built from this tree: `openam-e2e:5e4` (the repo
`openam-distribution/openam-distribution-docker/Dockerfile` with its three `#COPY` lines uncommented, exactly
CI's `build-docker` sed) over a full `mvn install -DskipTests` of the working tree, plus
`openidentityplatform/opendj:latest` on the `test-openam` network, configured with CI's `conf.file`. Restlet
still serves `/oauth2`: the endpoint under test is reached through `OAuth2RouterProvider:131-133`, and no CHF
`HttpRouteProvider` claims those paths.

⚠ The image's banner reads `Build 32f2b9572d (2026-July-27)` — that is the branch's merge base, which is what
the build-number plugin stamps. It is **not** the provenance of the classes: `WEB-INF/lib/openam-oauth2-*.jar`
carries `org/openidentityplatform/openam/oauth2/http/` compiled from this working tree.

**Deliverables — e2e only, zero main-source lines:**

| File | Change |
|---|---|
| `e2e/oauth2/oauth2-endpoints-test.spec.mjs` | new describe `/oauth2/resource_set contract lock (5-E4, live Restlet)` — **20 rows** (17 items; item 1 splits into 1/1b, item 2 into 2a/2b, item 3 into 3/3b), **25 after S4 added rows 18–22**; `ADMIN_USER`/`ADMIN_PASS` imported for row 10's second resource owner, and `node:http` for the one request Playwright cannot express |

`npx playwright test oauth2 uma` — **94 passed**: oauth2 **83** (63 before) and uma **11**, unchanged. Run in
one pass on a freshly built container; see the note below on why that matters. No existing row edited, no
fixture changed.

⚠ **Deviation from the plan, deliberate.** The plan said to extend the existing
`/oauth2/resource_set registration` describe. The rows went into a **separate** describe instead, matching the
5-E2/5-E3 precedent: the label `(5-E4, live Restlet)` then rides on every row's full title, which is what makes
`-g "5-E4"` a usable selector at the 5d-1 re-run, and it keeps the byte oracle from mixing with the
lifecycle rows that are deliberately shape-only.

### The recorded rows

| # | Request | Recorded |
|---|---|---|
| 1 | `PUT` `If-Match: W/"12345"` and `If-Match: "12345"` (stale) | **412** `{"error":"precondition_failed"}` — that field and nothing else, `application/json`, **no `ETag`**. Identical for the weak and the strong form |
| 2a | `PUT`/`DELETE` `If-Match: <the ETag a GET returned>`, verbatim including `W/` | **200** / **204**. Weakness is ignored, and the `PUT` answers a new tag on the same response |
| 1b | `If-Match` in eleven forms, each against a freshly read tag | the parsing table below — and three outcomes, not two: **200** (parsed, matched), **412** (parsed, no match) and **400** (⚠ *did not parse*, so byte-identical to the missing-header answer of row 4) |
| 2b | the same, using the ETag the **`POST`** returned | **200 if the client's label order matches the store's, 412 if it does not.** ⚠ The store's order is neither sorted nor the client's — see below |
| 3 | `GET`/`HEAD` `If-None-Match: <current>` | **304**, **carrying the `ETag`**, **no `Content-Type` at all**, **no `Content-Length`**. Stale tag → 200. `If-None-Match: *` → **200**, not the 304 RFC 7232 §3.2 asks for. (Body emptiness is unobservable on a 304 for the same reason as row 15, so only headers are asserted) |
| 3b | `If-Match` on a **`GET`** | `*` → 200. A non-matching tag → **412 carrying the full representation and the `ETag`** — a 200-shaped body under an error status, produced by no other path on this endpoint |
| 4 | `PUT` without `If-Match` | **400** `{"error":"server_error","error_description":"precondition_failed (512) - Require If-Match header to update Resource Set"}` |
| 5 | the `ETag` bytes on `POST`/`PUT`/`GET` | `W/"<signed decimal>"` — weak, quoted, `Integer.toString`, negatives included. The **list** carries no `ETag` |
| 6 | `DELETE` without `If-Match` | the same 400 `server_error`, `…Require If-Match header to **delete** Resource Set` |
| 7 | `POST` a duplicate name for the same owner | **400** `{"error":"Bad Request","error_description":"A shared item with the name 'X' already exists"}` — a reason **phrase** in the `error` field, and the **only** response on the endpoint with `Content-Type: application/json;charset=UTF-8` |
| 8 | `POST` an invalid description | **400** `bad_request`; `Invalid Resource Set Description. Missing required attribute, 'name'.` / `…, 'scopes'.` / `Required attribute, 'scopes', must be an array of Strings.` An empty object `{}` gives the `'name'` message |
| 9 | `PUT`/`DELETE` on `/resource_set` **and** `/resource_set/` | three answers by `If-Match` form, identical for both URLs and both verbs: `*` → **400** `server_error` `Internal Server Error (500) - The server encountered an unexpected condition which prevented it from fulfilling the request`; a concrete tag → **412** `precondition_failed`; absent → the row-4/6 400 |
| 10 | `GET`/`PUT`/`DELETE` an rsid owned by another resource owner | **404** `not_found`, `Resource set does not exist with id <id>` — the same answer as a nonexistent id, for all three verbs. Never 403 |
| 11 | an unmapped verb | `OPTIONS`, `PROPFIND` → **405** `{"error":"unsupported_method_type"}` + **`Allow: POST, PUT, GET, DELETE`**. ⚠ `PATCH` is **not** unmapped — see below |
| 12 | `POST` with `Content-Type: text/plain` / `application/xml` / absent | **201** in all three. The media type is ignored entirely; only an unparseable body fails, with **400** `bad_request` `A JSONObject text must begin with '{' at 1 [character 2 line 1]` |
| 13 | cache headers, every verb, 2xx **and** 4xx | **none** — no `Cache-Control`, `Pragma` or `Expires`, on 201/200/304/400/404/405/412/401 |
| 14 | `Content-Type` | bare **`application/json`** on 200, 201, **204**, 400, 401, 404, 405 and 412. Two exceptions: the 304 sends **none**, and row 7's in-band 400 sends `;charset=UTF-8` |
| 15 | `HEAD` on the item and both collection forms | **200**, `application/json`, **no `Content-Length`**, headers identical to the same URL's `GET`; the item form carries the `ETag`, the collection forms do not. `HEAD` also honours `If-None-Match` → 304. ⚠ *Body* emptiness is **not** recorded — an HTTP client discards a HEAD entity whatever the server sent, so it is unobservable and no row claims it |
| 16 | `POST` to `/resource_set/{rsid}` | **201** with a **new** `_id`; the rsid in the URL is ignored |
| 17 | `GET /oauth2/resource_set/a/b` | **404 CREST** `{"code":404,"reason":"Not Found","message":"No mapping organization found for organization identifier: /resource_set"}` — no `error` field. Identical with a valid bearer, a bogus bearer and no bearer, so it is raised **before** authentication |
| 18 | `If-None-Match` on `PUT`/`DELETE` | matching → **412** `precondition_failed` (never 304, and the write does not happen); non-matching → falls through to row 4's **400**. ⚠ `If-Match: <current>` **plus** `If-None-Match: <current>` is also **412** — a winning `If-Match` does not stop the second header being evaluated |
| 19 | `If-Match` on a `POST` | evaluated like every other verb: `*` → **201**; a stale tag → **412**, at the collection and item URLs alike. A matching tag at the item URL → **201** with a new `_id` |
| 20 | the same headers at the **collection** URL, whose representation has no tag | stale `If-Match` → **412 carrying the whole id array**, `application/json`, **no `ETag`**; `If-None-Match: *` → **304** (the *opposite* of row 3's item answer, and the only place Restlet's `noneMatch` wildcard is live); `If-None-Match: <concrete>` → 200; `POST` + `If-None-Match: *` → **412**, so the RFC 7232 create-if-absent idiom is refused |
| 21 | `If-None-Match: "<strong form of the weak current tag>"` | **200 on a `GET`, 412 on a `PUT`** — the `checkWeakness` flag is `GET‖HEAD` and genuinely varies. `If-None-Match: W/*` is **not** the wildcard (a `POST` carrying it → 201) |
| 22 | request bodies that are not strict JSON | the parser is **`org.json`, and it is lenient**: single-quoted strings, unquoted keys and a trailing comma all **201**. Duplicate keys are **400** `Duplicate key "name" at 33 [character 34 line 1]`; a top-level array and plain text are **400** with row 12's message. ⚠ Must be measured with a **raw client** — see below |

<a id="as-built-5-e4-rows-18-21"></a>
#### ⚠ Rows 18–22, added 2026-07-29 while planning and building 5c-2 S4

Not part of the original gate. D6 assigned conditional evaluation **per verb** — `If-Match` to
`GET`/`PUT`/`DELETE`, `If-None-Match` to `GET` — and S4 stopped to check that against the oracle before
building a handler around it, because `doConditionalHandle` is verb-independent in the bytecode and the plan's
rules were not. **Every one of rows 18–21 contradicts the per-verb model**, and row 21 contradicts a
claim [the S1 review itself introduced](#-corrected-in-review-same-day--two-divergences-both-from-reading-the-parser-and-not-the-comparator)
(that `GET`/`HEAD` are the only verbs reaching the `noneMatch` comparison, so its weakness flag is constant).

**Row 22 arrived later and from a different question** — a review challenge to the handler's body parsing
(*"why not simply use Jackson?"*), which turned out to be a wire contract on five inputs rather than a style
choice. See the [S4 as-built](#as-built-s4). ⚠ It is also the row that exposed the Playwright body-encoding
trap now recorded in [test-infrastructure](../../test-infrastructure.md#gotchas-that-have-actually-bitten):
written with the usual `request.post`, it asserted the **test client's** behaviour and read as a clean 400
for three requests the server really answers 201 to.

Measured against `openam-e2e:5c1` — the image the 5c-1 gate built from this tree, with Restlet still serving
`/oauth2`, so it is the same oracle `:5e4` was. `npx playwright test oauth2 uma` on a **freshly recreated**
container: **99 passed** (94 + these 5), no existing row edited.

⚠ **Recreating the container was necessary, and the failure that forced it is the one the
[fresh-container note](#run-this-gate-against-a-fresh-container) predicts.** After ~40 resource sets had
accumulated, `warmUpResourceSetStore` began failing every create with
`400 {"error":"server_error","error_description":"Internal Server Error (500) - …"}` — which is incidentally a
third independent sighting of the row-9 rule below. `docker restart` does **not** clear it (the orphaned
policies are in the store, not in memory); recreating both containers from the existing image does, and costs
~3 minutes because no Maven or `docker build` is involved. The recipe is
[`.github/workflows/build.yml`'s `build-docker` leg](../../test-infrastructure.md#running-layer-4-locally-against-a-war-built-from-your-tree)
run against an image that already exists.

<a id="the-runtime-exception-rule"></a>
#### ⚠ Row 9's real mechanism: **any** runtime exception is a 400 `server_error`

Traced at S4, because the port has to reproduce it deliberately. Row 9's
`Internal Server Error (500) - The server encountered an unexpected condition which prevented it from
fulfilling the request` is not a message this endpoint produces. `store.read(null, owner)` throws a raw
runtime exception, Restlet wraps it as `ResourceException(Status.SERVER_ERROR_INTERNAL, cause)` — whose
`getMessage()` formats as `"<reason> (<code>) - <description>"` from the **status**, since no description was
given — and `ExceptionHandler.toOAuth2RestletException`'s `else` then does `new ServerException(throwable)`,
i.e. **400 `server_error`** with that string ([finding 4](phase-5c-research.md#4--the-512-throw-never-reaches-the-wire-as-512)).

⇒ **on this endpoint, every non-`OAuth2Exception` throwable is a 400 `server_error`**, and the description is
the generic 500 sentence unless the throw site supplied one (D4's two `ResourceException(512, …)` throws are
the case that does). `AbstractOAuth2HttpJsonEndpoint` deliberately lets an unexpected throwable fall to the
framework's CREST 500, so the CHF handler must catch `RuntimeException` itself and rethrow
`ServerException(<that exact sentence>)`. **Decided 2026-07-29: reproduce.** Row 9 is already in the oracle,
the alternative costs an e2e edit plus a divergence row at 5d-1, and the guard is six lines.

### `If-Match` parsing — the actual specification for [D6](phase-5c.md#d6)'s helper

Every line of this table is asserted by **row 1b**, each against a freshly read tag (a successful `PUT` moves
it, so a shared fixture would make every line after the first assert a stale tag). ⚠ It was prose only in the
first draft of this as-built, which was a real gap: Restlet's parser dies at the flip, so a `HttpConditions`
that 412s on garbage, or that cannot parse a comma list, would have gone green at 5d-1 with nothing left to
check it against.

| Header | Outcome | Why it matters |
|---|---|---|
| `*` | **match** | what every existing e2e row uses |
| `W/"<current>"` (verbatim) | **match** | the round trip a well-behaved client performs |
| `"<current>"` (strong form of the same tag) | **match** | weakness is ignored on both sides of the comparison |
| `W/"nope", W/"<current>"` | **match** | comma lists are parsed; position does not matter |
| `W/"<current>", W/"nope"` | **match** | |
| `W/"nope",W/"<current>"` (no space) | **match** | |
| `W/"nope", W/"nope2"` | **412** | |
| `""` (a quoted empty string) | **412** | it parses as a *tag*, so it reaches the comparison and loses |
| `<current>` **unquoted** | **treated as ABSENT** → the row-4 400 | ⚠ |
| the header present but empty | **treated as ABSENT** → the row-4 400 | ⚠ |
| `!!!` | **treated as ABSENT** → the row-4 400 | ⚠ |

⚠ The last three are the trap. An unparseable `If-Match` does **not** 412 — Restlet's parser drops what it
cannot read, the match list comes out empty, and `isConditionalRequest()` (`:301-303`) then reports *"no
`If-Match` at all"*. So a garbage header and a missing header are indistinguishable on the wire, and a
`HttpConditions` that returned "present but unmatched" for garbage would 412 where live Restlet 400s.

### What this gate found that the plan had wrong

Six corrections, all wire-visible. Every one of them would have shipped as a silent behaviour change.

1. ⚠ **`PATCH` is a working full update, not a 405.** The plan's row 11 predicted the framework's 405. Restlet
   routes `PATCH` to the `@Put` method: it 200s and really replaces the resource set (verified by reading it
   back — `scopes` went from `["read","write"]` to `["read"]`). `Endpoints.from` maps only
   `{DELETE, GET, POST, PUT}`, so **the port turns a working update into a 405**. This is a divergence, and
   arguably a fix, but it is not the port's to make silently. The 405 *shape* the row was written for is real
   and was recorded off `OPTIONS`/`PROPFIND` instead.
2. ⚠ **The 400's `error_description` carries the Restlet exception's formatted message**, not the endpoint's
   string: `"precondition_failed (512) - Require If-Match header to update Resource Set"`, i.e.
   `"<reason> (<code>) - <description>"`. [D4](phase-5c.md#d4) proposed throwing
   `ServerException("Require If-Match header to update Resource Set")`, which would drop the
   `precondition_failed (512) - ` prefix — a byte change on a path the existing e2e already exercises. The
   general rule this exposes, and the one the port should encode: **every non-`OAuth2Exception` throwable on
   this endpoint reaches the wire as 400 `server_error` with `error_description` = the Restlet
   `ResourceException`'s formatted message.** Row 9's collection case is the same rule with a different
   message ([finding 4](phase-5c-research.md#4--the-512-throw-never-reaches-the-wire-as-512) had the mechanism right and the
   string wrong).
3. ⚠ **The 304 carries the `ETag`.** The plan predicted the opposite — *"expected to carry no `ETag`"* — and
   asked for the absence to be recorded. It carries the validator and omits `Content-Type`. And
   `If-None-Match: *` answers **200**, where RFC 7232 §3.2 asks for 304.
4. ⚠ **The collection with `If-Match: *` is a 500-derived 400, not a 404.** The plan predicted
   `store.read(null, owner)` → `NotFoundException` → 404
   ([finding 6](phase-5c-research.md#6--rsid-the-three-attachments-and-the-list-vs-read-split)). It is
   `Internal Server Error (500) - …` wrapped into the row-4 400 shape. The *reasoning* — that `*` lets the
   conditional layer pass and a concrete tag does not — held exactly.
5. ⚠ **Media types are not enforced at all, so [finding 3](phase-5c-research.md#3--three-error-producers-one-endpoint--and-only-one-of-them-is-the-endpoint)'s
   predicted NPE never fires on this path.** `text/plain`, `application/xml` and a missing `Content-Type` all
   create a resource set. [D7](phase-5c.md#d7)'s third outcome is the one that happened: accept, no divergence, and the
   `@Consumes` question ([C1](phase-5c.md#framework-items-openam-http-is-ours)) is answered — there is nothing to
   reproduce, so deleting the dead annotations costs no parity.
6. ⚠ **Row 17's answer is right and its reasoning was wrong.** The CREST 404 is not Restlet's router: the
   extra segment is read as a **realm** by the layer above the OAuth2 router
   (`No mapping organization found for organization identifier: /resource_set`), and it fires **before the
   protection filter** — a bogus bearer changes nothing. [D9](phase-5c.md#d9)'s conclusion stands (the error filter
   belongs on the handler, not around the router) and is now pinned by an oracle that also constrains the CHF
   chain from answering 401 there.

Two further facts no planned row asked for. Both were prose in the first draft of this as-built and are now
asserted, for the reason row 1b exists: prose does not survive the flip.

- **A labels-less `PUT` wipes the labels.** `updateLabelsForExistingResourceSet` is driven from the request
  body, so an update that does not resend `labels` deletes them — changing the `GET` body *and*, since
  labels are in the hash, the `ETag`. **Asserted in row 2a**; the first draft argued it needed no test
  because the logic is ported verbatim, which is precisely the assumption this gate exists to distrust.
- **`If-Match` on a `GET`** behaves like a conditional read: `*` → 200; a stale tag → **412 carrying the full
  representation and the `ETag`**. **Asserted in row 3b.** A handler that consults `If-Match` only on
  `PUT`/`DELETE` answers 200 here — a silent 412 → 200 change with no oracle left to catch it.

### The gated decisions, settled

| Decision | Gated on | Outcome |
|---|---|---|
| [D3](phase-5c.md#d3) | row 12 | **stands, but row 12 did not exercise it.** Media types never reach producer B's `else`, so the `else` branch's 500/`server_error` mapping is still untested by observation. Rows 4/6/9 show the *equivalent* path through producer **A** landing on 400 `server_error`, which is what the filter's table should be read against |
| [D4](phase-5c.md#d4) | rows 4, 6 | **stands with correction 2** — the thrown message must carry the `precondition_failed (512) - ` prefix, or an expected-divergence row is owed |
| [D5](phase-5c.md#d5) | row 5 | **confirmed verbatim.** `W/"<signed decimal>"`, weak, on POST/PUT/GET; no tag on the list. The dead `!isDefined(LABELS)` branch stays reproduced, unexercised as [finding 18](phase-5c-research.md#18--the-extension-point-sees-a-description-without-labels-and-without-an-id) established |
| [D6](phase-5c.md#d6) | rows 1, 1b, 2a, 2b, 3, 3b | **confirmed on the central claim, amended four times.** Restlet does the matching; the helper's real spec is the `If-Match` table above. D6 has been edited in place for all four: unparseable-is-absent, `noneMatches` must not honour `*`, the 304's headers, and `If-Match` on a `GET` |
| [D7](phase-5c.md#d7) | row 12 | **resolved to the third outcome** — Restlet accepts any media type; accept it, no divergence, no 415 path to build |
| [D9](phase-5c.md#d9) | row 17 | **confirmed**, with correction 6's mechanism |

[Finding 17](phase-5c-research.md#17--the-conditional-comparison-tag-comes-from-the-read-model-labels-and-all) is no longer a
hazard argued from source: row 2b **demonstrates** it. A port that hashes the bare `store.read` result, or
that hashes the client's `labels` rather than the store's, passes the matching-order case and fails the
opposite-order one. That is the mutation check R-5c.11 asked for, available before a line of the handler exists.

<a id="the-label-order-is-not-sorted"></a>
#### ⚠ …and the label order is **not** sorted — it is per-JVM

The first draft of this as-built said the store returns labels *sorted*. It does not, and a port that
implements sorting emits ETags Restlet never emitted. The real mechanism, from source:

- `UmaLabelsStore.query` returns a **`new HashSet<>()`** (`:256-278`);
- `ResourceSetLabel.hashCode()` (`:98-104`) mixes in `type.hashCode()`, and `LabelType` is an **`enum`**, so
  that term is `Object`'s **identity** hash — a fresh value on every JVM start;
- `readResourceSet` (`:235-245`) copies the names out in **set-iteration order** and Jackson serialises the
  list as-is.

⇒ the order is stable *within* a container and can **flip when it restarts**. Verified rather than reasoned:
the same two labels read back `["alpha","beta"]` before a `docker restart openam-idp` and `["beta","alpha"]`
after it, on the same data.

Two consequences, and the second is a genuine incumbent defect:

1. **Any row that hard-codes an order is a coin flip per restart.** Row 2b therefore *discovers* the store's
   order first and drives both directions off it, and row 5 uses an **unlabelled** resource set so its
   POST-tag-equals-GET-tag assertion holds unconditionally. Both were hard-coded in the first draft and both
   would have failed on the very next container start.
2. **A restart silently invalidates every cached ETag for a resource set with ≥ 2 labels** — `List.hashCode`
   is order-sensitive, so the tag changes although nothing about the resource set did. Reproduced for free by
   a port that hashes the read model, and worth a post-migration ticket in its own right; it is not something
   the port introduces or can fix without changing the tag.

<a id="run-this-gate-against-a-fresh-container"></a>
### ⚠ Run this gate against a **fresh** container — and why the teardown cannot be trusted

Found while acting on a review comment about the describe leaking resource sets. The teardown that was
supposed to fix it reports, on a freshly built container after one full run, something like:

```
[5-E4] teardown: 3/31 deleted; 28 could not be removed (statuses 400, 404)
[5-E4] teardown: 4/32 deleted; 28 could not be removed (statuses 400, 404)
```

(two consecutive fresh-container runs — the totals move by one or two because a few rows race the client
rewrite described below; the *undeletable* count does not move, which is the point.)

The 404s are rows that deleted their own fixture. The **400s are the endpoint refusing to delete its own
resource sets**, and the cause is in the server, not the test:

- `UmaResourceSetRegistrationHook.resourceSetCreated` / `resourceSetDeleted` resolve the client's UMA
  **resource type**, and throw `EntitlementException: Resource Type <id> does not exist in realm /` when it
  has been replaced (45 occurrences in `debug/UmaProvider` after one run);
- the shared fixtures rewrite the OAuth2 client on **every** run — `ensureClient` is an unconditional full
  `PUT`, deliberately (*"a client left over from an earlier revision of these fixtures … would otherwise
  survive"*) — which mints a new resource-type id and orphans the policies of every resource set created
  before it;
- `resourceSetCreated` throws **after** `store.create` has persisted the row, so a *failed* create still
  leaves a resource set behind. The owner's list grows while `POST` answers 400.

⇒ two practical consequences:

1. **Run the suites in ONE pass against a freshly built container** — `npx playwright test oauth2 uma`, or the
   unqualified `npx playwright test` CI's `build-docker` leg uses. Playwright runs spec *files* in parallel,
   so a single pass is fine: **94 passed** (83 + 11) that way, repeatedly. What does *not* work is running
   them **sequentially** against the same container: `oauth2` then `uma` fails `uma`'s
   `warmUpResourceSetStore` with `Internal Server Error (500)`, and further runs degrade until every
   `POST /oauth2/resource_set` answers 400. Reproduced four times here, and the cause of two intermediate gate
   runs in this step going red for reasons that had nothing to do with the rows. ⚠ If a `uma` row fails right
   after an `oauth2` run, rebuild the container before believing it.
2. **The teardown mitigates, it does not guarantee.** It is kept because deleting a handful is better than deleting 0
   and because it *reports* — a teardown built on `deleteResourceSet` (which swallows every error) made the
   describe look tidy while removing nothing, which is how the leak survived a first fix.

⚠ The underlying behaviour is a **product** defect worth a ticket independent of this migration: rewriting an
OAuth2 client makes every resource set registered against it permanently undeletable through its own API, and
the endpoint reports that as a 400 `server_error`. 5c reproduces it for free — the hook call is ported
verbatim — so it is neither introduced nor fixed here.

<a id="exit-criterion-2-map"></a>
### Exit criterion 2 — every 5-E4 row mapped to a CHF-side assertion (2026-07-30)

The oracle dies at the flip, so a recorded row with no port-side test is a measurement that expires unused.
Mapping all **25** rows found **18 already covered**, **2 exempt**, and **7 with no CHF assertion at all**.

| Row | CHF-side assertion |
|---|---|
| 1 stale `If-Match` → 412 | `anUpdateWithAStaleIfMatchIsABare412`, `aDeleteWithAStaleIfMatchDeletesNothing`, IT `aStalePreconditionIs412WithTheFiltersBody` |
| 1b `If-Match` parsing | 18 `HttpConditionsTest` rows |
| 2a matching `If-Match` round trip | `anUpdateWithAMatchingIfMatchAnswers200AndTheNewTag`, IT row 13 |
| **2b POST tag vs store label order** | **new** — `theCreatesEtagGoesStaleWhenTheStoreReadsTheLabelsBackInAnotherOrder` |
| 3 `If-None-Match` → 304 + ETag | `aGetWithAMatchingIfNoneMatchIs304CarryingTheEtagAndNoBody` |
| 3b GET honours `If-Match` | `aGetWithAStaleIfMatchIs412CarryingTheRepresentationAndTheEtag` |
| 4 PUT without `If-Match` | `anUpdateWithoutIfMatchIs400ServerErrorCarryingRestletsFormattedMessage` |
| 5 ETag shape | `ResourceSetRegistrationHandlerTest:468,719`; `aListAnswersTheIdsAndNoEtag` |
| 6 DELETE without `If-Match` | `aDeleteWithoutIfMatchIs400WithTheDeleteWording` |
| 7 duplicate name | `aDuplicateNameIsAnInBand400CarryingAReasonPhraseAndTheOneCharset` |
| **8 validator rejections verbatim** | **new** — `aValidatorRejectionPassesThroughAsItsOwnBadRequest` |
| 9 collection write, three answers | `aConditionalWriteOnTheCollectionGivesRow9sThreeAnswers` |
| **10 another owner → 404** | **new** — `anotherOwnersResourceSetIs404NotFoundAndNot403` |
| 11 405 `unsupported_method_type` | IT `anUnmappedVerbKeepsTheResourceSetVocabularyThroughBothFilters` |
| **12 media type ignored** | **new** — `theRequestsMediaTypeIsIgnoredEntirelyAndOnlyTheBodyCanFail` (body half already covered) |
| **13 no cache headers** | **new** — `noResponseOnThisEndpointCarriesACacheHeader` |
| 14 bare `application/json` | `theRewrittenBodyIsBareApplicationJson` + the 204 and duplicate-name rows |
| 15 `HEAD` | ⚠ **exempt** — [handed to 5d-1](#handed-to-5d-1) |
| 16 POST at item URL | `anUnconditionalPostAtAnItemUrlDoesNotReadThatResourceSet` |
| 17 router 404 | ⚠ **exempt** — [handed to 5d-1](#handed-to-5d-1) |
| **18 `If-None-Match` on DELETE** | **new** — `aDeleteWithAMatchingIfNoneMatchIs412AndDeletesNothing` (PUT half already covered) |
| 19 POST is conditional | `aCreateIsConditionalToo` |
| **20 POST + `If-None-Match: *`** | **new** — `aCreateWithAWildcardIfNoneMatchIs412BecauseTheCollectionHasNoTag` (GET halves covered) |
| 21 weakness by verb | `aGetWithTheStrongForm…`, `anUpdateWithTheStrongForm…`, 5 `HttpConditionsTest` rows |
| 22 `org.json` leniency | `theBodyParserIsLenient…`, `aDuplicateKeyIsRejected…`, `anUnparseableBodyIs400…` |

All seven new rows passed on the first run — they characterise a handler that was already correct. **1281
surefire** (was 1274), 38 failsafe, and the handler is byte-identical to `cfc213ae11`.

⚠ **The mutation check earned its keep, on my own test.** Two mutations were run against the new rows:
dropping the `If-None-Match` arm of the precondition gate killed rows 18 and 20 (plus two existing rows), but
**sorting labels on create — the one "fix" R-5c.11 forbids —
survived row 2b's first draft**, because the fixture posted `["alpha","beta"]`, which is *already sorted*, so
the mutation was a no-op against it. The row asserted both tags and still could not see the thing it existed to
catch. Fixed by making the client's order descending (`["zeta","alpha"]`) against the store's ascending one;
the mutation now dies on the exact assertion. **A characterisation row that passes first time proves nothing
until a mutation kills it** — and the fixture, not just the assertion, decides whether it can.

### Handed to 5d-1

**Four** items 5c records and cannot close. They belong in the flip's checklist, not in a 5c gate:

1. **Row 15 — `HEAD`.** 200 today, 405 after the flip, on **all 15** ported endpoints, not just this one
   ([finding 13](phase-5c-research.md#13--head-is-served-by-restlet-and-405d-by-chf--and-it-is-not-a-5c-problem),
   [C3](phase-5c.md#framework-items-openam-http-is-ours)). Decide once, for all of them, before the flip — afterwards
   there is no oracle left to ask.
2. **Row 17 — the pre-authentication CREST 404.** No 5c class produces it; only the assembled 5d-1 route can
   be checked against it.
3. **`PATCH`** — new, from correction 1. Same shape as `HEAD`: a verb Restlet serves and `Endpoints.from`
   does not. Unlike `HEAD` it is **not** Phase-5-wide — it matters wherever a `@Put` exists, which on the
   ported surface is this endpoint alone.
4. **The `Allow` header on a 405 disappears.** Verified in `openam-http`: `Endpoints.from`'s unmapped-verb
   branch builds `new Response(Status.METHOD_NOT_ALLOWED)` with a CREST entity and **no `Allow`**, and nothing
   downstream adds one — whereas Restlet sends `Allow: POST, PUT, GET, DELETE` (row 11). RFC 7231 §6.5.5 makes
   `Allow` **mandatory** on a 405, so this is a spec regression, not a cosmetic one, and it is
   **Phase-5-wide** like `HEAD`: every ported endpoint 405s some verb. ⚠ [D3](phase-5c.md#d3) keeps the 405 *body*
   identical, so a body diff at the flip shows nothing — the header is the entire divergence. Row 11 asserts
   the header is present *before* asserting its contents, so this reports as a missing `Allow` rather than as
   a `TypeError`. **Fix (two lines, beside the `HEAD` one) or record; owner 5d-1.**

Rows 15 and 17 are the two the whole-phase exit criteria exempt from needing a CHF-side assertion. Row 11's
`PATCH` half joins them: it is recorded here and answered there.
