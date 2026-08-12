# Capture review — first recording of the OpenAM REST API (task 2.3)

What this is: the first real run of `local/capture.mjs` (task 2.2) against a freshly reset
instance, reviewed for anything that must not enter version control, and mapped so that tasks
2.6, 2.10 and 2.11 can read this file instead of the capture. **Nothing was redacted and the tool
was not edited** — the apply prompt does both, so the rules live in the tool.

- Recorded to `/tmp/capture-review/` (left in place for spot-checking; the committed copy is
  placed by the apply prompt).
- Tool log: `/tmp/2.3-capture.txt`. Reset log: `/tmp/2.3-reset.txt`.

## Preconditions and reset

| Check | Result |
|---|---|
| `local/capture.mjs` + `local/capture-lib/` present, `--help` exits 0 | pass (Node v22.20.0) |
| `local/NOTES-volatility.md` present | pass (23901 bytes) |
| `http://openam.example.org:8080/openam` answers | pass (`/json/serverinfo/*` → 200) |
| docker reaches the container | pass (`openam-idp`, health `healthy`) |

`./local/openam-reset.sh > /tmp/2.3-reset.txt 2>&1` ran **before** the recording: exit 0, 391 lines,
ending `Configuration complete!` … `==> creating the demo user` … `==> verifying demo can
authenticate` … `==> ready`. The capture therefore describes a post-configuration baseline
instance with no leftover realm or service.

Then `node local/capture.mjs --out /tmp/capture-review`: exit 0, `REQUESTS.md` coverage satisfied,
`Wrote 48 calls to /tmp/capture-review`, every call at its expected status (the 401s and 404s in
the list are deliberately recorded negative cases, not failures).

**Build drift worth flagging.** `NOTES-volatility.md` recorded revision `8628aba262` /
`2026-August-08 09:56` across its two bringups; this instance reports `fc8e2e67c7` /
`2026-August-04 10:48`. Same `16.2.0-SNAPSHOT`. So the version triple is image-bound and *does*
move between image builds — it is not a constant that a re-record can be diffed against across
machines. Nothing else in the capture differed in a way the review could detect.

## Size

- **162 729 bytes total, 49 files** (all `.json`; 292 KB on disk after block rounding).
- Largest single file: `json/global-config/authentication/POST.action=schema.json` — **29 044 bytes**.
- Next: `index.json` 26 343 · `…/realms/{realm}/realm-config/authentication/POST.action=schema.json`
  23 988 · `…/root/realm-config/authentication/POST.action=schema.json` 23 969 ·
  `…/{realm}/realm-config/authentication/PUT.json` 4 098.
- Split: 136 386 bytes across 48 call payloads + 26 343 bytes of `index.json`.
- Three SMS authentication schema documents are **77 001 bytes — 56 % of all payload bytes**.

## Security review

Method: grep only, never a whole-file read. Sweeps run over the whole tree for token field names,
AM token signatures (`AQIC…`, `AAJTSQ…`, `*…*`), JWT shapes (`eyJ…`), `bearer`/`authorization`,
base64 literals ≥ 24 chars and any `…==` padding, `ampassword`/`changeit`, every key matching
`*password*`/`*secret*`/`*passwd*`/`*credential*`/`*keystore*`, `iPlanetDirectoryPro`,
`example.org`, `8080`, `https?://`, version/revision/date, ISO-8601 and RFC-1123 dates, 10–13
digit epoch integers, container names/IDs (`db250c103c03`, `openam-idp`, `opendj-idp`),
`localhost`/`127.0.0.1`/`172.*`, and `"/usr|/opt|/var|/home|/root|/etc|/tmp|/Users"` paths.

### Verdict: nothing in this capture must be redacted before commit

The tool's `normalise.mjs` already masked every secret the sweeps looked for, at record time:

| Placeholder | Uses | Where |
|---|---|---|
| `<TOKEN>` | 8 | `$.response.body.tokenId`, `$.request.query.tokenId` (index), and the `iPlanetDirectoryPro=` value inside `$.response.headers.set-cookie[0]` |
| `<TS>` | 7 | `$.response.body.{latestAccessTime,maxIdleExpirationTime,maxSessionExpirationTime}`, `$.response.body.{createTimestamp,modifyTimestamp}[0]` |
| `<AUTHID>` | 3 | `$.response.body.authId`, `$.request.body.authId` |
| `<PASSWORD>` | 1 | `$.request.body.callbacks[1].input[0].value` in `json/realms/root/authenticate/POST.success.json` |
| `<AUTH-COOKIE>` | 1 | `AMAuthCookie=` value in `json/realms/root/authenticate/POST.callbacks.json` `set-cookie[0]` |
| `<SESSION-HANDLE>` | 1 | `$.response.body.sessionHandle` in `json/sessions/POST.action=getSessionInfo.json` |
| `{{BASE_URL}}` | 2 | `$.response.headers.location` in `json/global-config/realms/POST.action=create.json`; the declaration in `index.json` |

Confirmed absent, each by an explicit search that returned nothing:

- No `AQIC…` / `AAJTSQ…` / `*…*` AM token, no JWT, no `Bearer`, no `Authorization` header, no
  base64 blob ≥ 24 chars outside ordinary identifier names, no `…==` padding anywhere.
- No `ampassword`, no `changeit`. The admin credentials travel in `X-OpenAM-Username` /
  `X-OpenAM-Password` headers, and **request headers are not recorded at all** — the recorded
  request object is only `{method, path, query, acceptApiVersion, session, body}`. That is the
  structural reason the admin password cannot leak, not just a masking rule.
- No `date`, `etag` or `content-length` response header in any file (dropped at record time), and
  no `_rev` value anywhere. Only 11 distinct response headers survive.
- No epoch integer, no container hostname or ID, no absolute filesystem path from inside the
  container, no `localhost`/loopback/bridge address.

### Judged safe, with the reason (do not "fix" these)

| Value | File / JSON path | Judgement |
|---|---|---|
| `"not-the-password"` | `json/realms/root/authenticate/POST.failure.json` `$.request.body.callbacks[1].input[0].value` | **Safe.** A deliberately wrong string, not a credential. Masking it would destroy the negative case. |
| `"sharedSecret": null` | `…/realm-config/authentication/{GET,PUT}.json` `$.…body.sharedSecret` | **Safe.** Always `null` on a baseline instance; the schema files only declare the property. |
| `"cookieName": "iPlanetDirectoryPro"` | `json/serverinfo/star/GET.resource=1.{0,1}.json` `$.response.body.cookieName` | **Safe.** The cookie *name*, which the XUI needs; no value. |
| `AMAuthCookie=LOGOUT; Expires=Thu, 01 Jan 1970 00:00:10 GMT` | `json/authenticate/POST.json`, `…/authenticate/POST.success.json` `$.response.headers.set-cookie[2]` | **Safe.** A fixed expiry constant AM emits to clear the cookie — masked deliberately only when the value is not `LOGOUT`. |
| `demo`, `demo@example.com`, `Demo Demo`, `amadmin`/`amAdmin` | `json/realms/root/users/{demo,amadmin}/*.json`, `…/POST.action=idFromSession.json` | **Safe.** Exactly the two seeded accounts. No third identity, no real user data anywhere in the tree. |

## Host-specific values — normalise for portability, none are secrets

> **Decision taken in task 2.3, after this review.** Everything in the table below was normalised
> *except* the AM version/revision/build-date triple, which was deliberately left literal so task
> 2.15's drift job still notices the instance under test changed. The row recommending normalisation
> for it is the review's finding, not what was implemented — see `capture/README.md`, "Deliberately
> **not** normalised".

None of these leak anything; all of them pin the capture to this box or this build, so the apply
prompt should turn each into a placeholder. Listed with the JSON path a normaliser has to reach.

| Value | File · JSON path | Judgement |
|---|---|---|
| `openam.example.org` | `json/global-config/realms/GET.queryFilter=true.json` `$.response.body.result[0].aliases[1]` | **Normalise.** The only literal hostname left in the tree; a root-realm DNS alias. |
| `openam` (bare alias) | same file, `…aliases[0]` | **Normalise** with it — same array, same origin. |
| `example.org` (cookie domain) | 11 occurrences total: `json/serverinfo/star/GET.resource=1.{0,1}.json` `$.response.body.domains[0]` (2), the `openam.example.org` alias above (1), and the `domain=`/`Domain=` attribute of every `set-cookie` line in `json/authenticate/POST.json` and `…/authenticate/POST.{callbacks,success}.json` (**8 occurrences over 3 files**) | **Normalise.** Survives inside the cookie attribute string even though the cookie *value* is masked. |
| `16.2.0-SNAPSHOT` / `fc8e2e67c7` / `2026-August-04 10:48` | `json/serverinfo/version/GET.json` `$.response.body.{version,revision,date}` | **Normalise.** Image-bound and demonstrably drifting (see build drift above). The `date` here is a build date, the one date string the timestamp rules do not cover. |
| `/openam` deployment URI | 19 occurrences: `$.…body.successUrl` (`/openam/console`, 6×), `$.…body.contextPath` in every baseurl payload (8×), `$.…body.{gotoUrl,loginUrl}`-style `/openam/UI/Login?realm=%2F` (2×), baseurl template `$.response.body.contextPath` | **Normalise.** Portable only if the deployment URI is. |
| `{{BASE_URL}}/json/global-config/L2UyZS1jYXB0dXJl` | `json/global-config/realms/POST.action=create.json` `$.response.headers.location` | **Already normalised for host, still carries the realm id.** The base URL became `{{BASE_URL}}`; the trailing `L2UyZS1jYXB0dXJl` did not become `{realmId}`. See the placeholder gap below. |
| `dc=openam,dc=openidentityplatform,dc=org` | 6 files · `$.…body.universalid[0]`, `$.…body.dn[0]` (amadmin), `$.…body.universalId`, `$.…body.dn` | **Normalise.** Config-store suffix. Product default, so likely stable, but still deployment shape. |
| `dc=example,dc=com` | `json/realms/root/users/demo/{GET,PUT}.json` `$.response.body.dn[0]` | **Normalise.** User-store suffix — a *different* suffix from the one above; a single rule that assumes one suffix will miss this. |
| `amlbcookie=01` | 3 files · `$.response.headers.set-cookie[1]` | **Normalise.** The server id. `NOTES-volatility.md` measured it stable across bringups, so it is portability-only. |
| Site id | — | **Absent.** No site is configured; nothing to normalise. Confirmed by the sweep, matching `NOTES-volatility.md`. |
| `8080`, any `http(s)://` | — | **Absent.** The only absolute URL in the tree is `http://json-schema.org/draft-04/schema#` in `json/global-config/realms/POST.action=schema.json` `$.…body.$schema`, which is a spec identifier and must stay verbatim. |

### Placeholder gap the apply prompt should decide about

`index.json` declares `pathPlaceholders = {"{realm}": "e2e-capture", "{realmId}": "L2UyZS1jYXB0dXJl"}`,
and those placeholders **are** applied to directory names. They are **not** applied inside file
contents: `e2e-capture` / `L2UyZS1jYXB0dXJl` appear literally **65 times across 25 files** — in
every `$.request.path`, in `$.request.query.realm` (`/e2e-capture`), in
`$.response.body.{_id,name}` of the realm CRUD payloads, in `$.response.body.aliases[0]`
(`e2e-capture-alias`), and in the 404 message `"Realm cannot be read: /e2e-capture"`. This is
consistent (the declaration exists so a reader can substitute), not a defect — but a consumer that
renames the realm via `--realm` and expects the payloads to follow will be wrong.

## Structure map — read this instead of the capture

### Layout and naming

```
/tmp/capture-review/
  index.json                     # metadata only: no response bodies
  json/<resource path>/<METHOD>[.<discriminator>].json
```

- Directories mirror the REST path, with two substitutions: `*` → `star`
  (`/json/serverinfo/*` → `json/serverinfo/star/`), and the realm segments → `{realm}` /
  `{realmId}` literal directory names.
- Filename = HTTP method, then zero or more dot-separated discriminators, then `.json`:
  `action=<name>` (`POST.action=schema.json`), `queryFilter=true`, `resource=<x.y>` for version
  negotiation (`GET.resource=1.0.json` vs `1.1`), the numeric status for negative cases
  (`GET.404.json`, `POST.action=idFromSession.401.json`), or a semantic tag for several successes
  on one path (`POST.callbacks.json`, `POST.success.json`, `POST.failure.json`).
- **48 calls → 48 payload files, one-to-one, no collisions.**
- Each payload file is `{request: {method, path, query, acceptApiVersion, session, body},
  response: {status, headers, body}}`. Request headers are deliberately not recorded.
- `index.json` = `{rules, baseUrlPlaceholder, pathPlaceholders, callCount, calls[48]}`; each call is
  `{order, id, file, method, path, query, acceptApiVersion, session, status, row, note}` where `row`
  is the `REQUESTS.md` row it satisfies and `note` is prose quoting that document.
- Only 11 response header names survive anywhere: `connection`, `content-type`, `keep-alive`,
  `x-frame-options` (48 each), `cache-control`, `content-api-version` (47), `transfer-encoding`
  (44), `expires`, `pragma`, `set-cookie` (3 each), `location` (1).

### Resource types

`V` = verbatim-servable (pure static description, byte-identical whatever the server's state).
`S` = stateful (a fixture server has to model something to answer it).

| # | Resource | Kind | Calls | Largest payload | V/S |
|---|---|---|---|---|---|
| 1 | `/json/serverinfo/*` | singleton, 2 API versions | 2 | 1 250 B | **V** — identical body under `resource=1.0` and `1.1`, both answering `content-api-version: resource=1.1` |
| 2 | `/json/serverinfo/version` | singleton | 1 | 664 B | **V** (build constants) |
| 3 | `/json/authenticate` (legacy, realm-less) | action endpoint | 1 | 949 B | **S** — mints a session |
| 4 | `/json/realms/root/authenticate` | action endpoint | 3 (callbacks · success · 401 failure) | 1 790 B | **S** — callback chain state |
| 5 | `/json/users` + `/json/realms/root/users` `_action=idFromSession` | collection action | 3 (401 anonymous · 2× 200) | 803 B | **S** — answer depends on the session |
| 6 | `/json/realms/root/users/{id}` | collection member | 3 (`amadmin` GET · `demo` GET · `demo` PUT) | 1 965 B | **S** — PUT then GET must agree |
| 7 | `/json/sessions` | action endpoint | 2 (`getSessionInfo` · `logout`) | 905 B | **S** — session lifecycle |
| 8 | `/json/global-config/services/rest` | singleton | 2 (GET · schema) | 2 338 B | GET **S**-ish (config document, read-only here) · schema **V** |
| 9 | `/json/global-config/realms` (+ `/{realmId}`) | **collection**, full CRUD | 9 (list · schema · template · create 201 · GET 404 · GET 200 · PUT · DELETE 200 · DELETE 404) | 1 544 B | schema+template **V** · the other 7 **S** — the 404-before-create / 404-after-delete pair is the whole point |
| 10 | `/json/global-config/authentication` | singleton | 2 (schema · template) | **29 044 B** | **V** |
| 11 | `/json/realms/{realm}/realm-config/authentication` | singleton per realm | 5 (root GET+schema · `{realm}` GET+schema+PUT) | 23 988 B | schema **V** · GET/PUT **S** |
| 12 | `/json/realms/{realm}/realm-config/services` | collection listing | 3 (`_queryFilter=true` · `getCreatableTypes` · same via legacy realm-less path) | 3 051 B | listing **S** · `getCreatableTypes` **undetermined**, see below |
| 13 | `/json/.../realm-config/services/baseurl` | **singleton** service instance, full CRUD | 10 (getAllTypes · schema · template · GET 404 · create 201 · GET · legacy GET · PUT · DELETE · legacy create 201) | 2 105 B | getAllTypes+schema+template **V** · the other 7 **S** |
| 14 | `/json/.../realm-config/services/dashboard` | singleton | 2 (schema · template) | 983 B | **V** |

**Totals: 15 verbatim-servable calls, 93 330 bytes (68 % of payload bytes) · 33 stateful calls,
43 056 bytes (32 %).** The static description is two thirds of the capture by size and under a
third by count, because the SMS schema documents are enormous and everything stateful is small.

Verbatim-servable = every `_action=schema` (7), every `_action=template` (4), `_action=getAllTypes`
(1), and the three `serverinfo` responses.

### Two findings that matter for implementing a server

1. **The realm-config authentication schema is realm-independent.** The root-realm and
   created-realm schema documents differ **only** in `$.request.path` — 23 969 vs 23 988 bytes,
   the 19-byte path difference and nothing else. One stored document can answer both. The
   *global*-config authentication schema is a genuinely different, larger document (485 vs 425
   lines).
2. **`getCreatableTypes` is realm-path-independent too**, in the same way: the realm-scoped call
   and the legacy realm-less call returned byte-identical bodies (3 051 B each), differing only in
   `$.request.path` and the presence of `$.request.query.realm`.

## Not determined

- **Whether `getCreatableTypes` is state-dependent.** In AM it should drop a service type once an
  instance of it exists in the realm, which would make it stateful rather than verbatim-servable.
  Both recordings (orders 29 and 30) happen **before** the `baseurl` create at order 35, and
  `"baseurl"` is present in both. The capture therefore contains no evidence either way. Recorded,
  not worked around. A server that serves this payload verbatim will be right for the recorded
  sequence and possibly wrong for any other.
- **`AM_ENC_KEY` / `am.encryption.pwd`** remains unobservable over REST, exactly as
  `NOTES-volatility.md` concluded. No in-scope response exposed an encrypted value, and this
  review found none either.
- **Whether the `dc=openam,dc=openidentityplatform,dc=org` and `dc=example,dc=com` suffixes are
  install-configurable here.** They look like product defaults, but nothing in the capture proves
  the local configurator could not have been given others.
