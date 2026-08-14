# The recorded AM capture

A recording of a real AM answering every request the phase-0 Playwright specs cause the XUI to
issue. It is the source of the local backend's response *shapes* — see D15: the server initialises
in-memory state from this tree and mutates it, rather than replaying these files.

**Read this document instead of the capture.** The tree is 160 KB of JSON and three SMS schema
documents are 56 % of its payload bytes; opening them to answer a structural question is the
expensive way to learn what is written here.

- Recorded by [`../capture.mjs`](../capture.mjs), from the request list in
  [`../REQUESTS.md`](../REQUESTS.md).
- The rules that make a re-record byte-identical are in [`../NOTES-volatility.md`](../NOTES-volatility.md),
  implemented in [`../capture-lib/normalise.mjs`](../capture-lib/normalise.mjs).
- The review that admitted this tree to version control is in
  [`../NOTES-capture-review.md`](../NOTES-capture-review.md).

## Re-recording

```bash
cd OpenAM/e2e
./local/openam-reset.sh      # ~2 minutes; returns the instance to its post-configuration baseline
node local/capture.mjs       # writes local/capture/
```

**Record from a reset instance, never from one a spec run has touched.** A realm or service a test
left behind becomes a permanent phantom in the baseline the local server is built from.

Flags: `--out DIR` (default `local/capture`), `--base-url URL` (default `$OPENAM_BASE_URL`, else
`http://openam.example.org:8080/openam`), `--realm NAME` (default `e2e-capture`).

Two consecutive recordings against an unchanged instance are byte-identical, which is what task
2.15's drift job asserts. The run is re-runnable rather than one-shot: it removes a realm an earlier
failed run left behind, and ends every session it opened even when it throws.

The tool deletes only what it generates — `index.json` and `json/` — so this README survives a
re-record. Do not add other files here expecting the same; the rule is derived from the recorded call
paths, not from a keep-list.

The rules themselves are unit-tested, stdlib only, no new dependency:

```bash
npm run test:capture      # node --test local/capture-lib/*.test.mjs
```

## Layout

```
capture/
  README.md                      # this file; not generated
  index.json                     # metadata and capture order; no response bodies
  json/<resource path>/<METHOD>[.<discriminator>].json
```

**48 calls → 48 payload files, one-to-one, no collisions.** Directories mirror the REST path, with
two substitutions:

- `*` → `star`, because `*` is a legal AM path segment and an illegal filename on some platforms
  (`/json/serverinfo/*` → `json/serverinfo/star/`).
- The realm segments become the literal directory names `{realm}` and `{realmId}`.

The filename is the HTTP method, then zero or more dot-separated discriminators, then `.json`:

| Discriminator | Example | Used for |
|---|---|---|
| `action=<name>` | `POST.action=schema.json` | the `_action` query parameter |
| `queryFilter=true` | `GET.queryFilter=true.json` | a `_queryFilter` listing |
| `resource=<x.y>` | `GET.resource=1.0.json` | two API versions of one request |
| numeric status | `GET.404.json` | a deliberately recorded negative case |
| semantic tag | `POST.success.json` | several successes on one path |

### Directories keep `{realm}`; the payload inside resolves it

The one thing about this layout that surprises people, and it is deliberate. A **directory name is a
route** — the local server has to answer requests for realms the specs invent at run time under
unique names, so a tree keyed on the one realm this capture used would answer none of them. The
**envelope inside is a transcript** — it records what was actually sent to produce this exact
response, which is what makes the recording auditable rather than merely plausible.

So `e2e-capture` and its base64url id `L2UyZS1jYXB0dXJl` appear literally inside the payloads: in
every `request.path`, in `request.query.realm`, in the realm CRUD bodies' `_id` / `name`, in
`aliases[0]` (`e2e-capture-alias`), and in the 404 message `Realm cannot be read: /e2e-capture`.
`index.json`'s `pathPlaceholders` records what they stood for. **A consumer that re-records under a
different `--realm` and expects the payload contents to follow will be wrong.**

### Envelope

Every payload file:

```json
{
  "request":  { "method", "path", "query", "acceptApiVersion", "session", "body" },
  "response": { "status", "headers", "body" }
}
```

Request headers are deliberately **not** recorded. That is the structural reason the admin password
cannot leak — it travels in `X-OpenAM-Username` / `X-OpenAM-Password`. The request is recorded at all
because the response shape sometimes depends on it: `GET /json/serverinfo/*` returns `_id` and `_rev`
only when no `Accept-API-Version` is negotiated.

Only 11 response header names survive anywhere: `connection`, `content-type`, `keep-alive`,
`x-frame-options` (48 each), `cache-control`, `content-api-version` (47), `transfer-encoding` (44),
`expires`, `pragma`, `set-cookie` (3 each), `location` (1).

### `index.json`

`{rules, placeholders, pathPlaceholders, callCount, calls[48]}`. Each call is
`{order, id, file, method, path, query, acceptApiVersion, session, status, row, note}` — `row` is the
`REQUESTS.md` row it satisfies, `note` is prose quoting that document.

**The order is load-bearing.** The authenticate exchange is stateful; realm-scoped requests need the
realm to exist; the `404` probes only answer `404` before their create; and `PUT users/demo`
permanently adds a `modifyTimestamp` key to every later `GET`. Replaying these in a different order
does not reproduce them.

## Size

**163 778 bytes, 49 files** — 136 411 bytes across 48 payloads plus a 27 367-byte `index.json`.
Largest payload: `json/global-config/authentication/POST.action=schema.json`, **29 044 bytes**.

## Resource types

`V` = verbatim-servable: pure static description, byte-identical whatever the server's state.
`S` = stateful: the server has to model something to answer it.

| # | Resource | Kind | Calls | Largest | V/S |
|---|---|---|---|---|---|
| 1 | `/json/serverinfo/*` | singleton, 2 API versions | 2 | 1 256 B | **V** — identical body under `resource=1.0` and `1.1` |
| 2 | `/json/serverinfo/version` | singleton | 1 | 664 B | **V** |
| 3 | `/json/authenticate` (legacy, realm-less) | action | 1 | 983 B | **S** — mints a session |
| 4 | `/json/realms/root/authenticate` | action | 3 (callbacks · success · 401) | 1 824 B | **S** — callback-chain state |
| 5 | `…/users?_action=idFromSession` | collection action | 3 (401 anonymous · 2× 200) | 790 B | **S** — depends on the session |
| 6 | `/json/realms/root/users/{id}` | collection member | 3 (`amadmin` GET · `demo` GET+PUT) | 1 940 B | **S** — PUT then GET must agree |
| 7 | `/json/sessions` | action | 2 (`getSessionInfo` · `logout`) | 882 B | **S** — session lifecycle |
| 8 | `/json/global-config/services/rest` | singleton | 2 (GET · schema) | 2 338 B | GET **S** · schema **V** |
| 9 | `/json/global-config/realms` (+ `/{realmId}`) | **collection**, full CRUD | 9 | 1 544 B | schema+template **V** · other 7 **S** |
| 10 | `/json/global-config/authentication` | singleton | 2 (schema · template) | **29 044 B** | **V** |
| 11 | `…/realms/{realm}/realm-config/authentication` | singleton per realm | 5 | 23 988 B | schema **V** · GET/PUT **S** |
| 12 | `…/realm-config/services` | collection listing | 3 | 3 051 B | listing **S** · `getCreatableTypes` **see below** |
| 13 | `…/realm-config/services/baseurl` | **singleton** service, full CRUD | 10 | 2 105 B | getAllTypes+schema+template **V** · other 7 **S** |
| 14 | `…/realm-config/services/dashboard` | singleton | 2 (schema · template) | 983 B | **V** |

**15 verbatim-servable calls, 93 347 bytes (68 % of payload bytes) · 33 stateful calls, 43 064 bytes
(32 %).** Static description is two thirds of the capture by size and under a third by count: the SMS
schema documents are enormous and everything stateful is small.

The verbatim set is exactly: every `_action=schema` (7), every `_action=template` (4),
`_action=getAllTypes` (1), and the three `serverinfo` responses.

### Two findings that matter for implementing the server

1. **The realm-config authentication schema is realm-independent.** The root-realm and created-realm
   schema documents differ *only* in `request.path` — 23 969 vs 23 988 bytes, the 19-byte path
   difference and nothing else. One stored document answers both. The *global*-config authentication
   schema is a genuinely different, larger document.
2. **`getCreatableTypes` is realm-path-independent too.** The realm-scoped call and the legacy
   realm-less call returned byte-identical bodies (3 051 B each), differing only in `request.path` and
   the presence of `request.query.realm`.

## Redaction and normalisation

Three categories, kept apart because they answer three different questions. All of them run at record
time — **fix a rule, never a recorded file**, because task 2.15 re-records and a hand edit is lost.

### 1. Volatility — what moves between two identical calls

Fourteen rules, specified by [`../NOTES-volatility.md`](../NOTES-volatility.md), measured across two
passes on one instance and a third on a rebuilt one. Without these a re-record never diffs clean.

| Placeholder | Replaces | Why |
|---|---|---|
| `<TS>` | `latestAccessTime`, `maxIdleExpirationTime`, `maxSessionExpirationTime`, and the `createTimestamp` / `modifyTimestamp` arrays | regenerated per call; `createTimestamp` moves only when the configurator runs, which a two-run diff cannot surface |
| `<TOKEN>` | `tokenId`, and the `iPlanetDirectoryPro=` cookie value | per-session |
| `<AUTHID>` | `authId` | the JWT carrying authentication-chain state |
| `<AUTH-COOKIE>` | the `AMAuthCookie=` value | per-authentication |
| `<SESSION-HANDLE>` | `sessionHandle` | per-session |

Also: `date`, `etag` and `content-length` response headers are dropped outright (`ETag` moves between
calls on a byte-identical body, so it is not a content hash in any usable sense), and **object keys
are sorted recursively while arrays are never sorted** — the schema payloads reorder their
`properties` on every call while staying deep-equal, but listing order was reproduced exactly across a
full reconfigure and is real API signal.

### 2. Secrecy — what may not be committed at all

| Placeholder | Replaces | Why |
|---|---|---|
| `<PASSWORD>` | a `PasswordCallback` input whose value is a password this run authenticated with | AM never echoes a credential back, but the login the capture performs fills a `PasswordCallback` with a working one, and that request body is recorded |

Deliberately narrow on both axes: only a `PasswordCallback` input, and only where the value is a
credential this run actually used. `"not-the-password"` in
`json/realms/root/authenticate/POST.failure.json` is left alone — it is a deliberately wrong string,
and masking it would destroy the negative case.

### 3. Portability — what pins the capture to one box

Every value here was measured **stable** across a full destroy-and-reconfigure, so none of it can
create or hide a re-record diff. It is normalised because the local server serves these shapes under
its own origin, context path and cookie domain, where the recorded values would be wrong.

| Placeholder | Replaces | Where | Why |
|---|---|---|---|
| `{{BASE_URL}}` | the AM origin and deployment URI | `location` header of the realm create | absolute URLs pointing at the recording host |
| `{{HOSTNAME}}` | the AM host's FQDN | root realm `aliases[1]` | the only literal host name AM returns |
| `{{HOST_ALIAS}}` | the host's bare first label | root realm `aliases[0]` | same array, same origin |
| `{{PORT}}` | the port AM was reached on | nowhere in this capture | the base URL rule catches the port only inside a full absolute URL; an authority written without its scheme, or under a different one, would otherwise commit a port the local server does not listen on |
| `{{COOKIE_DOMAIN}}` | the cookie domain | `serverinfo/*` `domains[]`, and the `domain=` / `Domain=` attribute of every `Set-Cookie` | the XUI reads `domains` to decide what domain to write its session cookie for; served verbatim from a local origin it sends the browser after a cookie that can never be set |
| `{{CONTEXT}}` | the servlet context, without its leading slash | `successUrl` / `successURL` (`/{{CONTEXT}}/console`), `fullLoginURL`, and every baseurl `contextPath` | D14 makes the context configurable, defaulting to `openam` |
| `{{CONFIG_SUFFIX}}` | the config store's LDAP suffix | `universalid`, `universalId`, `amadmin`'s `dn` | deployment shape |
| `{{USER_SUFFIX}}` | the user store's LDAP suffix | `demo`'s `dn` | a **different** suffix from the config store's; a rule assuming one suffix silently commits the other |
| `{{SERVER_ID}}` | the AM server id | the `amlbcookie=` value | this container's id; the local server has one of its own |

`<ANGLE>` marks a value removed because it was volatile or secret; `{{DOUBLE_BRACE}}` marks one
removed because it belongs to a deployment. `index.json`'s `placeholders` map lists all of them with
what they stand for — meanings, not the values they replaced, since recording those would put the
host name back into the tree.

The two LDAP suffixes are the one pair of targets that cannot be derived from `--base-url`, so they
are named literally in `normalise.mjs` (matched case-insensitively — a directory echoes back whatever
case its suffix was configured with). `auditPortability` is what makes that safe: after the rules run,
the tool fails the recording on any surviving base URL, host name, port, cookie domain, deployment
URI, `dc=` chain or unmasked server id. A differently-configured deployment stops the tool instead of
committing its directory layout.

**If the audit fails on a `dc=` chain, read the quoted context before changing anything.** That check
is the one that can fire on something legitimate: AM's SMS schemas carry example DNs in their
`description` prose, and widening `REQUESTS.md` in a later task may pull one in. A real suffix means
adding it to `LDAP_SUFFIXES`; AM's own documentation prose means narrowing the check. Stopping to tell
the two apart is deliberate — the alternative is a real suffix committed silently.

### Deliberately **not** normalised

- **The AM version, build revision and build date** in `json/serverinfo/version/GET.json`. They are
  host-bound in the same sense as everything in category 3, and pinning them is how task 2.15 notices
  the instance under test changed. The review measured the revision moving between two image builds,
  so the drift job goes red on a rebuild — a true positive worth a human look, one line in one file,
  and nothing downstream reads them for behaviour.
- **`AMAuthCookie=LOGOUT; Expires=Thu, 01 Jan 1970 00:00:10 GMT`** — a fixed sentinel AM emits to
  clear the cookie, not a timestamp. Replacing it would hide the difference between a login that
  cleared the auth cookie and one that did not. Its `Domain=` attribute *is* normalised.
- **`"cookieName": "iPlanetDirectoryPro"`** — the cookie's name, which the XUI needs. No value.
- **`http://json-schema.org/draft-04/schema#`** in the realms schema — a spec identifier, and the only
  absolute URL left in the tree.
- **`demo`, `demo@example.com`, `Demo Demo`, `amadmin`** — exactly the two seeded accounts. There is
  no third identity anywhere. `admin@example.com` appears only inside the SMS schema's
  `lockoutEmailAddress` description, as AM's own documentation prose.
- **`e2e-capture` / `L2UyZS1jYXB0dXJl`** inside payloads — see the routes-versus-transcripts note
  above.

## Known limits

- ~~**Whether `getCreatableTypes` is state-dependent is not determined.**~~ **Resolved by task 2.11:
  it is.** The capture still holds no evidence either way — both recordings happen *before* the
  `baseurl` create and `"baseurl"` is present in both — but AM's source settles it:
  `SmsRouteTree.handleAction` dispatches the action to `readTypes(context, NOT_CREATED_SINGLETONS,
  forUI)`, whose predicate reads each singleton in the realm and includes the type only when that
  read 404s. So this payload is **stateful, not verbatim-servable**, and the local server recomputes
  it per call rather than serving it (`server-lib/state.mjs`, `realmCreatableTypes`). What the
  recording *is* good for is the catalogue to subtract from: it was taken against a realm holding
  exactly `policyconfiguration`, which is what a freshly created realm holds, so `catalogue − what
  the realm has` reproduces it byte for byte for such a realm. See `../NOTES-sms.md`.
- **The capture pins response shapes, not AM's semantics** (D15). The state machine's rules are ours,
  and can be wrong in ways the drift diff will not catch — a validation AM enforces and we do not, an
  ordering guarantee we invent. This is why the acceptance gate stays on the real instance (D16).
