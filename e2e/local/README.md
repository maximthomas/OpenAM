<!--
  The contents of this file are subject to the terms of the Common Development and
  Distribution License (the License). You may not use this file except in compliance with the
  License.

  You can obtain a copy of the License at legal/CDDLv1.0.txt. See the License for the
  specific language governing permission and limitations under the License.

  When distributing Covered Software, include this CDDL Header Notice in each file and include
  the License file at legal/CDDLv1.0.txt. If applicable, add the following below the CDDL
  Header, with the fields enclosed by brackets [] replaced by your own identifying
  information: "Portions copyright [year] [name of copyright owner]".

  Copyright 2026 3A Systems, LLC.
-->

# Local OpenAM instance for the e2e suite

A configured OpenAM serving the XUI built by **this working tree**, for `e2e/` to target.

The container topology, the configurator input and the seeded `demo` user mirror the
`build-docker` job in `.github/workflows/build.yml`. That is deliberate: a green run here should
predict a green run in CI. When that job changes, change `lib.sh` and `openam-up.sh` with it.

The XUI migration (`modernize-openam-ui-build`) uses this instance as its regression oracle — the
Playwright suite has to produce the same result against a Grunt-built and a Vite-built `/XUI`, so
the instance and the UI build are deliberately swappable independently of one another.

## Two backends, and which to reach for

This directory stands up two backends, and they are good at opposite things (design.md D13). Both
serve the same XUI build, and the suite picks between them at the point of a test run rather than
in the UI — see [Running the suite](#running-the-suite-against-either-backend).

| | Deployed AM | Local API server |
|---|---|---|
| Start | `./openam-up.sh`, from here | `npm run local-server`, from `e2e/` |
| Ready in | 3–8 minutes cold, ~2 minutes warm | a second or two |
| Needs | Docker, ~3 GB, the war build, an `/etc/hosts` entry | Node ≥18.2, and a built XUI to point at |
| Base URL | <http://openam.example.org:8080/openam> | <http://127.0.0.1:8090/openam> |
| Runs | all 57 XUI tests, in 12 spec files | the 23 tagged `@local-server`, in 5 of those 12 |
| Reset | `./openam-reset.sh`, ~2 minutes | `POST /local-api-server/reset`, milliseconds |
| Detail | [Bring it up](#bring-it-up) | [The local API server](#the-local-api-server) |

**The container is trustworthy and slow; the local server is fast and only as true as we keep it.**
The container runs a real AM, so a green run against it means something — and the failure modes this
suite exists to catch (a broken runtime template fetch, a mis-aliased module ID, a theme that stops
applying) are only observable end to end. The local server answers a recorded subset of AM's REST
surface out of an in-memory state machine whose rules are *ours*, and they can be wrong in ways no
capture diff will catch.

So: **develop against the local server, sign off against the instance.** Making the fast one
authoritative would hollow out the regression suite within a release; making the slow one the only
option means the suite gets run rarely, which hollows it out just as effectively. The acceptance
gate does not move — the migration's task 10.1 requires the phase-0 suite green against a Vite-built
XUI *deployed to this instance*, and no `@local-server` run satisfies it.

**There are two backends, not three.** The local server can also proxy its XUI half to a Vite dev
server for live reload, which is a shorter inner loop *on* that backend rather than another thing to
be green against — see [Live reload against a Vite dev
server](#live-reload-against-a-vite-dev-server). It serves unbundled dev modules that no deployment
ever receives, so it sits one step further from the oracle than the row above already does, and the
suite is not run against it at all.

## Prerequisites

- Docker running, and roughly 3 GB free for the AM container.
- The `/etc/hosts` entry AM needs — it will not run on a bare hostname, because it has to set a
  cookie domain:

  ```
  echo '127.0.0.1 openam.example.org' | sudo tee -a /etc/hosts
  ```

- The build artifacts, from the repo root:

  ```
  mvn -DskipTests install
  ```

  `openam-up.sh` names the three it needs if any is missing.

## Bring it up

```
cd e2e/local
./openam-up.sh
```

Roughly 3–8 minutes cold: image build, container start, configurator, `ssoadm` setup, demo user.
Subsequent runs reuse the cached image layer and take about 2 minutes.

| | |
|---|---|
| XUI | <http://openam.example.org:8080/openam/XUI/> |
| admin | `amadmin` / `ampassword` |
| end user | `demo` / `changeit` |

Then, once — to install the suite and its browser:

```
cd ..
npm install
npm run setup            # on Linux: npm run setup -- --with-deps
```

`--with-deps` installs the system libraries Chromium needs; without them on a bare Linux box the
browser is downloaded but fails to launch. macOS does not need it.

To run the suite:

```
npm run test:xui
```

`npm run test:e2e` in `openam-ui/openam-ui-ria` runs the same command, for when you are working in
the UI module rather than here — it still needs the one-time install above, since it delegates to
this project. `.github/workflows/xui-e2e.yml` runs the suite in CI against an instance brought up
by the script above, so this path is the one that stays exercised.

## Reset between runs

**Use `./openam-reset.sh`.** It tears both containers down and brings them back up, so the
instance returns to exactly its post-configuration baseline. Both containers run with `--rm` and
hold no volumes, so stopping them destroys their state — there is no residue to miss. Takes about
2 minutes, since the image layer is already cached.

Reset when:

- a test failed partway through and may have left a realm, service or user behind;
- you changed the war (`openam-up.sh` rebuilds the image);
- you are about to record a baseline result that has to be trustworthy.

You do **not** need a reset between ordinary green runs. The specs create their fixtures under
unique names and remove them in teardown, so a clean run leaves the instance as it found it.
The reset exists because a *failed* run makes no such promise.

There is intentionally no faster partial reset. A snapshot-and-restore of `$OPENAM_DATA_DIR`
would shave a minute off, at the cost of a reset that is only as complete as the snapshot — and
the one thing this instance exists to provide is a baseline you can trust.

The local API server has its own reset, and that one *is* fast enough to run between individual
tests — see "Reset between tests" below. It resets that server and nothing here; the two backends
share no state.

## Getting a built XUI

(For the inner loop there is a third option that needs no artifact at all: `--dev-server` proxies the
XUI to a running Vite dev server, so there is no zip to build and nothing to unpack. It is for
editing source, not for judging a build — see [Live reload against a Vite dev
server](#live-reload-against-a-vite-dev-server).)

Both backends serve the same artifact — `xui-deploy.sh` copies it into the container, the local
server unpacks it — and producing it needs neither a container nor the war. The
`mvn -DskipTests install` in [Prerequisites](#prerequisites) is the war build, which the container
needs and this does not; the UI module on its own is enough:

```
cd ../../openam-ui/openam-ui-ria
mvn -o -DskipTests package
```

**35–40 seconds** against a warm `~/.m2`, producing `target/openam-ui-ria-<version>-www.zip` — the
path both `xui-deploy.sh` and `npm run local-server` default to when given no argument, so the two
backends serve the same bytes without being told to.

Three things about it were measured rather than assumed, and each one bites:

- **`npm run build:grunt` alone cannot produce it.** (This was `build:production` until the Vite
  migration's task 4.1; that name now runs `vite build`, and the Grunt pipeline described here moved
  to `build:grunt`.) Grunt composes `target/XUI` out of two
  directories Maven writes at `process-resources`, and `grunt-contrib-copy` ignores a missing source
  silently — the build fails later, in `requirejs:compile`, having quietly dropped the entire
  `org/forgerock/commons` tree and all 47 vendor libraries. The zip itself is `maven-assembly-plugin`
  at `package`, which Grunt never reaches.
- **On a cold `~/.m2` you need `-am`**, from the repo root — `mvn -pl openam-ui/openam-ui-ria -am
  -DskipTests package`. The ~58 `commons.ui.libs` artifacts are published nowhere and exist locally
  only because `maven-external-dependency-plugin` fetched them from CDNs, and that plugin does not
  run for `openam-ui-ria` alone. Without `-am`, a build failure at 110 s; with it, 355 s and a build.
- **Never run `clean` on `openam-ui` or with `-am`** — `clean-external` deletes those same
  CDN-provisioned artifacts *from `~/.m2`*. `rm -rf openam-ui/openam-ui-ria/target` instead.

[NOTES-xui-build.md](NOTES-xui-build.md) has the measurements, the CI caching, and one shortcut:
the `-www.zip` is **published**, and `curl`-ing the current snapshot takes **2.78 s** against the
35–40 s above — §4(a) has the URL and how to resolve the current timestamped name. Use it when you
just need a servable XUI. It is built from upstream `master`, not from your working tree, so it is
the wrong answer the moment you have local XUI changes — and it cannot be used for the
Grunt-versus-Vite comparison this migration exists to make.

## Swapping the deployed XUI

```
./xui-deploy.sh                  # the built openam-ui-ria-<version>-www.zip
./xui-deploy.sh path/to/www.zip
./xui-deploy.sh path/to/outDir   # e.g. a Vite build directory
```

Replaces `/XUI` inside the running container — no war rebuild, no Tomcat restart. The XUI is
static content, so a redeploy really is just a file copy.

This is how the migration compares builds: run the suite against the Grunt output, deploy the
Vite output, run the identical suite again. It is also how the specs that need a file to exist in
the *deployed* tree work — a theme template override, or an operator-supplied module named by
`AppConfiguration`.

`xui-deploy.sh` replaces rather than merges, so nothing from the previous build survives. Run
`./openam-reset.sh` afterwards to get back to the war's own XUI.

## Recording the capture for the local backend

```
./openam-reset.sh                         # first — record from a reset instance, never a used one
node capture.mjs                          # writes ./capture
node capture.mjs --out /tmp/capture-b     # somewhere else, e.g. to diff two runs
```

Drives this instance through every request in [REQUESTS.md](REQUESTS.md) and records what it
answers, so the local backend serves shapes a real AM produced rather than shapes somebody guessed.
A realm or service a spec run left behind becomes a permanent phantom in the baseline the local
server is built from, which is what the reset is for.

Four documents govern it, and they are worth reading before changing anything:

| | |
|---|---|
| [capture/README.md](capture/README.md) | The recorded tree itself: the re-record procedure and its flags, the layout, and what each of the 48 calls is for. Read it *instead of* the capture — that is 160 KB of JSON, and three SMS schema documents are over half of it. |
| [REQUESTS.md](REQUESTS.md) | The scope. A request absent from it is out of scope by construction, and the tool refuses to run unless every in-scope row is covered and no extra one is. |
| [NOTES-volatility.md](NOTES-volatility.md) | Why the output is byte-identical across runs and across rebuilds. Sixteen rules, each one something AM was measured to vary. |
| [capture-lib/manifest.mjs](capture-lib/manifest.mjs) | The capture order, the request bodies, and the reason for each. The order is load-bearing — several calls only answer what they answer because of what ran before them. |

The run creates a realm named `e2e-capture`, uses it, and deletes it. It removes one an earlier
failed run left behind before it starts, and it ends every session it opened even when it fails, so
re-running it is safe. It needs Node 20 or later.

Two runs against an unchanged instance produce identical trees; `diff -r` between them is the check
that the normalisation rules still hold. If that diff is not empty, the instance changed — which is
the signal, not a bug in the tool.

## The local API server

The second backend: the XUI and the AM REST surface on one origin, and no AM at all. Run from
`e2e/`, not from here:

```
npm run local-server                     # serves the built openam-ui-ria-<version>-www.zip
npm run local-server -- path/to/www.zip  # serves some other zip
npm run local-server -- path/to/outDir   # serves a directory, e.g. a Vite build

npm run local-server -- --dev-server http://127.0.0.1:5173   # live reload; see below
```

Those are `xui-deploy.sh`'s three inputs, deliberately — the artifact you point at this server is
the artifact you deploy to AM, not something assumed to match it, and with no argument both resolve
the same default zip. [Getting a built XUI](#getting-a-built-xui) is where that comes from. A zip is
unpacked to a temp directory, which is removed when the server stops; nothing is cached between runs.

**Port 8090, context `openam`** — so both surfaces sit under `/openam/`, the path they occupy on the
instance above:

| | |
|---|---|
| XUI | <http://127.0.0.1:8090/openam/XUI/> |
| REST | `http://127.0.0.1:8090/openam/json/` — the administrative reads, authentication, sessions, the bootstrap's configuration, realm and service administration, and the user profile; 501 for the rest |
| RESET | `POST http://127.0.0.1:8090/local-api-server/reset` — back to the baseline. Not an AM path, deliberately; see below |

Ready in about a second, from a checkout, with no war build and no container runtime — which is the
entire point of it, against the 3–8 minutes and the Docker daemon the instance above needs. It is
what the inner loop and the pull-request checks run against.

Both surfaces sit under one context because the XUI has no configurable backend URL: `Constants.host`
is `""` and the context is derived from `location.pathname`, so it asks whatever origin served it,
under the path it was served from. That is what lets one build run against either backend unmodified.

`--port`, `--context`, `--host` and the zip or tree each override their default, as do `OPENAM_LOCAL_PORT`,
`OPENAM_LOCAL_CONTEXT`, `OPENAM_LOCAL_HOST` and `OPENAM_LOCAL_XUI`. `--dev-server`
(`OPENAM_LOCAL_DEV_SERVER`) is the one that is *not* independent of the others: it replaces the zip
or tree rather than joining it, so it cannot be given with `--xui` or with a positional path, and
both spellings on one command line are refused at startup rather than resolved by a precedence
nobody would guess. Any context is accepted but
`local-api-server`, which is the control prefix in the table above and is refused at startup rather
than left to shadow both AM mounts. Port 8090 avoids both 8080 (the
AM container) and 8081 (`sp.mycompany.org` in the SAML specs), so this and the instance above can run
at the same time — comparing them is the point. `node local/server.mjs --help` lists the rest.

The REST surface answers the administrative reads — realms, the global REST service, and a realm's
authentication configuration and service instances, plus the SMS schema and template documents the
console generates its forms from. They come from an in-memory baseline built at startup out of
`local/capture/`, not from replaying it, which is what lets a write show up in the next read.

It answers realm administration whole: create, read, update and delete, plus the
`realm-config/authentication` PUT the console pairs every realm save with — creating a realm through
the form is two writes, and the console treats a failure of the second as a failed create. A realm
created through the console is in the next listing and a deleted one is gone from it.

And it answers service administration on the same terms: create, read, update and delete over a
realm's service instances, beside the schema and template documents above. Two things about it are
worth knowing before reading the code. A realm the console creates is **seeded with
`policyconfiguration`**, because that is what the capture recorded a freshly created realm holding.
And `_action=getCreatableTypes` — the list the create form's type selector is built from — is
**recomputed on every call** from what the realm currently holds, never cached and never served from
the recording: AM drops a type from it once the realm has an instance, and a server that returned a
fixed list would let a service left behind by one test change what the next one is offered. Its
sub-schema routes are not served, and are not scheduled to be; see `NOTES-sms.md`.

It also answers the authentication exchange: the credential requirements, the submission, and the
session cookie a completed authentication sets. The credentials are the suite's own — whatever
`OPENAM_USERNAME` / `OPENAM_ADMIN_USER` and their passwords resolve to, so this server and the specs
cannot disagree about who can log in. The cookie is **host-only**: it carries AM's `Path=/` and
`SameSite=Lax` but not its `Domain`, which names the recording deployment and which a browser would
reject here. See `NOTES-auth.md` for the whole exchange.

And it answers the rest of that session's life: `users?_action=idFromSession` and the `sessions`
collection's `getSessionInfo` and `logout`. A session resolves from the `tokenId` parameter, the
session cookie or the `iPlanetDirectoryPro` header, **any one of them alone** — the cookie by itself
is what a reloaded page has, and it is all it needs. Logout invalidates the token server-side and
clears no cookie, because AM clears none either.

And it answers the two documents the XUI fetches while starting up: `GET /json/serverinfo/*`, which
is AM's *site configuration* under a name that does not say so, and `GET /json/serverinfo/version`
for the console footer. The first is the only request gating the XUI's initialisation, and it is
where the UI learns the session cookie's name, its locale, and which optional features to present —
the self-service links, social sign-in, KBA. Every value is served as recorded except `domains`,
which is `[]` so the cookie stays host-only, matching the `Set-Cookie` above. `NOTES-siteconfig.md`
is the enumeration of what the UI reads from it and what each value changes.

And it answers two calls that are not realm administration but that no console spec can run without:
the fixtures' one-call header authentication — `X-OpenAM-Username` / `X-OpenAM-Password` on
`/json/authenticate`, which is how every Playwright fixture provisions — and `GET
/json/realms/root/users/<admin>`, the profile read whose `roles` are what get a logged-in browser off
`#login`.

That profile is now a resource in its own right — the administrator's and the end user's, read and
updated, so an edit saved through the console is what the next read answers with. Two things about it
are worth knowing before reading the code. **`roles` is virtual**: it is on the document when the
session reading it is the account being read, and the key is absent when it is not, which is exactly
how the capture recorded the two of them and what decides whether a browser lands in the console or
on `#profile`. And **a save merges rather than replaces**, because the console PUTs only the five
attributes its form owns. Password change, KBA and self-registration are not served and are not
scheduled to be. The update does carry rules neither the request list nor the capture settled — what
an empty array means, what an unrecognised attribute may do — and each is written down at the point
that enforces it, in `state.mjs` and `rest.mjs`.

Everything else answers a labelled 501, deliberately: a stub that let the XUI past something it had
not actually done would make the real thing, whenever it is built, unverifiable.

**A browser bootstraps, logs in, lands in the admin console and drives realm and service
administration — and an end user logs in and edits their own profile.** Five spec files carry
`@local-server` and run against this backend end to end: `xui-cache-busting` (2 tests),
`xui-login` (4), `xui-profile` (3), `xui-realms` (7) and `xui-services` (7) — 23 of the XUI suite's
57 tests. [PARITY.md](PARITY.md) is the record of that lane run against both backends on the same
build, and of the one test in it that is flaky on either.

### What this backend does not cover

The other seven XUI spec files are `@deployed-am` only, and a `--grep @local-server` run does not
run them. Each is on that list because reproducing what it asserts here would mean reimplementing
the thing under test, or because it reaches a surface this server does not have at all:

| Spec | Tests | Why it is deployed-AM only |
|---|---:|---|
| `xui/xui-httponly.spec.mjs` | 3 | The worked example (D16): it asserts the session cookie's `HttpOnly` attribute and AM's server-side session-upgrade fallback. Reproducing that would mean reimplementing the behaviour under test, so a green run would prove only that both sides were written to agree. |
| `xui/xui-auth-chains.spec.mjs` | 9 | Drives `/realm-config/authentication/*`, which is outside this server's scope by construction — its request list is what the phase-0 specs cause, and these endpoints are reached only from `@deployed-am` specs. |
| `xui/xui-auth-modules.spec.mjs` | 7 | The same endpoints, the same reason. |
| `xui/xui-authorize.spec.mjs` | 5 | The consent screen is delivered by AM's `/oauth2/…/authorize`, not from the XUI tree; rendering it means running AM's own OAuth2 request validation, consent decision and token issuance. |
| `xui/xui-device.spec.mjs` | 3 | The device pages come from AM's `/oauth2/device/user`; reaching them means AM issuing a user code, storing it, resolving the owner's session and authorizing the device. |
| `xui/xui-theming.spec.mjs` | 5 | Writes a theme and a template override into the *deployed* webapp with `docker exec` and asserts they are served from disk (`common/deployed-xui-commons.mjs`) — the question is what an operator can do to a deployed instance, which interception would answer by assuming it. |
| `xui/xui-operator-module.spec.mjs` | 2 | The same mechanism: it drops an operator-supplied module into the deployed `/XUI` and asserts the loader reaches it by ID. |

That is 34 of the 57 XUI tests. `oauth2/` and `saml/` are `@deployed-am` too, for the reason the two
OAuth2 specs above are.

Two further gaps are not spec-shaped, and matter more than the list:

- **The capture pins response *shapes*, not AM's *semantics*** (D15). The state machine's rules are
  ours, and they can be wrong in ways the drift job cannot see — a validation AM enforces and this
  server does not, an ordering AM guarantees and this one invents. Both re-record identically.
- **Everything outside the surface above answers a labelled 501**, deliberately. The named absences
  are the SMS sub-schema routes ([NOTES-sms.md](NOTES-sms.md)), password change, KBA and
  self-registration; none is scheduled.

### Live reload against a Vite dev server

> **The transport is in place; the UI cannot boot under it yet.** The application source is still
> AMD until the migration's groups 5 and 6 land, so a Vite dev server cannot serve a running XUI
> today and the recipe below will not give you a working page. What is finished, and tested, is the
> proxying — read *What is proved today* at the end of this section before you spend time on it.

The XUI half of this backend, served by a Vite dev server instead of from a built tree, so a source
edit shows up in the browser without a package-and-deploy cycle. The REST half is unchanged and
still comes from `capture/`.

**Two terminals, and the order matters.** This server does not start Vite — see below for why.

```
# terminal 1, from openam-ui/openam-ui-ria
npx vite --base=/openam/XUI/ --port 5173

# terminal 2, from e2e/
npm run local-server -- --dev-server http://127.0.0.1:5173
```

**`base` must be `/{context}/XUI/`, with the trailing slash, and it must agree with `--context`.**
That is not cosmetic and it is not negotiable (design.md D14). `Constants.host` is `""` and
`Constants.context` is derived from `location.pathname`, so the XUI asks whatever origin served it,
under the path it was served from — it has no configurable backend URL to point elsewhere. `base` is
what every asset URL Vite generates is prefixed with, so a dev server on `/` emits `/@vite/client`
and `/src/…`, which are under neither mount here and get the 404 that names all three surfaces: the
document loads and not one module does. If you run this server with `--context am`, the `base` has
to be `/am/XUI/` to match.

Note that `vite.config.js`'s own `base` is `./` for the *build*, deliberately, so that one built tree
works under whatever context path serves it. The two differ and must; pass `--base` on the dev
server's command line rather than editing the config, or the build breaks.

**The path is forwarded whole, in both directions, query included** — no rewriting, because `base`
already is the mount. **`Host` is forwarded unchanged**, which matters more than it looks: Vite's HMR
client builds the socket URL it connects back to out of the host it was served under, so rewriting it
would send the browser's HMR socket straight to 5173 and around this server — a second origin, which
is the thing D14 exists to prevent.

**HMR is a WebSocket, and this server forwards the upgrade** (`node:http`'s `'upgrade'` event, not
the ordinary request path). Nothing about it appears in the request log beyond a single `101` line,
because a log line is written when a *response* finishes and an upgrade has none.

**If `--host` is not a loopback address**, note first that this then relays anything on the network
to the dev server under that one path prefix — the target is fixed at startup from your own flag, so
it is not an open proxy, but it is a door. Vite also applies its own `server.allowedHosts` check to the
host this server forwards, and its default admits IPv4 literals and `localhost` and little else. So
reaching this server by a name — `openam.example.org`, the alias the deployed instance uses — gets a
`Blocked request. This host is not allowed` from Vite, whose message names a Vite option and says
nothing about the proxy. Add the name to `server.allowedHosts` in the dev config.

**Why this server does not start Vite.** It would be one command instead of two, and it would make
the `base`/`--context` disagreement above impossible. It would also make `npm run local-server`
depend on `openam-ui/openam-ui-ria/node_modules` being installed, which it does not today; it would
put Vite's compile errors either interleaved with this server's request log or swallowed entirely;
and it would make an orphaned Vite holding a port after a crash this server's problem. The trade was
taken deliberately in favour of two processes that fail independently and say so.

**Not for judging a build, and not a third backend.** What Vite serves in dev is unbundled source
modules with an HMR client injected — not the artifact any deployment receives, and not the artifact
task 10.1 signs off. There is no `@dev-server` spec tag, no npm script that runs Playwright against
it, and no row of its own in [the table above](#two-backends-and-which-to-reach-for), on purpose:
each of those would let a green run against it read as evidence about a build. Point the suite at a
built tree — [Running the suite](#running-the-suite-against-either-backend).

**What is proved today, and what is not.** The proxy is exercised by
`local/server-lib/dev-proxy.test.mjs` (in `npm run test:server`) against a stand-in origin: the path
and query cross unrewritten, `Host` is forwarded, `/{context}/json/` and the control mount are still
answered locally, the WebSocket upgrade reaches the upstream with its subprotocol and query intact,
and both buffered head buffers survive the hop. **None of that is a running XUI.** The application
source is still AMD until the migration's groups 5 and 6 land, so a Vite dev server cannot boot this
UI yet, and neither scenario of the *Development server with live reload* requirement is exercised:
*Source change visible without redeploying* has its transport but nothing to transport, and
*Templates served in development* — a template fetched by path, with a theme override — is not
addressed here at all. The 229 runtime templates and the locale JSON are not in the module graph, so
serving them is a `publicDir`-or-plugin question in `vite.config.js` rather than a proxy question,
and it is still open.

### Reset between tests

```
curl -X POST http://127.0.0.1:8090/local-api-server/reset
```

Milliseconds, against the two minutes `./openam-reset.sh` costs on the container — which is what
makes this one usable *between individual tests* rather than only between runs. **They are not
alternatives.** `openam-reset.sh` destroys and rebuilds two containers and resets nothing in this
process; this rebuilds this process's in-memory state and resets nothing in those containers. Run
the one belonging to the backend you are pointed at. It answers
`{"reset": true, "realms": 1, "milliseconds": …}`, and the process keeps running: the port, the URL
and the unpacked XUI are all untouched, so nothing that was pointed at this server has to be pointed
at it again.

**What it does is throw the whole in-memory state away and build a new baseline from `capture/`,
exactly as startup does.** Nothing is enumerated and nothing is cleared in place, which is why
"leaves no residue" is a property of the mechanism rather than a list to keep current: realms,
services, profiles, sessions and half-finished writes all go together because they are all reachable
only from the object being replaced, and the rebuild re-reads the capture from disk rather than
reusing a parse the discarded state may have written into. A write that a test began and never
finished is gone for the same reason a completed one is, which is the case a teardown cannot cover —
a test that fails partway does not run its own cleanup.

Sessions go too. A browser left holding a session cookie is then in the position it would be in
after any other reset of a backend: the session it names no longer exists and the XUI returns it to
the login page. Log in again after a reset, as a test would.

**It is not an AM route, and its name says so.** No deployed AM answers `/local-api-server/reset` and
no spec that is also valid against a deployed instance may call it. It sits outside `/openam/json/`
so that it cannot be read, in a request log or in a spec, as an AM call that a real instance had
somehow failed to serve — and every call to it is logged, since a reset changes the meaning of every
line after it.

**This backend is not the acceptance oracle.** A green run against it does not satisfy sign-off; that
needs the suite green against a deployed AM — see
[Running the suite](#running-the-suite-against-either-backend).

```
npm run test:server      # the server's own unit tests, from e2e/
```

## Running the suite against either backend

The backend is chosen outside the UI, at the point a run is pointed at one — `Constants.host` is
`""` and the context comes from `location.pathname`, so one build runs against either unmodified.
From `e2e/`:

```
npm run test:xui                                    # the deployed instance: 57 tests, 12 files

OPENAM_BASE_URL=http://127.0.0.1:8090/openam \
  npx playwright test xui/ --grep @local-server     # the local server: 23 tests, 5 files
```

**The suite is not run against `--dev-server`.** There is no tag for it and no script that does it.
Dev-mode assets are unbundled source modules with an HMR client in them, so a green run there would
be further from acceptance than a `@local-server` run, not closer — it would be a claim about a
thing no deployment contains. Point a run at a built tree, in either of the two forms above.

`OPENAM_BASE_URL` defaults to `http://openam.example.org:8080/openam` — the instance above — in
`common/openam-commons.mjs`. `--grep @local-server` is the whole selection: what a spec declares is
what runs (D16), and the tag is on its `test.describe`. Those two forms are what
`.github/workflows/xui-e2e.yml` and `.github/workflows/xui-local-server.yml` run.

**What a filtered run's summary means.** The second form's `23 passed` is the same shape as a full
run's green line, and nothing in Playwright's own output says the other nine spec files were never
collected. What says so is the block `common/backend-tag-reporter.mjs` prints after the summary,
headed `Backend coverage (D16)`: `filter`, the tag filter this run applied; `ran`, *5 of 14 spec
files, 23 tests*; and `NOT RUN`, naming the other nine with a reason each — here all nine are
*excluded by the tag filter*, being the seven above plus `oauth2/` and `saml/`, none of which
carries `@local-server`. The first form's block instead reports those last two as *not selected by
this run's paths*, since it applies no tag filter and asks only for `xui/`. It also names any spec
file declaring no backend tag at all, since no tag-filtered run will ever execute one. It never
changes the exit status: an undeclared spec is loud, not blocking.

**A CLI `--reporter` replaces the config's reporter list rather than adding to it** (verified on
Playwright 1.60), so a bare `--reporter=line` silently drops that reporter — and with it the only
output that says what did not run. Append it instead:

```
--reporter=line,./common/backend-tag-reporter.mjs
```

This has been got wrong twice, once in a CI job and once in a set of parity runs. Both times the
run was green and said nothing about its own scope.

**One red result is known and open, on both backends.** `xui/xui-login.spec.mjs:123` — *logout ends
the session and protected routes return to the login form* — fails intermittently and has never been
root-caused: 3 of 6 gated runs against the deployed instance ([xui/BASELINE.md](../xui/BASELINE.md)),
5 of 10 against the local server, and 1 of 2 in the parity runs ([PARITY.md](PARITY.md)). It tracks
run duration rather than backend, so it being red is not evidence that you broke something — check
whether it is the only failure, and run it again. It is deliberately neither retagged nor skipped: a
flaky spec quietly moved off a lane is the shrinking suite D16 exists to prevent.

**A green run against the local server is not sign-off.** It means the `@local-server` specs pass
against the local server. The migration's task 10.1 requires the phase-0 suite green against a
Vite-built XUI deployed to the instance above, and this is the sentence that stops a fast green run
being read as acceptance.

## Tear down

```
./openam-down.sh
```

## Troubleshooting

Tomcat's stdout:

```
docker logs openam-idp
```

AM's own diagnostics — where a stack trace actually lands — are files under the configured data
directory, not stdout:

```
docker exec openam-idp find /usr/openam -maxdepth 4 -type d -name debug
docker exec openam-idp cat /usr/openam/config/openam/debug/CoreSystem
```

If `openam-up.sh` reports the container never became healthy, that is Tomcat failing to start;
`docker logs openam-idp` is the place to look.

**Every XUI request 502s, under `--dev-server`.** Nothing is answering at the origin you named. Vite
is not up yet — start it first — or it is on a different port than you told this server: a busy 5173
makes Vite increment silently, so read the port off its own banner rather than assuming. The 502 body
names the origin it tried and the error code.

**The page loads under `--dev-server` but nothing reloads.** The HMR WebSocket is not connecting.
Check that Vite's `base` is `/{context}/XUI/` with the trailing slash and agrees with `--context`;
check for a `101` line in this server's log when the page loads, whose absence means the upgrade
never arrived; and if `--host` is not a loopback address, check Vite's `server.allowedHosts` — its
refusal names a Vite option and not this proxy.

**Assets 404 under `--dev-server` while the document loads.** Vite's `base` and this server's
`--context` disagree, so every generated URL is prefixed with a path this server does not serve. It
looks like a broken build and is a mismatched flag.
