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
node capture.mjs                          # writes ./capture
node capture.mjs --out /tmp/capture-b     # somewhere else, e.g. to diff two runs
```

Drives this instance through every request in [REQUESTS.md](REQUESTS.md) and records what it
answers, so the local backend serves shapes a real AM produced rather than shapes somebody guessed.

Three documents govern it, and they are worth reading before changing anything:

| | |
|---|---|
| [REQUESTS.md](REQUESTS.md) | The scope. A request absent from it is out of scope by construction, and the tool refuses to run unless every in-scope row is covered and no extra one is. |
| [NOTES-volatility.md](NOTES-volatility.md) | Why the output is byte-identical across runs. Fourteen measured rules, each one something AM was observed to vary. |
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
```

Those are `xui-deploy.sh`'s three inputs, deliberately — the artifact you point at this server is
the artifact you deploy to AM, not something assumed to match it. A zip is unpacked to a temp
directory, which is removed when the server stops; nothing is cached between runs.

| | |
|---|---|
| XUI | <http://127.0.0.1:8090/openam/XUI/> |
| REST | `http://127.0.0.1:8090/openam/json/` — the administrative reads, authentication, sessions, the bootstrap's configuration, realm and service administration, and the user profile; 501 for the rest, until task 2.13 |

Ready in about a second, from a checkout, with no war build and no container runtime — which is the
entire point of it, against the 3–8 minutes and the Docker daemon the instance above needs. It is
what the inner loop and the pull-request checks run against.

Both surfaces sit under one context because the XUI has no configurable backend URL: `Constants.host`
is `""` and the context is derived from `location.pathname`, so it asks whatever origin served it,
under the path it was served from. That is what lets one build run against either backend unmodified.

`--port`, `--context`, `--host` and the zip or tree each override their default, as do `OPENAM_LOCAL_PORT`,
`OPENAM_LOCAL_CONTEXT`, `OPENAM_LOCAL_HOST` and `OPENAM_LOCAL_XUI`. Port 8090 avoids both 8080 (the
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
not actually done would make the real thing in task 2.13 unverifiable.

**A browser bootstraps, logs in, lands in the admin console and drives realm and service
administration — and an end user logs in and edits their own profile.**
`xui/xui-realms.spec.mjs`, `xui/xui-services.spec.mjs` and `xui/xui-profile.spec.mjs` are the
`@local-server` specs that run against this backend end to end.

**This backend is not the acceptance oracle.** A green run against it does not satisfy sign-off; that
needs the suite green against a deployed AM.

```
npm run test:server      # the server's own unit tests, from e2e/
```

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
