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
| REST | `http://127.0.0.1:8090/openam/json/` — the administrative reads; 501 for the rest, until tasks 2.7–2.13 |

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
`local/capture/`, not from replaying it, so a write will show up in the next read once tasks
2.10–2.12 add the writes.

Everything else answers a labelled 501, deliberately: a stub that let the XUI past the login form on
invented responses would make the real authentication in tasks 2.7–2.13 unverifiable. So
authentication, sessions, `serverinfo`, every write and reset are still 501, and until they land you
need the deployed instance above to run a spec that logs in.

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
