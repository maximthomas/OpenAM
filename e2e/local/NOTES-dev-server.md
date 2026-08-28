# Proxying `/{context}/XUI/` to a Vite dev server, with the Node standard library only

Design notes for task 4.10. **Nothing here is implemented** — this file is the design, written
before the code, and no file under `local/` was edited to produce it.

The constraint that shapes every answer below is the one in `server.mjs`'s header:

> Node standard library only, deliberately: `e2e/package.json`'s single devDependency is the cache
> key for the Playwright browser download in `.github/workflows/xui-e2e.yml`, so a dependency added
> here costs every CI run a browser download.

Confirmed at the time of writing: `e2e/package.json` has exactly one devDependency,
`@playwright/test`. So no `http-proxy`, no `http-proxy-middleware`, no `ws`. Everything below is
`node:http`, `node:net` and `node:url`.

The second constraint is D14
(`openspec/changes/modernize-openam-ui-build/design.md`, *One origin, one path prefix*), which
`server.mjs` restates and which already names this task:

> It serves the XUI two ways: a built tree (a `www` zip or a Vite `outDir`, the same inputs
> `xui-deploy.sh` takes), or a proxy to the Vite dev server for HMR once phase 2 lands. Both
> preserve the path prefix.

---

## 1. The insertion point

### Where the XUI tree is served today

`local/server-lib/router.mjs`, in the handler `createRequestHandler` returns —
`return async function handle (req, res)` at **router.mjs:173**. It dispatches in this fixed order
(router.mjs:181-206):

```
181   const isUnder = (mount) => url.pathname === mount || url.pathname.startsWith(`${mount}/`);
183   if (isUnder(CONTROL_MOUNT))  -> serveControl        // /local-api-server
186   if (isUnder(xuiMount))       -> serveStatic(...)    // /{context}/XUI      <-- HERE
189   if (isUnder(jsonMount))      -> serveRest(...)      // /{context}/json
      if (pathname is "/" | "/{context}" | "/{context}/") -> 302 to `${xuiMount}/`
      otherwise                    -> 404 naming the three surfaces
```

`xuiMount` and `jsonMount` are built at router.mjs:76-77 from the `context` option.

### Where the proxy branch goes

**`local/server-lib/router.mjs`, inside `createRequestHandler`'s returned `handle`, replacing the
body of the `isUnder(xuiMount)` branch at router.mjs:186 — and nothing else.**

```js
if (isUnder(xuiMount)) {
    return devServer
        ? proxyToDevServer(req, res, { devServer, mount: xuiMount, url })
        : serveStatic(req, res, { root, mount: xuiMount, url });
}
```

`devServer` arrives as a new field on `createRequestHandler`'s single options object, beside
`root`, `context`, `state` and `rebuildState`. It is `null` in the ordinary mode, and the resolved
target (`{ protocol, hostname, port }`) in dev-server mode. `root` is `null` in dev-server mode and
`devServer` is `null` otherwise — exactly one of them is set, which is the same mutual exclusion
the flag enforces (§2) restated where it is consumed.

The proxy itself belongs in a new sibling of `static-tree.mjs` — `local/server-lib/dev-proxy.mjs`
— exporting `proxyToDevServer` and the upgrade handler of §4, with `dev-proxy.test.mjs` beside it.
That is the split every other file here already uses (`server.mjs` is the process, `server-lib/` is
what it answers with, and the tests live next to the code).

**There is a second insertion point, and it is not in the router.** The WebSocket upgrade never
reaches `handle` at all — see §4. It is wired in `local/server.mjs`, in `async function serve`
(**server.mjs:182**), as a `server.on("upgrade", ...)` registration immediately after
`const server = createServer(...)` at **server.mjs:217**. Missing this second point is the failure
mode this task's brief specifically warns about, and it is invisible until HMR silently does not
reload.

### What must NOT be proxied, and how the router already distinguishes it

| Path | Must be | Why |
|---|---|---|
| `/{context}/json/...` | answered locally by `serveRest` | It is the whole point of D14. Vite's dev server would treat `/openam/json/...` as a missing static file and 404 it — `NOTES-vite-build.md` §7 says so in as many words. |
| `/local-api-server/...` | answered locally by `serveControl` | Reset is an operation on *this process*. `router.mjs`'s header is explicit that no AM answers it and that its request-log line is what makes a reset legible. |
| `/`, `/{context}`, `/{context}/` | the local 302 to `${xuiMount}/` | A convenience for a human who opened the port. It must behave identically in both modes, or "which mode am I in" becomes something you diagnose from a redirect. |
| everything else | the local 404 that names the three surfaces | `router.mjs`'s header: *"It would be friendlier to proxy the unknown paths to a real AM, and wrong — the local backend's scope is the request list in local/REQUESTS.md, and a silent fallthrough to something else is how that scope stops being true without anyone noticing."* The same argument forbids falling through to Vite. |

**The mechanism that keeps them apart is already there and needs no change:** `isUnder`
(router.mjs:181) matches the mount *exactly* or followed by a slash. Three consequences the proxy
inherits for free:

- `/openam/json` and `/openam/json/...` can never be captured by the XUI mount, because
  `"/openam/json".startsWith("/openam/XUI/")` is false. The two mounts are siblings under
  `/{context}/`, not nested.
- `/openam/XUIsomething` matches *neither* mount and falls to the 404. Verified — §5, assertion 5.
- `CONTROL_MOUNT` is tested **first**, so the reset path is unreachable from the proxy branch
  regardless of what `--context` is. (`--context local-api-server` is separately refused where the
  handler is built, router.mjs:69-73.)

So the proxy branch does not need its own path filter. It needs to be *inside* the existing
`isUnder(xuiMount)` branch and nowhere else. The upgrade handler in `server.mjs` does need its own
copy of the predicate, because it does not go through `handle` — and it must be the *same*
predicate, or the two disagree about `/openam/XUIsomething`. Exporting `isUnder` (or a
`xuiMountFor(context)` + shared predicate) from `router.mjs` is the way to keep one rule.

---

## 2. The flag

### The surface today

`local/server-lib/options.mjs`: `FLAGS = ["--port", "--context", "--host", "--xui"]`, plus
`--help`/`-h`, plus **one** positional (`positional === 0` sets `options.xui`; a second positional
throws). Every setting also has an `OPENAM_LOCAL_*` environment variable, and the documented
precedence is *"Argument beats environment beats default, each setting independently."*

The complication the brief names is real: **the XUI source is already both positional and named.**
`npm run local-server -- path/to/www.zip` and `--xui path/to/www.zip` are the same setting. So a
dev-server flag has to be mutually exclusive with *two* spellings of one setting, not one.

### Proposed surface (option A) — a named flag taking an origin

Add `--dev-server` to `FLAGS`, and `devServer` to `defaults()`:

```js
const FLAGS = ["--port", "--context", "--host", "--xui", "--dev-server"];
// in defaults(env):
devServer: fromEnv(env, "OPENAM_LOCAL_DEV_SERVER") ?? null,
```

**The exact usage line**, in the shape and column alignment `USAGE` already uses:

```
  --dev-server ORIGIN
                    proxy /{context}/XUI/ to a Vite dev server already running
                    at ORIGIN instead of serving a built tree; the REST surface
                    is unaffected. Not usable with XUI or --xui
                    [off]                                  (OPENAM_LOCAL_DEV_SERVER)
```

and the first line of `USAGE` becomes:

```
node local/server.mjs [XUI] [options]
node local/server.mjs --dev-server ORIGIN [options]
```

Two synopsis lines rather than one, because that is what makes the exclusivity readable at a
glance: `[XUI]` appears on the first and not the second.

Typical use:

```
node local/server.mjs --dev-server http://127.0.0.1:5173
node local/server.mjs --dev-server http://127.0.0.1:5173 --context am --port 9000
```

`--port`, `--context` and `--host` keep their exact meanings — they configure *this* server's
socket and mount, not Vite's. Nothing about them becomes ambiguous, because `--dev-server` names a
different machine's origin and always carries a scheme.

### How a wrong combination is rejected

All of it in `parseArgs`, before anything binds. A `throw` there reaches `server.mjs`'s top-level
catch, which prints `error <message>` and sets exit code 1 — the same one-line failure a bad
`--port` gives today, and before the socket, the capture load and any zip unpack.

**(a) Both answers to "what serves the XUI".** The subtlety is that a blanket
"`devServer && xui` → error" would break the documented per-setting precedence: a contributor with
`OPENAM_LOCAL_XUI` exported in their shell could then never use `--dev-server` without first
unsetting it. The rule must be *conflict at the same precedence level*, which needs two booleans
tracked inside the existing parse loop:

```js
let sawXui = false;        // set by the positional branch and by `--xui`
let sawDevServer = false;  // set by `--dev-server`
...
if (sawXui && sawDevServer) {
    throw new Error("--dev-server serves the XUI from a running Vite dev server, and "
        + "XUI / --xui serves it from a built tree. Give one or the other.\n\n" + USAGE);
}
if (sawDevServer) { options.xui = null; }        // an argument beats OPENAM_LOCAL_XUI
if (sawXui) { options.devServer = null; }        // and beats OPENAM_LOCAL_DEV_SERVER
if (options.xui !== null && options.devServer !== null) {
    throw new Error("OPENAM_LOCAL_XUI and OPENAM_LOCAL_DEV_SERVER are both set, and they are "
        + "alternatives. Unset one, or override it with XUI / --xui / --dev-server.");
}
```

The last check is the environment-versus-environment case, which has no precedence to break the
tie and so must be an error rather than a silent pick.

**(b) The value must be an origin.** `new URL(value)` inside a `try`, then require
`protocol === "http:" || protocol === "https:"`, a non-empty `hostname`, and no path beyond `/`
(a trailing slash is tolerated and dropped). Reject a bare port:

```
"5173" is not a dev-server origin. Use http://127.0.0.1:5173.
```

This matters because `5173` is exactly what a contributor will type, and a `new URL("5173")` throws
a `TypeError` whose message says nothing useful.

**(c) It must not point at this server.** A `--dev-server` naming this process's own host and port
is an infinite proxy loop that shows up as memory exhaustion, not as an error. Compare the resolved
`--dev-server` host/port against `options.host`/`options.port` in `parseArgs` and refuse. **Limits,
recorded rather than papered over:** this catches only literal equality — `localhost:8090` and
`127.0.0.1:8090` are the same socket and will not compare equal without name resolution, which
`parseArgs` must not do (it is synchronous and must stay so). And with `--port 0` the bound port is
not known until `listen`. So the string check is a courtesy, and the *complete* answer is a
loop-guard header: the proxy sets a header on every outbound request and refuses any inbound
request that already carries it, with a 508. That is cheap and total; the string check is what
turns the common case into a startup error instead of a runtime one.

**(d) `--dev-server` with a second positional** is already an error today ("Unexpected argument"),
unchanged.

### Alternatives considered, with their costs

| | Surface | Gain | Cost |
|---|---|---|---|
| **A** (above) | `--dev-server ORIGIN` | One new flag. Mutual exclusion is explicit and its error message can say why. Host and port are both expressible, so it survives Vite picking a different port. | The exclusivity rule has to be written and tested; three new rejections. |
| **B** | Overload the XUI source to accept a URL: `npm run local-server -- http://127.0.0.1:5173` | No new flag at all, and exclusivity is free — it is one setting with one value. | `parseArgs` does `options.xui = resolve(options.xui)` unconditionally, which mangles a URL into a path under the cwd; `resolveXuiSource` grows a third input kind; `OPENAM_LOCAL_XUI` becomes two types; the banner's `serving ${source}` line stops meaning one thing. Worst: `server.mjs`'s header states *"What it serves is a `www` zip or a directory — the same two inputs `xui-deploy.sh` takes"* as a load-bearing property, and `xui-deploy.sh` will never take a URL. B makes that sentence false. |
| **C** | `--dev-server` as a boolean + `--dev-server-port N` (default 5173) | Shortest to type in the common case. | Two flags for one setting. A hard-coded 5173 is wrong whenever 5173 was taken and Vite incremented — which is the normal outcome of leaving a previous run open. No way to name another host. |
| **D** | A wrapper script, `"local-server:dev"` in `package.json` | Discoverable from `npm run`. | Not an alternative — it is a wrapper over A, B or C, and a second place that can drift from the flag it wraps. Worth having *after* the flag exists, not instead of it. |

**A is what this note proposes.** B is the tempting one and is rejected on the `xui-deploy.sh`
parity property specifically, not on taste.

### Who starts Vite — the options and their costs. Not decided here.

**Option 1 — the contributor starts Vite separately; the local server only proxies.**

- `server.mjs` stays a pure HTTP process: no `child_process`, no assumption about where
  `openam-ui/openam-ui-ria` sits, no dependence on that module's `node_modules` being installed.
  Today `npm run local-server` works from a checkout with only `e2e/node_modules`; option 2 would
  end that.
- Vite's own output — its startup banner, its transform errors, its HMR log — stays on its own
  terminal, unmixed with this server's one-line-per-request log. A Vite compile error stays
  legible.
- Restarting Vite (a `vite.config.js` edit) does not restart the API server, so the in-memory state
  and every open session survive it, and vice versa.
- Nothing new to clean up on exit or on crash (§7 stays almost empty).
- **Costs:** two terminals and an ordering rule to document. The server can start before Vite is
  listening, and then every XUI request 502s until it is — so the 502 has to be a sentence, not an
  `ECONNREFUSED` stack. Vite's port has to be told to the server by hand and *goes stale silently*
  when Vite increments past a busy 5173. And Vite's `base` and this server's `--context` are set in
  two places by two people and nothing checks that they agree.

**Option 2 — `server.mjs` spawns Vite as a child process.**

- One command, one terminal. The ordering problem disappears: the parent can wait for the child to
  be listening before printing its banner.
- The two disagreements above become impossible by construction. The parent passes
  `--base=/${context}/XUI/` on the child's command line, which is exactly what `vite.config.js`
  already asks for (see §3) — *"must be derived from the same context value e2e/local uses
  (`--context` / `OPENAM_LOCAL_CONTEXT`) rather than hard-coded"* — and it can pass or read back the
  port, so the port cannot go stale.
- **Costs:** process-tree cleanup becomes this server's problem (§7 grows: SIGTERM to the child on
  the abort path, SIGKILL on the second Ctrl-C, and an orphaned Vite holding a port after a parent
  crash, which `node:http` gives no help with). Vite's stdout must be either interleaved with the
  request log or swallowed, and swallowing a Vite compile error is the worst available failure
  mode. And it couples `e2e`'s process model to the UI module's toolchain: `npm run local-server`
  starts failing when `openam-ui/openam-ui-ria/node_modules` is absent, which it does not today.
  (Spawning is itself stdlib, so this does not violate the dependency constraint — it violates a
  weaker but real independence property.)

**Option 3 — a variant, not a third position:** option 1, plus the 502 and the startup probe print
the exact `cd ../../openam-ui/openam-ui-ria && npx vite --base=/openam/XUI/ --port 5173` command to
run. Costs nothing beyond a good error message and removes most of option 1's ergonomic loss. It
does not fix the stale-port problem.

---

## 3. The path prefix

### What Vite's `base` must be

```
base = "/" + context + "/XUI/"          // "/openam/XUI/" for the default context
```

Leading slash, trailing slash, and derived from the same `--context` / `OPENAM_LOCAL_CONTEXT` value
this server mounts under.

**This was read, not derived.** It is recorded in two places in the checkout, and they agree:

- `openam-ui/openam-ui-ria/NOTES-vite-build.md` §7 *What the dev server needs*: *"`base` must be
  `/openam/XUI/` and must end in a slash. It is not cosmetic: it is what every generated asset URL
  is prefixed with, and `Constants.context` is derived from `location.pathname`... Note the context
  is configurable on the local server (`--context`, `OPENAM_LOCAL_CONTEXT`), so `base` should be
  derived from the same value rather than hard-coded, or the two can disagree."*
- `openam-ui/openam-ui-ria/vite.config.js:1160-1171`, in the comment on `base`, which hands this
  task the decision by name: *"4.10 owns the dev-server half, where base DOES have to be the served
  prefix (e.g. `/openam/XUI/`, trailing slash required) and must be derived from the same context
  value e2e/local uses (`--context` / `OPENAM_LOCAL_CONTEXT`) rather than hard-coded."*

**A trap worth stating plainly: the build base and the dev base differ, and must.**
`vite.config.js:1171` is `base: "./"` — relative, deliberately, so the *built* tree works under
whatever context path serves it and the "one build, either backend" property holds. A dev server
cannot use `"./"`; it needs an absolute prefix. So the dev-server base must be set
mode-conditionally (`defineConfig(({ command }) => ...)` with `command === "serve"`, or simply
`--base=` on the CLI, which overrides the config and leaves line 1171 untouched). **Changing line
1171 to `/openam/XUI/` would break the build**, and is the obvious wrong move for anyone who reads
only §3 of this file.

### What the proxy does to the request path

**In both directions: nothing. Byte for byte.**

- **Client → dev server.** Forward `req.url` verbatim — path *and* query. No strip of the mount, no
  rewrite, no re-encoding. Because `base` is already exactly the mount, Vite expects the full
  `/openam/XUI/...` path; stripping it would be correct only if `base` were `/`, and `base` cannot
  be `/` (below).
  - The query is not optional. Two independent reasons. (i) `index.html` configures RequireJS with
    `urlArgs: "v=<build version>"`, so ~38 of 41 URLs on a page carry `?v=...`;
    `static-tree.mjs` handles this by resolving off `URL.pathname` and ignoring `URL.search`, and
    the proxy must instead *preserve* it. (ii) **Vite 5.4.21's HMR WebSocket URL carries a
    `?token=`** and the handshake is refused without it — see §4.
- **Dev server → client.** Relay the status line, the headers and the body unchanged. No `Location`
  rewriting is needed, because Vite's own redirects are already `base`-prefixed. No body rewriting,
  because Vite already emits `base`-prefixed URLs.

### The one header that must be handled deliberately: `Host`

**Forward the client's `Host` unchanged** (`changeOrigin: false` in Vite's proxy vocabulary). In a
`node:http` client request the `Host` header is synthesised from the target unless you set it
explicitly, so this needs a line of code, not the absence of one.

The reason for *this* direction of proxying is stronger than the cookie argument in
`NOTES-vite-build.md` §7 (that one is about Vite proxying to the local server; Vite sets no
cookies). Verified against the installed Vite 5.4.21: the HMR client computes

```js
socketHost = `${__HMR_HOSTNAME__ || importMetaUrl.hostname}:${hmrPort || importMetaUrl.port}${__HMR_BASE__}`
```

so with `Host` rewritten to `127.0.0.1:5173` the browser would open its HMR socket **directly
against Vite on 5173, bypassing the proxy** — a second origin, which is precisely what D14 exists to
prevent, and which then fails or half-works depending on the browser's mixed-origin rules.

**Recorded risk, from the same reading of Vite 5.4.21:** forwarding `Host` unchanged means Vite
sees a host it was not started on, and Vite 5.4.21 has an `allowedHosts` check
(`Blocked request. This host (X) is not allowed. To allow this host, add X to
\`server.allowedHosts\``). Its default (`isHostAllowedWithoutCache`) permits **any IPv4 literal**
and `localhost` / `*.localhost`. So the default `--host 127.0.0.1` passes. But
`--host 0.0.0.0` reached through a *hostname* — `openam.example.org`, the alias the deployed
instance uses — would be 403'd by Vite with a message that reads as nothing to do with the proxy.
The fix is `server.allowedHosts` in the dev config; the point here is that this must be documented,
because the error names a Vite option and the cause is a `--host` on a different server.

### What breaks if the prefix is dropped or rewritten

- **Dropped** (proxy strips `/openam/XUI`, Vite runs with `base: "/"`). The HTML Vite serves
  references `/@vite/client`, `/src/...` and `/node_modules/.vite/deps/...` — all absolute, all
  outside both mounts, all answered by `router.mjs`'s 404, which by explicit design does not fall
  through to anything. The document loads and not one module does.
- **Rewritten to another prefix** (`/XUI/`, or `/`). `Constants.js` derives the context by
  stripping a leading and trailing slash and dropping the last segment, so the UI would compute a
  different REST root and every call would land somewhere `serveRest` never sees. `server.mjs`'s
  header notes that `serverinfo/*` is *"the only request gating `EVENT_APP_INITIALIZED`"* — so the
  UI does not merely misbehave, it never initialises.
- **A base with a file in it** (`/openam/XUI/index.html`). `static-tree.mjs`'s header already
  records this hazard: it derives to `openam/XUI` and addresses every REST call at
  `/openam/XUI/json/...`. A deployed AM behaves identically, so it is the XUI's to own — but a
  mis-set `base` is a new way to reach it.
- **`base` and `--context` disagreeing** (Vite on `/openam/XUI/`, server on `--context am`). Every
  asset 404s and the failure looks like a broken build rather than a mismatched flag. Under option 2
  (§2) this is impossible; under option 1 the server should probe `GET {devServer}{base}` at startup
  and refuse, or at minimum warn, rather than leaving it to be diagnosed from 404s.

---

## 4. The WebSocket upgrade

### Why the ordinary handler cannot do it

`node:http` does not route an upgrade through the request handler. When a request arrives with
`Connection: Upgrade`, the server emits **`'upgrade'` (req, socket, head)** instead — and *if
nothing is listening for that event, Node destroys the socket*. There is no `res`, so nothing in
`router.mjs`'s `handle` can ever see it, and none of `res.writeHead` / `sendText` / `serveStatic` is
available. The observable symptom of omitting it is exactly the one the brief predicts: the page
loads, HMR never connects, the browser retries forever, and nothing in the request log says so
(the log is written from `res.on("finish")`, and there is no `res`).

Registered in `local/server.mjs`, `async function serve` (server.mjs:182), right after
`const server = createServer(...)` (server.mjs:217):

```js
server.on("upgrade", (req, socket, head) => { /* below */ });
```

### What the handler has to do, in order

**1. Decide, with the same predicate as the router.** Parse `req.url` against the same fixed base
(`new URL(req.url, "http://localhost")`; `router.mjs`'s header explains why it is a fixed base and
not the `Host` header) and apply the same exact-or-slash `isUnder(xuiMount)`. If it is not under the
mount, or dev-server mode is off:

```js
socket.write("HTTP/1.1 404 Not Found\r\nConnection: close\r\n\r\n");
socket.destroy();
```

Write the status line **by hand** — there is no `res`. And write *something*: a bare
`socket.destroy()` gives the client a connection reset with no reason, which is indistinguishable
from the server not existing.

**2. Set the client socket up before anything else.**

```js
socket.setNoDelay(true);        // interactive duplex; Nagle adds latency to every HMR frame
socket.setTimeout(0);           // an HMR socket is idle by definition between edits
socket.setKeepAlive(true, 0);
```

`setTimeout(0)` is the second-most-likely silent omission after the event itself: a default socket
timeout closes the HMR connection during any pause in editing, and the symptom is "HMR works for a
minute and then stops".

**3. Open the upstream request, forwarding everything.**

```js
const out = http.request({
    host: devServer.hostname,
    port: devServer.port,
    path: req.url,              // verbatim -- path AND query
    method: req.method,
    headers: { ...req.headers },// including Host, Upgrade, Connection, Origin,
                                // Sec-WebSocket-Key / -Version / -Protocol
    agent: false,               // never pool a socket that is about to be detached
});
out.end();
```

Three of those are load-bearing and each fails silently if dropped, **verified against the installed
Vite 5.4.21's `shouldHandle`**:

```js
const shouldHandle = (req) => {
  const hostHeader = req.headers.host;
  if (!hostHeader || !isHostAllowed(config, false, hostHeader)) return false;
  if (config.legacy?.skipWebSocketTokenCheck) return true;
  if (req.headers.origin) {
    const parsedUrl = new URL(`http://example.com${req.url}`);
    return hasValidToken(config, parsedUrl);   // url.searchParams.get("token")
  }
  return true;
};
```

- **`Sec-WebSocket-Protocol: vite-hmr`** — Vite discriminates its HMR socket from any other upgrade
  by this subprotocol (`const HMR_HEADER = "vite-hmr"`). Dropping it leaves the socket up and HMR
  dead.
- **The `?token=` query** — a browser always sends `Origin` on a WebSocket handshake, so Vite 5.4.21
  always takes the `hasValidToken` branch. Dropping the query string refuses the handshake.
- **`Host`** — must pass `isHostAllowed`; see §3.

**4. Handle the upstream's `'upgrade'`.**

```js
out.on("upgrade", (up, upSocket, upHead) => {
    upSocket.setNoDelay(true);
    upSocket.setTimeout(0);

    // (a) reconstruct the 101 by hand from rawHeaders -- there is no writeHead on a raw socket,
    //     and rawHeaders preserves header case and any repeated header.
    const lines = [`HTTP/1.1 ${up.statusCode} ${up.statusMessage}`];
    for (let i = 0; i < up.rawHeaders.length; i += 2) {
        lines.push(`${up.rawHeaders[i]}: ${up.rawHeaders[i + 1]}`);
    }
    socket.write(`${lines.join("\r\n")}\r\n\r\n`);

    // (b) THE BYTES PAST THE HEADER BLOCK, BOTH WAYS. This is the classic proxy bug.
    if (upHead?.length) { socket.write(upHead); }    // upstream bytes read past the 101
    if (head?.length)   { upSocket.write(head); }    // client bytes read past the handshake

    // (c) full duplex
    socket.pipe(upSocket).pipe(socket);
});
```

**(b) is the part that is invisible until it is not.** `head` and `upHead` are the bytes the HTTP
parser read past the end of the header block and buffered. They are empty *most* of the time, so
dropping them produces a proxy that works in testing and loses the first WebSocket frame whenever
the peer happened to put the frame in the same TCP segment as the handshake. §5 forces both cases
deterministically.

**5. Errors and teardown, both directions.**

```js
out.on("error", (e) => {   // dev server down, or restarting
    socket.write(`HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\n\r\n`
        + `no Vite dev server at ${devServer.host}:${devServer.port}: ${e.code}\r\n`);
    socket.destroy();
});
socket.on("error", () => upSocket.destroy());
upSocket.on("error", () => socket.destroy());
socket.on("close", () => upSocket.destroy());
upSocket.on("close", () => socket.destroy());
```

Without the symmetric `close` handlers, restarting Vite leaves a half-open connection and the
browser never reconnects.

**6. A response instead of an upgrade.** If the dev server is up but answers this path with an
ordinary response rather than upgrading, `out` emits `'response'`, not `'upgrade'`. Relay it and end
the socket — otherwise the client hangs with no diagnosis:

```js
out.on("response", (up) => {
    socket.write(`HTTP/1.1 ${up.statusCode} ${up.statusMessage}\r\nConnection: close\r\n\r\n`);
    up.pipe(socket);
});
```

**7. Register the pair for shutdown.** Keep a module-level `Set` of `{ socket, upSocket }` and
destroy both on the abort path. This is not optional — see §7, where it is measured.

`node:net` is needed only if you want to type-check or construct a `Socket` directly; the handler
above is `node:http` plus the sockets it is handed.

---

## 5. What can be proven today, and what cannot

The application source is still AMD, so a Vite dev server cannot serve a running XUI until groups 5
and 6 land. **The proxy, however, does not care what is behind it.** So the proof stands up a
trivial HTTP+upgrade origin, points the proxy at it, and asserts on what crosses the boundary.

### The procedure

Throwaway script outside the repo (`/tmp/...`, so nothing tracked under `local/` is touched). It:

1. **Imports the real router unchanged** — `createRequestHandler` and `RESET_PATH` from
   `local/server-lib/router.mjs`, `buildBaselineState` from `local/server-lib/state.mjs`, built
   over the committed `local/capture/`. Nothing in `server-lib/` is edited; the harness *wraps* the
   real handler with the proposed branch, so what is proven is the branch placement against the
   real dispatch order.
2. **Stands up a stand-in dev server** on port 0 with `node:http`: its request handler answers
   `200 {"upstream":true,"path":req.url,"host":req.headers.host}`; its `'upgrade'` handler completes
   a WebSocket handshake by hand — `Sec-WebSocket-Accept` = `base64(sha1(key + GUID))` with
   `node:crypto` — and **writes the 101 header block and a payload marker in a single
   `socket.write`**, which forces the proxy's client parser to surface those bytes as `upHead`. It
   then echoes everything it receives. No `ws` package; the handshake is about fifteen lines.
3. **Stands up the local server** on port 0: request handler = `isUnder(xuiMount) ? proxy : handle`,
   plus the `'upgrade'` handler of §4.
4. **Drives it with `fetch` and a raw `net.Socket`.** The WebSocket client writes its handshake
   **and a payload marker in a single `socket.write`**, which forces the proxy's server parser to
   surface those bytes as `head`. Both buffered-head paths are therefore exercised deterministically
   rather than by luck.

### The assertions, and the result

Run on Node v22.20.0 against this checkout. **16/16 passed.**

| # | Assertion | Result |
|---|---|---|
| 1 | `GET /openam/XUI/deep/module/Foo.js?v=16.2.0-SNAPSHOT&x=1` reaches the upstream with the path **and query** unrewritten | PASS — upstream saw the identical string |
| 1b | `Host` forwarded unchanged (`127.0.0.1:<proxy port>`, not the target's) | PASS |
| 2 | Upgrade under the same prefix reaches the upstream; 101 comes back | PASS |
| 2b | `Sec-WebSocket-Accept` is the upstream's, computed from the client's key | PASS |
| 2c | `Sec-WebSocket-Protocol: vite-hmr` survived the hop | PASS |
| 2d | Upstream saw the full path **including `?token=`** | PASS |
| 2e | Upstream's buffered head (bytes past the 101) reached the client | PASS |
| 2f | Client's buffered head (bytes past the handshake) reached the upstream | PASS |
| 2g | Duplex: bytes written after the handshake are echoed back | PASS |
| 3 | `GET /openam/json/serverinfo/*` is answered **locally** (`cookieName=iPlanetDirectoryPro`, no `upstream` key) | PASS |
| 4 | `POST /local-api-server/reset` still resets locally (`{"reset":true,"realms":1}`) | PASS |
| 5 | `GET /openam/XUIsomething` is **not** proxied — 404 naming the three surfaces | PASS |
| 6 | Dev server down → `502` naming it (`... is not answering: ECONNREFUSED`) | PASS |
| 6b | Upgrade with the dev server down → `502` written to the socket, not a bare reset | PASS |
| 7 | `server.closeAllConnections()` does **not** close an upgraded socket | PASS — see §7 |
| 7b | Explicit tracking does close it | PASS |

The harness was deleted after the run and no process from it is listening.

### What this proves

- The proxy branch sits in the right place in the dispatch order, against the real
  `createRequestHandler`.
- The request path and query cross the boundary byte-for-byte in both directions.
- `Host` is forwarded rather than rewritten.
- The REST surface, the control mount and the 404 are untouched, and `isUnder`'s exact-or-slash rule
  still bounds the proxy at `/openam/XUIsomething`.
- The `'upgrade'` event is wired, and it carries the subprotocol, the query string and **both**
  buffered head buffers.
- An absent dev server is reported as a readable 502 on both surfaces rather than as a hang or a
  reset.
- An upgraded socket outlives `closeAllConnections()`, so §7's tracking is necessary and not
  defensive.

### What this does NOT prove

- **That Vite serves anything usable.** The source is AMD until groups 5 and 6. This says nothing
  about whether a dev server can boot the XUI.
- **That `base: "/openam/XUI/"` produces working asset URLs.** That is 4.1's and group 5's to show;
  here it is read from `NOTES-vite-build.md` §7 and `vite.config.js:1160-1171`.
- **That HMR reloads a module.** Only that a WebSocket reaches the upstream and bytes flow. The
  reload itself needs a real Vite, a real module graph and a real edit.
- **That Vite's HMR socket is in fact at `base`.** The `socketHost` expression and `HMR_HEADER` were
  read out of the installed `vite@5.4.21`, not observed on a running dev server. Re-check when 4.1
  pins a version.
- **`allowedHosts`.** The 403 path was read, not triggered.
- **The 229 runtime templates and the locale JSON.** `NOTES-vite-build.md` §7's third bullet: they
  are not in the module graph, so Vite will not serve them without `publicDir` or a plugin. That is
  a Vite-config question, not a proxy question, and this proof is silent on it. It is also half of
  the *Development server with live reload* requirement's second scenario, so **it must not be
  assumed closed by 4.10**.
- Anything about theme overrides.

---

## 6. The README

`local/README.md` documents both backends. Dev-server mode is **not a third backend** — it is a
second way the *same* local backend serves the XUI half, with the REST half byte-identical. Every
edit below follows from that.

### Sections to extend

| Section | Line | Edit |
|---|---:|---|
| **Two backends, and which to reach for** | 29 | **Do not add a column.** A third column makes it read as a third thing you could sign off against, which is exactly what §6's constraint forbids. Add one sentence after the table, or a footnote on the *Local API server* column: the same backend can proxy the XUI half to a Vite dev server for live reload, with a link to the new subsection. |
| **Getting a built XUI** | 139 | One sentence, not a rewrite: in dev-server mode you need no zip and no `mvn package` at all — that is the gain — with a back-link. |
| **The local API server** | 227 | The main edit. A fourth line in the usage block, and `--dev-server` / `OPENAM_LOCAL_DEV_SERVER` added to the `--port`, `--context`, `--host` paragraph. |
| **new subsection, e.g. "Live reload against a Vite dev server"** | after 335 | Sits beside *What this backend does not cover* and *Reset between tests*. Content: what to run (one terminal or two, per the §2 decision), that `base` must be `/{context}/XUI/` and must agree with `--context`, that the REST half is unchanged and still comes from the capture, that HMR is a WebSocket the proxy forwards, and the `allowedHosts` note for a non-loopback `--host`. |
| **Running the suite against either backend** | 405 | One sentence: the suite is **not** run against dev-server mode. Dev-mode assets are unbundled dev modules, not the artifact that gets deployed, so a green run there is *further* from acceptance than a `@local-server` run. No `@dev-server` tag, no entry in D16's backend-tag vocabulary, no npm script that runs Playwright against it. |
| **Troubleshooting** | 464 | Two new failure modes: *every XUI request 502s* (Vite not up, or on a port other than `--dev-server` says — Vite increments past a busy 5173), and *the page loads but nothing reloads* (the HMR socket is not connecting: check `base`, check the upgrade reaches the proxy, check `allowedHosts` if `--host` is not loopback). |

### The acceptance-oracle constraint, stated

`openspec/changes/modernize-openam-ui-build/specs/ui-local-backend/spec.md`, **Requirement: The
local backend is not the acceptance oracle**:

> Acceptance of a UI build change SHALL require the suite to be green against a deployed AM; a green
> run against the local backend alone SHALL NOT satisfy it.

The README already carries two sentences doing this work — *"develop against the local server, sign
off against the instance"* (~line 52) and *"A green run against the local server is not sign-off"*
(~line 450). **The dev-server section must be written inside that frame, not beside it.** It is an
inner-loop convenience layered on the fast backend, and therefore one step *further* from the oracle
than the fast backend already is: it serves unbundled dev modules that no deployment ever receives.

Concretely, the mode must not acquire any of: a column in the two-backends table, a "Base URL" row
of its own, an npm test script, or a D16 backend tag. Each of those would let a green run against it
read as evidence about a build, and it is not — task 10.1 still requires the phase-0 suite green
against a Vite-built XUI **deployed to the instance**.

---

## 7. Process hygiene

### What `server.mjs` already does

- A zip is unpacked to `mkdtemp(join(tmpdir(), "xui-www-"))` (`xui-source.mjs:113`).
- `staging` is captured via the `onStaging` callback **as soon as the directory exists** rather than
  on return (server.mjs:167-173), so a Ctrl-C *during* the unpack can still find it.
- Normal exit: `finally { await xui.cleanup(); }` (server.mjs:174-178).
- Second Ctrl-C: `rmSync(staging, {recursive:true, force:true})` **synchronously**, then
  `process.exit(130)` (server.mjs:151-156) — because an async `rm` started there would be abandoned.
- Shutdown closes the socket with `server.closeAllConnections()` before `server.close()`
  (server.mjs:275-281), so an idle keep-alive connection cannot hold the port into the next start.
- `SIGKILL` is the acknowledged remaining leak, and the header says so.

### What dev-server mode adds — option 1 (contributor starts Vite)

**Less on disk, more in sockets.**

1. **No temp directory at all, and this must be explicit.** In dev-server mode `resolveXuiSource`
   must not be called: `options.xui` is `null` and there is nothing to unpack. Skipping it is not an
   optimisation — calling it would unpack ~650 files that will never be served and pay the entire
   startup cost the mode exists to avoid, and it would need an `--xui` that §2 forbids. `staging`
   stays `null`, so the existing `rmSync` and `cleanup()` paths remain correct as no-ops.

2. **Upgraded sockets must be tracked, and this is measured, not assumed.** §5 assertion 7:
   **`server.closeAllConnections()` does not close a socket that has been detached by an upgrade.**
   So a single browser tab with an open HMR connection keeps the process alive after `server.close()`
   — Ctrl-C appears to hang, and the cause is invisible. The fix is a module-level
   `Set` of `{ socket, upSocket }` pairs, added in the `'upgrade'` handler (§4 step 7) and drained
   inside the existing `close()` at server.mjs:275:

   ```js
   const close = () => {
       for (const { socket, upSocket } of liveUpgrades) { socket.destroy(); upSocket.destroy(); }
       liveUpgrades.clear();
       server.closeAllConnections();
       server.close(() => resolveClosed());
   };
   ```

   Both halves of each pair: destroying only the client side leaves an outbound socket to Vite open.

3. **In-flight outbound requests.** Each proxied request holds a `ClientRequest` to Vite. A request
   outstanding at shutdown holds the same kind of handle. The same `Set` (or a second one) with a
   `destroy()` on the abort path covers it.

4. **Nothing new for the second Ctrl-C.** `socket.destroy()` is synchronous, so the escalation path
   at server.mjs:151-156 needs no addition beyond the drain above — and the existing `rmSync` is
   already a no-op when `staging` is `null`.

5. **Nothing new on crash.** No child process, no temp directory, no file. Sockets die with the
   process. This is a genuine and under-rated argument for option 1.

### What dev-server mode adds — option 2 (server spawns Vite)

Everything above, plus:

6. **A child process on the abort path.** `child.kill("SIGTERM")` before `server.close()` resolves,
   and the shutdown must *wait* for the child's `'exit'` — otherwise the parent exits first and the
   next start meets a Vite still holding the port.

7. **Escalation on the second Ctrl-C.** `process.kill(child.pid, "SIGKILL")` **synchronously**
   before `process.exit(130)`, exactly parallel to the existing `rmSync` and for the same reason.

8. **An orphaned Vite after a parent crash**, which `node:http` gives no help with. The honest
   options are (a) accept it, and make the next start's error say *"something is on port 5173 — it
   may be an orphaned Vite from a previous run"*; or (b) give the child an IPC channel
   (`stdio: [..., "ipc"]`) and have it exit on `'disconnect'`. (b) is real work, and it is a cost
   that belongs to the §2 decision rather than to the implementation.

9. **Vite's own caches are left behind on purpose.** `node_modules/.vite` (the dependency
   pre-bundle) and `node_modules/.vite-temp` (config-loading scratch) are Vite's to manage and are
   deliberately persistent. Removing them on exit would make every start pay a cold optimize. They
   must not be added to the cleanup path — this is worth writing down because "the server removes
   its temp directory on the way out" invites exactly that mistake.

### Unchanged either way

The listening socket (`close()` + `closeAllConnections()`), the `EADDRINUSE` message, and `--port 0`
— the proxy target is a fixed origin and is independent of the port this server binds.

---

## Open, and deliberately not resolved here

- **Who starts Vite** (§2). Presented with costs; not decided.
- **Whether `base` is set by a mode-conditional `vite.config.js` or by `--base` on the CLI** (§3).
  The CLI form leaves `vite.config.js:1171` untouched and derives from `--context` for free under
  option 2; the config form works under option 1 without the contributor retyping it. This depends
  on the previous bullet.
- **Whether the startup probe of `GET {devServer}{base}` is worth its complexity** under option 1
  (§3). It is the only thing that catches a `base`/`--context` disagreement before 404s do.
- **The 229 templates and the locale JSON** (`NOTES-vite-build.md` §7). Not a proxy question, and
  not closed by 4.10 — but the *Development server with live reload* requirement's second scenario
  needs it, so somebody must own it.
- **Vite's HMR socket path and `allowedHosts` behaviour were read out of the installed
  `vite@5.4.21`, not observed on a running dev server** (§5). Re-verify when 4.1 pins a version.
