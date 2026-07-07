# Mock AM server & legacy XUI harness

Two dev scripts powered by the shared MSW handlers in `commons-ui-next/src/mock` (ADR-0010).
Run from `openam-ui/openam-ui-eui` (or `npm -w eui run …` from the workspace root).

## Standalone mock AM server

```sh
npm run mock              # listens on http://localhost:4000  (override: MOCK_PORT=4001)
```

Exposes the shared handlers over real HTTP. Useful for `curl`, Playwright, or any tool that
needs a real HTTP endpoint.

```sh
# Step 1 — get the auth challenge
curl -sX POST http://localhost:4000/json/authenticate | jq .

# Step 2 — authenticate (replace <authId> with the value from step 1)
curl -sX POST http://localhost:4000/json/authenticate \
  -H 'Content-Type: application/json' \
  -d '{"authId":"<authId>","callbacks":[{"type":"NameCallback","input":[{"name":"IDToken1","value":"demo"}]},{"type":"PasswordCallback","input":[{"name":"IDToken2","value":"changeit"}]}]}' \
  | jq .
# → {"tokenId":"…","successUrl":"/XUI/","realm":"/"}

# Server info
curl -s http://localhost:4000/json/serverinfo/contextPath | jq .
```

Credentials: **demo / changeit** (from the shared fixtures).

## Legacy XUI no-AM harness

> **Prerequisite:** build `openam-ui-ria` once so `target/compiled/` exists:
> ```sh
> mvn -pl openam-ui/openam-ui-ria install
> # or (if Maven deps already unpacked):
> cd openam-ui/openam-ui-ria && npm run build:production
> ```

```sh
npm run dev:xui           # http://localhost:8081/openam/XUI/  (override: XUI_PORT=9090)
```

Serves the compiled legacy XUI as static assets and intercepts its AM REST calls
(`/openam/XUI/json/*`) with the same mock handlers — runs the old UI in a browser with **no
`OPENAM_HOME` or Tomcat required**.

Open `http://localhost:8081/openam/XUI/` and log in with **demo / changeit**.

> The `/openam` segment isn't cosmetic — it must be there. The app's `Constants.js` derives its AM
> deployment context from `location.pathname` by dropping the last segment; serving bare at `/XUI/`
> makes that resolve to an empty context, breaking every REST base URL the app builds (`//json/...`
> instead of `/json/...`) and leaving the login view stuck on "Loading...".
