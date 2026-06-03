# Development Workflow

## Prerequisites

- Node.js (matches `v20.12.2` or later LTS)
- `npm install` in `openam-ui/openam-ui-ria/`
- Set `OPENAM_HOME` to your expanded OpenAM webapp directory:
  ```bash
  export OPENAM_HOME=~/tomcat/webapps/openam
  ```

## Watch Mode (Backbone)

Syncs changed files directly to the running server:

```bash
cd openam-ui/openam-ui-ria
npm install
npx grunt
```

Grunt watches `src/` and syncs any changed file to `$OPENAM_HOME`.

## Unit Tests (Backbone)

Run continuously in a separate terminal:

```bash
npx grunt karma:unit
```

Open `http://localhost:9876/debug.html` in a browser and check DevTools console for test failures.

## Vite Dev Server

```bash
cd openam-ui-ria
npx vite
```

Starts on port 3000 with HMR. Proxies `/openam` to `localhost:8080` if a local OpenAM instance is running.

## Mock Server

A Vite dev server wrapper (`mock-server/`) enables testing Vue pages in the browser with real assets, source maps, and mock data — without a running OpenAM instance.

```bash
cd openam-ui-ria
node mock-server/server.js
```

### What it covers

- **Device pages:** 4 scenarios (form, success, error, locale-specific)
- **Authorize pages:** 4 scenarios (consent, consent-no-details, error, error-with-uri)
- Static assets from `target/compiled/` (Grunt build), stubs as fallback

### How it works

- Uses Vite `createServer()` programmatically (source maps + HMR in browser)
- `configureServer` plugin hook — mock middleware runs before Vite's internal middleware
- `configFile: false` — bypasses `vite.config.ts` proxy that would intercept mock routes
- Static asset handlers (CSS, images, favicon) come BEFORE page route handlers

### Smoke tests

```bash
cd openam-ui-ria
node mock-server/tests/smoke.js
```

Runs 8 scenarios with 34 checks against the mock server.
