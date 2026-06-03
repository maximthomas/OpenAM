# Build System

## Full Maven Build

```bash
# From the repository root — builds everything including openam-ui
mvn -DskipTests install -f OpenAM

# Build only the UI modules
mvn install -pl openam-ui -am
```

Maven drives the frontend toolchain automatically via `frontend-maven-plugin`. You do **not** need Node or npm pre-installed; the plugin downloads them on first run.

## openam-ui-ria — Grunt Pipeline

Maven runs `grunt prod` during the `package` phase:

| Step | Task | Description |
|---|---|---|
| 1 | `copy:compose` | Assembles sources and downloaded deps into `target/` |
| 2 | `eslint:lint` | Lints all JavaScript |
| 3 | `requirejs:compile` | r.js optimizer — bundles AMD modules |
| 4 | `less:compile` | Compiles LESS → CSS (`structure.css`, `theme.css`, `styles-admin.css`) |
| 5 | `replace:buildNumber` | Stamps the build version string |
| 6 | `copy:compiled` | Copies final artifacts to output directory |
| 7 | `karma:build` | Runs unit tests (headless) |

**Output:** `target/openam-ui-ria-<version>-www.zip` — deployed into the OpenAM WAR.

## openam-ui-api — npm / Webpack

Packaged as a JAR via Maven and embedded in the server-side classpath.

Key dependencies tracked by Dependabot:
- `axios` (HTTP client)
- `@babel/runtime`, `@babel/runtime-corejs3` (ES6+ polyfills)
- `swagger-ui` (API explorer)
- `dompurify` (XSS sanitisation)

## Vite Build

Vite builds the Vue 3 SPA from `src/main/vue/`.

### SPA Mode (main app)

```bash
cd openam-ui-ria
npx vite build
```

Produces hashed assets in `target/compiled-vite/`.

### UMD Library Mode (main-device, main-authorize)

Uses `VITE_UMD_ENTRY` env variable to select entry point (Vite 8 UMD single-entry constraint):

```bash
VITE_UMD_ENTRY=main-device npx vite build
VITE_UMD_ENTRY=main-authorize npx vite build
```

Grunt runs `vite build` twice — once per entry. `emptyOutDir: true` means each build clears the output; the Grunt task copies device output before building authorize.

The UMD output includes an AMD factory (`typeof define=="function"&&define.amd`) so RequireJS loads it seamlessly.

### Dev Server

```bash
cd openam-ui-ria
npx vite
```

Starts on port 3000 with HMR.
