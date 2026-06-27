# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Active migration (read before architectural work)

This module is being migrated off RequireJS/Backbone/Grunt onto a modern React/Vite/TypeScript stack via an **incremental strangler-fig** (new app at `/EUI`, legacy at `/XUI`, side by side). **Before making architectural changes or starting new feature work, read [`docs/migration/context.md`](docs/migration/context.md)**, then `docs/migration/tasks.yml` (status), `docs/migration/route-ownership.yml` (what's migrated), and the ADRs in `docs/migration/decisions/`. The full plan is in [`MIGRATION.md`](MIGRATION.md). Net direction: new code is React 19 + Vite + TS (strict) + react-router 7 + TanStack Query + react-bootstrap/Sass + Vitest; **no new Backbone/RequireJS/jQuery/Redux**. (The sibling `openam-ui-js-sdk` module is an independent example — not a template; do not copy or depend on it.)

**Migration skills** (in `openam-ui/.claude/skills/`): use **`migrate-slice`** to port a route/feature from legacy XUI to the new EUI app (full strangler loop), and **`scaffold-eui`** when writing any new EUI/commons-ui-next code (enforces the stack conventions). The new app is its own Maven module `openam-ui/openam-ui-eui` (ADR-0009).

## What this is

`openam-ui-ria` is the **XUI** — the AngularJS-era-free, RequireJS/Backbone single-page admin and end-user UI for OpenAM. It builds into a `target/openam-ui-ria-<version>-www.zip` artifact that is unpacked into the OpenAM webapp under `/XUI`. It is consumed as a Maven module of the larger OpenAM build but has its own npm/Grunt toolchain.

The app is layered on top of the shared **ForgeRock Commons UI** (`org.openidentityplatform.commons.ui:user`, a.k.a. `forgerock-ui-user` / `forgerock-ui-commons`), which is downloaded and unpacked at build time. Many core modules (`Router`, `EventManager`, `SessionManager`, `Constants`, base views) live in `org/forgerock/commons/...` and come from that dependency, not this repo. This repo's own code lives under `org/forgerock/openam/...`.

## Commands

All commands run from this directory (`openam-ui/openam-ui-ria`).

- **Full build (production):** `mvn install` — runs the frontend-maven-plugin which calls `npm run build:production` (Grunt `prod`/`build` task) and packages the zip. This is the only build path that wires up the ForgeRock Commons UI dependency unpack correctly.
- **Build via npm directly:** `npm run build:production` — `grunt prod` (compose → eslint → babel → requirejs → less). Requires the Maven-provided `target/dependencies*` to already exist, so run `mvn install` at least once first.
- **Dev watch / live sync:** `npm start` (= `grunt`, default task `dev`). Watches source and syncs changed files into your running server. Requires two env vars:
  - `FORGEROCK_UI_SRC` — path to a checkout containing `forgerock-ui-commons` and `forgerock-ui-user` source (so watch reads commons UI from source instead of the unpacked jar).
  - `OPENAM_HOME` — path to an expanded OpenAM webapp (e.g. `~/tomcat/webapps/openam`); compiled files are synced to `$OPENAM_HOME/XUI`.
- **Lint:** `npx grunt eslint` (also runs as part of `build`). ESLint config is `.eslintrc.js`.
- **Tests (watch):** `npm test` (= `grunt karma:build`). Karma + Mocha + Chai + Sinon, headless Chrome.
- **Tests (single run / CI):** done by Maven `test` phase, or `npx grunt karma:build` (karma `singleRun: true`).
- **Debug a test:** open `http://localhost:9876/debug.html` in a browser while karma is running and use devtools.

### Running a single test

There is no built-in filter flag. Karma loads every `*Test.js` it finds (see `src/test/js/test-main.js`, which regex-matches `Test.js` files). To run one test in isolation, either add `.only` to the Mocha `describe`/`it`, or temporarily narrow the `TEST_REGEXP` / file globs. Tests execute against **compiled output** in `target/compiled` and `target/test-classes`, so the Grunt build/sync must have run first (Maven build, `npm start`, or a prior `npm run build:production`).

## Build pipeline (important to understand before changing build behavior)

The Grunt build (`Gruntfile.js`) is a multi-stage copy-and-transform pipeline through `target/` subdirectories:

1. **compose** (`target/XUI`) — overlays three source trees *in order*, last wins: ForgeRock Commons UI deps → unpacked `forgerock-ui-user` → this project's `src/main/js` + `src/main/resources`. This is why a file here can override a commons-UI file of the same path.
2. **babel** → `target/transpiled` — transpiles `.js`/`.jsm`/`.jsx` (Babel `preset-env` + `preset-react`). `.jsm`/`.jsx` are renamed to `.js` and compiled as AMD modules. Anything under `libs/` is **not** transpiled.
3. **requirejs** (`r.js`) → `target/compiled/main.js` — concatenates/uglifies. `config/AppConfiguration` and `config/ThemeConfiguration` are intentionally **excluded from optimization** so deployments can customize them without repackaging.
4. **less** → compiled CSS (`structure.css`, `theme.css`, `styles-admin.css`).
5. **replace** — injects `${version}` into `index.html` for cache-busting.

`dev`/watch uses `grunt-sync` (md5 diff) instead of full copy/requirejs for speed — it does **not** run the requirejs optimization step, so the watched app loads unbundled modules.

## Application architecture

- **Module system:** RequireJS AMD. `src/main/js/main.js` is the entry point — it holds the full `require.config` (path aliases for all `libs/*`, the `map` of friendly names like `LoginView`/`Router` to concrete modules, and shim deps). When adding a third-party lib, register it here.
- **Bootstrap config:** `config/AppConfiguration.js` declares `moduleDefinition[]` — the wiring of core services (`SessionManager`, `Router`, `SiteConfigurator`, `ProcessConfiguration`, `ServiceInvoker`, `ErrorsHandler`, `UIUtils`). This is the closest thing to a DI/startup manifest.
- **Routing:** route tables are plain modules returning route maps, loaded via the Router's `loader` list in `AppConfiguration`. Project routes: `config/routes/AMRoutesConfig.js`, `config/routes/admin/{RealmsRoutes,GlobalRoutes}.js`, `config/routes/user/UMARoutes.js`. Each route maps a URL regex/pattern to a `view` module path.
- **Event-driven config:** `config/process/AMConfig.js` registers handlers keyed by `startEvent` (e.g. `EVENT_LOGOUT`) with declared `dependencies` and a `processDescription` callback. Use this to hook/override commons-UI lifecycle events (`override: true` replaces the commons default).
- **Feature code:** `org/forgerock/openam/ui/` is split into `admin/` (`models`, `services`, `utils`, `views/{realms,configuration,deployment,api,common}`), `user/` (`login`, `dashboard`, `oauth2`, `uma`, `anonymousProcess`, `services`), and `common/` (`sessions`, `models`, `services`, `components`, `views`, `util`). Views are Backbone views; services wrap REST calls to the AM endpoints.
- **Redux store:** `src/main/js/store/` (`.jsm` files) is a small Redux store (`index`, `actions/{types,creators}`, `reducers/{session,server,index}`) used alongside Backbone for cross-cutting state. Most store tests live in `src/test/js/store/`.
- **React/JSX:** newer leaf components are `.jsx`/React (`src/main/js/components/*.jsx`, `react-bootstrap`, `react-select`), rendered into Backbone views. JSX and `.jsm` are first-class — both transpile to AMD modules.

## Conventions

- **File extensions carry meaning:** `.js` = AMD module (legacy style), `.jsm` = ES-module-authored code transpiled to AMD, `.jsx` = React. Babel handles all three; `libs/` is exempt from transpilation and linting.
- **Lint is enforced in the build.** `.eslintrc.js` extends `forgerock` + `forgerock/react`. Notable hard rules (errors): 4-space indent, double quotes, `prefer-const`, `prefer-template`, `space-before-function-paren: always`, max line length 120, `camelcase`. `no-var`/`prefer-arrow-callback`/`prefer-spread` are warnings (legacy debt being migrated), so prefer `const`/`let` and arrow callbacks in new code.
- **Dependency versions are pinned** (no `^` in `package.json` for app deps) and shrink-wrapped. Update via the README's `ncu` + `npm run deps` flow, not ad-hoc edits. Many runtime libs are vendored under `src/main/js/libs/` and resolved through `main.js` paths rather than npm.
- Source files carry the CDDL license header — preserve it when editing, and follow the existing "Portions copyright [year]" pattern.
