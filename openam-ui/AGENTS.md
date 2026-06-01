# AGENTS.md — openam-ui

> Guidance for AI agents and contributors working in the `openam-ui` module of
> [OpenIdentityPlatform/OpenAM](https://github.com/OpenIdentityPlatform/OpenAM/tree/master/openam-ui).

---

## Module Overview

`openam-ui` is the **frontend parent module** of OpenAM. It is a Maven POM-only aggregator that owns two sub-modules and all shared frontend dependency resolution:

| Sub-module | Artifact ID | Role |
|---|---|---|
| `openam-ui-ria` | `openam-ui-ria` | Rich Internet Application — the full admin & end-user web UI |
| `openam-ui-api` | `openam-ui-api` | REST API client library (Axios-based) bundled as a JAR |

The parent POM (`openam-ui/pom.xml`) pre-fetches all third-party JS/CSS libraries via `maven-external-dependency-plugin` before either sub-module build starts. Node.js `v20.12.2` / npm `v10.5.0` are installed into the working directory by `frontend-maven-plugin v1.15.0`.

Key runtime constants (override via Maven properties):

```
jquery.version   = 3.7.1
bootstrap.version = 3.3.5
```

---

## Repository Layout

```
openam-ui/
├── pom.xml                     # Aggregator POM; downloads all JS/CSS deps
├── openam-ui-ria/              # Legacy Backbone/RequireJS admin UI
│   ├── pom.xml
│   ├── Gruntfile.js            # Build orchestration (copy → eslint → requirejs → less → karma)
│   ├── package.json            # npm dev-dependencies (grunt, karma, eslint, less, requirejs)
│   └── src/
│       └── main/js/            # AMD (RequireJS) JavaScript source
│           ├── org/forgerock/openam/   # OpenAM-specific views, models, routes
│           └── org/forgerock/commons/  # Shared UI framework components
│       └── main/less/          # LESS stylesheets (compiles to structure.css, theme.css, styles-admin.css)
│       └── main/resources/     # Static assets, i18n JSON bundles
│       └── test/               # Karma/QUnit unit tests
└── openam-ui-api/              # Modern REST client (Babel + Webpack + Axios)
    ├── pom.xml
    └── src/
        └── main/js/            # ES6+ source; Babel-compiled
```

---

## Build System

### Full Maven Build (recommended)

```bash
# From the repository root — builds everything including openam-ui
mvn -DskipTests install -f OpenAM

# Build only the UI modules
mvn install -pl openam-ui -am
```

Maven drives the frontend toolchain automatically via `frontend-maven-plugin`. You do **not** need Node or npm pre-installed; the plugin downloads them on first run.

### openam-ui-ria — Grunt Tasks

The sub-module delegates to Grunt. Maven runs `grunt prod` during the `package` phase. The pipeline executes these Grunt tasks in order:

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

### openam-ui-api — npm / Webpack

The `openam-ui-api` sub-module is a modern JavaScript package (Babel + Webpack, Axios HTTP client). It is packaged as a JAR via Maven and embedded in the server-side classpath.

Key dependencies tracked by Dependabot:
- `axios` (HTTP client)
- `@babel/runtime`, `@babel/runtime-corejs3` (ES6+ polyfills)
- `swagger-ui` (API explorer)
- `dompurify` (XSS sanitisation)

---

## Development Workflow (openam-ui-ria)

For rapid front-end iteration without a full Maven build:

**Prerequisites:**
- Node.js (matches `v20.12.2` or later LTS)
- `npm install` in `openam-ui/openam-ui-ria/`
- Set `OPENAM_HOME` to your expanded OpenAM webapp directory, e.g.:
  ```bash
  export OPENAM_HOME=~/tomcat/webapps/openam
  ```

**Watch mode** (syncs changed files directly to the running server):
```bash
cd openam-ui/openam-ui-ria
npm install
npx grunt
```

Grunt will watch `src/` and sync any changed file to `$OPENAM_HOME`.

**Run unit tests continuously** (separate terminal):
```bash
npx grunt karma:unit
```

Open `http://localhost:9876/debug.html` in a browser and check DevTools console for test failures.

---

## Testing

| Layer | Tool | Command |
|---|---|---|
| openam-ui-ria unit | Karma + QUnit | `npx grunt karma:unit` (watch) or `mvn test -pl openam-ui/openam-ui-ria` |
| openam-ui-ria full build + test | Grunt `karma:build` | Triggered automatically by `mvn package` |
| openam-ui-api | npm test (see sub-module scripts) | `cd openam-ui/openam-ui-api && npm test` |

Tests live under `openam-ui-ria/src/test/`. Failures are reported in the Karma console; for debugging open `http://localhost:9876/debug.html`.

---

## Third-Party Dependency Management

All vendored JS/CSS libraries are **not committed to source**. They are downloaded by Maven during `process-resources` from CDNs (cdnjs, unpkg, raw.githubusercontent.com) and placed under `target/dependencies/`.

To add or update a library, edit the `<artifactItems>` list in `openam-ui/pom.xml`. Use the existing `<downloadUrl>` template variables (`{version}`, `{artifactId}`, `{classifier}`, `{packaging}`).

Key libraries included:

- **UI framework:** Backbone.js 1.1.2, Backbone Paginator 2.0.2, Backbone-Relational 0.9.0
- **Grid:** Backgrid 0.3.5 (with paginator, filter, select-all extensions)
- **Templating:** Handlebars 4.7.7
- **DOM:** jQuery 3.7.1, jQuery Placeholder, jQuery Sortable, jQuery ba-dotimeout
- **Styles:** Bootstrap 3.3.5, Font Awesome 4.5.0, Selectize 0.12.1, Dragula 3.6.7, Bootstrap Dialog 1.34.4, Bootstrap Clockpicker, Bootstrap DateTimePicker
- **Module loader:** RequireJS 2.3.7 (r.js optimizer), RequireJS text plugin 2.0.15
- **i18n:** i18next 1.7.3
- **React stack (legacy):** React 15.2.1, ReactDOM, react-bootstrap 0.30.1, react-select 1.0.0-rc.2, classnames, react-input-autosize
- **State:** Redux 3.5.2
- **Utilities:** Lodash 2.4.1 / 3.10.1, Moment.js 2.28.0, XDate 0.8, spin.js, base64, form2js / js2form, QRCode, JSON Editor 0.7.9
- **Editor:** CodeMirror 4.10
- **Testing:** QUnit 1.15.0, Sinon.js 1.15.4, Squire.js 0.2.0 (AMD mock injector)

---

## Code Style & Conventions

- **JavaScript (openam-ui-ria):** AMD modules (`define([...], function(...) {})`). ESLint is run on every build; fix all errors before committing. JSDoc warnings are tolerated but should not be added.
- **JavaScript (openam-ui-api):** ES6+ modules with Babel transpilation. Follow the existing module structure.
- **LESS:** BEM-style selectors where possible. Do not write plain CSS; all styles go through the LESS pipeline.
- **i18n:** All user-visible strings must be externalised to JSON resource bundles under `src/main/resources/`. Never hard-code English strings in templates or JS.
- **No direct CDN links at runtime:** All third-party assets must go through the Maven dependency pipeline, not be loaded from a CDN at runtime.

---

## Security Notes

- **CVE-2024-38999** — RequireJS ≤ 2.3.6 had a prototype pollution vulnerability. The project uses 2.3.7+; do not downgrade.
- **CVE-2025-26791** — DOMPurify and swagger-ui in `openam-ui-api` must be kept up-to-date. Dependabot PRs for these should be merged promptly.
- **CVE-2025-8662** — Tampering with request parameters can corrupt the internal SAML IdP cache. Validate all user-supplied input before passing to OpenAM REST endpoints.

---

## Common Agent Tasks

### Adding a new admin UI view (openam-ui-ria)

1. Create an AMD module under `src/main/js/org/forgerock/openam/ui/admin/views/`.
2. Register the route in the appropriate router module.
3. Add a Handlebars template (`.html`) in the corresponding `templates/` directory.
4. Externalise all strings to the i18n bundle.
5. Write a QUnit test in `src/test/`.
6. Run `npx grunt` and verify no ESLint errors and all tests pass.

### Updating a REST API call (openam-ui-api)

1. Edit or add the relevant service file under `openam-ui-api/src/main/js/`.
2. Use the existing Axios instance — do not create raw `fetch()` or `XMLHttpRequest` calls.
3. Bump the affected test fixtures and run `npm test`.

### Changing a shared third-party library version

1. Update the `<version>` in the matching `<artifactItem>` block in `openam-ui/pom.xml`.
2. Update `<downloadUrl>` if the CDN path changed.
3. Run `mvn process-resources -pl openam-ui` to verify the download succeeds.
4. Run `mvn package -pl openam-ui` and confirm the full Grunt pipeline passes.

---

## Useful References

- [OpenAM GitHub repository](https://github.com/OpenIdentityPlatform/OpenAM)
- [OpenAM Wiki](https://github.com/OpenIdentityPlatform/OpenAM/wiki)
- [frontend-maven-plugin docs](https://github.com/eirslett/frontend-maven-plugin)
- [RequireJS optimiser (r.js)](https://requirejs.org/docs/optimization.html)
- [Karma test runner](https://karma-runner.github.io)
- License: [CDDL-1.0](https://github.com/OpenIdentityPlatform/OpenAM/blob/master/LICENSE.md)