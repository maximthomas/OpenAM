# Migration Context

## Project

`openam-ui-ria` — the admin and end-user web UI for OpenAM. A Backbone.js + RequireJS
application with 268 source files (209 AMD `.js` + 31 `.jsm` + 15 `.jsx`), 187 Handlebars
templates, and 21 LESS stylesheets.

## Current Tech Stack

| Layer | Technology | Version |
|-------|-----------|---------|
| Framework | Backbone.js | 1.1.2 |
| Module System | RequireJS (AMD) | 2.3.7 |
| DOM | jQuery | 3.7.1 |
| Templates | Handlebars | 4.7.7 |
| CSS | LESS + Bootstrap 3 | 3.3.5 |
| State | Redux | 3.5.2 |
| Build | Grunt | 1.6.2 |
| Testing | Karma + Mocha + Chai + Squire.js | — |
| i18n | i18next | 1.7.3 |
| React (legacy) | React | 15.2.1 |

## Target Tech Stack

| Layer | Technology | Rationale |
|-------|-----------|-----------|
| Framework | Vue 3 (Composition API) | Natural fit for template-driven views, SFCs |
| Module System | ES Modules (Vite native) | No AMD loader needed |
| TypeScript | `<script lang="ts">` | Type safety, better DX, first-class Vue support |
| CSS | Hybrid: global LESS + `<style scoped>` | Preserves theme switching, eliminates collisions |
| State | Reactive composable (`reactive()`) | Only 3 strings of global state, zero deps needed |
| i18n | vue-i18n | Native Vue integration, same translation JSON keys |
| UI Library | Bootstrap 3 CSS (no component lib) | 722 class matches, works as-is in Vue templates |
| Routing | Vue Router 4 (hash mode) | Matches current behavior, no server config needed |
| Build | Vite 8 | Fast, native LESS/TS, per-entry-point builds |
| Testing | Vitest + @vue/test-utils | Vite-native, zero config, Vue component testing |
| Commons | Pure TS services | Framework-agnostic, reusable across modules |

## Architectural Decisions

### Migration Strategy: Strangler Fig at Entry Points

Migrate the two smallest entry points first (`main-device`, `main-authorize`), then the
main SPA. This proves the toolchain before tackling the 200+ file main app.

**Entry points:**
1. `main-device.js` (88 lines) → device auth pages (complete)
2. `main-authorize.js` (162 lines) → OAuth2 consent pages (complete)
3. `main.js` (~200 lines bootstrap + 268 files) → main SPA (migrated last)

### Commons Layer: Pure JS/TS Services

The existing `org.openidentityplatform.commons.ui.libs` Maven JAR provides AMD modules
(443 references in openam-ui-ria). Instead of rewriting all commons modules, extract
framework-agnostic logic into pure TypeScript (completed in task 2-2):

| New Module | Replaces | Exports |
|-----------|----------|---------|
| `services/config.ts` | `Configuration` | `config.host`, `config.globalData` (reactive) |
| `services/constants.ts` | `Constants` + OpenAM extension | All event names, patterns, header params, self-service paths |
| `services/api.ts` | `AbstractDelegate` + `ServiceInvoker` | `RestClient` class, `getDifferences()`, `patchDifferences()` |
| `services/i18n.ts` | `i18nManager` | `t()`, `setLocale()`, `getCurrentLocale()`, `mapTranslate()` |
| `i18n/index.ts` | `i18nManager.init()` | `configureI18n(basePath, ns, pageData)` — fetches translations via HTTP, loads into vue-i18n. Custom `messageCompiler: (message) => () => message` bypasses vue-i18n template parser that crashes on HTML in translations (e.g., `<a href>` in copyright string). |
| `services/theme.ts` | `ThemeManager` | `getTheme(config, realm?, isAdmin?)` with vanilla DOM |
| `services/themeConfiguration.ts` | `ThemeConfiguration` | Typed theme config data |
| `services/events.ts` | `EventManager` | Synchronous `on/off/emit/once` emitter |
| `services/oauth2.ts` | `OAuth2ConsentPageHelper` | `getUserSessionId()` — CSRF token fetch |

These become the new shared commons library, consumable by openam-ui-ria (Vue),
openam-ui-js-sdk (React), and future modules. Key design decisions:
- `ThemeConfig` passed as parameter to `theme.ts` (not imported directly)
- `i18n.ts` is thin vue-i18n wrapper (no cookie detection, no Handlebars helpers)
- `events.ts` uses synchronous dispatch (no setTimeout/Deferred)
- `config.passwords` and `HEADER_PARAM_REAUTH` dropped (dead code in OpenAM)
- `errorsHandlers` suppression map preserved in `api.ts` (~8 call sites depend on it)

### Build Integration: Vite + Grunt Coexistence

During transition, both build systems run:
- **Grunt** builds `src/main/js/` (Backbone AMD) → `target/compiled/`
- **Vite** builds `src/main/vue/` (Vue 3) → `target/compiled-vite/`
  - **Library mode (UMD)**: `device-main.ts` → `main-device.js`, `authorize-main.ts` → `main-authorize.js` (loaded by RequireJS `data-main`). Uses `VITE_UMD_ENTRY` env variable to select entry (Vite 8 UMD single-entry constraint).
  - **SPA mode** (dev): `index.html` → assets with content hashes
- **Maven** assembles both into the final ZIP artifact

Vite detects `NODE_ENV=production` to switch between library and SPA modes. The UMD
output includes an AMD factory (`typeof define=="function"&&define.amd`) so RequireJS
loads it seamlessly. No server-side FTL changes needed.

Multiple entry points use `VITE_UMD_ENTRY` env variable (e.g., `VITE_UMD_ENTRY=main-authorize`).
Grunt runs `vite build` twice — once per entry. `emptyOutDir: true` means each build
clears the output; the Grunt task must copy device output before building authorize.

`vite.config.ts` includes `define: { 'process.env.NODE_ENV': ... }` to expose
`NODE_ENV` in client code (required by vue-i18n and other libraries).

Once all entry points are migrated, Grunt is removed.

### Mock Server for Browser Testing

A Vite dev server wrapper (`mock-server/`) enables testing Vue pages in the browser with
real assets, source maps, and mock data — without a running OpenAM instance.

**Key design decisions:**
- **Vite `createServer()` programmatically** — source maps + HMR in browser
- **`configureServer` plugin hook** — mock middleware runs before Vite's internal middleware
- **`configFile: false`** — bypasses `vite.config.ts` proxy (`/openam` → localhost:8080) that would intercept mock routes
- **Middleware ordering** — static asset handlers (CSS, images, favicon) must come BEFORE page route handlers, because `/device/error/css/...` resolves relative to `/device/error/`, not `/device/`
- **Custom `messageCompiler`** in `i18n/index.ts` — vue-i18n's default compiler crashes on HTML in translation strings (e.g., `<a href="mailto:...">` in copyright); `(message) => () => message` returns raw string
- **`app.use(i18n)`** required in entry points — `useI18n()` in child components needs the plugin registered on the app instance
- Real CSS/images from `target/compiled/` (Grunt build), stubs as fallback
- **Authorize flow**: 4 scenarios — `/authorize/consent` (scopes + claims), `/authorize/consent-no-details` (empty), `/authorize/error`, `/authorize/error-with-uri`
- Zero new npm dependencies — uses Node built-in `http`, `fs`, `path`, `url`

### Template Migration: Codemod + Manual

Automated replacements (80% of cases):
- `{{t "key"}}` → `{{ $t("key") }}`
- `{{#if cond}}` → `v-if="cond"`
- `{{#each items}}` → `v-for="item in items"`
- `data-field="x"` → `v-model="formData.x"`
- `data-click="handler"` → `@click="handler"`

Manual fixes (20%):
- `{{> partial}}` → `<ComponentName />`
- `{{routeTo 'name' arg}}` → `router.resolve({ name: '...' })`
- `{{#equals a b}}` → computed property or custom directive

## Directory Structure

```
openam-ui-ria/
├── vite.config.ts                    # Vite configuration
├── vitest.config.ts                  # Vitest configuration
├── tsconfig.json                     # TypeScript configuration
├── Gruntfile.js                      # UNCHANGED during transition
├── package.json                      # Updated with new deps
├── pom.xml                           # Updated with Vite build execution
├── mock-server/                      # Vite dev server wrapper for browser testing
│   ├── server.js                     # createViteServer() — mock data plugin, static assets
│   ├── checks.js                     # Diagnostic check functions (device pages, locale, CSS)
│   ├── stub-assets/                  # Fallback assets (favicon, login-logo, CSS stubs)
│   └── tests/
│       └── smoke.js                  # CLI test runner (8 scenarios, 34 checks)
├── src/
│   ├── main/
│   │   ├── js/                       # OLD: Backbone AMD (Grunt builds)
│   │   │   ├── components/
│   │   │   ├── config/
│   │   │   ├── libs/
│   │   │   ├── org/
│   │   │   └── store/
│   │   ├── vue/                      # NEW: Vue 3 (Vite builds)
│   │   │   ├── index.html
│   │   │   ├── main.ts
│   │   │   ├── App.vue
│   │   │   ├── device-main.ts            # main-device UMD entry (Vite library mode)
│   │   │   ├── router/
│   │   │   ├── composables/
│   │   │   ├── services/             # Pure TS commons extraction
│   │   │   ├── types/
│   │   │   │   ├── device.d.ts           # DevicePageData + Window.pageData
│   │   │   │   └── authorize.d.ts        # AuthorizePageData + Window.pageData
│   │   │   ├── views/
│   │   │   │   ├── device/           # main-device entry point (complete)
│   │   │   │   │   ├── DeviceApp.vue
│   │   │   │   │   ├── DeviceForm.vue
│   │   │   │   │   ├── DeviceDone.vue
│   │   │   │   │   └── DeviceError.vue
│   │   │   │   ├── authorize/        # main-authorize entry point (complete)
│   │   │   │   │   ├── AuthorizeApp.vue
│   │   │   │   │   ├── AuthorizeForm.vue
│   │   │   │   │   ├── ScopeList.vue
│   │   │   │   │   └── ErrorDisplay.vue
│   │   │   │   ├── user/             # User-facing views
│   │   │   │   └── admin/            # Admin console views
│   │   │   ├── components/
│   │   │   │   └── common/               # Shared components
│   │   │   │       ├── LoginHeader.vue
│   │   │   │       └── LoginFooter.vue
│   │   │   ├── i18n/
│   │   │   │   └── index.ts              # vue-i18n instance + configureI18n() + custom messageCompiler
│   │   │   └── assets/
│   │   └── resources/                # SHARED: CSS, images, locales
│   │       ├── css/
│   │       ├── templates/            # Handlebars (being replaced)
│   │       ├── locales/
│   │       └── images/
│   └── test/
│       ├── js/                       # OLD: Karma tests
│       └── vue/                      # NEW: Vitest tests
│           ├── helpers/
│           │   ├── device.ts             # createDeviceTestWrapper, default pageData
│           │   └── authorize.ts          # createAuthorizeTestWrapper, default pageData
│           ├── device/
│           │   └── components.test.ts    # 12 tests: form/done/error/app rendering
│           ├── authorize/
│           │   └── components.test.ts    # 12 tests: error/scopeList/form/app rendering
│           ├── services/                 # Pure TS service tests (48 tests)
│           └── smoke.test.ts
```

## File Counts

| Category | Current | Migration Effort |
|----------|---------|-----------------|
| AMD `.js` files | 209 | Rewrite to Vue SFCs |
| ES6 `.jsm` files | 31 | Rewrite to `.ts` |
| JSX `.jsx` files | 15 | Rewrite to `.vue` |
| Handlebars templates | 187 | Codemod + manual → `<template>` |
| LESS stylesheets | 21 | Keep as Vite entry points |
| Test files | 9 | Vitest (72 unit tests) |
| Mock server files | 4 | Browser testing (12 scenarios, 42 checks) |
| Entry points | 3 | Migrate independently |

## Key Dependencies

### New (to install)

```json
{
  "dependencies": {
    "vue": "^3.5",
    "vue-router": "^4.5",
    "i18next": "^24.0",
    "vue-i18n": "^11.0",
    "axios": "^1.8"
  },
  "devDependencies": {
    "vite": "^8.0",
    "@vitejs/plugin-vue": "^6.0",
    "vitest": "^3.0",
    "happy-dom": "^17.0",
    "@vue/test-utils": "^2.4",
    "vue-tsc": "^2.0",
    "typescript": "~5.8",
    "less": "^4.0",
    "i18next-http-backend": "^3.0"
  }
}
```

### Existing (kept)

- Maven `frontend-maven-plugin` — installs Node.js, runs npm
- Maven `maven-assembly-plugin` — assembles final artifact
- `eslint-config-forgerock` — linting rules (adapted for Vue)

### Removed (after migration)

- Grunt, grunt-* plugins
- RequireJS, text plugin, AMD shim configs
- Babel (Vite handles transpilation)
- Backbone.js, jQuery, Handlebars
- React 15, react-bootstrap, react-select
- Redux 3.5.2
- Karma, Mocha, Chai, Squire.js, Sinon

## Risk Register

| Risk | Impact | Likelihood | Mitigation |
|------|--------|------------|------------|
| 187 templates take too long | High | Medium | Codemod automates 80%, start with leaf templates |
| Commons extraction incomplete | High | Low | Extract only what entry points need (5 modules) |
| Two build systems confuse devs | Medium | Medium | Clear directory separation, documented in AGENTS.md |
| Maven WAR packaging breaks | High | Low | Vite outputs to same `target/` structure |
| Bootstrap 3 CSS breaks in Vue | Low | Low | CSS classes work as-is, no runtime dependency |
| Theme switching stops working | Medium | Low | Keep global LESS entry points, test early |
| Mock server middleware ordering | Medium | Medium | Static assets (CSS/images) must be checked before page routes; `/device/error/css/...` resolves relative to `/device/error/`, not `/device/` |
| Vite 8 UMD single-entry constraint | Low | High | UMD format doesn't support multiple entry points; solved with `VITE_UMD_ENTRY` env variable, Grunt runs `vite build` twice |
