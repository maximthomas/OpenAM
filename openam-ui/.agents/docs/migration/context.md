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
3. `main.js` (~200 lines bootstrap + 268 files) → main SPA (router + layout + common components complete, views pending)

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
| `services/jsonSchema/JSONSchema.ts` | `common/models/JSONSchema` | JSON Schema model class with lodash 3→4 compatible API |
| `services/jsonSchema/JSONValues.ts` | `common/models/JSONValues` | JSON Values model class with lodash 3→4 compatible API |
| `services/jsonSchema/schemaTransforms.ts` | 3 `schemaTransforms/*` files | Merged boolean/enum/password transforms |
| `services/jsonSchema/JSONEditorTheme.ts` | `admin/utils/JSONEditorTheme` | Bootstrap theme for JSONEditor (jQuery eliminated) |
| `composables/useDialog.ts` | `BootstrapDialog.show()` | Promise-based confirm/cancel dialog API |

**User services (task 3-3a):**

| New Module | Replaces | Exports |
|-----------|----------|---------|
| `services/user.ts` | `UserModel` | `read()`, `update()`, `changePassword()`, `validateGoto()` |
| `services/authN.ts` | `AuthNService` | `begin()`, `submitRequirements()`, `validateGoto()`, `getServerInfo()` |
| `services/session.ts` | Session REST calls | `getSessionInfo()`, `destroySession()`, `getSessionProperties()` |
| `services/token.ts` | `TokenService` | `getAllTokens()`, `deleteToken()`, `getTokenById()` |
| `services/dashboard.ts` | Device/Token/App services | `getTrustedDevices()`, `deleteTrustedDevice()`, `getOathDevices()`, `getMyApplications()` |
| `services/uma.ts` | `UMAService` | `getResourceSets()`, `createResourceSet()`, `getLabels()`, `approveRequest()`, `getHistory()` |
| `services/selfService.ts` | `AnonymousProcessDelegate` | `begin()`, `submitRequirements()`, `getRequirements()` |
| `services/kba.ts` | `KBADelegate` | `getPredefinedQuestions()`, `submitKbaAnswers()`, `validateKbaAnswers()` |

**Realm URL convention:** All realm-scoped endpoints use `/json/{realm}/endpoint` format (e.g., `/json/root/authenticate`, `/json/b2c/clients/selfservice/forgottenPassword`). Realm is passed as `root` or `b2c/clients` (no leading slash, no `/realms/` prefix).

These become the new shared commons library, consumable by openam-ui-ria (Vue),
openam-ui-js-sdk (React), and future modules. Key design decisions:
- `ThemeConfig` passed as parameter to `theme.ts` (not imported directly)
- `i18n.ts` is thin vue-i18n wrapper (no cookie detection, no Handlebars helpers)
- `events.ts` uses synchronous dispatch (no setTimeout/Deferred)
- `config.passwords` and `HEADER_PARAM_REAUTH` dropped (dead code in OpenAM)
- `errorsHandlers` suppression map preserved in `api.ts` for legacy callers
- New user services (3-3a) do NOT use `errorsHandlers` — all errors propagate to `useAlert().danger()`

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

### Common Components Migration (Task 3-2)

Migrated shared Backbone components to Vue 3. Key decisions:

- **JSON Schema Form System**: Kept vendored JSONEditor 0.7.23 (global IIFE, copied to `vendor/`).
  Ported `JSONSchema`/`JSONValues` models to pure TypeScript. Created `JSONEditorTheme.ts`
  eliminating jQuery calls (`$(input).prop("type")` → `input.type`,
  `$(element).addClass/removeClass` → `element.classList.add/remove`). Registered theme via
  `JSONEditor.defaults.themes.openam` in Vue component `onMounted()`. Parent interaction via
  `defineExpose({ isValid, getData, setData })` — matches legacy Backbone API.
- **Lodash 3→4 Migration**: `_.pick(obj, predicate)` removed in lodash 4; replaced with
  `_.pickBy()`. `_.omit(obj, predicate)` was recursive in lodash 3 but not in lodash 4;
  implemented `recursiveOmitBy()` helper for `removeUnrequiredProperties()`.
- **BootstrapDialog → ConfirmDialog.vue**: Created `useDialog()` composable with Promise-based
  `confirm()` API. Covers "simple confirm" and "dynamic content" patterns. "View redirection"
  pattern (`self.element = dialog.message`) deferred to task 3-3/3-4 view migration.
- **Messages/Toast → useAlert expansion**: Added `response` parameter (extracts
  `responseJSON.message`), type constants (`TYPE_DANGER`/`TYPE_INFO`/etc.), deduplication,
  legacy dismiss formula (`2500ms + length * 20ms`). `AlertContainer.vue` updated with
  `v-html` + DOMPurify sanitization for raw HTML messages.
- **TreeNavigation**: Skipped — existing `RealmLayout.vue`, `ServerLayout.vue`, etc. already
  implement sidebar navigation via Vue Router.
- **Footer**: Skipped — `AppFooter.vue` and `LoginFooter.vue` already migrated.
- **PanelComponent/TabComponent**: Deferred to tasks 3-3/3-4 (view-specific helpers).

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
│   │   │   ├── main.ts               # SPA bootstrap (serverinfo → session check → i18n → theme → mount)
│   │   │   ├── App.vue               # Root layout (AppHeader + AlertContainer + router-view + AppFooter)
│   │   │   ├── authorize-main.ts     # main-authorize UMD entry (Vite library mode)
│   │   │   ├── device-main.ts        # main-device UMD entry (Vite library mode)
│   │   │   ├── router/
│   │   │   │   ├── index.ts          # 90 named routes (hash mode, auth guards)
│   │   │   │   └── guards.ts         # authGuard + defaultRouteGuard
│   │   │   ├── composables/
│   │   │   │   ├── useAuth.ts        # Reactive auth state (loggedUser, roles, isAuthenticated)
│   │   │   │   ├── useRealm.ts       # Realm from URL param (decoded %2F)
│   │   │   │   ├── useAlert.ts       # Alert queue: response parsing, dedup, dismiss formula
│   │   │   │   └── useDialog.ts      # Promise-based confirm/cancel dialog API
│   │   │   ├── services/             # Pure TS commons extraction
│   │   │   │   ├── api.ts
│   │   │   │   ├── authN.ts          # Authentication (begin, submitRequirements)
│   │   │   │   ├── config.ts         # + version field in GlobalData
│   │   │   │   ├── constants.ts
│   │   │   │   ├── dashboard.ts      # Trusted devices, OATH, applications
│   │   │   │   ├── events.ts
│   │   │   │   ├── i18n.ts
│   │   │   │   ├── kba.ts            # KBA questions and answers
│   │   │   │   ├── logout.ts         # REST logout + cookie cleanup + page reload
│   │   │   │   ├── oauth2.ts
│   │   │   │   ├── selfService.ts    # Password reset, forgot username, registration
│   │   │   │   ├── session.ts        # Session info, destroy, properties
│   │   │   │   ├── theme.ts
│   │   │   │   ├── themeConfiguration.ts
│   │   │   │   ├── token.ts          # OAuth2 token CRUD
│   │   │   │   ├── uma.ts            # UMA resources, labels, requests, history
│   │   │   │   ├── user.ts           # User profile CRUD, changePassword
│   │   │   │   └── jsonSchema/
│   │   │   │       ├── index.ts              # Re-exports + iteratees (lodash 3→4 compatible)
│   │   │   │       ├── JSONSchema.ts         # JSON Schema model (ported from AMD)
│   │   │   │       ├── JSONValues.ts         # JSON Values model (ported from AMD)
│   │   │   │       ├── schemaTransforms.ts   # Boolean/enum/password transforms
│   │   │   │       └── JSONEditorTheme.ts    # Bootstrap theme (jQuery eliminated)
│   │   │   ├── vendor/
│   │   │   │   └── jsoneditor-0.7.23-custom.js  # Vendored JSONEditor library
│   │   │   ├── types/
│   │   │   │   ├── authorize.d.ts
│   │   │   │   ├── device.d.ts
│   │   │   │   ├── router.d.ts       # RouteMeta augmentation (roles, navGroup, view)
│   │   │   │   ├── uma.d.ts          # UMA resource sets, labels, requests, pagination
│   │   │   │   └── user.d.ts         # User profile, auth callbacks, KBA, dashboard
│   │   │   ├── components/
│   │   │   │   ├── AppHeader.vue     # Bootstrap 3 navbar (logo, nav links, user dropdown)
│   │   │   │   ├── AppFooter.vue     # Mailto, copyright, version (admin-only)
│   │   │   │   ├── AlertContainer.vue # Fixed-position alert toast (v-html + DOMPurify)
│   │   │   │   └── common/
│   │   │   │       ├── LoginHeader.vue
│   │   │   │       ├── LoginFooter.vue
│   │   │   │       ├── ConfirmDialog.vue       # Bootstrap 3 modal (teleport to body)
│   │   │   │       ├── JSONSchemaForm.vue      # JSONEditor wrapper (defineExpose)
│   │   │   │       ├── TogglableJSONSchemaForm.vue  # Enable/disable toggle
│   │   │   │       ├── FlatJSONSchemaForm.vue  # Non-collection schemas
│   │   │   │       ├── GroupedJSONSchemaForm.vue  # Collection schemas
│   │   │   │       ├── JSONSchemaFormFooter.vue # Save/revert buttons
│   │   │   │       ├── InlineEditTable.vue     # Editable table (one row at a time)
│   │   │   │       ├── InlineEditRow.vue       # Row: readonly/edit/new modes
│   │   │   │       └── SelectInput.vue         # Custom combobox with search
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
│   │   │   │   ├── errors/
│   │   │   │   │   ├── NotFoundView.vue   # 404 page
│   │   │   │   │   └── ForbiddenView.vue  # 403 page
│   │   │   │   ├── realm/
│   │   │   │   │   └── RealmLayout.vue    # Sidebar: dashboard/auth/services/sessions/authorization/scripts
│   │   │   │   ├── server/
│   │   │   │   │   ├── ServerLayout.vue         # Sidebar: 8 server edit sections
│   │   │   │   │   └── ServerDefaultsLayout.vue # Sidebar: 7 server defaults sections
│   │   │   │   ├── uma/
│   │   │   │   │   ├── LabelTreeLayout.vue  # Sidebar: my resources/shared/starred/labels
│   │   │   │   │   ├── resources/           # Placeholder stubs (5 views)
│   │   │   │   │   ├── history/             # Placeholder stubs (1 view)
│   │   │   │   │   ├── requests/            # Placeholder stubs (2 views)
│   │   │   │   │   └── share/               # Placeholder stubs (1 view)
│   │   │   │   ├── common/
│   │   │   │   │   ├── DefaultView.vue
│   │   │   │   │   └── EnableCookiesView.vue
│   │   │   │   ├── user/             # Placeholder stubs (12 views)
│   │   │   │   │   ├── ProfileView.vue
│   │   │   │   │   ├── dashboard/DashboardView.vue
│   │   │   │   │   ├── oauth2/TokensView.vue
│   │   │   │   │   └── ... (9 more)
│   │   │   │   └── admin/            # Placeholder stubs (36 views across 12 subdirs)
│   │   │   │       ├── realms/
│   │   │   │       ├── authentication/
│   │   │   │       ├── services/
│   │   │   │       ├── sessions/
│   │   │   │       ├── authorization/
│   │   │   │       ├── scripts/
│   │   │   │       ├── applications/
│   │   │   │       ├── api/
│   │   │   │       ├── configuration/
│   │   │   │       └── deployment/
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
│           │   ├── device.ts
│           │   └── authorize.ts
│           ├── device/
│           │   └── components.test.ts
│           ├── authorize/
│           │   └── components.test.ts
│           ├── composables/
│           │   └── useAlert.test.ts          # useAlert expanded API tests (14 tests)
│           ├── services/
│           │   ├── authN.test.ts             # Authentication service tests (8 tests)
│           │   ├── dashboard.test.ts         # Dashboard service tests (10 tests)
│           │   ├── kba.test.ts               # KBA service tests (5 tests)
│           │   ├── selfService.test.ts       # Self-service tests (5 tests)
│           │   ├── session.test.ts           # Session service tests (4 tests)
│           │   ├── token.test.ts             # Token service tests (4 tests)
│           │   ├── uma.test.ts               # UMA service tests (11 tests)
│           │   ├── user.test.ts              # User service tests (6 tests)
│           │   └── jsonSchema/
│           │       ├── JSONSchema.test.ts    # JSON Schema model tests (14 tests, ported)
│           │       └── JSONValues.test.ts    # JSON Values model tests (19 tests, ported)
│           └── smoke.test.ts         # Updated: stubs AppHeader/AppFooter/AlertContainer
```

## File Counts

| Category | Current | Migrated | Remaining |
|----------|---------|----------|-----------|
| AMD `.js` files | 209 | 0 | 209 (rewrite to Vue SFCs) |
| ES6 `.jsm` files | 31 | 0 | 31 (rewrite to `.ts`) |
| JSX `.jsx` files | 15 | 0 | 15 (rewrite to `.vue`) |
| Handlebars templates | 187 | 0 | 187 (codemod + manual) |
| LESS stylesheets | 21 | 0 | 21 (keep as Vite entry points) |
| Vue components | 8 | 94 (incl. 64 placeholders) | Real views pending |
| Vue composables | 0 | 4 (+useDialog.ts) | — |
| Vue services | 7 | 20 (+authN, dashboard, kba, selfService, session, token, uma, user) | — |
| Vue types | 3 | 5 (+uma.d.ts, user.d.ts) | — |
| Vue router routes | 0 | 90 named | — |
| Test files | 9 | 21 (177 tests) | New tests for composables/guards/layouts |

## Key Dependencies

### New (to install)

```json
{
  "dependencies": {
    "vue": "^3.5",
    "vue-router": "^4.5",
    "i18next": "^24.0",
    "vue-i18n": "^11.0",
    "axios": "^1.8",
    "@tanstack/vue-table": "^8.21"
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
    "i18next-http-backend": "^3.0",
    "@types/lodash": "^4.17"
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
| Lodash 3→4 breaking changes | Medium | High | `_.pick`/`_.omit` with predicates no longer recursive in lodash 4; `_.pickBy`/`_.omitBy` used instead, `recursiveOmitBy()` helper for nested omit |
