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
1. `main-device.js` (88 lines) → device auth pages
2. `main-authorize.js` (162 lines) → OAuth2 consent pages
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
| `services/theme.ts` | `ThemeManager` | `getTheme(config, realm?, isAdmin?)` with vanilla DOM |
| `services/themeConfiguration.ts` | `ThemeConfiguration` | Typed theme config data |
| `services/events.ts` | `EventManager` | Synchronous `on/off/emit/once` emitter |

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
- **Maven** assembles both into the final ZIP artifact

Once all entry points are migrated, Grunt is removed.

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
│   │   │   ├── router/
│   │   │   ├── composables/
│   │   │   ├── services/             # Pure TS commons extraction
│   │   │   ├── views/
│   │   │   │   ├── device/           # main-device entry point
│   │   │   │   ├── authorize/        # main-authorize entry point
│   │   │   │   ├── user/             # User-facing views
│   │   │   │   └── admin/            # Admin console views
│   │   │   ├── components/
│   │   │   ├── i18n/
│   │   │   └── assets/
│   │   └── resources/                # SHARED: CSS, images, locales
│   │       ├── css/
│   │       ├── templates/            # Handlebars (being replaced)
│   │       ├── locales/
│   │       └── images/
│   └── test/
│       ├── js/                       # OLD: Karma tests
│       └── vue/                      # NEW: Vitest tests
```

## File Counts

| Category | Current | Migration Effort |
|----------|---------|-----------------|
| AMD `.js` files | 209 | Rewrite to Vue SFCs |
| ES6 `.jsm` files | 31 | Rewrite to `.ts` |
| JSX `.jsx` files | 15 | Rewrite to `.vue` |
| Handlebars templates | 187 | Codemod + manual → `<template>` |
| LESS stylesheets | 21 | Keep as Vite entry points |
| Test files | 18 | Rewrite in Vitest |
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
    "less": "^4.0"
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
