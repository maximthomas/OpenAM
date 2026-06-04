# AGENTS.md — openam-ui

> Guidance for AI agents and contributors working in the `openam-ui` module of
> [OpenIdentityPlatform/OpenAM](https://github.com/OpenIdentityPlatform/OpenAM/tree/master/openam-ui).


---

## Work Rules
- Work on one feature at a time
- Only start the next feature after the current one passes end-to-end verification
- Don't "also refactor" feature B while implementing feature A

---

## Module Overview

`openam-ui` is the **frontend parent module** of OpenAM. It is a Maven POM-only aggregator that owns two sub-modules and all shared frontend dependency resolution:

| Sub-module | Artifact ID | Role |
|---|---|---|
| `openam-ui-ria` | `openam-ui-ria` | Rich Internet Application — the full admin & end-user web UI |
| `openam-ui-api` | `openam-ui-api` | REST API client library (Axios-based) bundled as a JAR |

The parent POM (`openam-ui/pom.xml`) pre-fetches all third-party JS/CSS libraries via `maven-external-dependency-plugin` before either sub-module build starts. Node.js `v20.12.2` / npm `v10.5.0` are installed into the working directory by `frontend-maven-plugin v1.15.0`.

---

## Repository Layout

```
openam-ui/
├── pom.xml                     # Aggregator POM; downloads all JS/CSS deps
├── openam-ui-ria/
│   ├── pom.xml
│   ├── Gruntfile.js            # Build orchestration (legacy Backbone)
│   ├── package.json
│   ├── vite.config.ts          # Vite configuration (Vue 3)
│   ├── vitest.config.ts        # Vitest configuration
│   └── src/
│       ├── main/
│       │   ├── js/             # OLD: Backbone AMD (Grunt builds)
│       │   │   ├── org/forgerock/openam/
│       │   │   └── org/forgerock/commons/
│       │   └── vue/            # NEW: Vue 3 (Vite builds)
│       │       ├── services/   # Pure TS REST service wrappers
│       │       ├── composables/# Vue composables (useAuth, useAlert, etc.)
│       │       ├── components/ # Vue SFCs
│       │       ├── views/      # Route-level view components
│       │       ├── router/     # Vue Router 4 config + guards
│       │       └── types/      # TypeScript declarations
│       └── test/
│           ├── js/             # OLD: Karma tests
│           └── vue/            # NEW: Vitest tests
└── openam-ui-api/              # Modern REST client (Babel + Webpack + Axios)
    ├── pom.xml
    └── src/main/js/
```

---

## Code Style & Conventions

- **Vue (openam-ui-ria):** `<script lang="ts">` in all SFCs. Bootstrap 3 classes as-is. `<style scoped>` for component styles.
- **TypeScript services:** Use `RestClient` from `@/services/api`. No `errorsHandlers` suppression — errors propagate to `useAlert().danger()`.
- **LESS:** BEM-style selectors where possible. Global LESS entry points preserved for theme switching.
- **i18n:** All user-visible strings externalised to `src/main/resources/locales/en/translation.json`. Single namespace.
- **No direct CDN links at runtime:** All third-party assets go through Maven dependency pipeline.

---

## Agent Guides

Load the relevant file for your task:

| When to load | File |
|---|---|
| Build, compile, package, maven, grunt, vite | `.agents/docs/build.md` |
| Test, vitest, karma, coverage, typecheck | `.agents/docs/testing.md` |
| Dev, watch, mock server, local development | `.agents/docs/development.md` |
| Add dependency, update library, npm | `.agents/docs/dependencies.md` |
| Vue SFC, composable, service migration, realm URL | `.agents/docs/vue-migration.md` |
| Security audit, CVE check | `.agents/docs/security.md` |
| Backbone, AMD, Handlebars, legacy tasks | `.agents/docs/legacy.md` |
| Migration progress, task tracking | `.agents/docs/migration/context.md` |
| Migration task status | `.agents/docs/migration/progress.yml` |

---

## Useful References

- [OpenAM GitHub repository](https://github.com/OpenIdentityPlatform/OpenAM)
- [OpenAM Docs](https://doc.openidentityplatform.org/openam)
- [OpenAM Wiki](https://github.com/OpenIdentityPlatform/OpenAM/wiki)
- [frontend-maven-plugin docs](https://github.com/eirslett/frontend-maven-plugin)
- [RequireJS optimiser (r.js)](https://requirejs.org/docs/optimization.html)
- [Karma test runner](https://karma-runner.github.io)
- License: [CDDL-1.0](https://github.com/OpenIdentityPlatform/OpenAM/blob/master/LICENSE.md)

