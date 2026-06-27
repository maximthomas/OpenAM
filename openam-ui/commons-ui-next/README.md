# @openidentityplatform/commons-ui-next

Reusable, **app-agnostic** UI primitives for the OpenAM EUI (`openam-ui-eui`). This package
reimplements only the Commons UI primitives a migration slice actually needs, as thin TypeScript
modules with **no app-specific imports** — so it can later be extracted to the Open Identity
Platform commons repo and consumed as a published artifact (ADR-0002, phase-5).

It is an npm workspace member of `openam-ui/` and is consumed by the `eui` app **as TypeScript
source** (resolved through the `exports` map by the app's bundler — Vite/Vitest — in `bundler`
module-resolution mode). There is no separate build step.

## Modules (skeleton — filled in by later tasks)

| Subpath import                                    | Responsibility                                              | Task  |
| ------------------------------------------------- | ----------------------------------------------------------- | ----- |
| `@openidentityplatform/commons-ui-next/session`   | AM session/auth lifecycle (authenticate flow, sessions)     | P1-1  |
| `@openidentityplatform/commons-ui-next/http`      | AM REST fetch client (realm path, CSRF/auth, errors)        | P1-2  |
| `@openidentityplatform/commons-ui-next/i18n`      | i18next + react-i18next setup                               | P1-3  |
| `@openidentityplatform/commons-ui-next/shell`     | App shell (header/footer/nav) — react-bootstrap + Sass      | P1-4  |
| `@openidentityplatform/commons-ui-next/routing`   | Path-relocatable routing helpers + CrossLink                | P0-4  |

## Boundary rule

Nothing here may import from `openam-ui-eui` or any app feature. Extraction (phase-5) must be a
move-and-publish + import flip, not a refactor.
