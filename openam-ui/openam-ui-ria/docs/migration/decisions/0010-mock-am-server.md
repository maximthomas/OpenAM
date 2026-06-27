# ADR-0010: Mock AM backend for standalone browser dev & test of both UIs

Status: Accepted · Date: 2026-06-27

## Context
Developing and testing either UI normally requires a running OpenAM (Java/Tomcat) backend — slow to start, heavy, and stateful. We want to run **both** the legacy XUI (`/XUI`) and the new EUI (`/EUI`) **in a browser with no OpenAM**, for fast inner-loop dev, deterministic UI tests, and demos. MSW (Mock Service Worker) is already the mock layer for the new app's Vitest tests (ADR-0005 testing, tasks P1-9), so the AM REST contract can be modeled once and reused everywhere.

## Decision
Model the AM REST surface **once** as a set of **MSW request handlers** (the single source of truth): the authenticate callback flow (`/json/authenticate`), `/json/serverinfo/*`, `/json/sessions`, realm-scoped config CRUD, and the endpoints each migrated slice touches. Run those same handlers in **three modes**:

1. **Vitest (node)** — `setupServer`, for unit/integration tests of `eui`/`commons-ui-next`. (already planned)
2. **EUI in-browser** — `setupWorker` (service worker), toggled by an env flag (e.g. `VITE_MOCK=1`); `npm run dev:mock` serves the new UI at `/EUI` against the mock with no backend.
3. **Standalone mock server** — the same handlers exposed over real HTTP via `@mswjs/http-middleware` + a tiny Node/Express server on a port. The **legacy XUI** is served as static compiled assets and **proxies AM calls to this mock server** (no `OPENAM_HOME`/Tomcat). Also usable by Playwright/manual testing and `curl`.

Handlers + fixtures **grow per slice**, alongside the route-compat map. Seed realistic fixtures by occasionally **recording real AM responses** to limit contract drift.

## Consequences
- Either UI boots in a browser without OpenAM; tests and demos are deterministic and infra-free.
- One contract powers node tests, the EUI worker, and the standalone server — no duplicated mocks.
- The legacy XUI gets a no-AM harness (static serve + proxy) without touching its bootstrap.
- Cost: the mock can drift from real AM REST — mitigate with recorded fixtures and a periodic check against a real AM.

## Alternatives considered
- **Off-the-shelf mock (Mockoon / Prism / json-server / WireMock)** — no-code, but no reuse with Vitest, and AM's stateful authenticate callback flow is awkward to express. Rejected as the primary; may still record fixtures from one.
- **Full AM in Docker for local dev** — most faithful but heavy and slow; defeats the "no OpenAM" goal. Keep for integration/e2e, not the inner loop.
- **Separate mocks per app** — duplication and divergence between what XUI and EUI mock. Rejected in favor of one shared handler set.
