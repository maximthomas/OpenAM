# ADR-0003: Login/auth as the first slice

Status: Accepted · Date: 2026-06-27

## Context
Strangler-fig needs a first slice that proves the whole pattern end-to-end (new shell + session + routing + side-by-side deploy) before tackling the 13.4k-LOC admin bulk.

## Decision
Migrate the **login / authentication flow first** (`RESTLoginView`, login dialog, `anonymousProcess`: password reset, self-registration, forgot username).

## Consequences
- Forces building the reusable `commons-ui-next` core (SessionService, http client, i18n, shell) that every later slice depends on — the riskiest plumbing is proven first.
- Self-contained against AM's auth REST (`/json/authenticate`), so the slice can be built and validated without touching admin/Commons-coupled areas.
- Least Commons-coupled area, so the first side-by-side deploy is the cleanest test of the coexistence mechanism (ADR-0004).

## Alternatives considered
- **User self-service first** — real value, smaller, but still needs the core built and defers the riskiest plumbing. Rejected as first slice (it is Phase 2).
- **One admin leaf first** — tackles the hard area early and reuses existing `.jsx`, but admin is the most Commons-coupled, so you fight shell/nav/realm-context on day one. Rejected.
