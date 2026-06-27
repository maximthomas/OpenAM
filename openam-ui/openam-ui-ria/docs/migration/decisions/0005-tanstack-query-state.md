# ADR-0005: TanStack Query + light client state; drop Redux

Status: Accepted · Date: 2026-06-27

## Context
The admin area is almost entirely CRUD against AM REST endpoints (`/json/...`). Legacy uses Backbone models/collections (+ `backbone-relational`) and a small Redux store.

## Decision
Manage **server state with TanStack Query** (`useQuery`/`useMutation`), and **client/session/UI state with React Context or Zustand**. Drop Redux and Backbone models entirely.

## Consequences
- Caching, request dedup, retries, and invalidation come from the library — admin screens become thin query/mutation wrappers.
- Least boilerplate per feature for this app's shape.
- Team must learn TanStack patterns (cache keys, invalidation) instead of Redux.

## Alternatives considered
- **Redux Toolkit + RTK Query** — natural path from today's small Redux store, one unified store, but more boilerplate/ceremony for the same CRUD. Rejected.
- **Context + custom fetch hooks only** — fewest deps but reinvents caching/dedup/invalidation across many admin screens. Rejected.
