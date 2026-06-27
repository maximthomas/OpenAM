# ADR-0002: Self-contained new app; reusable core as workspace package, extracted to commons later

Status: Accepted · Date: 2026-06-27

## Context
XUI references **45 distinct `org.forgerock/commons/...` modules** (Router, EventManager, SessionManager, ProcessConfiguration, Constants, base views) from the external Maven artifact `org.openidentityplatform.commons.ui:user`. The new app needs session/auth, routing, an app shell, and config — today all provided by that artifact via RequireJS AMD.

## Decision
The new app depends on **zero** Commons UI. Reimplement only the primitives a slice actually needs as thin TypeScript modules, placed in a local **workspace package `commons-ui-next`** (`@openidentityplatform/commons-ui-next`) with **no app-specific imports**. Once battle-tested in XUI, **extract `commons-ui-next` to the Open Identity Platform commons repo** and consume it as a published artifact (npm + optional Maven www zip). The legacy XUI keeps using the old `commons.ui:user` artifact untouched throughout.

## Consequences
- No fragile AMD↔ESM bridge; the new app is never chained to RequireJS.
- Primitives are proven in one real consumer before being promoted — safer than designing a shared lib speculatively.
- Until extraction, the primitives live in this repo, so other products can't reuse them yet (acceptable: XUI is the first/only consumer).
- Extraction is a move-and-publish + import flip, not a refactor — enforced by the no-app-imports boundary.

## Alternatives considered
- **Embed React into the Commons shell via an AMD↔ESM bridge** — less early duplication but chains the whole migration to RequireJS/Commons; bridge is fiddly. Rejected.
- **Fork Commons UI into this repo and migrate it too** — full control but balloons scope; other products consume that artifact and would diverge. Rejected.
