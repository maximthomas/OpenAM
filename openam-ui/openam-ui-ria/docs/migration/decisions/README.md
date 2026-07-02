# Architecture Decision Records — XUI migration

Each ADR captures one locked decision, its context, and trade-offs. To change a decision, add a new ADR that **supersedes** the old one (mark the old `Superseded by ADR-NNNN`) — don't silently diverge.

Use the table below to load **only** the ADR you need; don't read all eleven (`context.md` already summarizes the gist).

| ADR | Decision | Status |
|-----|----------|--------|
| [0001](0001-incremental-strangler-fig.md) | Incremental strangler-fig migration | Accepted |
| [0002](0002-self-contained-commons-extract-later.md) | Self-contained new app; reusable core as workspace package, extracted to commons later | Accepted |
| [0003](0003-first-slice-login.md) | Login/auth as the first slice | Accepted |
| [0004](0004-coexistence-separate-mounts.md) | Separate mounts (temporary `/EUI` + `/XUI`) + full-page handoff; final path `/XUI` | Accepted |
| [0005](0005-tanstack-query-state.md) | TanStack Query + light client state; drop Redux | Accepted |
| [0006](0006-react-bootstrap-sass-ui.md) | react-bootstrap 5 + Sass; TanStack Table; rjsf | Accepted |
| [0007](0007-adopt-js-sdk-stack.md) | Target a modern React / Vite / TypeScript stack | Accepted |
| [0008](0008-preserve-xui-urls.md) | New UI served at `/XUI`, preserving legacy deep-link URLs | Superseded by 0011 |
| [0009](0009-new-app-separate-module.md) | New app as a separate Maven module `openam-ui-eui` (rename `app-next` → `eui`) | Accepted |
| [0010](0010-mock-am-server.md) | Mock AM backend (shared MSW handlers) for standalone browser dev/test of both UIs | Accepted |
| [0011](0011-hash-routing-for-url-parity.md) | New app uses HashRouter for `/XUI` URL parity with the legacy hash-routed app | Accepted |

_Template: Context → Decision → Consequences → Alternatives considered._
