# ADR-0006: react-bootstrap 5 + Sass; TanStack Table; rjsf

Status: Accepted · Date: 2026-06-27

## Context
Legacy UI is Bootstrap 3.3.5 + react-bootstrap + LESS, with 187 Handlebars templates, `backgrid` data grids, and JSON-schema-driven config forms via `jsoneditor`. New and legacy run side by side for months, so a jarring mid-migration redesign is bad UX.

## Decision
- **Components:** react-bootstrap (Bootstrap 5) — already used in existing `.jsx`.
- **Styling:** Sass (modern successor to the legacy LESS); migrate LESS → Sass.
- **Data grids:** TanStack Table (replaces `backgrid`).
- **JSON-schema forms:** rjsf (`@rjsf/core` + ajv8 validator) — replaces `jsoneditor`.
- Defer any visual redesign until after legacy is removed.

## Consequences
- Closest visual continuity with `/XUI` during coexistence; smallest design-parity effort.
- **rjsf vs `jsoneditor` parity is the biggest risk** (custom widgets, conditional schemas) — gap analysis required in Phase 2 before the admin bulk; may need a custom-widget set in `commons-ui-next`.

## Alternatives considered
- **Modern lib (Mantine/MUI)** — better end-state DX but a visual redesign; `/EUI` and `/XUI` diverge during coexistence. Rejected for now (revisit post-cutover).
- **Tailwind + headless (shadcn/Radix)** — max control but biggest departure and most upfront design-system work. Rejected.
