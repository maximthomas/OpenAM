# ADR-0012: Deployment-time customization parity deferred until after cutover

Status: Accepted · Date: 2026-07-03

## Context
Legacy XUI supports rebrand-without-rebuild deployment customization: `config/ThemeConfiguration.js` and
`config/AppConfiguration.js` are deliberately excluded from the r.js optimization step so a deployment can
override them post-build; `/XUI/themes/` holds swappable theme assets; per-auth-module template overrides
live at `templates/openam/authn/${stage}.html`; and `confirm.html` is a static, independently-editable
self-service confirmation page. Together these let a deployment rebrand or reshape auth-module UI without
rebuilding the app.

Vite bundles everything at build time — there is no equivalent "excluded from optimization, edit the
output" mechanism, and no runtime-pluggable template-per-stage system exists in the new app. Building one
now has no validated consumer demand; the 2026-07 docs review found this gap had no decision recorded
anywhere (finding A5).

## Decision
Deployment-time customization parity is **out of scope until after cutover**. Revisit then with a
runtime-config/CSS-custom-properties approach (e.g. a runtime-loaded theme config + CSS custom properties
for rebrand, rather than build-time-excluded JS files).

## Consequences
- Deployments that currently customize `ThemeConfiguration.js`/`AppConfiguration.js`, `/XUI/themes/`,
  per-stage auth templates, or `confirm.html` **cannot cut over blindly** — their customizations will not
  carry over to the new app as-is.
- A risk row is added to `MIGRATION.md` §7 and a caveat line to §8 (definition of done) so this is visible
  before cutover planning.
- The `xui-url-audit.md` "best-effort" custom-UI rows (`/XUI/themes/`, `/XUI/config/ThemeConfiguration.js`,
  `/XUI/templates`) point here for the underlying rationale.

## Alternatives considered
- **Design a customization mechanism now** — rejected: no validated demand yet during the login/auth slice;
  building speculative configurability this early risks the wrong shape. Revisit once more of the app is
  migrated and real deployment customization needs (if any) are known.
