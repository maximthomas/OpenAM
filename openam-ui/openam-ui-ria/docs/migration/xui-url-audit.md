<!--
  The contents of this file are subject to the terms of the Common Development and
  Distribution License (the License). You may not use this file except in compliance with the
  License.

  You can obtain a copy of the License at legal/CDDLv1.0.txt. See the License for the
  specific language governing permission and limitations under the License.

  When distributing Covered Software, include this CDDL Header Notice in each file and include
  the License file at legal/CDDLv1.0.txt. If applicable, add the following below the CDDL
  Header, with the fields enclosed by brackets [] replaced by your own identifying
  information: "Portions copyright [year] [name of copyright owner]".

  Copyright 2026 3A Systems LLC.
-->

# /XUI URL Audit (P0-6)

Produced by task P0-6. This is a **static reference document** — do not update it as the migration progresses; use it as the stable input to P1-10 (building the route-compat/redirect map) and P4-2 (final coverage verification).

## Purpose

Classify every `/XUI` deep-link reference in the repository into:

- **Must-preserve** — permanent client-side redirects the new app must implement from day one (URLs hardcoded in server-side code or embedded in emails that cannot be changed without a release).
- **Best-effort** — links that appear only in docs or internal console navigation; updated in-place per slice, no redirect required.
- **Infrastructure** — plumbing that must change at cutover but is not a user-facing deep link and does not belong in the redirect map.

---

## Must-preserve (permanent redirects in the new app)

These URL patterns are either embedded in server-side email templates or hardcoded in Java/XML as redirect targets. External systems (OAuth2 clients, SAML SPs, email inboxes) hold them; the server cannot fix them without a release.

| URL pattern | Source file(s) | Why |
|---|---|---|
| `/XUI/#login` | `chap-auth-services.adoc`, `chap-federation.adoc`, `SAML2ProxyTest.java` (constant) | Primary auth entry point; referenced in OAuth2/SAML redirect URI configs and bookmarks |
| `/XUI/#login/{realm}` | `chap-federation.adoc`, `chap-auth-services.adoc` | Realm-specific login via sub-path |
| `/XUI/?realm={realm}#login` | `RealmHelper.js` (comment), docs | Realm-qualified login via query param |
| `/XUI/#login&realm={realm}` | `RealmHelper.js` (comment) | Alternate realm-qualified login (hash-query form) |
| `/XUI/#login?{query}` (goto, gotoOnFail, service, locale, …) | `chap-auth-services.adoc` | SAML/OAuth2 post-login redirect parameters; `service=` targets authentication chains by name |
| `/XUI/#logout/` | `AppConfiguration.js` hash route `#logout/` | Session logout; may be bookmarked or called by external SSO integrations |
| `/XUI/?realm=${realm}#register/` | `selfService.xml` line 523 | **Email-embedded** — self-service registration confirmation link; users receive this in email |
| `/XUI/?realm=${realm}#passwordReset/` | `selfService.xml` line 535 | **Email-embedded** — forgotten-password confirmation link; users receive this in email |
| `/XUI/?realm={realm}#uma/share/{resourceSetId}` | `OAuth2UrisFactory.java` line 165 | Hardcoded server-side UMA share link; ends up in UMA pending-request emails |
| `/XUI/#uma/requests/{id}` | `UmaProvider.properties` line 57 | **Email-embedded** — UMA resource-sharing request approval link |
| `/XUI/confirm.html` | `RestSecurity.xml` lines 87, 123 | Default value for the self-service email-confirmation page; referenced in REST security config |
| `/XUI/?realm={realm}#{route}` | `XuiRedirectHelper.java` (template), `RedirectToRealmHomeViewBean.java`, `ConfigureSalesForceAppsFinishWarningViewBean.java` | Server-side 302 redirect target; realm dashboard entry (`../XUI#realms/{realm}/dashboard`) |

**Concrete realm-dashboard forms** (from the Java console redirect helpers):
- `../XUI#realms/%2F/dashboard` (root realm)
- `../XUI#realms/%2FrealmName/dashboard` (named realm)

**Total: ~10 distinct patterns, ~20 concrete URL shapes when realm/query variants are counted.**

### Notes for P1-10

Implement in this order:
1. Auth first (`#login` all variants including `goto`/`gotoOnFail`/`service`) — Phase 1 login slice depends on these.
2. Self-service callbacks (`#register/`, `#passwordReset/`) — Phase 1 / Phase 2 boundary; needed before self-service goes live.
3. UMA links (`#uma/share/{id}`, `#uma/requests/{id}`) — Phase 2.
4. `confirm.html` static redirect — Phase 2 (self-service).
5. Realm dashboard redirects — Phase 3 (admin).
6. `#logout/` — Phase 1 (needed as soon as the login slice ships).

---

## Best-effort (update in-place at cutover, no redirect needed)

These references appear only in documentation or internal admin-console navigation. They can be updated in a doc PR or a console code change when the relevant slice lands. No permanent redirect is required.

| Area | Source(s) | Action |
|---|---|---|
| Admin deep links in docs: `/XUI/#realms/…`, `/XUI/#configure/…`, `/XUI/#deployment/…` | `chap-auth-services.adoc` and other admin-guide AsciiDoc/DocBook files (~50 occurrences) | Update examples in docs per phase as screens migrate |
| `propertiesViewBeanURL` in service descriptors: `../XUI/%23realms/{0}/scripts/edit/{1}` | `scripting.xml`, `amAuthScripted.xml`, `amAuthDeviceIdMatch.xml`, `OAuth2Provider.xml` | Update when the scripting/admin screen migrates (Phase 3) |
| `/XUI/#dashboard/` | `chap-dashboard.adoc` | Update doc when user dashboard migrates (Phase 2) |
| `/XUI/#oauth2/tokens` | docs + route-ownership map | Update doc when OAuth2 tokens view migrates (Phase 2) |
| Custom-UI deployment examples: `/XUI/themes/`, `/XUI/config/ThemeConfiguration.js`, `/XUI/templates` | `chap-custom-ui.adoc`, `install-guide/chap-custom-ui.adoc` | Update docs at/after cutover |

---

## Infrastructure changes (cutover only — not redirect map items)

These are plumbing references that must change at cutover but are not user-facing deep links.

| Item | File | Action at cutover |
|---|---|---|
| `XUIFilter` servlet mapping `/XUI/*` and filter wiring | `openam-server-only/src/main/webapp/WEB-INF/web.xml` lines 87, 179, 190, 196, 209, 213; `XUIFilter.java` line 74 | Remap to serve the new app from `/XUI`; or extend the filter to serve `openam-ui-eui` at `/XUI` |
| `OAuth2.java` referer path detection: `request…contains("/XUI/")` | `openam-auth-oauth2/…/OAuth.java` lines 189, 197 | Update the path check to match the new app mount after cutover |
| FreeMarker templates `data-main="…/XUI/main-authorize"` and `data-main="…/XUI/main-device"` | `openam-oauth2/src/main/resources/templates/authorize.ftl`, `CodeThanks.ftl`, `CodeVerificationForm.ftl`, `error.ftl`, `popup/authorize.ftl`, `touch/authorize.ftl` | Replace RequireJS bootstrap with the new Vite bundle entry point |
| Maven assembly `outputDirectory: ${build.directory}/XUI` | `openam-server-only/pom.xml` | Swap to assemble from `openam-ui-eui` artifact at `/XUI` instead of `openam-ui-ria` |
| Grunt `target/XUI` and `$OPENAM_HOME/XUI` | `Gruntfile.js` lines 39, 79 | Legacy build; goes away when `openam-ui-ria` module is deleted (Phase 4) |
| `XUIState.java` + `SystemProperties.get("XUI.enable")` | `openam-core/…/XUIState.java` | Evaluate whether the XUI-enable flag needs a successor or can be removed |
| `ResourceSetPolicyUrlUpgradeStep` `oauth2/XUI` → `XUI` replacement | `openam-upgrade/…/ResourceSetPolicyUrlUpgradeStep.java` lines 109, 145 | Historical upgrade step; leave as-is but note the `/XUI` prefix it normalises to is the canonical path |
