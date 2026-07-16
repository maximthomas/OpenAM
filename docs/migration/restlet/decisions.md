# Restlet → CHF Migration: Decision Record

Restlet removal from OpenAM, planned 2026-07-08 on branch `features/restlet-migration`.
This is the durable summary of the locked decisions; the executable detail lives in
[plan.md](plan.md) and the research backing it in [inventory.md](inventory.md).

## Locked decisions

- **Target**: CHF Handlers (`org.forgerock.http`) — `HttpRouteProvider` SPI +
  `Endpoints.from` annotated POJOs.
- **Strategy**: incremental strangler, one endpoint area per shippable green commit, in
  order: XACML → core `OAuth2Request` re-plumb → UMA → OAuth2/OIDC (flip in the last
  sub-phase) → WebFinger/stragglers → outbound scripting client (`java.net.http`) →
  delete `openam-restlet` + `transform-jakarta/restlet-parent-jakarta`.
- **Scope**: full Restlet removal, including outbound clients and the vendored
  jakarta-transformed fork.
- **New-class conventions** (locked 2026-07-16, during 3b): every class *authored* by this
  migration goes under **`org.openidentityplatform.openam.<area>`**, mirroring the legacy
  structure it replaces (`org.forgerock.oauth2.core` → `org.openidentityplatform.openam.oauth2.core`;
  3c's response layer → `…openam.oauth2.http`; Phase 4 → `…openam.uma`). New files carry the CDDL
  header with **`Copyright 2026 3A Systems LLC.`** and **no `@since` tag**. Do not copy the header or
  `@since` from the class being ported — that is the failure mode.
  - *Applies to new classes only.* Classes **modified** in place keep their existing package and
    header; add a `Portions copyright … 3A Systems LLC.` line as the surrounding files do.
  - *Exception — tests needing package-private access.* A test stays in the package of its subject
    when it calls package-private members: `OAuth2GuiceModuleTest` lives in
    `org.forgerock.openam.oauth2.guice` because it invokes the module's package-private `@Provides`
    methods directly.
  - *Applied retroactively to 3a (done in 3b).* `ChfOAuth2Request`, `BasicAuthHeader` and
    `ChfOAuth2RequestTest` shipped into `org.forgerock.oauth2.core` before this rule existed; 3b
    relocated all three to `org.openidentityplatform.openam.oauth2.core` and dropped their
    `@since 15.2.0` tags. Six files took import-only updates (`OAuth2Request`, `OAuth2RequestFactory`,
    `RestletOAuth2Request`, `ClientCredentialsReader`, `IdTokenInfo`, plus two tests).
  - *The Restlet shims stay put.* `RestletOAuth2Request`/`RestletOAuth2RequestTest` were also authored
    by 3a, but are deliberately **not** moved: the new package is for target-state code, and these exist
    only to hold Restlet-coupled logic until Phase 5d deletes them. Same reasoning for any future
    `Restlet*` shim.

## Cutover lever

The `OpenAM` `HttpFrameworkServlet` in
`openam-server-only/src/main/webapp/WEB-INF/web.xml` uses
`routing-base=context_path`, so each area moves by adding an `HttpRouteProvider` for
its leading path segment (+ `META-INF/services` registration) and moving its
`<servlet-mapping>` from `ForgeRockRest` to `OpenAM`.

## Status tracking

Update the phase-status table in [plan.md](plan.md) as phases land.
