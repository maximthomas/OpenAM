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

## Cutover lever

The `OpenAM` `HttpFrameworkServlet` in
`openam-server-only/src/main/webapp/WEB-INF/web.xml` uses
`routing-base=context_path`, so each area moves by adding an `HttpRouteProvider` for
its leading path segment (+ `META-INF/services` registration) and moving its
`<servlet-mapping>` from `ForgeRockRest` to `OpenAM`.

## Status tracking

Update the phase-status table in [plan.md](plan.md) as phases land.
