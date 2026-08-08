/*
 * The contents of this file are subject to the terms of the Common Development and
 * Distribution License (the License). You may not use this file except in compliance with the
 * License.
 *
 * You can obtain a copy of the License at legal/CDDLv1.0.txt. See the License for the
 * specific language governing permission and limitations under the License.
 *
 * When distributing Covered Software, include this CDDL Header Notice in each file and include
 * the License file at legal/CDDLv1.0.txt. If applicable, add the following below the CDDL
 * Header, with the fields enclosed by brackets [] replaced by your own identifying
 * information: "Portions copyright [year] [name of copyright owner]".
 *
 * Copyright 2026 3A Systems LLC.
 */

package org.openidentityplatform.openam.oauth2.http;

import static org.forgerock.http.routing.RouteMatchers.requestUriMatcher;
import static org.forgerock.http.routing.RoutingMode.EQUALS;
import static org.forgerock.http.routing.RoutingMode.STARTS_WITH;
import static org.forgerock.openam.http.HttpRoute.newHttpRoute;
import static org.forgerock.openam.rest.RealmRoutingFactory.REALM_ROUTE;
import static org.openidentityplatform.openam.oauth2.audit.HttpBodyAuditor.noBodyAuditor;

import java.util.Collections;
import java.util.Set;

import jakarta.inject.Inject;
import jakarta.inject.Named;

import org.forgerock.http.Handler;
import org.forgerock.http.handler.Handlers;
import org.forgerock.http.routing.Router;
import org.forgerock.oauth2.core.OAuth2RequestFactory;
import org.forgerock.openam.audit.AuditEventFactory;
import org.forgerock.openam.audit.AuditEventPublisher;
import org.forgerock.openam.http.HttpRoute;
import org.forgerock.openam.http.HttpRouteProvider;
import org.forgerock.openam.http.annotations.Endpoints;
import org.forgerock.openam.rest.RealmContextFilter;
import org.forgerock.openam.rest.RealmRoutingFactory;
import org.openidentityplatform.openam.oauth2.audit.HttpBodyAuditor;
import org.openidentityplatform.openam.oauth2.audit.OAuth2HttpAccessAuditFilter;

/**
 * HTTP route provider for the {@literal /.well-known} endpoints -- the CHF replacement for the Restlet
 * {@code WebFinger} router ({@code openam-oauth2/.../restlet/WebFinger.java}).
 *
 * <p>The chain is <strong>copied</strong> from {@link OAuth2HttpRouteProvider#get()}, not re-derived: realm layer,
 * audit placement and error shape are all wire contract, and {@literal /.well-known} must answer with the same
 * vocabulary as the rest of the migrated OAuth2 surface (phase 5d-2, D1).
 *
 * <p>⚠ {@code Endpoints.from} resolves through Guice at route-construction time, and {@code HttpRouterProvider}
 * adds this route to the same {@code Router} that serves {@code /json}, {@code /oauth2} and the rest -- a Guice
 * failure here takes down the whole CHF surface, not just {@literal /.well-known}.
 */
public class WellKnownHttpRouteProvider implements HttpRouteProvider {

    /**
     * Registered so realm resolution cannot shadow this surface. Realm resolution greedily consumes leading path
     * elements that resolve as realms, so a realm named {@code webfinger} would eat the endpoint segment.
     * {@code .well-known} is listed here as well rather than leaning on {@link OAuth2HttpRouteProvider} having
     * already added it -- a provider registers its own segments. Consulted on realm <em>creation</em> only
     * ({@code OrganizationConfigManager}); existing realms are unaffected.
     */
    private static final String[] ENDPOINT_SEGMENTS = {".well-known", "webfinger"};

    private AuditEventPublisher eventPublisher;
    private AuditEventFactory eventFactory;
    private OAuth2RequestFactory requestFactory;
    private RealmRoutingFactory realmRoutingFactory;
    private RealmContextFilter realmContextFilter;
    private Set<String> invalidRealmNames;

    // Setter injection, not an @Inject constructor: HttpRouterProvider loads these through ServiceLoader -- which
    // needs a public no-arg constructor -- and only then calls injectMembers. A constructor annotation never runs.

    @Inject
    public void setEventPublisher(AuditEventPublisher eventPublisher) {
        this.eventPublisher = eventPublisher;
    }

    @Inject
    public void setEventFactory(AuditEventFactory eventFactory) {
        this.eventFactory = eventFactory;
    }

    @Inject
    public void setRequestFactory(OAuth2RequestFactory requestFactory) {
        this.requestFactory = requestFactory;
    }

    @Inject
    public void setRealmRoutingFactory(RealmRoutingFactory realmRoutingFactory) {
        this.realmRoutingFactory = realmRoutingFactory;
    }

    @Inject
    public void setRealmContextFilter(RealmContextFilter realmContextFilter) {
        this.realmContextFilter = realmContextFilter;
    }

    @Inject
    public void setInvalidRealmNames(@Named("InvalidRealmNames") Set<String> invalidRealmNames) {
        this.invalidRealmNames = invalidRealmNames;
    }

    @Override
    public Set<HttpRoute> get() {
        Collections.addAll(invalidRealmNames, ENDPOINT_SEGMENTS);

        Router endpointRouter = new Router();

        // OpenID Connect Discovery / WebFinger -- WebFinger.java:76.
        endpoint(endpointRouter, "webfinger",
                Endpoints.from(WebFingerHandler.class), noBodyAuditor(), noBodyAuditor());

        endpointRouter.setDefaultRoute(new OAuth2NotFoundHandler());

        // The realm layer, as OAuth2HttpRouteProvider builds it. `root` is passed to createRouter so the
        // /realms/{realmId} recursion terminates on root's own default route.
        Router root = new Router();
        root.addRoute(requestUriMatcher(STARTS_WITH, REALM_ROUTE),
                Handlers.chainOf(realmRoutingFactory.createRouter(root), realmRoutingFactory.createHostnameFilter()));
        root.setDefaultRoute(Handlers.chainOf(endpointRouter, realmContextFilter));

        // STARTS_WITH, not EQUALS: the provider owns the whole `.well-known` segment because the servlet mapping
        // does, so an unmatched child has to reach the endpoint router's OAuth2NotFoundHandler rather than fall
        // through to a container 404.
        //
        // The error filter wraps everything, realm failures included -- otherwise a bad ?realm= surfaces as the
        // CREST {code,reason,message} body instead of the OAuth2 {error,error_description} shape. Plain `new`:
        // OAuth2ErrorFilter is stateless with a default constructor and takes no collaborators.
        return Collections.singleton(
                newHttpRoute(STARTS_WITH, ".well-known", Handlers.chainOf(root, new OAuth2ErrorFilter())));
    }

    /**
     * Attaches one endpoint with its audit wrap, as {@code OAuth2HttpRouteProvider.endpoint(...)} does.
     *
     * <p>⚠ Audit sits inside the realm layer: the chain is built <em>within</em> {@code endpointRouter}, which is
     * behind {@link RealmContextFilter}. Hoisting it out would publish every webfinger access event with no realm
     * on it -- and {@code WebFinger:76} audited inside its {@code RestletRealmRouter} too.
     * {@code Handlers.chainOf(H, A)} builds {@code A(H)}, so the filter argument is the outermost of the two.
     */
    private void endpoint(Router router, String uriTemplate, Handler handler,
            HttpBodyAuditor requestDetail, HttpBodyAuditor responseDetail) {
        router.addRoute(requestUriMatcher(EQUALS, uriTemplate),
                Handlers.chainOf(handler, auditFilter(requestDetail, responseDetail)));
    }

    private OAuth2HttpAccessAuditFilter auditFilter(HttpBodyAuditor requestDetail, HttpBodyAuditor responseDetail) {
        return new OAuth2HttpAccessAuditFilter(eventPublisher, eventFactory, requestFactory, requestDetail,
                responseDetail);
    }
}
