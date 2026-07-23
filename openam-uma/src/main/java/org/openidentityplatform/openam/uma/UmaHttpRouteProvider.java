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

package org.openidentityplatform.openam.uma;

import static org.forgerock.http.routing.RouteMatchers.requestUriMatcher;
import static org.forgerock.http.routing.RoutingMode.EQUALS;
import static org.forgerock.http.routing.RoutingMode.STARTS_WITH;
import static org.forgerock.openam.http.HttpRoute.newHttpRoute;
import static org.forgerock.openam.rest.RealmRoutingFactory.REALM_ROUTE;
import static org.forgerock.openam.uma.UmaConstants.AAT_SCOPE;
import static org.forgerock.openam.uma.UmaConstants.PAT_SCOPE;
import static org.forgerock.openam.uma.UmaConstants.RESOURCE_SET_ID;
import static org.forgerock.openam.uma.UmaConstants.SCOPES;
import static org.openidentityplatform.openam.oauth2.audit.HttpBodyAuditor.jsonAuditor;
import static org.openidentityplatform.openam.oauth2.audit.HttpBodyAuditor.noBodyAuditor;

import java.util.Collections;
import java.util.Set;

import jakarta.inject.Inject;
import jakarta.inject.Named;

import org.forgerock.http.Handler;
import org.forgerock.http.handler.Handlers;
import org.forgerock.http.routing.Router;
import org.forgerock.oauth2.core.OAuth2RequestFactory;
import org.forgerock.oauth2.core.TokenStore;
import org.forgerock.openam.audit.AuditEventFactory;
import org.forgerock.openam.audit.AuditEventPublisher;
import org.forgerock.openam.http.HttpRoute;
import org.forgerock.openam.http.HttpRouteProvider;
import org.forgerock.openam.http.annotations.Endpoints;
import org.forgerock.openam.rest.RealmContextFilter;
import org.forgerock.openam.rest.RealmRoutingFactory;
import org.forgerock.openam.uma.AuthorizationRequestEndpoint;
import org.forgerock.openam.uma.PermissionRequestEndpoint;
import org.forgerock.openam.uma.UmaWellKnownConfigurationEndpoint;
import org.openidentityplatform.openam.oauth2.audit.HttpBodyAuditor;
import org.openidentityplatform.openam.oauth2.audit.UMAHttpAccessAuditFilter;
import org.openidentityplatform.openam.oauth2.http.ChfAccessTokenProtectionFilter;

/**
 * HTTP route provider for the {@literal /uma} endpoints. The CHF replacement for the Restlet
 * {@code UmaRouterProvider}: mirrors the realm-routing wrapper used by {@code XacmlHttpRouteProvider}
 * but routes directly to the annotated UMA endpoints ({@link Endpoints#from}).
 *
 * <p>Unlike {@code /json} and {@code /xacml} there is no global authentication filter — each protected
 * endpoint carries its own {@link ChfAccessTokenProtectionFilter} enforcing the required PAT/AAT scope,
 * and the {@literal .well-known} discovery endpoint is public. Also unlike {@code /xacml} there is no
 * error filter wrapping the route (D4): endpoint business errors are already rendered as UMA
 * {@code {error, error_description}} bodies by the endpoints themselves, and framework/realm-resolution
 * failures fall through to the default CREST {@code {code, reason, message}} rendering, exactly as they
 * did under Restlet.
 */
public class UmaHttpRouteProvider implements HttpRouteProvider {

    private static final String PERMISSION_REQUEST = "permission_request";
    private static final String AUTHZ_REQUEST = "authz_request";
    private static final String WELL_KNOWN = ".well-known/uma-configuration";

    private AuditEventPublisher eventPublisher;
    private AuditEventFactory eventFactory;
    private OAuth2RequestFactory requestFactory;
    private TokenStore tokenStore;
    private RealmRoutingFactory realmRoutingFactory;
    private RealmContextFilter realmContextFilter;
    private Set<String> invalidRealmNames;

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
    public void setTokenStore(TokenStore tokenStore) {
        this.tokenStore = tokenStore;
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
        // The endpoint segments are not realm names: guard the realm router from swallowing them.
        invalidRealmNames.add(PERMISSION_REQUEST);
        invalidRealmNames.add(AUTHZ_REQUEST);

        Router endpointRouter = new Router();
        endpointRouter.addRoute(requestUriMatcher(EQUALS, PERMISSION_REQUEST),
                audited(protect(PermissionRequestEndpoint.class, PAT_SCOPE),
                        jsonAuditor(RESOURCE_SET_ID, SCOPES), noBodyAuditor()));
        endpointRouter.addRoute(requestUriMatcher(EQUALS, AUTHZ_REQUEST),
                audited(protect(AuthorizationRequestEndpoint.class, AAT_SCOPE),
                        noBodyAuditor(), noBodyAuditor()));
        // Well-Known Discovery: public (no protection filter).
        endpointRouter.addRoute(requestUriMatcher(EQUALS, WELL_KNOWN),
                audited(Endpoints.from(UmaWellKnownConfigurationEndpoint.class), noBodyAuditor(), noBodyAuditor()));

        Router root = new Router();
        root.addRoute(requestUriMatcher(STARTS_WITH, REALM_ROUTE),
                Handlers.chainOf(realmRoutingFactory.createRouter(root), realmRoutingFactory.createHostnameFilter()));
        root.setDefaultRoute(Handlers.chainOf(endpointRouter, realmContextFilter));

        return Collections.singleton(newHttpRoute(STARTS_WITH, "uma", root));
    }

    /** Wraps an endpoint handler in its scope-enforcing access-token protection filter. */
    private Handler protect(Class<?> endpointClass, String requiredScope) {
        return Handlers.chainOf(Endpoints.from(endpointClass),
                new ChfAccessTokenProtectionFilter(requiredScope, tokenStore, requestFactory));
    }

    /** Wraps a handler in the UMA access-audit filter (audit runs outermost, before protection). */
    private Handler audited(Handler handler, HttpBodyAuditor requestDetail, HttpBodyAuditor responseDetail) {
        return Handlers.chainOf(handler,
                new UMAHttpAccessAuditFilter(eventPublisher, eventFactory, requestFactory, requestDetail,
                        responseDetail));
    }
}
