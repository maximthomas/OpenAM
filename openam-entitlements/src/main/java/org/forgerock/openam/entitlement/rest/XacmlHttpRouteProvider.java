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
 * Portions copyright 2026 3A Systems LLC.
 */

package org.forgerock.openam.entitlement.rest;

import static org.forgerock.http.routing.RouteMatchers.requestUriMatcher;
import static org.forgerock.http.routing.RoutingMode.EQUALS;
import static org.forgerock.http.routing.RoutingMode.STARTS_WITH;
import static org.forgerock.openam.http.HttpRoute.newHttpRoute;
import static org.forgerock.openam.rest.RealmRoutingFactory.REALM_ROUTE;

import java.util.Collections;
import java.util.Set;

import jakarta.inject.Inject;
import jakarta.inject.Named;

import org.forgerock.http.Filter;
import org.forgerock.http.Handler;
import org.forgerock.http.handler.Handlers;
import org.forgerock.http.routing.Router;
import org.forgerock.openam.http.HttpRoute;
import org.forgerock.openam.http.HttpRouteProvider;
import org.forgerock.openam.http.annotations.Endpoints;
import org.forgerock.openam.rest.RealmContextFilter;
import org.forgerock.openam.rest.RealmRoutingFactory;
import org.forgerock.openam.xacml.v3.rest.XacmlServiceHandler;
import org.forgerock.openam.xacml.v3.rest.XacmlXmlErrorFilter;

/**
 * HTTP route provider for the {@literal /xacml} endpoints. Mirrors the realm-routing wrapper
 * used by the {@literal /json} root router ({@code RestGuiceModule.getChfRootRouter()}) but
 * routes directly to the {@link XacmlServiceHandler} CHF handler rather than into the CREST
 * layer.
 */
public class XacmlHttpRouteProvider implements HttpRouteProvider {

    private Filter authenticationFilter;
    private RealmRoutingFactory realmRoutingFactory;
    private RealmContextFilter realmContextFilter;
    private XacmlXmlErrorFilter xacmlXmlErrorFilter;
    private Set<String> invalidRealmNames;

    /**
     * Uses the authentication filter that requires a token, rather than the {@literal AuthenticationFilter}
     * that {@literal /json} uses. Every {@literal /xacml} operation is permission-checked against the
     * caller's token, so there is no anonymous use case to preserve. Without this,
     * {@code OptionalSSOTokenSessionModule} would admit a request carrying no token, and
     * {@link XacmlServiceHandler} would then fail trying to build an {@code SSOToken} from a null id,
     * reporting a missing credential as {@literal 500} rather than {@literal 401}.
     *
     * @param authenticationFilter The filter that rejects unauthenticated requests.
     */
    @Inject
    public void setAuthenticationFilter(@Named("RequiredAuthenticationFilter") Filter authenticationFilter) {
        this.authenticationFilter = authenticationFilter;
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
    public void setXacmlXmlErrorFilter(XacmlXmlErrorFilter xacmlXmlErrorFilter) {
        this.xacmlXmlErrorFilter = xacmlXmlErrorFilter;
    }

    @Inject
    public void setInvalidRealmNames(@Named("InvalidRealmNames") Set<String> invalidRealmNames) {
        this.invalidRealmNames = invalidRealmNames;
    }

    @Override
    public Set<HttpRoute> get() {
        invalidRealmNames.add("policies");

        // Deliberately unversioned, unlike the /json routes that Routers.ServiceRoute.toService()
        // registers (those default to requestResourceApiVersionMatcher(version(1))). The legacy Restlet
        // /xacml application had no version gate, so its clients — ssoadm and the CLI-era exporters —
        // send no Accept-API-Version header and cannot be changed to send one. Adding a gate here would
        // subject them to the global "REST APIs > Default Version" setting: an administrator selecting
        // None (RestApis.xml, openam-rest-apis-default-version) would turn every one of those clients
        // into a 404. Any Accept-API-Version value is therefore ignored, as it was under Restlet.
        Router endpointRouter = new Router();
        endpointRouter.addRoute(requestUriMatcher(EQUALS, "policies"), Endpoints.from(XacmlServiceHandler.class));

        Handler innerChain = Handlers.chainOf(endpointRouter, authenticationFilter);

        Router root = new Router();
        root.addRoute(requestUriMatcher(STARTS_WITH, REALM_ROUTE),
                Handlers.chainOf(realmRoutingFactory.createRouter(root), realmRoutingFactory.createHostnameFilter()));
        root.setDefaultRoute(Handlers.chainOf(innerChain, realmContextFilter));

        // The XML error filter wraps the whole route (outside realm routing) so that realm-resolution
        // failures are rendered as XML <error> bodies too, matching the legacy XACML Restlet application
        // whose XMLRestStatusService covered errors raised by RestletRealmRouter.
        return Collections.singleton(newHttpRoute(STARTS_WITH, "xacml",
                Handlers.chainOf(root, xacmlXmlErrorFilter)));
    }
}
