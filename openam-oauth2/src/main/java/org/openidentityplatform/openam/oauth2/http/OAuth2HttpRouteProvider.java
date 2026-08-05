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
import static org.forgerock.openam.oauth2.OAuth2Constants.IntrospectionEndpoint.ACTIVE;
import static org.forgerock.openam.oauth2.OAuth2Constants.IntrospectionEndpoint.TOKEN_TYPE_HINT;
import static org.forgerock.openam.oauth2.OAuth2Constants.Params.CLIENT_ID;
import static org.forgerock.openam.oauth2.OAuth2Constants.Params.GRANT_TYPE;
import static org.forgerock.openam.oauth2.OAuth2Constants.Params.REDIRECT_URI;
import static org.forgerock.openam.oauth2.OAuth2Constants.Params.RESPONSE_TYPE;
import static org.forgerock.openam.oauth2.OAuth2Constants.Params.SCOPE;
import static org.forgerock.openam.oauth2.OAuth2Constants.Params.TOKEN_TYPE;
import static org.forgerock.openam.oauth2.OAuth2Constants.Params.USERNAME;
import static org.forgerock.openam.oauth2.OAuth2Constants.ResourceSets.NAME;
import static org.forgerock.openam.oauth2.OAuth2Constants.ResourceSets.SCOPES;
import static org.forgerock.openam.oauth2.OAuth2Constants.ShortClientAttributeNames.APPLICATION_TYPE;
import static org.forgerock.openam.oauth2.OAuth2Constants.ShortClientAttributeNames.CLIENT_NAME;
import static org.forgerock.openam.oauth2.OAuth2Constants.ShortClientAttributeNames.REDIRECT_URIS;
import static org.forgerock.openam.rest.RealmRoutingFactory.REALM_ROUTE;
import static org.openidentityplatform.openam.oauth2.audit.HttpBodyAuditor.formAuditor;
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
import org.openidentityplatform.openam.oauth2.audit.HttpBodyAuditor;
import org.openidentityplatform.openam.oauth2.audit.OAuth2HttpAccessAuditFilter;
import org.openidentityplatform.openam.oauth2.http.ChfAccessTokenProtectionFilter.ErrorShape;
import org.openidentityplatform.openam.openidconnect.http.CheckSessionHandler;
import org.openidentityplatform.openam.openidconnect.http.EndSessionHandler;

/**
 * HTTP route provider for the {@literal /oauth2} endpoints -- the CHF replacement for the Restlet
 * {@code OAuth2RouterProvider}.
 *
 * <p>The route table and the audit matrix are <strong>copied</strong>, not re-derived: both are wire contract,
 * and the source of truth is
 * {@code openam-oauth2/src/main/java/org/forgerock/openam/oauth2/rest/OAuth2RouterProvider.java:94-147}, whose
 * line numbers each route below cites. Two mechanical conversions apply throughout: Restlet's
 * {@code jacksonAuditor(...)} and {@code jsonAuditor(...)} both become CHF {@code jsonAuditor(...)}, and
 * {@code noBodyAuditor()} is {@code null} on this side -- the constant is kept for readability.
 *
 * <p><strong>No authentication filter.</strong> {@code XacmlHttpRouteProvider} chains a
 * {@code RequiredAuthenticationFilter} inside its realm filter; copying that here would demand an OpenAM session
 * on {@code /access_token} and break every OAuth2 client at once. Restlet wrapped this router in nothing but a
 * status service, so {@code UmaHttpRouteProvider} is the template: per-route protection, no global authentication.
 *
 * <p><strong>{@code connect/checkSession} needs no carve-out.</strong> {@code web.xml} maps
 * {@code /oauth2/connect/checkSession} <em>exactly</em> to the JSP servlet, and an exact mapping out-ranks the
 * {@code /oauth2/*} path mapping (Servlet spec 12.2) whichever servlet owns the prefix. So registering it here
 * yields exactly the Restlet arrangement: JSP on the bare path, handler on the realm-prefixed one.
 *
 * <p>⚠ Every handler below is <strong>constructed when this method runs</strong> ({@code Endpoints.from} resolves
 * through Guice at route-construction time), and {@code HttpRouterProvider} adds these routes to the same
 * {@code Router} that serves {@code /json}, {@code /xacml}, {@code /uma} and {@code /rest-sts}. A Guice failure
 * building any one of them takes down the whole CHF surface, not just {@code /oauth2}.
 */
public class OAuth2HttpRouteProvider implements HttpRouteProvider {

    /**
     * The <em>first path segment</em> of every route. Realm resolution greedily consumes leading path elements
     * that resolve as realms, so a realm named {@code connect} would shadow four endpoints at once -- hence the
     * segments rather than the full two-segment paths. Consulted on realm <em>creation</em> only
     * ({@code OrganizationConfigManager}); existing realms are unaffected.
     */
    private static final String[] ENDPOINT_SEGMENTS = {
        "authorize", "access_token", "tokeninfo", "introspect", "userinfo", "idtokeninfo", "resource_set",
        "device", "connect", "token", ".well-known",
    };

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
        Collections.addAll(invalidRealmNames, ENDPOINT_SEGMENTS);

        Router endpointRouter = new Router();

        // Standard OAuth2 endpoints. The no-cache filter is on these two and nowhere else: they are the routes
        // the Restlet OAuth2Filter wrapped (:72-77), so they are the only ones whose framework-produced
        // responses -- a 405, a 404, a non-OAuth2 500 -- ever carried no-store/Pragma. The handlers keep their
        // own noCache() calls; stamping twice is idempotent.
        endpoint(endpointRouter, "authorize",                            // :100
                noCache(Endpoints.from(AuthorizeHandler.class)),
                noBodyAuditor(), noBodyAuditor());
        endpoint(endpointRouter, "access_token",                         // :102
                noCache(Endpoints.from(TokenEndpointHandler.class)),
                formAuditor(RESPONSE_TYPE, GRANT_TYPE, CLIENT_ID, USERNAME, SCOPE, REDIRECT_URI),
                jsonAuditor(SCOPE, TOKEN_TYPE));
        endpoint(endpointRouter, "tokeninfo",                            // :106
                Endpoints.from(TokenInfoHandler.class),
                noBodyAuditor(), jsonAuditor(SCOPE, TOKEN_TYPE));

        // OAuth 2.0 Token Introspection Endpoint
        endpoint(endpointRouter, "introspect",                           // :111
                Endpoints.from(TokenIntrospectionHandler.class),
                formAuditor(TOKEN_TYPE_HINT),
                jsonAuditor(SCOPE, TOKEN_TYPE, CLIENT_ID, USERNAME, ACTIVE));

        // OpenID Connect endpoints
        endpoint(endpointRouter, "connect/register",                     // :117
                Endpoints.from(ConnectClientRegistrationHandler.class),
                jsonAuditor(CLIENT_NAME.getType(), APPLICATION_TYPE.getType(), REDIRECT_URIS.getType()),
                jsonAuditor(CLIENT_ID, CLIENT_NAME.getType(), APPLICATION_TYPE.getType(),
                        REDIRECT_URIS.getType()));
        endpoint(endpointRouter, "userinfo",                             // :120
                Endpoints.from(UserInfoHandler.class), noBodyAuditor(), noBodyAuditor());
        endpoint(endpointRouter, "idtokeninfo",                          // :121
                Endpoints.from(IdTokenInfoHandler.class), noBodyAuditor(), noBodyAuditor());
        endpoint(endpointRouter, "connect/checkSession",                 // :122
                Endpoints.from(CheckSessionHandler.class), noBodyAuditor(), noBodyAuditor());
        endpoint(endpointRouter, "connect/endSession",                   // :123
                Endpoints.from(EndSessionHandler.class), noBodyAuditor(), noBodyAuditor());
        endpoint(endpointRouter, "connect/jwk_uri",                      // :124
                Endpoints.from(JwkUriHandler.class), noBodyAuditor(), noBodyAuditor());

        // Resource Set Registration -- :131-133, three Restlet attachments as one nested router.
        endpointRouter.addRoute(requestUriMatcher(STARTS_WITH, "resource_set"), resourceSetRouter());

        // OpenID Connect Discovery
        endpoint(endpointRouter, ".well-known/openid-configuration",     // :137
                Endpoints.from(OpenIDConnectConfigurationHandler.class), noBodyAuditor(), noBodyAuditor());

        // OAuth 2 Device Flow
        endpoint(endpointRouter, "device/user",                          // :141
                Endpoints.from(DeviceCodeVerificationHandler.class), noBodyAuditor(), noBodyAuditor());
        endpoint(endpointRouter, "device/code",                          // :142
                Endpoints.from(DeviceCodeHandler.class),
                formAuditor(RESPONSE_TYPE, GRANT_TYPE, CLIENT_ID, SCOPE), noBodyAuditor());

        // OAuth2 Token Revocation
        endpoint(endpointRouter, "token/revoke",                         // :146
                Endpoints.from(TokenRevocationHandler.class), noBodyAuditor(), noBodyAuditor());

        endpointRouter.setDefaultRoute(new OAuth2NotFoundHandler());

        // The realm layer, as UmaHttpRouteProvider and XacmlHttpRouteProvider build it. `root` is passed to
        // createRouter so the /realms/{realmId} recursion terminates on root's own default route.
        Router root = new Router();
        root.addRoute(requestUriMatcher(STARTS_WITH, REALM_ROUTE),
                Handlers.chainOf(realmRoutingFactory.createRouter(root), realmRoutingFactory.createHostnameFilter()));
        root.setDefaultRoute(Handlers.chainOf(endpointRouter, realmContextFilter));

        // The error filter wraps everything: /oauth2's contract is the OAuth2 error shape end to end, realm
        // failures included. It is idempotent, which is what lets ResourceSetErrorFilter keep its own
        // vocabulary inside it.
        return Collections.singleton(
                newHttpRoute(STARTS_WITH, "oauth2", Handlers.chainOf(root, new OAuth2ErrorFilter())));
    }

    /**
     * The three Restlet {@code resource_set} attachments as one nested router (D2). Three sibling {@code EQUALS}
     * routes cannot express the family: CHF {@code EQUALS} matches the whole remaining URI, so nothing matches a
     * path ending in {@code /}. A {@code STARTS_WITH} parent consumes {@code resource_set} and leaves the child
     * an empty remaining URI for both collection spellings.
     *
     * <p>⚠ The chain wraps the <strong>handler</strong>, not the router. Wrapping the router would put
     * {@code ResourceSetErrorFilter} outside the child's no-match 404 -- and its catch-all row would turn a
     * bodiless 404 into a 500. Since D5 gives the child a default route the mistake would now answer 404 rather
     * than 500, which makes the placement no less right and its guard no less necessary
     * ({@code ResourceSetRouteCompositionIT} row 9 keeps the counterfactual alive deliberately).
     *
     * <p>⚠ The protection filter is the {@code ErrorShape.OAUTH2} overload. The 3-arg constructor defaults to
     * {@code CREST}, which is what {@code /uma} needs and what {@code resource_set} must not have -- passing the
     * wrong one is a silent 401-shape regression.
     */
    private Handler resourceSetRouter() {
        Handler chain = Handlers.chainOf(Endpoints.from(ResourceSetRegistrationHandler.class),
                auditFilter(jsonAuditor(NAME, SCOPES), jsonAuditor("_id")),          // outermost
                new ResourceSetErrorFilter(),
                new ChfAccessTokenProtectionFilter(null, tokenStore, requestFactory, ErrorShape.OAUTH2));

        Router resourceSetRouter = new Router();
        resourceSetRouter.addRoute(requestUriMatcher(EQUALS, ""), chain);        // resource_set, resource_set/
        resourceSetRouter.addRoute(requestUriMatcher(EQUALS, "{rsid}"), chain);  // resource_set/{rsid}
        // A nested Router answers its own 404 rather than falling through to the parent's default route, so
        // without this the one 404 the migration has an oracle for would be the only bodiless one on the surface.
        resourceSetRouter.setDefaultRoute(new OAuth2NotFoundHandler());
        return resourceSetRouter;
    }

    /**
     * Attaches one endpoint with its audit wrap. Audit sits <strong>outermost</strong> on every route, which is
     * not a choice: {@code auditWithOAuthFilter} wrapped each attached restlet individually, outside that
     * endpoint's own {@code OAuth2Filter}, and the result is what {@code attach(...)} received.
     * {@code Handlers.chainOf(H, A, B)} builds {@code A(B(H))}, so the first filter argument is the outermost.
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

    private static Handler noCache(Handler handler) {
        return Handlers.chainOf(handler, new OAuth2NoCacheFilter());
    }
}
