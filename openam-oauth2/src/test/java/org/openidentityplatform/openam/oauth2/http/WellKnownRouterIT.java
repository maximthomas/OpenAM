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

import static org.assertj.core.api.Assertions.assertThat;
import static org.forgerock.http.routing.RouteMatchers.requestUriMatcher;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

import java.lang.annotation.Annotation;
import java.net.URI;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import jakarta.servlet.http.HttpServletRequest;

import org.forgerock.audit.events.AuditEvent;
import org.forgerock.guice.core.GuiceModuleLoader;
import org.forgerock.guice.core.GuiceModuleLoaderAccessor;
import org.forgerock.guice.core.GuiceTestCase;
import org.forgerock.guice.core.InjectorConfiguration;
import org.forgerock.guice.core.InjectorHolder;
import org.forgerock.http.Handler;
import org.forgerock.http.protocol.Request;
import org.forgerock.http.protocol.Response;
import org.forgerock.http.routing.Router;
import org.forgerock.oauth2.core.ClientRegistrationStore;
import org.forgerock.oauth2.core.OAuth2Request;
import org.forgerock.oauth2.core.OAuth2RequestFactory;
import org.forgerock.openam.audit.AuditConstants;
import org.forgerock.openam.audit.AuditEventFactory;
import org.forgerock.openam.audit.AuditEventPublisher;
import org.forgerock.openam.audit.context.AuditRequestContext;
import org.forgerock.openam.core.CoreWrapper;
import org.forgerock.openam.core.realms.RealmTestHelper;
import org.forgerock.openam.http.HttpRoute;
import org.forgerock.openam.http.HttpRouteAccessor;
import org.forgerock.openam.rest.representations.JacksonRepresentationFactory;
import org.forgerock.openam.rest.router.RestRealmValidator;
import org.forgerock.openam.services.baseurl.BaseURLProvider;
import org.forgerock.openam.services.baseurl.BaseURLProviderFactory;
import org.forgerock.openam.utils.RealmNormaliser;
import org.forgerock.openidconnect.OpenIDConnectProviderDiscovery;
import org.forgerock.services.context.AttributesContext;
import org.forgerock.services.context.ClientContext;
import org.forgerock.services.context.RequestAuditContext;
import org.forgerock.services.context.RootContext;
import org.mockito.ArgumentCaptor;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import com.google.inject.Binder;
import com.google.inject.Key;
import com.google.inject.TypeLiteral;
import com.google.inject.name.Names;
import com.iplanet.sso.SSOToken;
import com.sun.identity.idm.IdRepoException;

/**
 * Dispatches real {@literal /.well-known} requests through the composition produced by the live
 * {@link WellKnownHttpRouteProvider}: the {@code webfinger} attachment, the realm layer under it, the audit
 * filter inside that layer, the endpoint router's {@link OAuth2NotFoundHandler} and the root
 * {@link OAuth2ErrorFilter}.
 *
 * <p>Sibling of {@link OAuth2RouterIT}, whose injector scaffolding, {@code handle(...)} helper and realm
 * mocking this reuses. {@code WebFingerHandlerTest} pins the handler; only this class pins the
 * <em>provider</em> -- that the route exists, that the layers are in the order the wire contract needs, and
 * that a realm failure comes back in the OAuth2 vocabulary rather than CREST's.
 *
 * <h2>Two traps this class is built around</h2>
 * <ul>
 * <li>{@code Endpoints.from(Class)} resolves through Guice when {@code get()} builds the route, not per
 *     request, so {@link #configure(Binder)} must bind every collaborator of {@link WebFingerHandler} and its
 *     base class or {@code provider.get()} itself throws.
 * <li>{@code HttpFrameworkServlet} publishes the servlet request on the {@link AttributesContext} keyed by
 *     class name ({@code ChfContexts}); without it {@code OAuth2Request.getHttpServletRequest()} is null and
 *     {@link WebFingerHandler} answers 400 rather than the JRD. {@link #handle} supplies it.
 * </ul>
 *
 * <h2>Name trap</h2>
 * {@code *IT.java} is bound to failsafe: {@code mvn -pl openam-oauth2 test} does <strong>not</strong> run this
 * class. It needs {@code mvn -pl openam-oauth2 verify}.
 */
public class WellKnownRouterIT extends GuiceTestCase {

    private static final String HOSTNAME = "openam.example";
    private static final String RESOURCE = "acct:joe@example.com";
    private static final String REL = "http://openid.net/specs/connect/1.0/issuer";
    private static final String ROOT_URL = "https://op.example:8443/openam";
    private static final String SUBREALM = "/subrealm";
    private static final Map<String, Object> JRD = Map.of(
            "subject", RESOURCE,
            "links", List.of(Map.of("rel", REL, "href", ROOT_URL + "/oauth2")));

    private Handler handler;

    private CoreWrapper coreWrapper;
    private RestRealmValidator realmValidator;
    private RealmTestHelper realmTestHelper;
    private AuditEventPublisher auditEventPublisher;
    private OpenIDConnectProviderDiscovery providerDiscovery;
    private BaseURLProviderFactory baseUrlProviderFactory;
    private HttpServletRequest servletRequest;
    private Set<String> invalidRealmNames;

    @BeforeMethod
    public void setupMocks() throws Exception {
        auditEventPublisher = mock(AuditEventPublisher.class);
        // Every audit code path is behind isAuditing(...), so false keeps all rows but the audit one audit-free.
        given(auditEventPublisher.isAuditing(any(), any(), any())).willReturn(false);

        coreWrapper = mock(CoreWrapper.class);
        given(coreWrapper.isValidFQDN(anyString())).willReturn(true);
        given(coreWrapper.getAdminToken()).willReturn(mock(SSOToken.class));
        // Default: nothing is a realm. `webfinger` must fail to resolve as one or the realm walk would swallow
        // the endpoint segment -- the failure the InvalidRealmNames registration exists to make impossible.
        given(coreWrapper.getOrganization(any(SSOToken.class), anyString())).willThrow(IdRepoException.class);
        realmValidator = mock(RestRealmValidator.class);
        realmTestHelper = new RealmTestHelper(coreWrapper);
        realmTestHelper.setupRealmClass();

        servletRequest = mock(HttpServletRequest.class);
        providerDiscovery = mock(OpenIDConnectProviderDiscovery.class);
        given(providerDiscovery.discover(any(), any(), anyString(), any(OAuth2Request.class))).willReturn(JRD);
        BaseURLProvider baseUrlProvider = mock(BaseURLProvider.class);
        given(baseUrlProvider.getRootURL(any(HttpServletRequest.class))).willReturn(ROOT_URL);
        baseUrlProviderFactory = mock(BaseURLProviderFactory.class);
        given(baseUrlProviderFactory.get(anyString())).willReturn(baseUrlProvider);

        invalidRealmNames = new HashSet<>();
    }

    @AfterMethod
    public void tearDown() {
        realmTestHelper.tearDownRealmClass();
        AuditRequestContext.clear();
    }

    @AfterMethod
    public void restoreModuleLoader() {
        // setupGuiceModules swaps the process-global loader for an empty one; GuiceTestCase.teardown restores
        // only the InjectorHolder, so reset the loader or later GuiceTestCase-based tests inherit the empty one.
        GuiceModuleLoaderAccessor.restoreDefault();
    }

    @BeforeMethod(dependsOnMethods = "setupMocks")
    @Override
    public void setupGuiceModules() throws Exception {
        InjectorConfiguration.setGuiceModuleLoader(new GuiceModuleLoader() {
            @Override
            public Set<Class<? extends com.google.inject.Module>> getGuiceModules(Class<? extends Annotation> clazz) {
                return new HashSet<>();
            }
        });
        super.setupGuiceModules();
    }

    /**
     * {@link WebFingerHandler}'s {@code @Inject} fields plus its base class's, plus the provider's own
     * collaborators. {@code BaseURLProviderFactory} is bound rather than JIT-built because it cannot construct
     * without a {@code ServletContext}; {@code OAuth2ErrorResponseFactory} JIT-builds from the three below it.
     */
    @Override
    public void configure(Binder binder) {
        binder.bind(AuditEventPublisher.class).toInstance(auditEventPublisher);
        binder.bind(AuditEventFactory.class).toInstance(new AuditEventFactory());
        binder.bind(CoreWrapper.class).toInstance(coreWrapper);
        binder.bind(RestRealmValidator.class).toInstance(realmValidator);
        binder.bind(Key.get(new TypeLiteral<Set<String>>() { }, Names.named("InvalidRealmNames")))
                .toInstance(invalidRealmNames);
        binder.bind(OAuth2RequestFactory.class).toInstance(new OAuth2RequestFactory(
                mock(JacksonRepresentationFactory.class), mock(ClientRegistrationStore.class)));

        binder.bind(FreemarkerTemplateRenderer.class).toInstance(new FreemarkerTemplateRenderer());
        binder.bind(BaseURLProviderFactory.class).toInstance(baseUrlProviderFactory);
        binder.bind(RealmNormaliser.class).toInstance(mock(RealmNormaliser.class));

        binder.bind(OpenIDConnectProviderDiscovery.class).toInstance(providerDiscovery);
    }

    @BeforeMethod(dependsOnMethods = "setupGuiceModules")
    public void setupRouter() throws Exception {
        Router router = new Router();
        for (HttpRoute route : InjectorHolder.getInstance(WellKnownHttpRouteProvider.class).get()) {
            router.addRoute(requestUriMatcher(HttpRouteAccessor.modeOf(route), HttpRouteAccessor.uriTemplateOf(route)),
                    HttpRouteAccessor.handlerOf(route));
        }
        handler = router;

        realmTestHelper.mockDnsAlias(HOSTNAME);
        mockRealmAlias(HOSTNAME, "/");
    }

    /**
     * The endpoint is reachable at its bare path and answers the JRD. Nothing else in the suite proves the
     * whole chain -- error filter, realm filter, audit filter, {@code Endpoints} framework -- passes a 200
     * body through untouched; {@code WebFingerHandlerTest} drives the handler with none of them mounted.
     */
    @Test
    public void theBarePathReturnsTheJrd() throws Exception {
        Response response = handle("GET", "/.well-known/webfinger?resource=" + RESOURCE + "&rel=" + REL);

        assertThat(response.getStatus().getCode()).isEqualTo(200);
        assertThat(bodyMap(response)).isEqualTo(JRD);
        assertThat(response.getHeaders().getFirst("Content-Type")).isEqualTo("application/json; charset=UTF-8");
        // the query parameters survived the realm layer's URI rewriting, and root picked the provider
        verify(providerDiscovery).discover(eq(RESOURCE), eq(REL), eq(ROOT_URL), any(OAuth2Request.class));
        verify(baseUrlProviderFactory).get("/");
    }

    /**
     * The {@literal /realms/{realmId}} style, which reaches the endpoint through {@code RealmRoutingFactory}'s
     * recursive router rather than through {@link org.forgerock.openam.rest.RealmContextFilter}. Without this
     * row the provider could mount the endpoint router directly and pass every other 200 row here.
     */
    @Test
    public void theRealmsPathStyleReachesTheEndpoint() throws Exception {
        Response response = handle("GET", "/.well-known/realms/root/webfinger");

        assertThat(response.getStatus().getCode()).isEqualTo(200);
        verify(baseUrlProviderFactory).get("/");
    }

    /**
     * R-5d1.6 for this surface: the legacy path style and the {@code ?realm=} override must both reach the
     * endpoint <em>and</em> resolve to the same realm. The realm is what picks the {@code BaseURLProvider},
     * hence the issuer in the JRD, so a status-only assertion would pass with the realm silently root --
     * which is exactly the WebFinger bug that matters, a subrealm's clients told the wrong issuer.
     */
    @Test
    public void theLegacyPathAndQueryRealmStylesResolveTheRealmThatPicksTheProvider() throws Exception {
        realmTestHelper.mockRealm("subrealm");
        given(coreWrapper.getOrganization(any(SSOToken.class), eq("subrealm"))).willReturn(SUBREALM);
        given(coreWrapper.convertOrgNameToRealmName(SUBREALM)).willReturn(SUBREALM);
        given(realmValidator.isRealm(SUBREALM)).willReturn(true);

        assertThat(handle("GET", "/.well-known/subrealm/webfinger").getStatus().getCode()).isEqualTo(200);
        assertThat(handle("GET", "/.well-known/webfinger?realm=" + SUBREALM).getStatus().getCode()).isEqualTo(200);

        verify(baseUrlProviderFactory, times(2)).get(SUBREALM);
    }

    /**
     * D5 on this surface. The route is {@code STARTS_WITH}, so the provider owns the whole segment and an
     * unmatched child has to reach {@link OAuth2NotFoundHandler} -- commons' own no-match answer is a bodiless
     * 404 that {@link OAuth2ErrorFilter} cannot rewrite, and CREST's {@code {code,reason,message}} is the wrong
     * vocabulary for this surface.
     */
    @Test
    public void anUnroutedChildGetsTheOAuth2NotFound() throws Exception {
        Response response = handle("GET", "/.well-known/nosuchthing");

        assertThat(response.getStatus().getCode()).isEqualTo(404);
        assertThat(bodyMap(response)).containsEntry("error", "not_found");
        assertThat(bodyMap(response)).doesNotContainKeys("code", "reason", "message");
    }

    /**
     * The audit filter sits <em>inside</em> the realm layer. Hoisting it to the root -- the obvious tidy-up,
     * since the chain then has one audit wrap instead of one per endpoint -- would leave every webfinger
     * access event with no realm on it, and {@code AuditEventFactory.accessEvent} drops a blank realm silently
     * rather than failing. Only an exact-value assertion on the field catches that.
     */
    @Test
    public void theAuditEventCarriesTheResolvedRealm() throws Exception {
        given(auditEventPublisher.isAuditing(any(), any(), any())).willReturn(true);
        realmTestHelper.mockRealm("subrealm");
        given(coreWrapper.getOrganization(any(SSOToken.class), eq("subrealm"))).willReturn(SUBREALM);
        given(coreWrapper.convertOrgNameToRealmName(SUBREALM)).willReturn(SUBREALM);
        given(realmValidator.isRealm(SUBREALM)).willReturn(true);

        assertThat(handle("GET", "/.well-known/subrealm/webfinger").getStatus().getCode()).isEqualTo(200);

        ArgumentCaptor<AuditEvent> captor = ArgumentCaptor.forClass(AuditEvent.class);
        verify(auditEventPublisher, times(2)).tryPublish(eq(AuditConstants.ACCESS_TOPIC), captor.capture());
        for (AuditEvent event : captor.getAllValues()) {
            assertThat(event.getValue().get(AuditConstants.EVENT_REALM).asString()).isEqualTo(SUBREALM);
        }
    }

    /**
     * The root {@link OAuth2ErrorFilter} wraps the realm layer, not the other way round. A realm that cannot
     * be resolved is thrown by {@code RealmContextFilter} as a CREST {@code BadRequestException} and rendered
     * as {@code {code,reason,message}}; mounting the filter inside {@code root} would let that shape onto a
     * surface whose every other error is {@code {error,error_description}}.
     */
    @Test
    public void anUnresolvableRealmComesBackInTheOAuth2ErrorShape() throws Exception {
        Response response = handle("GET", "/.well-known/webfinger?realm=bogus");

        assertThat(response.getStatus().getCode()).isEqualTo(400);
        assertThat(bodyMap(response)).containsEntry("error", "invalid_request");
        assertThat(bodyMap(response)).containsEntry("error_description", "Invalid realm, bogus");
        assertThat(bodyMap(response)).doesNotContainKeys("code", "reason", "message");
    }

    /**
     * D7: both first path segments are registered, so no realm can be created that shadows this surface. The
     * provider registers {@code .well-known} itself rather than leaning on {@link OAuth2HttpRouteProvider}
     * having done so -- drop either name and a realm creation could eat the endpoint.
     */
    @Test
    public void theProviderRegistersItsFirstPathSegmentsAsInvalidRealmNames() {
        assertThat(invalidRealmNames).containsExactlyInAnyOrder(".well-known", "webfinger");
    }

    // ---- Helpers -----------------------------------------------------------------------------------------------

    private Response handle(String method, String uri) throws Exception {
        Request request = new Request().setMethod(method).setUri(URI.create(uri));
        request.getUri().setHost(HOSTNAME);
        AttributesContext context = new AttributesContext(new RequestAuditContext(
                ClientContext.buildExternalClientContext(new RootContext())
                        .remoteAddress("127.0.0.1").remotePort(9000).build()));
        // What HttpFrameworkServlet publishes and ChfContexts reads back; OAuth2Request.getHttpServletRequest()
        // is null without it, and WebFingerHandler then answers 400 server_error instead of the JRD.
        context.getAttributes().put(HttpServletRequest.class.getName(), servletRequest);
        return handler.handle(context, request).getOrThrowUninterruptibly();
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> bodyMap(Response response) throws Exception {
        return (Map<String, Object>) response.getEntity().getJson();
    }

    private void mockRealmAlias(String alias, String realm) throws Exception {
        given(coreWrapper.getOrganization(any(SSOToken.class), eq(alias))).willReturn(realm);
        given(coreWrapper.convertOrgNameToRealmName(realm)).willReturn(realm);
        given(realmValidator.isRealm(realm)).willReturn(true);
    }
}
