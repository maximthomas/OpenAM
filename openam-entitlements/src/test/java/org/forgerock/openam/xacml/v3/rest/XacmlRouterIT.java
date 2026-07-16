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

package org.forgerock.openam.xacml.v3.rest;

import static org.assertj.core.api.Assertions.assertThat;
import static org.forgerock.http.routing.RouteMatchers.requestUriMatcher;
import static org.forgerock.http.routing.RouteMatchers.resourceApiVersionContextFilter;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyList;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyZeroInteractions;

import java.lang.annotation.Annotation;
import java.net.URI;
import java.security.PrivilegedAction;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import javax.security.auth.Subject;

import org.forgerock.guice.core.GuiceModuleLoader;
import org.forgerock.guice.core.GuiceTestCase;
import org.forgerock.guice.core.InjectorConfiguration;
import org.forgerock.guice.core.InjectorHolder;
import org.forgerock.http.Filter;
import org.forgerock.http.Handler;
import org.forgerock.http.protocol.Request;
import org.forgerock.http.protocol.Response;
import org.forgerock.http.routing.DefaultVersionBehaviour;
import org.forgerock.http.routing.ResourceApiVersionBehaviourManager;
import org.forgerock.http.routing.Router;
import org.forgerock.http.routing.RoutingMode;
import org.forgerock.openam.core.CoreWrapper;
import org.forgerock.openam.core.realms.RealmTestHelper;
import org.forgerock.openam.entitlement.rest.XacmlHttpRouteProvider;
import org.forgerock.openam.forgerockrest.utils.RestLog;
import org.forgerock.openam.http.HttpRoute;
import org.forgerock.openam.http.HttpRouteAccessor;
import org.forgerock.openam.rest.router.RestRealmValidator;
import org.forgerock.services.context.AttributesContext;
import org.forgerock.services.context.Context;
import org.forgerock.services.context.RootContext;
import org.forgerock.util.promise.NeverThrowsException;
import org.forgerock.util.promise.Promise;
import org.mockito.invocation.InvocationOnMock;
import org.mockito.stubbing.Answer;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

import com.google.inject.Binder;
import com.google.inject.Key;
import com.google.inject.Module;
import com.google.inject.TypeLiteral;
import com.google.inject.name.Names;
import com.iplanet.sso.SSOException;
import com.iplanet.sso.SSOToken;
import com.sun.identity.delegation.DelegationEvaluator;
import com.sun.identity.entitlement.xacml3.XACMLExportImport;
import com.sun.identity.entitlement.xacml3.core.PolicySet;
import com.sun.identity.idm.IdRepoException;
import com.sun.identity.shared.Constants;
import com.sun.identity.shared.debug.Debug;

/**
 * Dispatches requests through the real {@link XacmlHttpRouteProvider} route composition: realm
 * routing and the XML error filter.
 *
 * <p>Several cases here pin the <em>absence</em> of resource API version routing, which the route
 * deliberately omits for Restlet parity. See {@code XacmlHttpRouteProvider.get()} for why.
 *
 * <p>Authentication is stubbed here — the filter is replaced by a pass-through that seeds the
 * {@code AttributesContext} exactly as CAF does — so this test owns everything downstream of
 * authentication. Real authentication is covered by the {@code e2e/xacml} Playwright spec.
 *
 * <p>This test lives in {@code org.forgerock.openam.xacml.v3.rest} rather than alongside
 * {@link XacmlHttpRouteProvider} so that it can override the package-private
 * {@link XacmlServiceHandler#checkPermission(String, Context, Request, String)}, whose real
 * implementation reaches for the {@code SSOTokenManager} singleton.
 */
public class XacmlRouterIT extends GuiceTestCase {

    private static final String HOSTNAME = "HOSTNAME";
    private static final String AUTH_CONTEXT = "org.forgerock.authentication.context";

    private Handler handler;

    private XACMLExportImport importExport;
    private RestLog restLog;
    private DelegationEvaluator evaluator;
    private PrivilegedAction<SSOToken> adminTokenAction;
    private CoreWrapper coreWrapper;
    private RestRealmValidator realmValidator;
    private RealmTestHelper realmTestHelper;
    private ResourceApiVersionBehaviourManager versionBehaviourManager;
    private Set<String> invalidRealmNames;

    @BeforeMethod
    public void setupMocks() throws Exception {
        importExport = mock(XACMLExportImport.class);
        restLog = mock(RestLog.class);
        evaluator = mock(DelegationEvaluator.class);

        adminTokenAction = mockAdminTokenAction();

        coreWrapper = mock(CoreWrapper.class);
        given(coreWrapper.isValidFQDN(anyString())).willReturn(true);
        given(coreWrapper.getAdminToken()).willReturn(mock(SSOToken.class));
        realmValidator = mock(RestRealmValidator.class);
        realmTestHelper = new RealmTestHelper(coreWrapper);
        realmTestHelper.setupRealmClass();

        versionBehaviourManager = mock(ResourceApiVersionBehaviourManager.class);
        given(versionBehaviourManager.getDefaultVersionBehaviour()).willReturn(DefaultVersionBehaviour.LATEST);

        invalidRealmNames = new HashSet<>();
    }

    @AfterMethod
    public void tearDown() {
        realmTestHelper.tearDownRealmClass();
    }

    /**
     * Stops {@code InjectorHolder} scanning the classpath for {@code @GuiceModule}s, which would pull in
     * module graphs this test has no reason to satisfy. Only the bindings in {@link #configure(Binder)}
     * are used.
     */
    @BeforeMethod(dependsOnMethods = "setupMocks")
    @Override
    public void setupGuiceModules() throws Exception {
        InjectorConfiguration.setGuiceModuleLoader(new GuiceModuleLoader() {
            @Override
            public Set<Class<? extends Module>> getGuiceModules(Class<? extends Annotation> clazz) {
                return new HashSet<>();
            }
        });
        super.setupGuiceModules();
    }

    @Override
    public void configure(Binder binder) {
        binder.bind(XacmlServiceHandler.class).toInstance(
                new TestXacmlServiceHandler(importExport, adminTokenAction, mock(Debug.class), restLog, evaluator));

        binder.bind(CoreWrapper.class).toInstance(coreWrapper);
        binder.bind(RestRealmValidator.class).toInstance(realmValidator);

        binder.bind(Key.get(new TypeLiteral<Set<String>>() { }, Names.named("InvalidRealmNames")))
                .toInstance(invalidRealmNames);
        // Deliberately bound under RequiredAuthenticationFilter only. The provider must not fall back to
        // the AuthenticationFilter that /json uses, which admits unauthenticated requests; if it is ever
        // changed back, this injector has no binding for that name and every case here fails.
        binder.bind(Key.get(Filter.class, Names.named("RequiredAuthenticationFilter")))
                .toInstance(new StubAuthenticationFilter());
        binder.bind(Key.get(Filter.class, Names.named("ResourceApiVersionFilter")))
                .toInstance(resourceApiVersionContextFilter(versionBehaviourManager));
    }

    @BeforeMethod(dependsOnMethods = "setupGuiceModules")
    public void setupRouter() throws Exception {
        Router router = new Router();
        for (HttpRoute route : InjectorHolder.getInstance(XacmlHttpRouteProvider.class).get()) {
            router.addRoute(requestUriMatcher(HttpRouteAccessor.modeOf(route), HttpRouteAccessor.uriTemplateOf(route)),
                    HttpRouteAccessor.handlerOf(route));
        }
        handler = router;

        // The realm resolver walks the URI looking for realms; "policies" is not one, and an
        // unresolvable element ends the walk and leaves the realm as resolved so far.
        mockRealmAlias(HOSTNAME, "/");
        doThrow(IdRepoException.class).when(coreWrapper).getOrganization(any(SSOToken.class), eq("policies"));
        doThrow(IdRepoException.class).when(coreWrapper).getOrganization(any(SSOToken.class), eq("nonsense"));

        // The realms/{realmId} branch resolves the host through RealmLookup rather than CoreWrapper.
        realmTestHelper.mockDnsAlias(HOSTNAME);
    }

    @Test
    public void shouldRouteRootRealmExportToHandler() throws Exception {
        givenExportReturnsEmptyPolicySet("/");

        Response response = handle("GET", "/xacml/policies");

        assertThat(response.getStatus().getCode()).isEqualTo(200);
        verifyExported("/");
    }

    @Test
    public void shouldRouteLegacyPathRealmExportToHandler() throws Exception {
        realmTestHelper.mockRealm("subrealm");
        mockRealm("/subrealm");
        givenExportReturnsEmptyPolicySet("/subrealm");

        Response response = handle("GET", "/xacml/subrealm/policies", "resource=1.0");

        assertThat(response.getStatus().getCode()).isEqualTo(200);
        verifyExported("/subrealm");
    }

    @Test
    public void shouldRouteModernRealmExportToHandler() throws Exception {
        givenExportReturnsEmptyPolicySet("/");

        Response response = handle("GET", "/xacml/realms/root/policies", "resource=1.0");

        assertThat(response.getStatus().getCode()).isEqualTo(200);
        verifyExported("/");
    }

    @DataProvider(name = "acceptApiVersionHeaders")
    public Object[][] acceptApiVersionHeaders() {
        return new Object[][] {
            {null},               // every pre-existing XACML client
            {"resource=1.0"},
            {"resource=2.0"},     // no such version; under a version gate this would 404
            {"not-a-version"},    // unparseable; proves the header is never read
        };
    }

    /**
     * The {@literal /xacml} route is deliberately unversioned, matching the Restlet application it
     * replaced. Any {@code Accept-API-Version} value must be ignored rather than routed on.
     */
    @Test(dataProvider = "acceptApiVersionHeaders")
    public void shouldExportRegardlessOfAcceptApiVersionHeader(String acceptApiVersion) throws Exception {
        givenExportReturnsEmptyPolicySet("/");

        Response response = handle("GET", "/xacml/policies", acceptApiVersion);

        assertThat(response.getStatus().getCode()).isEqualTo(200);
        verifyExported("/");
    }

    /**
     * The regression this route's lack of a version gate exists to prevent. "REST APIs > Default
     * Version = None" makes every versioned route reject unversioned requests; Restlet's /xacml was
     * never subject to that setting, and its clients cannot send the header, so it must stay immune.
     *
     * <p>With no version filter in the chain the behaviour manager is wired to nothing, so this passes
     * by construction. It is kept as an executable statement of the constraint: it fails if the version
     * filter and matcher are reintroduced together, which is the combination that resurrects the bug.
     * A matcher added without the filter is caught by {@link #shouldExportRegardlessOfAcceptApiVersionHeader}
     * instead, since the matcher then falls back to a hardcoded LATEST.
     */
    @Test
    public void shouldExportWhenDefaultVersionBehaviourIsNone() throws Exception {
        given(versionBehaviourManager.getDefaultVersionBehaviour()).willReturn(DefaultVersionBehaviour.NONE);
        givenExportReturnsEmptyPolicySet("/");

        Response response = handle("GET", "/xacml/policies");

        assertThat(response.getStatus().getCode()).isEqualTo(200);
        verifyExported("/");
    }

    /** Restlet never sent this header; the route emits no version metadata. */
    @Test
    public void shouldNotSendContentApiVersionHeader() throws Exception {
        givenExportReturnsEmptyPolicySet("/");

        Response response = handle("GET", "/xacml/policies", "resource=1.0");

        assertThat(response.getHeaders().getFirst("Content-API-Version")).isNull();
    }

    /**
     * Proves the XML error filter is mounted on the route: the 405 originates in {@code Endpoints.from},
     * which emits a CREST JSON error map, and reaches the caller as XML.
     */
    @Test
    public void shouldRenderMethodNotAllowedAsXml() throws Exception {
        Response response = handle("PUT", "/xacml/policies");

        assertThat(response.getStatus().getCode()).isEqualTo(405);
        assertThat(response.getHeaders().getFirst("Content-Type")).isEqualTo("application/xml");
        assertThat(response.getEntity().getString()).contains("<error>");
    }

    @Test
    public void shouldReturnNotFoundForUnknownEndpoint() throws Exception {
        Response response = handle("GET", "/xacml/nonsense");

        assertThat(response.getStatus().getCode()).isEqualTo(404);
        verifyZeroInteractions(importExport);
    }

    /**
     * The provider registers its own first path segment as an invalid realm name, mirroring what
     * {@code Routers.ServiceRouterImpl.route} does for the {@literal /json} endpoints. The set is
     * write-only here: its sole reader is {@code OrganizationConfigManager.validateOrgName}, which
     * rejects creation of a realm that would clash with an endpoint name. So this guards realm
     * creation, not request routing.
     */
    @Test
    public void shouldRegisterPoliciesAsAnInvalidRealmName() {
        assertThat(invalidRealmNames).contains("policies");
    }

    @Test
    public void shouldMountRouteAtXacmlPrefix() {
        Set<HttpRoute> routes = InjectorHolder.getInstance(XacmlHttpRouteProvider.class).get();

        assertThat(routes).hasSize(1);
        HttpRoute route = routes.iterator().next();
        assertThat(HttpRouteAccessor.uriTemplateOf(route)).isEqualTo("xacml");
        assertThat(HttpRouteAccessor.modeOf(route)).isEqualTo(RoutingMode.STARTS_WITH);
    }

    private Response handle(String method, String uri) throws Exception {
        return handle(method, uri, null);
    }

    private Response handle(String method, String uri, String acceptApiVersion) throws Exception {
        Request request = new Request().setMethod(method).setUri(URI.create(uri));
        request.getUri().setHost(HOSTNAME);
        if (acceptApiVersion != null) {
            request.getHeaders().put("Accept-API-Version", acceptApiVersion);
        }
        Context context = new AttributesContext(new RootContext());
        return handler.handle(context, request).get();
    }

    private void givenExportReturnsEmptyPolicySet(String realm) throws Exception {
        given(importExport.exportXACML(eq(realm), any(Subject.class), anyList()))
                .willReturn(new PolicySet());
    }

    private void verifyExported(String realm) throws Exception {
        verify(importExport).exportXACML(eq(realm), any(Subject.class), anyList());
    }

    private void mockRealm(String realm) throws Exception {
        given(coreWrapper.getOrganization(any(SSOToken.class), eq(realm))).willReturn(realm);
        given(realmValidator.isRealm(realm)).willReturn(true);
    }

    private void mockRealmAlias(String alias, String realm) throws Exception {
        given(coreWrapper.getOrganization(any(SSOToken.class), eq(alias))).willReturn(realm);
        given(coreWrapper.convertOrgNameToRealmName(realm)).willReturn(realm);
        given(realmValidator.isRealm(realm)).willReturn(true);
    }

    private PrivilegedAction<SSOToken> mockAdminTokenAction() {
        @SuppressWarnings("unchecked")
        PrivilegedAction<SSOToken> action = mock(PrivilegedAction.class);
        doAnswer(new Answer<SSOToken>() {
            @Override
            public SSOToken answer(InvocationOnMock invocation) {
                SSOToken ssoToken = mock(SSOToken.class);
                try {
                    doReturn("my-uuid").when(ssoToken).getProperty(Constants.UNIVERSAL_IDENTIFIER);
                } catch (SSOException e) {
                    throw new RuntimeException(e);
                }
                return ssoToken;
            }
        }).when(action).run();
        return action;
    }

    /**
     * Reproduces the {@code AttributesContext} contract that the CAF authentication filter
     * establishes and {@link XacmlServiceHandler} reads back.
     */
    private static final class StubAuthenticationFilter implements Filter {

        @Override
        public Promise<Response, NeverThrowsException> filter(Context context, Request request, Handler next) {
            Map<String, String> authContext = new HashMap<>();
            authContext.put("tokenId", "TOKEN");
            context.asContext(AttributesContext.class).getAttributes().put(AUTH_CONTEXT, authContext);
            return next.handle(context, request);
        }
    }

    /**
     * Grants permission unconditionally; the real implementation resolves the caller's token via the
     * {@code SSOTokenManager} singleton, which is out of reach in an in-process test. Delegation is
     * covered by the {@code e2e/xacml} spec.
     */
    private static final class TestXacmlServiceHandler extends XacmlServiceHandler {

        TestXacmlServiceHandler(XACMLExportImport importExport, PrivilegedAction<SSOToken> admin, Debug debug,
                RestLog restLog, DelegationEvaluator evaluator) {
            super(importExport, admin, debug, restLog, evaluator);
        }

        @Override
        boolean checkPermission(String action, Context context, Request request, String realm) {
            return true;
        }
    }
}
