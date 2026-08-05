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
import static org.forgerock.json.JsonValue.field;
import static org.forgerock.json.JsonValue.json;
import static org.forgerock.json.JsonValue.object;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

import java.lang.annotation.Annotation;
import java.net.URI;
import java.util.Collections;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

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
import org.forgerock.oauth2.core.AccessToken;
import org.forgerock.oauth2.core.AccessTokenService;
import org.forgerock.oauth2.core.AuthorizationService;
import org.forgerock.oauth2.core.ClientAuthenticator;
import org.forgerock.oauth2.core.ClientRegistrationStore;
import org.forgerock.oauth2.core.CsrfProtection;
import org.forgerock.oauth2.core.OAuth2ProviderSettings;
import org.forgerock.oauth2.core.OAuth2ProviderSettingsFactory;
import org.forgerock.oauth2.core.OAuth2Request;
import org.forgerock.oauth2.core.OAuth2RequestFactory;
import org.forgerock.oauth2.core.RedirectUriResolver;
import org.forgerock.oauth2.core.ResourceOwnerSessionValidator;
import org.forgerock.oauth2.core.TokenInfoService;
import org.forgerock.oauth2.core.TokenIntrospectionService;
import org.forgerock.oauth2.core.TokenStore;
import org.forgerock.oauth2.resources.ResourceSetStore;
import org.forgerock.oauth2.restlet.resources.ResourceSetDescriptionValidator;
import org.forgerock.oauth2.restlet.resources.ResourceSetRegistrationHook;
import org.forgerock.openam.audit.AuditConstants;
import org.forgerock.openam.audit.AuditEventFactory;
import org.forgerock.openam.audit.AuditEventPublisher;
import org.forgerock.openam.audit.context.AuditRequestContext;
import org.forgerock.openam.core.CoreWrapper;
import org.forgerock.openam.core.realms.RealmTestHelper;
import org.forgerock.openam.http.HttpRoute;
import org.forgerock.openam.http.HttpRouteAccessor;
import org.forgerock.openam.oauth2.OAuth2RealmResolver;
import org.forgerock.openam.oauth2.OAuth2UrisFactory;
import org.forgerock.openam.oauth2.OAuth2Utils;
import org.forgerock.openam.oauth2.ResourceSetDescription;
import org.forgerock.openam.oauth2.extensions.ExtensionFilterManager;
import org.forgerock.openam.oauth2.resources.ResourceSetLabelRegistration;
import org.forgerock.openam.oauth2.resources.labels.ResourceSetLabel;
import org.forgerock.openam.oauth2.resources.labels.UmaLabelsStore;
import org.forgerock.openam.rest.representations.JacksonRepresentationFactory;
import org.forgerock.openam.rest.router.RestRealmValidator;
import org.forgerock.openam.services.baseurl.BaseURLProviderFactory;
import org.forgerock.openam.utils.RealmNormaliser;
import org.forgerock.openidconnect.CheckSession;
import org.forgerock.openidconnect.OpenIDConnectEndSession;
import org.forgerock.openidconnect.OpenIDConnectProviderConfiguration;
import org.forgerock.openidconnect.OpenIdConnectClientRegistrationService;
import org.forgerock.openidconnect.OpenIdConnectClientRegistrationStore;
import org.forgerock.openidconnect.UserInfoService;
import org.forgerock.services.context.AttributesContext;
import org.forgerock.services.context.ClientContext;
import org.forgerock.services.context.Context;
import org.forgerock.services.context.RequestAuditContext;
import org.forgerock.services.context.RootContext;
import org.mockito.ArgumentCaptor;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

import com.google.inject.Binder;
import com.google.inject.Key;
import com.google.inject.TypeLiteral;
import com.google.inject.name.Names;
import com.iplanet.sso.SSOToken;
import com.sun.identity.idm.IdRepoException;

/**
 * Dispatches real {@code /oauth2} requests through the composition produced by the live
 * {@link OAuth2HttpRouteProvider}: the 18 attachments, the audit matrix, the nested {@code resource_set} router,
 * the root {@link OAuth2ErrorFilter} and the two-route {@link OAuth2NoCacheFilter}.
 *
 * <p>Modelled on {@code UmaRouterIT} (minimal injector, empty {@code GuiceModuleLoader}, router built from
 * {@code provider.get()}, realm mocking via {@code RealmTestHelper} + {@code CoreWrapper}). Two row families,
 * because proving 18 attachments exist and proving the seams work are different problems at very different costs:
 *
 * <ul>
 * <li><strong>Probe rows</strong> -- one per attachment, data-driven. A {@code PROPFIND} is answered by the
 *     framework before any endpoint method runs, so a probe needs no collaborator stubbing; a missing or
 *     misspelled route answers 404 rather than 405, which is what makes the probe discriminate. Each one
 *     simultaneously proves {@code Endpoints.from} is behind the route, that the root error filter rewrote the
 *     CREST body, and -- on {@code resource_set} alone -- that {@code ResourceSetErrorFilter} won inside it.
 * <li><strong>Deep rows</strong> -- the seams a probe cannot reach.
 * </ul>
 *
 * <p>The five existing composition ITs pin <em>handler-plus-chain</em> behaviour; this pins the <em>provider</em>.
 * Neither subsumes the other. Nor does this prove the production bindings resolve -- only Cargo boot and e2e do.
 *
 * <h2>Name trap</h2>
 * {@code *IT.java} is bound to failsafe: {@code mvn -pl openam-oauth2 test} does <strong>not</strong> run this
 * class. It needs {@code mvn -pl openam-oauth2 verify}.
 */
public class OAuth2RouterIT extends GuiceTestCase {

    private static final String HOSTNAME = "openam.example";
    private static final String PAT = "protection-api-token";

    private Handler handler;

    private CoreWrapper coreWrapper;
    private RestRealmValidator realmValidator;
    private RealmTestHelper realmTestHelper;
    private AuditEventPublisher auditEventPublisher;
    private TokenStore tokenStore;
    private Set<String> invalidRealmNames;

    // Collaborators the deep rows stub; the probe rows need none of them.
    private TokenInfoService tokenInfoService;
    private AccessTokenService accessTokenService;
    private OAuth2ProviderSettingsFactory providerSettingsFactory;
    private ResourceSetStore resourceSetStore;
    private UmaLabelsStore umaLabelsStore;
    private ExtensionFilterManager extensionFilterManager;

    @BeforeMethod
    public void setupMocks() throws Exception {
        auditEventPublisher = mock(AuditEventPublisher.class);
        // Every audit code path is behind isAuditing(...), so false makes the probe rows audit-free.
        given(auditEventPublisher.isAuditing(any(), any(), any())).willReturn(false);

        coreWrapper = mock(CoreWrapper.class);
        given(coreWrapper.isValidFQDN(anyString())).willReturn(true);
        given(coreWrapper.getAdminToken()).willReturn(mock(SSOToken.class));
        // Default: nothing is a realm. Endpoint path segments must fail to resolve or the realm walk would
        // swallow them -- which is the failure D7's InvalidRealmNames registration exists to make impossible.
        given(coreWrapper.getOrganization(any(SSOToken.class), anyString())).willThrow(IdRepoException.class);
        realmValidator = mock(RestRealmValidator.class);
        realmTestHelper = new RealmTestHelper(coreWrapper);
        realmTestHelper.setupRealmClass();

        tokenStore = mock(TokenStore.class);
        AccessToken token = mock(AccessToken.class);
        given(token.isExpired()).willReturn(false);
        given(token.getScope()).willReturn(Collections.<String>emptySet());
        given(token.getClientId()).willReturn("client1");
        given(token.getResourceOwnerId()).willReturn("alice");
        given(tokenStore.readAccessToken(any(OAuth2Request.class), eq(PAT))).willReturn(token);

        tokenInfoService = mock(TokenInfoService.class);
        accessTokenService = mock(AccessTokenService.class);

        providerSettingsFactory = mock(OAuth2ProviderSettingsFactory.class);
        OAuth2ProviderSettings providerSettings = mock(OAuth2ProviderSettings.class);
        given(providerSettingsFactory.get(any(OAuth2Request.class))).willReturn(providerSettings);
        resourceSetStore = mock(ResourceSetStore.class);
        given(providerSettings.getResourceSetStore()).willReturn(resourceSetStore);
        umaLabelsStore = mock(UmaLabelsStore.class);
        given(umaLabelsStore.forResourceSet(any(), any(), any(), anyBoolean()))
                .willReturn(Collections.<ResourceSetLabel>emptySet());
        extensionFilterManager = mock(ExtensionFilterManager.class);
        given(extensionFilterManager.getFilters(any())).willReturn(Collections.emptyList());

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
     * The union of the 15 handlers' {@code @Inject} fields. Binding them is the closest a test gets to proving
     * the provider's Guice graph builds at all -- {@code Endpoints.from(Class)} resolves every one of them when
     * {@code get()} runs, not per request.
     */
    @Override
    public void configure(Binder binder) {
        // The provider's own collaborators.
        binder.bind(AuditEventPublisher.class).toInstance(auditEventPublisher);
        binder.bind(AuditEventFactory.class).toInstance(new AuditEventFactory());
        binder.bind(TokenStore.class).toInstance(tokenStore);
        binder.bind(CoreWrapper.class).toInstance(coreWrapper);
        binder.bind(RestRealmValidator.class).toInstance(realmValidator);
        binder.bind(Key.get(new TypeLiteral<Set<String>>() { }, Names.named("InvalidRealmNames")))
                .toInstance(invalidRealmNames);
        binder.bind(OAuth2RequestFactory.class).toInstance(new OAuth2RequestFactory(
                mock(JacksonRepresentationFactory.class), mock(ClientRegistrationStore.class)));

        // OAuth2ErrorResponseFactory is JIT-built from these three, so the deep rows see real error bodies.
        binder.bind(FreemarkerTemplateRenderer.class).toInstance(new FreemarkerTemplateRenderer());
        binder.bind(BaseURLProviderFactory.class).toInstance(mock(BaseURLProviderFactory.class));
        binder.bind(RealmNormaliser.class).toInstance(mock(RealmNormaliser.class));

        // The handlers' collaborators.
        binder.bind(AuthorizationService.class).toInstance(mock(AuthorizationService.class));
        binder.bind(RedirectUriResolver.class).toInstance(mock(RedirectUriResolver.class));
        binder.bind(ConsentPageRenderer.class).toInstance(mock(ConsentPageRenderer.class));
        binder.bind(AccessTokenService.class).toInstance(accessTokenService);
        binder.bind(TokenInfoService.class).toInstance(tokenInfoService);
        binder.bind(TokenIntrospectionService.class).toInstance(mock(TokenIntrospectionService.class));
        binder.bind(UserInfoService.class).toInstance(mock(UserInfoService.class));
        binder.bind(ClientAuthenticator.class).toInstance(mock(ClientAuthenticator.class));
        binder.bind(ClientRegistrationStore.class).toInstance(mock(ClientRegistrationStore.class));
        binder.bind(OAuth2ProviderSettingsFactory.class).toInstance(providerSettingsFactory);
        binder.bind(OAuth2UrisFactory.class).toInstance(mock(OAuth2UrisFactory.class));
        binder.bind(OAuth2RealmResolver.class).toInstance(mock(OAuth2RealmResolver.class));
        binder.bind(OAuth2Utils.class).toInstance(mock(OAuth2Utils.class));
        binder.bind(ResourceOwnerSessionValidator.class).toInstance(mock(ResourceOwnerSessionValidator.class));
        binder.bind(CsrfProtection.class).toInstance(mock(CsrfProtection.class));
        binder.bind(CheckSession.class).toInstance(mock(CheckSession.class));
        binder.bind(OpenIDConnectEndSession.class).toInstance(mock(OpenIDConnectEndSession.class));
        binder.bind(OpenIDConnectProviderConfiguration.class)
                .toInstance(mock(OpenIDConnectProviderConfiguration.class));
        binder.bind(OpenIdConnectClientRegistrationService.class)
                .toInstance(mock(OpenIdConnectClientRegistrationService.class));
        binder.bind(OpenIdConnectClientRegistrationStore.class)
                .toInstance(mock(OpenIdConnectClientRegistrationStore.class));
        binder.bind(ExtensionFilterManager.class).toInstance(extensionFilterManager);
        binder.bind(ResourceSetDescriptionValidator.class).toInstance(mock(ResourceSetDescriptionValidator.class));
        binder.bind(ResourceSetLabelRegistration.class).toInstance(mock(ResourceSetLabelRegistration.class));
        binder.bind(UmaLabelsStore.class).toInstance(umaLabelsStore);

        // The three hook multibindings: empty, since no hook is under test here.
        binder.bind(new TypeLiteral<Set<ChfAuthorizeRequestHook>>() { }).toInstance(Collections.emptySet());
        binder.bind(new TypeLiteral<Set<ChfTokenRequestHook>>() { }).toInstance(Collections.emptySet());
        binder.bind(new TypeLiteral<Set<ResourceSetRegistrationHook>>() { }).toInstance(Collections.emptySet());
    }

    @BeforeMethod(dependsOnMethods = "setupGuiceModules")
    public void setupRouter() throws Exception {
        Router router = new Router();
        for (HttpRoute route : InjectorHolder.getInstance(OAuth2HttpRouteProvider.class).get()) {
            router.addRoute(requestUriMatcher(HttpRouteAccessor.modeOf(route), HttpRouteAccessor.uriTemplateOf(route)),
                    HttpRouteAccessor.handlerOf(route));
        }
        handler = router;

        realmTestHelper.mockDnsAlias(HOSTNAME);
        mockRealmAlias(HOSTNAME, "/");
    }

    // ---- Probe rows: one per attachment ------------------------------------------------------------------------

    /**
     * The 18 attachments of {@code OAuth2RouterProvider:94-147}, minus the realm route (covered by the realm
     * rows) and with {@code resource_set}'s three spellings kept separate. {@code needsToken} is true only where
     * a protection filter sits above the handler and would answer 401 before the framework's 405.
     */
    @DataProvider(name = "attachments")
    public Object[][] attachments() {
        return new Object[][] {
            {"authorize", "method_not_allowed", false},
            {"access_token", "method_not_allowed", false},
            {"tokeninfo", "method_not_allowed", false},
            {"introspect", "method_not_allowed", false},
            {"connect/register", "method_not_allowed", false},
            {"userinfo", "method_not_allowed", false},
            {"idtokeninfo", "method_not_allowed", false},
            {"connect/checkSession", "method_not_allowed", false},
            {"connect/endSession", "method_not_allowed", false},
            {"connect/jwk_uri", "method_not_allowed", false},
            {".well-known/openid-configuration", "method_not_allowed", false},
            {"device/user", "method_not_allowed", false},
            {"device/code", "method_not_allowed", false},
            {"token/revoke", "method_not_allowed", false},
            // resource_set keeps its own vocabulary: ResourceSetErrorFilter wins inside the root filter, which
            // returns a body already carrying `error` untouched.
            {"resource_set", "unsupported_method_type", true},
            {"resource_set/", "unsupported_method_type", true},
            {"resource_set/rs-1", "unsupported_method_type", true},
        };
    }

    /**
     * Every attachment answers a {@code PROPFIND} with a 405, not a 404. The status alone proves the route
     * exists and reaches an {@code Endpoints.from} handler; the {@code error} field proves which error filter
     * owns it; {@code Allow} proves 5d-1a's stamp survives the whole chain.
     */
    @Test(dataProvider = "attachments")
    public void everyAttachmentIsRoutedToAnEndpointsHandler(String path, String expectedError, boolean needsToken)
            throws Exception {
        Response response = handle("PROPFIND", "/oauth2/" + path, needsToken ? PAT : null);

        assertThat(response.getStatus().getCode()).as(path).isEqualTo(405);
        assertThat(bodyMap(response)).as(path).containsEntry("error", expectedError);
        assertThat(response.getHeaders().getFirst("Allow")).as(path).isNotNull();
    }

    /** D7: the eleven first path segments are registered, so no realm can be created that shadows an endpoint. */
    @Test
    public void theProviderRegistersItsFirstPathSegmentsAsInvalidRealmNames() {
        assertThat(invalidRealmNames).containsExactlyInAnyOrder("authorize", "access_token", "tokeninfo",
                "introspect", "userinfo", "idtokeninfo", "resource_set", "device", "connect", "token",
                ".well-known");
    }

    // ---- Deep rows: the seams ----------------------------------------------------------------------------------

    /**
     * D1's negative half, and the guard for R-5d1.4. {@link OAuth2NoCacheFilter} is on {@code authorize} and
     * {@code access_token} and nowhere else -- those two are the routes the Restlet {@code OAuth2Filter} wrapped,
     * so they are the only ones whose <em>framework-produced</em> responses ever carried {@code no-store}.
     * Without an assertion on an unstamped route, a later tidy-up that hoists the filter to the root passes every
     * other row in this class.
     */
    @Test
    public void theNoCacheFilterIsOnTwoRoutesAndNoOthers() throws Exception {
        for (String stamped : new String[] {"authorize", "access_token"}) {
            Response response = handle("PROPFIND", "/oauth2/" + stamped, null);
            assertThat(response.getHeaders().getFirst("Cache-Control")).as(stamped).isEqualTo("no-store");
            assertThat(response.getHeaders().getFirst("Pragma")).as(stamped).isEqualTo("no-cache");
        }
        for (String bare : new String[] {"tokeninfo", "introspect", "userinfo", "connect/jwk_uri"}) {
            Response response = handle("PROPFIND", "/oauth2/" + bare, null);
            assertThat(response.getHeaders().getFirst("Cache-Control")).as(bare).isNull();
            assertThat(response.getHeaders().getFirst("Pragma")).as(bare).isNull();
        }
    }

    /**
     * 5d-1a mapped {@code HEAD} to the {@code @Get} entry, so a lookup endpoint serves it -- and
     * {@code /authorize} must not (5-E5 correction 2), or a {@code HEAD} would run the authorization flow and
     * hand out a code. Both halves through the real provider, which is where the guard has to hold.
     */
    @Test
    public void headServesALookupEndpointAndIsRefusedOnAuthorize() throws Exception {
        given(tokenInfoService.getTokenInfo(any(OAuth2Request.class)))
                .willReturn(json(object(field("scope", "read"), field("token_type", "Bearer"))));

        Response get = handle("GET", "/oauth2/tokeninfo", null);
        Response head = handle("HEAD", "/oauth2/tokeninfo", null);

        assertThat(get.getStatus().getCode()).isEqualTo(200);
        assertThat(head.getStatus().getCode()).isEqualTo(200);
        // A HEAD is its GET with the body dropped by the connector, so the headers must be the GET's.
        assertThat(head.getHeaders().getFirst("Content-Type")).isEqualTo(get.getHeaders().getFirst("Content-Type"));
        assertThat(head.getHeaders().getFirst("Cache-Control")).isEqualTo("no-cache, no-store");

        assertThat(handle("HEAD", "/oauth2/authorize", null).getStatus().getCode()).isEqualTo(405);
    }

    /**
     * D5, on <strong>both</strong> routers. The nested {@code resource_set} router answers its own 404 rather
     * than falling through to the parent's default route, so mounting the handler on the endpoint router alone
     * would leave {@code /oauth2/resource_set/a/b} -- the one 404 the migration has an oracle for (5-E4 row 17)
     * -- as the only bodiless one on the surface.
     */
    @Test
    public void bothRoutersAnswerAnUnroutedPathWithTheSynthesized404() throws Exception {
        for (String unrouted : new String[] {"/oauth2/nosuchendpoint", "/oauth2/connect/nosuch",
                "/oauth2/resource_set/a/b"}) {
            Response response = handle("GET", unrouted, PAT);
            assertThat(response.getStatus().getCode()).as(unrouted).isEqualTo(404);
            assertThat(bodyMap(response)).as(unrouted).containsEntry("error", "not_found");
        }
    }

    /**
     * R-5c.12, discharged: {@code ResourceSetRouteCompositionIT} proves this shape works, but its router is wired
     * inline -- only this row proves the <em>provider</em> uses it. All three Restlet attachments
     * ({@code :131-133}) reach the handler, and {@code rsid} binds on the item form alone.
     */
    @Test
    public void resourceSetAnswersAllThreeUrlFormsAndOnlyTheItemFormBindsAnRsid() throws Exception {
        given(resourceSetStore.read("rs-1", "alice")).willReturn(storedResourceSet());
        given(resourceSetStore.query(any())).willReturn(new LinkedHashSet<>(List.of(storedResourceSet())));

        Response collection = handle("GET", "/oauth2/resource_set", PAT);
        Response collectionSlash = handle("GET", "/oauth2/resource_set/", PAT);
        Response item = handle("GET", "/oauth2/resource_set/rs-1", PAT);

        assertThat(collection.getStatus().getCode()).isEqualTo(200);
        assertThat(collectionSlash.getStatus().getCode()).isEqualTo(200);
        assertThat(item.getStatus().getCode()).isEqualTo(200);
        assertThat(bodyMap(item)).containsEntry("_id", "rs-1");
        verify(resourceSetStore).read("rs-1", "alice");
    }

    /**
     * R-5d1.6: {@code RealmContextFilter} replaces {@code RestletRealmRouter}, and all three styles the live
     * surface accepts must still reach the endpoint. The legacy path style is the one no {@code e2e/oauth2} row
     * exercises.
     */
    @Test
    public void allThreeRealmStylesReachTheEndpoint() throws Exception {
        given(tokenInfoService.getTokenInfo(any(OAuth2Request.class))).willReturn(json(object()));

        assertThat(handle("GET", "/oauth2/realms/root/tokeninfo", null).getStatus().getCode()).isEqualTo(200);
        assertThat(handle("GET", "/oauth2/tokeninfo?realm=/", null).getStatus().getCode()).isEqualTo(200);

        realmTestHelper.mockRealm("subrealm");
        given(coreWrapper.getOrganization(any(SSOToken.class), eq("subrealm"))).willReturn("/subrealm");
        given(coreWrapper.convertOrgNameToRealmName("/subrealm")).willReturn("/subrealm");
        given(realmValidator.isRealm("/subrealm")).willReturn(true);
        assertThat(handle("GET", "/oauth2/subrealm/tokeninfo", null).getStatus().getCode()).isEqualTo(200);
    }

    /**
     * D3: the audit matrix is a transcription, so a dropped field must be visible rather than silent. Asserting
     * only "an event was emitted" would pass with an empty auditor. {@code /access_token} is the row with the
     * longest list on both sides, and the extra form field proves the auditor <em>selects</em> rather than
     * copying the body.
     */
    @Test
    public void theAccessTokenAuditDetailIsExactlyTheConfiguredFieldList() throws Exception {
        given(auditEventPublisher.isAuditing(any(), any(), any())).willReturn(true);
        AccessToken issued = mock(AccessToken.class);
        given(issued.toMap()).willReturn(new LinkedHashMap<>(Map.of(
                "access_token", "AT-1", "token_type", "Bearer", "scope", "read", "expires_in", 3600)));
        given(accessTokenService.requestAccessToken(any(OAuth2Request.class))).willReturn(issued);

        Response response = handle(HOSTNAME, "POST", "/oauth2/access_token", null,
                "application/x-www-form-urlencoded",
                "grant_type=client_credentials&client_id=c1&scope=read&response_type=token"
                        + "&username=alice&redirect_uri=http://rp.example/cb&client_secret=shh");

        assertThat(response.getStatus().getCode()).isEqualTo(200);
        List<AuditEvent> events = captureTwoEvents();
        // The six fields of formAuditor(RESPONSE_TYPE, GRANT_TYPE, CLIENT_ID, USERNAME, SCOPE, REDIRECT_URI) --
        // and client_secret, which is in the body but not in the list, must not be among them.
        assertThat(events.get(0).getValue().get("request").get("detail").asMap().keySet())
                .containsExactlyInAnyOrder("response_type", "grant_type", "client_id", "username", "scope",
                        "redirect_uri");
        // jsonAuditor(SCOPE, TOKEN_TYPE) on the response: the issued token's other fields are not audited.
        assertThat(events.get(1).getValue().get("response").get("detail").asMap().keySet())
                .containsExactlyInAnyOrder("scope", "token_type");
    }

    // ---- Helpers -----------------------------------------------------------------------------------------------

    private Response handle(String method, String uri, String bearer) throws Exception {
        return handle(HOSTNAME, method, uri, bearer, null, null);
    }

    private Response handle(String host, String method, String uri, String bearer, String contentType, String body)
            throws Exception {
        Request request = new Request().setMethod(method).setUri(URI.create(uri));
        request.getUri().setHost(host);
        if (bearer != null) {
            request.getHeaders().put("Authorization", "Bearer " + bearer);
        }
        if (contentType != null) {
            request.getHeaders().put("Content-Type", contentType);
            request.getEntity().setString(body);
        }
        Context context = new AttributesContext(new RequestAuditContext(
                ClientContext.buildExternalClientContext(new RootContext())
                        .remoteAddress("127.0.0.1").remotePort(9000).build()));
        return handler.handle(context, request).getOrThrowUninterruptibly();
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> bodyMap(Response response) throws Exception {
        return (Map<String, Object>) response.getEntity().getJson();
    }

    private List<AuditEvent> captureTwoEvents() {
        ArgumentCaptor<AuditEvent> captor = ArgumentCaptor.forClass(AuditEvent.class);
        verify(auditEventPublisher, times(2)).tryPublish(eq(AuditConstants.ACCESS_TOPIC), captor.capture());
        return captor.getAllValues();
    }

    private static ResourceSetDescription storedResourceSet() {
        Map<String, Object> description = new LinkedHashMap<>();
        description.put("name", "photo album");
        description.put("scopes", List.of("read", "write"));
        ResourceSetDescription resourceSet = new ResourceSetDescription("rs-1", "client1", "alice", description);
        resourceSet.setRealm("/");
        return resourceSet;
    }

    private void mockRealmAlias(String alias, String realm) throws Exception {
        given(coreWrapper.getOrganization(any(SSOToken.class), eq(alias))).willReturn(realm);
        given(coreWrapper.convertOrgNameToRealmName(realm)).willReturn(realm);
        given(realmValidator.isRealm(realm)).willReturn(true);
    }
}
