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

package org.forgerock.openam.uma;

import static java.util.Collections.emptyMap;
import static java.util.Collections.singleton;
import static org.assertj.core.api.Assertions.assertThat;
import static org.forgerock.http.routing.RouteMatchers.requestUriMatcher;
import static org.forgerock.json.JsonValue.array;
import static org.forgerock.json.JsonValue.field;
import static org.forgerock.json.JsonValue.json;
import static org.forgerock.json.JsonValue.object;
import static org.forgerock.openam.audit.AuditConstants.EventName.AM_ACCESS_ATTEMPT;
import static org.forgerock.openam.audit.AuditConstants.EventName.AM_ACCESS_OUTCOME;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.nullable;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.doThrow;
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
import org.forgerock.http.header.ContentTypeHeader;
import org.forgerock.http.protocol.Request;
import org.forgerock.http.protocol.Response;
import org.forgerock.http.routing.Router;
import org.forgerock.json.JsonValue;
import org.forgerock.oauth2.core.AccessToken;
import org.forgerock.oauth2.core.ClientRegistrationStore;
import org.forgerock.oauth2.core.OAuth2ProviderSettings;
import org.forgerock.oauth2.core.OAuth2ProviderSettingsFactory;
import org.forgerock.oauth2.core.OAuth2Request;
import org.forgerock.oauth2.core.OAuth2RequestFactory;
import org.forgerock.oauth2.core.TokenStore;
import org.forgerock.oauth2.resources.ResourceSetStore;
import org.forgerock.openam.audit.AuditConstants;
import org.forgerock.openam.audit.AuditEventFactory;
import org.forgerock.openam.audit.AuditEventPublisher;
import org.forgerock.openam.audit.context.AuditRequestContext;
import org.forgerock.openam.core.CoreWrapper;
import org.forgerock.openam.core.realms.Realm;
import org.forgerock.openam.core.realms.RealmTestHelper;
import org.forgerock.openam.http.HttpRoute;
import org.forgerock.openam.http.HttpRouteAccessor;
import org.forgerock.openam.oauth2.ResourceSetDescription;
import org.forgerock.openam.oauth2.extensions.ExtensionFilterManager;
import org.forgerock.openam.rest.representations.JacksonRepresentationFactory;
import org.forgerock.openam.rest.router.RestRealmValidator;
import org.forgerock.openam.services.baseurl.BaseURLProvider;
import org.forgerock.openam.services.baseurl.BaseURLProviderFactory;
import org.forgerock.openam.uma.audit.UmaAuditLogger;
import org.forgerock.services.context.AttributesContext;
import org.forgerock.services.context.ClientContext;
import org.forgerock.services.context.Context;
import org.forgerock.services.context.RequestAuditContext;
import org.forgerock.services.context.RootContext;
import org.mockito.ArgumentCaptor;
import org.openidentityplatform.openam.uma.UmaHttpRouteProvider;
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
 * Dispatches real {@code /uma} requests through the composition produced by the live
 * {@link UmaHttpRouteProvider}: realm routing, the {@code ChfAccessTokenProtectionFilter}, the UMA access-audit
 * wrap, and the two distinct error shapes. The single most important claim of Phase 4 is that both error shapes
 * survive in situ — CREST {@code {code,reason,message}} for the protection filter (case 2) and framework (case 8),
 * UMA {@code {error,error_description}} for endpoint exceptions (case 4) — which no layer-1 unit test exercises.
 *
 * <p>Modeled on {@code XacmlRouterIT} (minimal injector, empty {@code GuiceModuleLoader}, router built from
 * {@code provider.get()}, realm mocking via {@code RealmTestHelper}+{@code CoreWrapper}) and the audit-capture
 * style of {@code OAuth2AuditRouteCompositionIT}. Lives in {@code org.forgerock.openam.uma} so it can stub the
 * package-private {@code UmaTokenStore} methods. Authentication is not stubbed — each protected route carries the
 * real protection filter over a stubbed {@code TokenStore}; the real over-the-wire flow is the deferred
 * {@code e2e/uma} smoke.
 *
 * <p>Case 5 binds the <em>real</em> {@code OAuth2UrisFactory} (not a mock) so that
 * {@code AuthorizationRequestEndpoint}'s {@code oAuth2UrisFactory.get(oauth2Request)} runs the real
 * {@code getParameter("realmObject")} read — the Phase-4 silent-NPE guard (finding 6): with the 4a seed present it
 * resolves; without it, that line would NPE and surface as a 500 rather than the deterministic 400 asserted here.
 */
public class UmaRouterIT extends GuiceTestCase {

    private static final String HOSTNAME = "HOSTNAME";
    private static final String PAT = "PAT";
    private static final String AAT = "AAT";
    private static final String NO_SCOPE = "NOSCOPE";

    private Handler handler;

    private OAuth2RequestFactory oauth2RequestFactory;
    private TokenStore tokenStore;
    private AuditEventPublisher auditEventPublisher;
    private CoreWrapper coreWrapper;
    private RestRealmValidator realmValidator;
    private OAuth2ProviderSettingsFactory oauth2ProviderSettingsFactory;
    private UmaProviderSettingsFactory umaProviderSettingsFactory;
    private ExtensionFilterManager extensionFilterManager;
    private BaseURLProviderFactory baseURLProviderFactory;
    private UmaUrisFactory umaUrisFactory;
    private UmaAuditLogger umaAuditLogger;
    private PendingRequestsService pendingRequestsService;
    private Set<String> invalidRealmNames;
    private RealmTestHelper realmTestHelper;

    // Collaborators reachable through the mocked factories, stubbed per happy path.
    private OAuth2ProviderSettings oauth2ProviderSettings;
    private UmaProviderSettings umaProviderSettings;
    private UmaTokenStore umaTokenStore;
    private ResourceSetStore resourceSetStore;

    private AccessToken patToken;
    private AccessToken aatToken;
    private AccessToken noScopeToken;

    @BeforeMethod
    public void setupMocks() throws Exception {
        oauth2RequestFactory = new OAuth2RequestFactory(mock(JacksonRepresentationFactory.class),
                mock(ClientRegistrationStore.class));
        tokenStore = mock(TokenStore.class);
        auditEventPublisher = mock(AuditEventPublisher.class);
        given(auditEventPublisher.isAuditing(any(), any(), any())).willReturn(true);

        coreWrapper = mock(CoreWrapper.class);
        given(coreWrapper.isValidFQDN(anyString())).willReturn(true);
        given(coreWrapper.getAdminToken()).willReturn(mock(SSOToken.class));
        realmValidator = mock(RestRealmValidator.class);
        realmTestHelper = new RealmTestHelper(coreWrapper);
        realmTestHelper.setupRealmClass();

        oauth2ProviderSettingsFactory = mock(OAuth2ProviderSettingsFactory.class);
        umaProviderSettingsFactory = mock(UmaProviderSettingsFactory.class);
        extensionFilterManager = mock(ExtensionFilterManager.class);
        doReturn(java.util.Collections.emptyList()).when(extensionFilterManager).getFilters(any());
        baseURLProviderFactory = mock(BaseURLProviderFactory.class);
        BaseURLProvider baseURLProvider = mock(BaseURLProvider.class);
        // In-process the servlet request is null; give the real OAuth2UrisFactory a non-null baseUrl so its
        // ConcurrentHashMap keying (urisMap.get(baseUrl)) does not NPE on a null key.
        given(baseURLProvider.getRealmURL(nullable(HttpServletRequest.class), anyString(), any(Realm.class)))
                .willReturn("http://openam.example:8080/openam/oauth2");
        given(baseURLProvider.getRootURL(nullable(HttpServletRequest.class)))
                .willReturn("http://openam.example:8080/openam");
        given(baseURLProviderFactory.get(anyString())).willReturn(baseURLProvider);
        umaUrisFactory = mock(UmaUrisFactory.class);
        given(umaUrisFactory.get(any(Context.class), any())).willReturn(mock(UmaUris.class));
        umaAuditLogger = mock(UmaAuditLogger.class);
        pendingRequestsService = mock(PendingRequestsService.class);
        invalidRealmNames = new HashSet<>();

        // Shared provider-settings graph.
        oauth2ProviderSettings = mock(OAuth2ProviderSettings.class);
        given(oauth2ProviderSettingsFactory.get(any(OAuth2Request.class))).willReturn(oauth2ProviderSettings);
        resourceSetStore = mock(ResourceSetStore.class);
        given(oauth2ProviderSettings.getResourceSetStore()).willReturn(resourceSetStore);
        umaProviderSettings = mock(UmaProviderSettings.class);
        given(umaProviderSettingsFactory.get(any(OAuth2Request.class))).willReturn(umaProviderSettings);
        given(umaProviderSettingsFactory.get(anyString())).willReturn(umaProviderSettings);
        umaTokenStore = mock(UmaTokenStore.class);
        given(umaProviderSettings.getUmaTokenStore()).willReturn(umaTokenStore);

        patToken = accessToken(singleton("uma_protection"));
        aatToken = accessToken(singleton("uma_authorization"));
        noScopeToken = accessToken(java.util.Collections.<String>emptySet());
        given(tokenStore.readAccessToken(any(OAuth2Request.class), eq(PAT))).willReturn(patToken);
        given(tokenStore.readAccessToken(any(OAuth2Request.class), eq(AAT))).willReturn(aatToken);
        given(tokenStore.readAccessToken(any(OAuth2Request.class), eq(NO_SCOPE))).willReturn(noScopeToken);
    }

    private AccessToken accessToken(Set<String> scopes) {
        AccessToken token = mock(AccessToken.class);
        given(token.isExpired()).willReturn(false);
        given(token.getScope()).willReturn(scopes);
        given(token.getClientId()).willReturn("client1");
        given(token.getResourceOwnerId()).willReturn("ro1");
        return token;
    }

    @AfterMethod
    public void tearDown() {
        realmTestHelper.tearDownRealmClass();
        AuditRequestContext.clear();
    }

    @AfterMethod
    public void restoreModuleLoader() {
        // setupGuiceModules() swaps the process-global GuiceModuleLoader for an empty one; GuiceTestCase.teardown
        // restores only the InjectorHolder, so reset the loader to the framework default to avoid leaking the empty
        // loader to later GuiceTestCase-based tests in the same fork.
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

    @Override
    public void configure(Binder binder) {
        binder.bind(OAuth2RequestFactory.class).toInstance(oauth2RequestFactory);
        binder.bind(TokenStore.class).toInstance(tokenStore);
        binder.bind(AuditEventPublisher.class).toInstance(auditEventPublisher);
        binder.bind(AuditEventFactory.class).toInstance(new AuditEventFactory());
        binder.bind(CoreWrapper.class).toInstance(coreWrapper);
        binder.bind(RestRealmValidator.class).toInstance(realmValidator);
        binder.bind(Key.get(new TypeLiteral<Set<String>>() { }, Names.named("InvalidRealmNames")))
                .toInstance(invalidRealmNames);
        binder.bind(OAuth2ProviderSettingsFactory.class).toInstance(oauth2ProviderSettingsFactory);
        binder.bind(UmaProviderSettingsFactory.class).toInstance(umaProviderSettingsFactory);
        binder.bind(ExtensionFilterManager.class).toInstance(extensionFilterManager);
        binder.bind(BaseURLProviderFactory.class).toInstance(baseURLProviderFactory);
        binder.bind(UmaUrisFactory.class).toInstance(umaUrisFactory);
        binder.bind(UmaAuditLogger.class).toInstance(umaAuditLogger);
        binder.bind(PendingRequestsService.class).toInstance(pendingRequestsService);
        binder.bind(new TypeLiteral<Map<String, ClaimGatherer>>() { }).toInstance(emptyMap());
        // OAuth2UrisFactory is deliberately NOT bound — Guice just-in-time builds the real class from the mocked
        // OAuth2ProviderSettingsFactory + BaseURLProviderFactory, so case 5 exercises its real realmObject read.
    }

    @BeforeMethod(dependsOnMethods = "setupGuiceModules")
    public void setupRouter() throws Exception {
        Router router = new Router();
        for (HttpRoute route : InjectorHolder.getInstance(UmaHttpRouteProvider.class).get()) {
            router.addRoute(requestUriMatcher(HttpRouteAccessor.modeOf(route), HttpRouteAccessor.uriTemplateOf(route)),
                    HttpRouteAccessor.handlerOf(route));
        }
        handler = router;

        // The host resolves to the root realm; endpoint path segments are not realms — an unresolvable element ends
        // the realm walk and leaves the realm as resolved so far (mirrors XacmlRouterIT.setupRouter).
        mockRealmAlias(HOSTNAME, "/");
        for (String segment : new String[] {"permission_request", "authz_request", ".well-known", "uma-configuration",
                "nonsense"}) {
            doThrow(IdRepoException.class).when(coreWrapper).getOrganization(any(SSOToken.class), eq(segment));
        }
        realmTestHelper.mockDnsAlias(HOSTNAME);
    }

    // ---- Cases -------------------------------------------------------------------------------------------------

    /** Case 1 — happy path: token stash (protection filter → endpoint) + audit body detail compose in one request. */
    @Test
    public void permissionRequestWithValidPatReturns201AndAudits() throws Exception {
        givenResourceSet("rs1", "ro1", "read");
        PermissionTicket ticket = permissionTicket("TICKET-123");
        given(umaTokenStore.createPermissionTicket(eq("rs1"), any(), eq("client1"))).willReturn(ticket);

        Response response = handle("POST", "/uma/permission_request", PAT,
                "{\"resource_set_id\":\"rs1\",\"scopes\":[\"read\"]}");

        assertThat(response.getStatus().getCode()).isEqualTo(201);
        assertThat(bodyMap(response)).containsEntry("ticket", "TICKET-123");

        List<AuditEvent> events = captureTwoEvents();
        JsonValue attempt = events.get(0).getValue();
        assertThat(attempt.get("eventName").asString()).isEqualTo(AM_ACCESS_ATTEMPT.toString());
        assertThat(events.get(1).getValue().get("eventName").asString()).isEqualTo(AM_ACCESS_OUTCOME.toString());
        assertThat(attempt.get("request").get("detail").get("resource_set_id").asString()).isEqualTo("rs1");
        assertThat(attempt.get("request").get("detail").get("scopes").asList(String.class)).containsExactly("read");
    }

    /** Case 2 — no bearer: 401 in CREST shape (D5), no OAuth2 {@code error} field, no {@code WWW-Authenticate}. */
    @Test
    public void permissionRequestWithoutBearerReturns401Crest() throws Exception {
        Response response = handle("POST", "/uma/permission_request", null,
                "{\"resource_set_id\":\"rs1\",\"scopes\":[\"read\"]}");

        assertThat(response.getStatus().getCode()).isEqualTo(401);
        Map<String, Object> body = bodyMap(response);
        assertThat(body).containsKey("code").doesNotContainKey("error");
        assertThat(response.getHeaders().getFirst("Content-Type")).contains("application/json");
        assertThat(response.getHeaders().getFirst("WWW-Authenticate")).isNull();
        verify(umaProviderSettings, times(0)).getUmaTokenStore();
    }

    /** Case 3 — token lacking {@code uma_protection}: 403 CREST InsufficientScope. */
    @Test
    public void permissionRequestWithoutRequiredScopeReturns403() throws Exception {
        Response response = handle("POST", "/uma/permission_request", NO_SCOPE,
                "{\"resource_set_id\":\"rs1\",\"scopes\":[\"read\"]}");

        assertThat(response.getStatus().getCode()).isEqualTo(403);
        assertThat(bodyMap(response)).containsKey("code").doesNotContainKey("error");
    }

    /** Case 4 — valid PAT, body missing {@code resource_set_id}: 400 in UMA shape (endpoint path, not CREST). */
    @Test
    public void permissionRequestMissingResourceSetIdReturns400Uma() throws Exception {
        Response response = handle("POST", "/uma/permission_request", PAT, "{\"scopes\":[\"read\"]}");

        assertThat(response.getStatus().getCode()).isEqualTo(400);
        Map<String, Object> body = bodyMap(response);
        assertThat(body).containsEntry("error", "invalid_resource_set_id");
        assertThat(body).containsKey("error_description").doesNotContainKey("code");
    }

    /**
     * Case 5 — the realmObject silent-NPE guard (finding 6). Valid AAT, real {@code OAuth2UrisFactory}. Reaching the
     * deterministic 400 (invalid ticket) proves {@code oAuth2UrisFactory.get(oauth2Request)} resolved through the
     * seeded {@code "realmObject"}; an unseeded seed would NPE at that line and surface as a 500.
     */
    @Test
    public void authzRequestExercisesRealOAuth2UrisFactoryViaRealmObjectSeed() throws Exception {
        // An expired ticket takes the endpoint to a deterministic 400 (expired_ticket) after line 115; reaching it at
        // all proves the real OAuth2UrisFactory resolved through the seeded "realmObject" (else it would 500 there).
        given(umaTokenStore.readPermissionTicket(anyString())).willReturn(mock(PermissionTicket.class));

        Response response = handle("POST", "/uma/authz_request", AAT, "{\"ticket\":\"T1\"}");

        assertThat(response.getStatus().getCode()).isEqualTo(400);
        assertThat(bodyMap(response)).containsKey("error").doesNotContainKey("code");
        verify(umaTokenStore).readPermissionTicket("T1");
    }

    /** Case 6 — well-known discovery is public: 200 config JSON with no token. */
    @Test
    public void wellKnownConfigurationIsPublic() throws Exception {
        Response response = handle("GET", "/uma/.well-known/uma-configuration", null, null);

        assertThat(response.getStatus().getCode()).isEqualTo(200);
        assertThat(bodyMap(response)).containsKey("version");
    }

    /** Case 7 — modern ({@code /realms/root}) and legacy ({@code /subrealm}) realm styles both route to the endpoint. */
    @Test
    public void realmStylesBothRouteToEndpoint() throws Exception {
        Response modern = handle("GET", "/uma/realms/root/permission_request", PAT, null);
        assertThat(modern.getStatus().getCode()).isEqualTo(405); // route reached; GET unmapped (only @Post)

        realmTestHelper.mockRealm("subrealm");
        mockRealm("/subrealm");
        given(coreWrapper.getOrganization(any(SSOToken.class), eq("subrealm"))).willReturn("/subrealm");
        Response legacy = handle("GET", "/uma/subrealm/permission_request", PAT, null);
        assertThat(legacy.getStatus().getCode()).isEqualTo(405); // route reached after legacy realm consumed
    }

    /** Case 8 — wrong verb on a protected route (valid PAT): 405 in CREST shape — proves no OAuth2ErrorFilter (D4). */
    @Test
    public void wrongVerbReturns405Crest() throws Exception {
        Response response = handle("GET", "/uma/permission_request", PAT, null);

        assertThat(response.getStatus().getCode()).isEqualTo(405);
        assertThat(bodyMap(response)).containsKey("code").doesNotContainKey("error");
    }

    /** Case 9 — unknown endpoint: 404. */
    @Test
    public void unknownEndpointReturns404() throws Exception {
        Response response = handle("GET", "/uma/nonsense", null, null);

        assertThat(response.getStatus().getCode()).isEqualTo(404);
    }

    /** Case 10 — the provider registers its own endpoint segments as invalid realm names. */
    @Test
    public void providerRegistersEndpointSegmentsAsInvalidRealmNames() {
        assertThat(invalidRealmNames).contains("permission_request", "authz_request");
    }

    /**
     * Case 11 — a realm-resolution failure renders as native CREST {@code {code,reason,message}} (via
     * {@code RealmContextFilter}, not an error filter), not empty/HTML: pins that {@code /uma} needs no error filter
     * over the realm layer, unlike XACML (D4). Triggered here by an invalid FQDN, which {@code RealmContextFilter}
     * rejects with a {@code BadRequestException} it renders as CREST 400 ({@code RealmContextFilter.java:87-90}) —
     * the same native-CREST realm-error path the design relies on.
     */
    @Test
    public void realmResolutionFailureRendersCrest() throws Exception {
        given(coreWrapper.isValidFQDN("BADHOST")).willReturn(false);

        Response response = handle("BADHOST", "GET", "/uma/permission_request", null, null);

        assertThat(response.getStatus().getCode()).isEqualTo(400);
        Map<String, Object> body = bodyMap(response);
        assertThat(body).containsKey("code").doesNotContainKey("error");
    }

    // ---- Helpers -----------------------------------------------------------------------------------------------

    private void givenResourceSet(String resourceSetId, String resourceOwnerId, String... scopes) throws Exception {
        ResourceSetDescription description = mock(ResourceSetDescription.class);
        given(description.getResourceOwnerId()).willReturn(resourceOwnerId);
        given(description.getDescription()).willReturn(json(object(field("scopes", array((Object[]) scopes)))));
        given(resourceSetStore.read(resourceSetId, resourceOwnerId)).willReturn(description);
    }

    private PermissionTicket permissionTicket(String id) {
        PermissionTicket ticket = mock(PermissionTicket.class);
        given(ticket.getId()).willReturn(id);
        return ticket;
    }

    private Response handle(String method, String uri, String bearer, String jsonBody) throws Exception {
        return handle(HOSTNAME, method, uri, bearer, jsonBody);
    }

    private Response handle(String host, String method, String uri, String bearer, String jsonBody) throws Exception {
        Request request = new Request().setMethod(method).setUri(URI.create(uri));
        request.getUri().setHost(host);
        if (bearer != null) {
            request.getHeaders().put("Authorization", "Bearer " + bearer);
        }
        if (jsonBody != null) {
            request.getHeaders().put(ContentTypeHeader.valueOf("application/json"));
            request.getEntity().setString(jsonBody);
        }
        Context context = new AttributesContext(new RequestAuditContext(
                ClientContext.buildExternalClientContext(new RootContext())
                        .remoteAddress("127.0.0.1").remotePort(9000).build()));
        return handler.handle(context, request).getOrThrowUninterruptibly();
    }

    @SuppressWarnings("unchecked")
    private Map<String, Object> bodyMap(Response response) throws Exception {
        return (Map<String, Object>) response.getEntity().getJson();
    }

    private List<AuditEvent> captureTwoEvents() {
        ArgumentCaptor<AuditEvent> captor = ArgumentCaptor.forClass(AuditEvent.class);
        verify(auditEventPublisher, times(2)).tryPublish(eq(AuditConstants.ACCESS_TOPIC), captor.capture());
        return captor.getAllValues();
    }

    private void mockRealmAlias(String alias, String realm) throws Exception {
        given(coreWrapper.getOrganization(any(SSOToken.class), eq(alias))).willReturn(realm);
        given(coreWrapper.convertOrgNameToRealmName(realm)).willReturn(realm);
        given(realmValidator.isRealm(realm)).willReturn(true);
    }

    private void mockRealm(String realm) throws Exception {
        given(coreWrapper.getOrganization(any(SSOToken.class), eq(realm))).willReturn(realm);
        given(realmValidator.isRealm(realm)).willReturn(true);
    }
}
