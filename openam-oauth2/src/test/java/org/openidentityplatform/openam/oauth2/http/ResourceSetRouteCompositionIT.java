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
import static org.forgerock.http.routing.RoutingMode.EQUALS;
import static org.forgerock.http.routing.RoutingMode.STARTS_WITH;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.lang.reflect.Field;
import java.net.URI;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.forgerock.audit.events.AuditEvent;
import org.forgerock.http.Handler;
import org.forgerock.http.handler.Handlers;
import org.forgerock.http.header.ContentTypeHeader;
import org.forgerock.http.protocol.Request;
import org.forgerock.http.protocol.Response;
import org.forgerock.http.protocol.Status;
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
import org.forgerock.oauth2.restlet.resources.ResourceSetDescriptionValidator;
import org.forgerock.oauth2.restlet.resources.ResourceSetRegistrationHook;
import org.forgerock.openam.audit.AuditEventFactory;
import org.forgerock.openam.audit.AuditEventPublisher;
import org.forgerock.openam.audit.context.AuditRequestContext;
import org.forgerock.openam.core.realms.Realm;
import org.forgerock.openam.core.realms.RealmTestHelper;
import org.forgerock.openam.http.annotations.Endpoints;
import org.forgerock.openam.oauth2.ResourceSetDescription;
import org.forgerock.openam.oauth2.extensions.ExtensionFilterManager;
import org.forgerock.openam.oauth2.resources.ResourceSetLabelRegistration;
import org.forgerock.openam.oauth2.resources.labels.LabelType;
import org.forgerock.openam.oauth2.resources.labels.ResourceSetLabel;
import org.forgerock.openam.oauth2.resources.labels.UmaLabelsStore;
import org.forgerock.openam.rest.RealmContext;
import org.forgerock.openam.rest.representations.JacksonRepresentationFactory;
import org.forgerock.openam.services.baseurl.BaseURLProviderFactory;
import org.forgerock.openam.utils.RealmNormaliser;
import org.forgerock.services.context.AttributesContext;
import org.forgerock.services.context.ClientContext;
import org.forgerock.services.context.Context;
import org.forgerock.services.context.RequestAuditContext;
import org.forgerock.services.context.RootContext;
import org.forgerock.util.promise.Promises;
import org.mockito.ArgumentCaptor;
import org.openidentityplatform.openam.oauth2.audit.HttpBodyAuditor;
import org.openidentityplatform.openam.oauth2.audit.OAuth2HttpAccessAuditFilter;
import org.openidentityplatform.openam.oauth2.http.ChfAccessTokenProtectionFilter.ErrorShape;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import com.iplanet.sso.SSOToken;

/**
 * Composition guard for {@link ResourceSetRegistrationHandler}: the real handler behind the real filter chain
 * and the real nested {@link Router}, driven in process over a full context chain.
 *
 * <h2>What this proves, and what it cannot</h2>
 * The chain and the routing here reproduce
 * <a href="../../../../../../../../../docs/migration/restlet/phase-5c.md">phase-5c D9</a> inline, because
 * {@code OAuth2HttpRouteProvider} does not exist until 5d-1. So these rows prove the shape <strong>works</strong>;
 * they cannot prove 5d-1 <strong>uses</strong> it. Driving the real provider — as {@code UmaRouterIT} does through
 * {@code HttpRouteAccessor} — is a 5d-1 handoff item (R-5c.12).
 *
 * <h2>⚠ The {@link RealmContext} is not scaffolding</h2>
 * Without it {@code ChfOAuth2Request} seeds neither {@code realm} nor {@code realmObject}, and the create path
 * hands {@code null} to the registration hook, which NPEs on a live request while a {@code RootContext}-only test
 * stays green (phase-5c finding 16).
 *
 * <h2>Name trap</h2>
 * {@code *IT.java} is bound to failsafe: {@code mvn -pl openam-oauth2 test} does <strong>not</strong> run this
 * class. It needs {@code mvn -pl openam-oauth2 verify}.
 */
public class ResourceSetRouteCompositionIT {

    private static final String PATH = "/oauth2/resource_set";
    private static final String RSID = "rs-1";
    private static final String CLIENT = "rs-client";
    private static final String OWNER = "alice";
    private static final String PAT = "protection-api-token";
    private static final String JSON = "application/json";

    private Handler router;
    private TokenStore tokenStore;
    private ResourceSetStore store;
    private UmaLabelsStore umaLabelsStore;
    private ResourceSetLabelRegistration labelRegistration;
    private ResourceSetRegistrationHook hook;
    private AuditEventPublisher auditEventPublisher;
    private RealmTestHelper realmTestHelper;
    private OAuth2RequestFactory requestFactory;

    @BeforeMethod
    public void setUp() throws Exception {
        AuditRequestContext.clear();
        realmTestHelper = new RealmTestHelper();
        realmTestHelper.setupRealmClass();

        tokenStore = mock(TokenStore.class);
        // built first: stubbing a mock inside an unfinished when(...) is an UnfinishedStubbingException
        AccessToken token = accessToken();
        when(tokenStore.readAccessToken(any(), eq(PAT))).thenReturn(token);

        store = mock(ResourceSetStore.class);
        umaLabelsStore = mock(UmaLabelsStore.class);
        when(umaLabelsStore.forResourceSet(any(), any(), any(), anyBoolean()))
                .thenReturn(Collections.<ResourceSetLabel>emptySet());
        labelRegistration = mock(ResourceSetLabelRegistration.class);
        hook = mock(ResourceSetRegistrationHook.class);

        OAuth2ProviderSettings providerSettings = mock(OAuth2ProviderSettings.class);
        when(providerSettings.getResourceSetStore()).thenReturn(store);
        OAuth2ProviderSettingsFactory providerSettingsFactory = mock(OAuth2ProviderSettingsFactory.class);
        when(providerSettingsFactory.get(any(OAuth2Request.class))).thenReturn(providerSettings);

        ExtensionFilterManager extensionFilterManager = mock(ExtensionFilterManager.class);
        when(extensionFilterManager.getFilters(any())).thenReturn(Collections.emptyList());
        ResourceSetDescriptionValidator validator = mock(ResourceSetDescriptionValidator.class);
        when(validator.validate(any())).thenAnswer(invocation -> invocation.getArgument(0));

        // ⚠ The real factory, one instance for the whole chain: the protection filter stashes the access token
        // on the OAuth2Request it caches, and the handler reads it back from the cache (finding 14).
        requestFactory = new OAuth2RequestFactory(
                mock(JacksonRepresentationFactory.class), mock(ClientRegistrationStore.class));

        ResourceSetRegistrationHandler handler = new ResourceSetRegistrationHandler();
        inject(handler, "requestFactory", requestFactory);
        // Without this the base class's @ExceptionHandler NPEs, so no thrown OAuth2Exception could be composed
        // here at all. Only its JSON branch is reachable from this endpoint, and that touches none of the three.
        inject(handler, "errorResponseFactory", new OAuth2ErrorResponseFactory(
                mock(FreemarkerTemplateRenderer.class), mock(BaseURLProviderFactory.class),
                mock(RealmNormaliser.class)));
        inject(handler, "providerSettingsFactory", providerSettingsFactory);
        inject(handler, "validator", validator);
        inject(handler, "hooks", new LinkedHashSet<>(Collections.singletonList(hook)));
        inject(handler, "labelRegistration", labelRegistration);
        inject(handler, "extensionFilterManager", extensionFilterManager);
        inject(handler, "umaLabelsStore", umaLabelsStore);

        auditEventPublisher = mock(AuditEventPublisher.class);
        when(auditEventPublisher.isAuditing(any(), any(), any())).thenReturn(true);

        router = route(handler, requestFactory);
    }

    @AfterMethod
    public void tearDown() {
        AuditRequestContext.clear();
        realmTestHelper.tearDownRealmClass();
    }

    /**
     * D9 verbatim: the chain wraps the <em>handler</em>, and the two collection forms plus the item form are one
     * {@code STARTS_WITH} parent over a two-route child. The extra {@code oauth2} parent stands in for the
     * endpoint router the provider will mount this under at 5d-1.
     */
    private Handler route(ResourceSetRegistrationHandler handler, OAuth2RequestFactory requestFactory) {
        Handler chain = Handlers.chainOf(Endpoints.from(handler),
                auditFilter(requestFactory),                                             // outermost
                new ResourceSetErrorFilter(),                                            // then the error shape
                new ChfAccessTokenProtectionFilter(null, tokenStore, requestFactory, ErrorShape.OAUTH2));

        Router resourceSetRouter = new Router();
        resourceSetRouter.addRoute(requestUriMatcher(EQUALS, ""), chain);         // resource_set, resource_set/
        resourceSetRouter.addRoute(requestUriMatcher(EQUALS, "{rsid}"), chain);   // resource_set/{rsid}
        // 5d-1 D5: the nested router carries its own default route -- a child Router answers its own 404 rather
        // than falling through to the parent's, so without this the one 404 the migration has an oracle for
        // (5-E4 row 17) would be the only bodiless one on the surface.
        resourceSetRouter.setDefaultRoute(new OAuth2NotFoundHandler());

        Router endpointRouter = new Router();
        endpointRouter.addRoute(requestUriMatcher(STARTS_WITH, "resource_set"), resourceSetRouter);

        Router oauth2Router = new Router();
        oauth2Router.addRoute(requestUriMatcher(STARTS_WITH, "oauth2"), endpointRouter);
        return oauth2Router;
    }

    /** The audit filter as D9 configures it, minus the SSOTokenManager no in-process test can run. */
    private OAuth2HttpAccessAuditFilter auditFilter(OAuth2RequestFactory requestFactory) {
        return new OAuth2HttpAccessAuditFilter(auditEventPublisher, new AuditEventFactory(), requestFactory,
                HttpBodyAuditor.jsonAuditor("name", "scopes"), HttpBodyAuditor.jsonAuditor("_id")) {
            @Override
            protected SSOToken getSSOToken(OAuth2Request oAuth2Request) {
                return null;   // the access token supplies identity in process
            }
        };
    }

    // ---------------------------------------------------------------- rows 1-3: the plumbing

    /**
     * Row 1 — the request cache is shared. The protection filter stashes the access token on the
     * {@code OAuth2Request} it creates; the handler asks the factory again and must get the same instance back,
     * because the client and owner it writes come from that token and from nowhere else on the wire.
     */
    @Test
    public void theTokenTheProtectionFilterStashedIsTheTokenTheHandlerWrites() throws Exception {
        assignedOnCreate("new-id");

        Response response = through("POST", PATH, PAT, "{\"name\":\"photo album\",\"scopes\":[\"read\"]}");

        assertThat(response.getStatus().getCode()).isEqualTo(201);
        ArgumentCaptor<ResourceSetDescription> created = ArgumentCaptor.forClass(ResourceSetDescription.class);
        verify(store).create(any(), created.capture());
        // A second, uncached OAuth2Request would carry no token here and the create would answer 400.
        assertThat(created.getValue().getClientId()).isEqualTo(CLIENT);
        assertThat(created.getValue().getResourceOwnerId()).isEqualTo(OWNER);
    }

    /**
     * Row 2 — both readers coexist: the audit filter reads {@code name}/{@code scopes} out of the request body
     * and the handler still parses the same body and creates.
     * <p>
     * ⚠ Scope claimed honestly: audit runs <em>before</em> the handler and CHF entities are buffered, so this
     * proves the two reads coexist — <strong>not</strong> that the handler left the body alone for anyone after
     * it (finding 7).
     */
    @Test
    public void theAuditFilterReadsTheBodyAndTheHandlerStillCreates() throws Exception {
        assignedOnCreate("new-id");

        Response response = through("POST", PATH, PAT, "{\"name\":\"photo album\",\"scopes\":[\"read\"]}");

        assertThat(response.getStatus().getCode()).isEqualTo(201);
        JsonValue attempt = auditEvents().get(0).getValue();
        assertThat(attempt.get("request").get("detail").get("name").asString()).isEqualTo("photo album");
        assertThat(attempt.get("request").get("detail").get("scopes").asList(String.class)).containsExactly("read");
        // the response auditor's field, from the body the handler produced
        assertThat(auditEvents().get(1).getValue().get("response").get("detail").get("_id").asString())
                .isEqualTo("new-id");
    }

    /**
     * Row 3 — {@code rsid} arrives from the URI template through the nested {@link Router}, with no parsing in
     * the handler: {@code ChfOAuth2Request} merges nested {@code UriRouterContext}s (finding 6).
     */
    @Test
    public void theRsidComesFromTheUriTemplateNotFromTheHandler() throws Exception {
        when(store.read(RSID, OWNER)).thenReturn(storedResourceSet());

        Response response = through("GET", PATH + "/" + RSID, PAT, null);

        assertThat(response.getStatus().getCode()).isEqualTo(200);
        assertThat(bodyOf(response)).containsEntry("_id", RSID);
        verify(store).read(RSID, OWNER);
    }

    // ---------------------------------------------------------------- rows 4-9: the error and routing seams

    /**
     * Row 4 — an unmapped verb keeps <em>this</em> endpoint's vocabulary, and the root {@link OAuth2ErrorFilter}
     * mounted outside does not rewrite it (D3's idempotency claim, proven rather than argued).
     * <p>
     * ⚠ Not {@code PATCH}: 5-E4 row 11 measured Restlet routing {@code PATCH} to the {@code @Put} method, where
     * it 200s and really replaces the resource set. {@code PROPFIND} is unmapped on both engines.
     */
    @Test
    public void anUnmappedVerbKeepsTheResourceSetVocabularyThroughBothFilters() throws Exception {
        Response response = through("PROPFIND", PATH + "/" + RSID, PAT, null);

        assertThat(response.getStatus().getCode()).isEqualTo(405);
        assertThat(bodyOf(response)).containsEntry("error", "unsupported_method_type");
        assertThat(response.getHeaders().getFirst("Content-Type")).isEqualTo(JSON);
        // The handoff item this line was written to fail on: 5d-1a closed it. Restlet sent
        // `Allow: POST, PUT, GET, DELETE` (5-E4 row 11); Endpoints.allowHeader emits the same four verbs in its
        // own order, and HEAD is deliberately absent. The set is the contract -- the e2e row asserts a set too.
        assertThat(response.getHeaders().getFirst("Allow").split(", "))
                .containsExactlyInAnyOrder("DELETE", "GET", "POST", "PUT");

        // the root filter, outside: its containsKey("error") guard must return this body untouched
        Response throughRoot = Handlers.chainOf(router, new OAuth2ErrorFilter())
                .handle(context(), propfind()).getOrThrowUninterruptibly();
        assertThat(bodyOf(throughRoot)).containsEntry("error", "unsupported_method_type");
    }

    /** Row 5 — no bearer is an OAuth2-shaped 401, not CREST's {@code {code, reason, message}} (D2). */
    @Test
    public void aRequestWithoutABearerTokenIs401InTheOAuth2Shape() throws Exception {
        Response response = through("GET", PATH + "/" + RSID, null, null);

        assertThat(response.getStatus().getCode()).isEqualTo(401);
        Map<String, Object> body = bodyOf(response);
        assertThat(body).containsEntry("error", "invalid_token").doesNotContainKey("code");
        assertThat(response.getHeaders().getFirst("Content-Type")).isEqualTo(JSON);
    }

    /**
     * Row 6 — the 412 seam: the handler signals the precondition failure with a bare status and
     * {@link ResourceSetErrorFilter} supplies the body. Neither half produces this response alone.
     */
    @Test
    public void aStalePreconditionIs412WithTheFiltersBody() throws Exception {
        when(store.read(RSID, OWNER)).thenReturn(storedResourceSet());

        Response response = through("PUT", PATH + "/" + RSID, PAT, "{\"name\":\"renamed\"}",
                "If-Match", "W/\"12345\"");

        assertThat(response.getStatus().getCode()).isEqualTo(412);
        assertThat(bodyOf(response)).containsEntry("error", "precondition_failed");
        verify(store, org.mockito.Mockito.never()).update(any());
    }

    /** Row 7 — a delete answers 204 with no body and no ETag, over the real chain. */
    @Test
    public void aDeleteWithTheCurrentTagIs204WithNoBodyAndNoEtag() throws Exception {
        when(store.read(RSID, OWNER)).thenReturn(storedResourceSet());
        String etag = through("GET", PATH + "/" + RSID, PAT, null).getHeaders().getFirst("ETag");

        Response response = through("DELETE", PATH + "/" + RSID, PAT, null, "If-Match", etag);

        assertThat(response.getStatus().getCode()).isEqualTo(204);
        assertThat(response.getEntity().isRawContentEmpty()).isTrue();
        assertThat(response.getHeaders().getFirst("ETag")).isNull();
        verify(store).delete(RSID, OWNER);
    }

    /**
     * Row 8 — the guard for <a href="../../../../../../../../../docs/migration/restlet/phase-5c.md">finding 12</a>:
     * all three of Restlet's attachments route, the two collection forms to the collection and
     * {@code resource_set/{rsid}} to the item. Written against the real {@link Router} wiring on purpose — a
     * test that calls the handler directly cannot fail the way the trailing-slash bug fails.
     */
    @Test
    public void allThreeUrlFormsRouteAndOnlyTheThirdCarriesAnRsid() throws Exception {
        when(store.read(RSID, OWNER)).thenReturn(storedResourceSet());
        when(store.query(any())).thenReturn(new LinkedHashSet<>(List.of(storedResourceSet())));

        Response collection = through("GET", PATH, PAT, null);
        Response collectionSlash = through("GET", PATH + "/", PAT, null);
        Response item = through("GET", PATH + "/" + RSID, PAT, null);

        // The two collection forms list. In process getJson() hands back the very collection the handler set --
        // no serialization round-trip -- so compare membership, not type.
        assertThat(collection.getStatus().getCode()).isEqualTo(200);
        assertThat(idsOf(collection)).containsExactly(RSID);
        assertThat(collectionSlash.getStatus().getCode()).isEqualTo(200);
        assertThat(idsOf(collectionSlash)).containsExactly(RSID);
        // the item form reads
        assertThat(item.getStatus().getCode()).isEqualTo(200);
        assertThat(bodyOf(item)).containsEntry("_id", RSID);
    }

    /**
     * Row 9 — a no-match below the endpoint is the nested router's own 404, which the {@code ResourceSetErrorFilter}
     * never sees because the chain wraps the handler rather than the router (D9). Since 5d-1 D5 that 404 carries
     * {@link OAuth2NotFoundHandler}'s body rather than being bodiless (pairs with 5-E4 row 17).
     *
     * <p>⚠ <strong>D5 hides the bug this row exists to catch, so the counterfactual is re-expressed rather than
     * dropped.</strong> Wrapping {@code router} itself no longer demonstrates anything: the filter returns a body
     * already carrying {@code error} untouched, so the misplacement would now answer 404 instead of 500. The
     * lesson is about the <em>bodiless</em> 404 a router with no default route still produces — which is what
     * every other CHF router on the surface produces, and what {@code ResourceSetErrorFilter} turns into a
     * server error if it is ever hoisted above one. Deleting this half would retire D2's only executable guard.
     */
    @Test
    public void aNoMatchBelowTheEndpointIsA404TheResourceSetFilterNeverSees() throws Exception {
        Response response = through("GET", PATH + "/a/b", PAT, null);

        assertThat(response.getStatus().getCode()).isEqualTo(404);
        assertThat(bodyOf(response)).containsEntry("error", "not_found");

        Response wrapped = Handlers.chainOf(new Router(), new ResourceSetErrorFilter())
                .handle(context(), new Request().setMethod("GET").setUri(URI.create(PATH + "/a/b")))
                .getOrThrowUninterruptibly();
        assertThat(wrapped.getStatus().getCode()).isEqualTo(500);
        assertThat(bodyOf(wrapped)).containsEntry("error", "server_error");
    }

    // ---------------------------------------------------------------- rows 10-13: the derived and the realm

    /**
     * Row 10 — the one <em>derived</em> fact in this file, so it carries its trace: a token-store
     * {@code ServerException} answers <strong>400</strong> here, not 500.
     * {@code ChfAccessTokenProtectionFilter.crestError} is called with {@code code = 500}, but the
     * {@code OAUTH2} shape ignores that argument and takes the status from the exception, and
     * {@code ServerException} is {@code super(400, "server_error", ...)} — as
     * {@code ResourceSetRegistrationExceptionFilter.setExceptionResponse} did (finding 14).
     */
    @Test
    public void aTokenStoreServerExceptionIs400ServerErrorNotA500() throws Exception {
        when(tokenStore.readAccessToken(any(), eq(PAT)))
                .thenThrow(new org.forgerock.oauth2.core.exceptions.ServerException("token store fell over"));

        Response response = through("GET", PATH + "/" + RSID, PAT, null);

        assertThat(response.getStatus().getCode()).isEqualTo(400);
        assertThat(bodyOf(response)).containsEntry("error", "server_error");
    }

    /**
     * Row 14's two error producers side by side, which is only visible with the filter mounted: the THROWN 404
     * is stamped bare by {@code ResourceSetRegistrationHandler.withErrorHeaders}, while the in-band
     * duplicate-name 400 keeps the charset row 7 measured on Restlet.
     * <p>
     * The pair is the point. By the time {@link ResourceSetErrorFilter} sees them both are OAuth2-shaped 4xx
     * JSON bodies carrying a charset, so a normalisation placed in the filter cannot move one without moving
     * the other -- it would have passed every unit row in this suite while silently breaking row 7 on the wire.
     */
    @Test
    public void aThrownErrorIsBareJsonWhileTheInBandDuplicateKeepsItsCharset() throws Exception {
        when(store.read(RSID, OWNER))
                .thenThrow(new org.forgerock.oauth2.core.exceptions.NotFoundException("no such resource set"));

        Response thrown = through("GET", PATH + "/" + RSID, PAT, null);

        assertThat(thrown.getStatus().getCode()).isEqualTo(404);
        assertThat(bodyOf(thrown)).containsEntry("error", "not_found");
        assertThat(thrown.getHeaders().getFirst("Content-Type")).isEqualTo(JSON);

        when(store.query(any())).thenReturn(new LinkedHashSet<>(List.of(storedResourceSet())));

        Response inBand = through("POST", PATH, PAT, "{\"name\":\"photo album\",\"scopes\":[\"read\"]}");

        assertThat(inBand.getStatus().getCode()).isEqualTo(400);
        assertThat(bodyOf(inBand)).containsEntry("error", "Bad Request");
        assertThat(inBand.getHeaders().getFirst("Content-Type")).isEqualTo(JSON + "; charset=UTF-8");
    }

    /**
     * Row 11 — the same filter with its default {@code CREST} shape is unchanged: {@code /uma} still gets
     * {@code {code, reason, message}} at the code the call site passed. The D2 regression risk, in the same file
     * as the change rather than only in another module's suite.
     */
    @Test
    public void theCrestShapeIsUntouchedForUma() throws Exception {
        when(tokenStore.readAccessToken(any(), eq(PAT)))
                .thenThrow(new org.forgerock.oauth2.core.exceptions.ServerException("token store fell over"));
        Handler uma = Handlers.chainOf((context, request) -> Promises.newResultPromise(new Response(Status.OK)),
                new ChfAccessTokenProtectionFilter("uma_protection", tokenStore, requestFactory));

        Request request = new Request().setMethod("GET").setUri(URI.create("/uma/x"));
        request.getHeaders().put("Authorization", "Bearer " + PAT);
        Response response = uma.handle(context(), request).getOrThrowUninterruptibly();

        // 500 here, 400 above -- the same exception, two vocabularies, both deliberate
        assertThat(response.getStatus().getCode()).isEqualTo(500);
        assertThat(bodyOf(response)).containsEntry("code", 500).doesNotContainKey("error");
    }

    /**
     * Row 12 — the realm reaches the collaborators. This is the row that would have failed on the IT chain the
     * plan originally specified, which carried no {@link RealmContext} (finding 16).
     */
    @Test
    public void theRealmFromTheContextReachesTheRegistrationHook() throws Exception {
        assignedOnCreate("new-id");

        through("POST", PATH, PAT, "{\"name\":\"photo album\",\"scopes\":[\"read\"]}");

        verify(hook).resourceSetCreated(eq("/"), any(ResourceSetDescription.class));
    }

    /**
     * Row 13 — the conditional tag folds in the labels the <em>label store</em> holds, not just the stored
     * description (R-5c.11 / finding 17). Two labels, so the order-sensitive {@code List.hashCode} is exercised.
     * <p>
     * ⚠ The expected tag is computed here rather than replayed from the {@code GET}: a handler that hashed the
     * bare {@code store.read} would emit and expect the <em>same</em> wrong tag, so a replayed one passes the
     * mutation this row exists to catch.
     */
    @Test
    public void theEtagFoldsInTheLabelsAndRoundTripsFromGetToPut() throws Exception {
        ResourceSetDescription resourceSet = storedResourceSet();
        when(store.read(RSID, OWNER)).thenReturn(resourceSet);
        when(umaLabelsStore.forResourceSet(eq("/"), eq(OWNER), eq(RSID), anyBoolean()))
                .thenReturn(labels("alpha", "beta"));
        String expected = etagOf(resourceSet, List.of("alpha", "beta"));

        Response read = through("GET", PATH + "/" + RSID, PAT, null);
        assertThat(read.getHeaders().getFirst("ETag")).isEqualTo(expected);

        Response update = through("PUT", PATH + "/" + RSID, PAT, "{\"name\":\"renamed\"}",
                "If-Match", expected);

        assertThat(update.getStatus().getCode()).isEqualTo(200);
        verify(store).update(any(ResourceSetDescription.class));
    }

    // ---------------------------------------------------------------- helpers

    /** Dispatches through the real router, chain and context stack. Extra headers arrive as name/value pairs. */
    private Response through(String method, String uri, String bearer, String jsonBody, String... headers)
            throws Exception {
        Request request = new Request().setMethod(method).setUri(URI.create(uri));
        if (bearer != null) {
            request.getHeaders().put("Authorization", "Bearer " + bearer);
        }
        if (jsonBody != null) {
            request.getHeaders().put(ContentTypeHeader.valueOf(JSON));
            request.getEntity().setString(jsonBody);
        }
        for (int i = 0; i < headers.length; i += 2) {
            request.getHeaders().put(headers[i], headers[i + 1]);
        }
        return router.handle(context(), request).getOrThrowUninterruptibly();
    }

    private Request propfind() {
        Request request = new Request().setMethod("PROPFIND").setUri(URI.create(PATH + "/" + RSID));
        request.getHeaders().put("Authorization", "Bearer " + PAT);
        return request;
    }

    /**
     * {@code RootContext -> ClientContext -> RequestAuditContext -> AttributesContext -> RealmContext}: the audit
     * filter needs the first three, the real request factory caches on the fourth, and the fifth is finding 16's.
     */
    private Context context() {
        Context client = ClientContext.buildExternalClientContext(new RootContext())
                .remoteAddress("127.0.0.1").remotePort(9000).build();
        AttributesContext attributes = new AttributesContext(new RequestAuditContext(client));
        return new RealmContext(attributes, Realm.root());
    }

    private AccessToken accessToken() {
        AccessToken token = mock(AccessToken.class);
        when(token.isExpired()).thenReturn(false);
        when(token.getScope()).thenReturn(new LinkedHashSet<>(List.of("uma_protection")));
        when(token.getClientId()).thenReturn(CLIENT);
        when(token.getResourceOwnerId()).thenReturn(OWNER);
        return token;
    }

    private static ResourceSetDescription storedResourceSet() {
        Map<String, Object> description = new LinkedHashMap<>();
        description.put("name", "photo album");
        description.put("scopes", List.of("read", "write"));
        ResourceSetDescription resourceSet = new ResourceSetDescription(RSID, CLIENT, OWNER, description);
        resourceSet.setRealm("/");
        return resourceSet;
    }

    /** What {@code OpenAMResourceSetStore.create} does to the description it is handed. */
    private void assignedOnCreate(String id) throws Exception {
        org.mockito.Mockito.doAnswer(invocation -> {
            ResourceSetDescription resourceSet = invocation.getArgument(1);
            resourceSet.setId(id);
            resourceSet.setRealm("/");
            return null;
        }).when(store).create(any(), any(ResourceSetDescription.class));
    }

    private List<AuditEvent> auditEvents() {
        ArgumentCaptor<AuditEvent> events = ArgumentCaptor.forClass(AuditEvent.class);
        verify(auditEventPublisher, org.mockito.Mockito.atLeast(2))
                .tryPublish(eq("access"), events.capture());
        return events.getAllValues();
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> bodyOf(Response response) throws Exception {
        return (Map<String, Object>) response.getEntity().getJson();
    }

    @SuppressWarnings("unchecked")
    private static java.util.Collection<String> idsOf(Response response) throws Exception {
        return (java.util.Collection<String>) response.getEntity().getJson();
    }

    private static Set<ResourceSetLabel> labels(String... names) {
        Set<ResourceSetLabel> labelSet = new LinkedHashSet<>();
        for (String name : names) {
            labelSet.add(new ResourceSetLabel("id-" + name, name, LabelType.USER, Collections.emptySet()));
        }
        return labelSet;
    }

    /** The tag the read model hashes to -- computed the way the handler must, not replayed from a response. */
    private static String etagOf(ResourceSetDescription resourceSet, List<String> labels) {
        ResourceSetDescription model = new ResourceSetDescription(resourceSet.getId(), resourceSet.getClientId(),
                resourceSet.getResourceOwnerId(), new LinkedHashMap<>(resourceSet.getDescription().asMap()));
        model.setRealm(resourceSet.getRealm());
        model.setPolicyUri(resourceSet.getPolicyUri());
        model.getDescription().put("labels", labels);
        return "W/\"" + model.hashCode() + "\"";
    }

    private static void inject(Object target, String name, Object value) throws Exception {
        for (Class<?> type = target.getClass(); type != null; type = type.getSuperclass()) {
            try {
                Field field = type.getDeclaredField(name);
                field.setAccessible(true);
                field.set(target, value);
                return;
            } catch (NoSuchFieldException keepWalking) {
                // declared on a superclass
            }
        }
        throw new NoSuchFieldException(name);
    }
}
