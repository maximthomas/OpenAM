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

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.io.IOException;
import java.lang.reflect.Field;
import java.net.URI;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import jakarta.servlet.http.HttpServletRequest;

import org.forgerock.audit.AuditException;
import org.forgerock.http.Filter;
import org.forgerock.http.Handler;
import org.forgerock.http.handler.Handlers;
import org.forgerock.http.header.ContentTypeHeader;
import org.forgerock.http.protocol.Request;
import org.forgerock.http.protocol.Response;
import org.forgerock.json.JsonValue;
import org.forgerock.oauth2.core.AuthorizationService;
import org.forgerock.oauth2.core.ClientRegistration;
import org.forgerock.oauth2.core.ClientRegistrationStore;
import org.forgerock.oauth2.core.CsrfProtection;
import org.forgerock.oauth2.core.DeviceCode;
import org.forgerock.oauth2.core.OAuth2ProviderSettings;
import org.forgerock.oauth2.core.OAuth2ProviderSettingsFactory;
import org.forgerock.oauth2.core.OAuth2Request;
import org.forgerock.oauth2.core.OAuth2RequestFactory;
import org.forgerock.oauth2.core.ResourceOwner;
import org.forgerock.oauth2.core.ResourceOwnerSessionValidator;
import org.forgerock.oauth2.core.TokenStore;
import org.forgerock.oauth2.core.UserInfoClaims;
import org.forgerock.oauth2.core.exceptions.InvalidScopeException;
import org.forgerock.oauth2.core.exceptions.ResourceOwnerAuthenticationRequired;
import org.forgerock.oauth2.core.exceptions.ResourceOwnerConsentRequired;
import org.forgerock.openam.http.annotations.Endpoints;
import org.forgerock.openam.oauth2.OAuth2Constants.UrlLocation;
import org.forgerock.openam.rest.representations.JacksonRepresentationFactory;
import org.forgerock.openam.services.baseurl.BaseURLProvider;
import org.forgerock.openam.services.baseurl.BaseURLProviderFactory;
import org.forgerock.openam.utils.RealmNormaliser;
import org.forgerock.openam.xui.XUIState;
import org.forgerock.services.context.AttributesContext;
import org.forgerock.services.context.Context;
import org.forgerock.services.context.RootContext;
import org.forgerock.util.promise.NeverThrowsException;
import org.forgerock.util.promise.Promise;
import org.mockito.ArgumentMatchers;
import org.openidentityplatform.openam.oauth2.audit.HttpBodyAuditor;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

/**
 * Composition guard for {@link DeviceCodeVerificationHandler}: the real handler, the real
 * {@link OAuth2RequestFactory}, the real templates and the real filter chain, driven end to end in process.
 *
 * <p>Sibling of {@link AuthorizeRouteCompositionIT}, which pins what the framework and {@link OAuth2ErrorFilter}
 * do to a browser endpoint in general. This class pins what they do to <em>this</em> endpoint, whose shape
 * differs in three ways that matter: its pages are returned rather than thrown, its consent page is rendered
 * from inside a {@code @Post} whose body a filter may already have read, and its request state comes from a
 * stored device code rather than from the wire.
 *
 * <h2>Why the real factory, everywhere</h2>
 * Every unit suite in this migration mocks {@link OAuth2RequestFactory} and passes a bare {@code RootContext},
 * which hands the handler and the base's {@code @ExceptionHandler} the same stub <em>by construction</em>. The
 * request cache is therefore untestable there (finding 14), and on this endpoint the cache is behaviour, not
 * convenience: {@link #theErrorMapperReadsTheDeviceCodesStateThroughTheRequestCache()} is the named row for it.
 * Using the real factory in every row also means each one exercises real parameter resolution -- query for
 * {@code GET}, form body for {@code POST}, request attribute ahead of both -- rather than a stubbed
 * {@code getParameter}.
 *
 * <h2>Name trap</h2>
 * {@code *IT.java} is bound to failsafe: {@code mvn -pl openam-oauth2 test} does <strong>not</strong> run this
 * class. It needs {@code mvn -pl openam-oauth2 verify}.
 */
public class DeviceCodeRouteCompositionIT {

    private static final String PATH = "/oauth2/device/user";
    private static final String USER_CODE = "BDWD-HQPK";
    private static final String BASE_URL = "https://openam.example.com:8443/openam";
    private static final String LOGIN_URI = "https://openam.example.com:8443/openam/UI/Login?goto=device";
    private static final String CLIENT_URI = "https://client.example/cb";
    /** The device code's own {@code state}, which the wire never carries on a device verification. */
    private static final String DEVICE_STATE = "af0ifjsldkj";
    private static final String FORM_TYPE = "application/x-www-form-urlencoded";

    private DeviceCodeVerificationHandler handler;
    private TokenStore tokenStore;
    private OAuth2ProviderSettings providerSettings;
    private ClientRegistration clientRegistration;
    private AuthorizationService authorizationService;
    private ResourceOwnerSessionValidator resourceOwnerSessionValidator;
    private CsrfProtection csrfProtection;

    @BeforeMethod
    public void setUp() throws Exception {
        tokenStore = mock(TokenStore.class);
        when(tokenStore.readDeviceCode(eq(USER_CODE), any())).thenReturn(deviceCode());

        providerSettings = mock(OAuth2ProviderSettings.class);
        // Consent required by default; the two rows that skip it flip this.
        when(providerSettings.clientsCanSkipConsent()).thenReturn(false);
        OAuth2ProviderSettingsFactory providerSettingsFactory = mock(OAuth2ProviderSettingsFactory.class);
        when(providerSettingsFactory.get(any(OAuth2Request.class))).thenReturn(providerSettings);

        clientRegistration = mock(ClientRegistration.class);
        ClientRegistrationStore clientRegistrationStore = mock(ClientRegistrationStore.class);
        when(clientRegistrationStore.get(anyString(), any())).thenReturn(clientRegistration);

        authorizationService = mock(AuthorizationService.class);
        csrfProtection = mock(CsrfProtection.class);
        when(csrfProtection.createCsrfToken(any())).thenReturn("csrf-token");
        ResourceOwner resourceOwner = mock(ResourceOwner.class);
        when(resourceOwner.getId()).thenReturn("demo");
        resourceOwnerSessionValidator = mock(ResourceOwnerSessionValidator.class);
        when(resourceOwnerSessionValidator.validate(any())).thenReturn(resourceOwner);

        BaseURLProviderFactory baseURLProviderFactory = baseURLProviderFactory();
        RealmNormaliser realmNormaliser = mock(RealmNormaliser.class);
        when(realmNormaliser.normalise(anyString())).thenAnswer(call -> call.getArgument(0));
        XUIState xuiState = mock(XUIState.class);
        when(xuiState.isXUIEnabled()).thenReturn(true);
        FreemarkerTemplateRenderer templateRenderer = new FreemarkerTemplateRenderer();

        handler = new DeviceCodeVerificationHandler();
        // The real factory, and the one instance both the handler and the base's mapper resolve through.
        inject(handler, "requestFactory", new OAuth2RequestFactory(
                mock(JacksonRepresentationFactory.class), clientRegistrationStore));
        inject(handler, "errorResponseFactory", new OAuth2ErrorResponseFactory(templateRenderer,
                baseURLProviderFactory, realmNormaliser));
        inject(handler, "templateRenderer", templateRenderer);
        inject(handler, "baseURLProviderFactory", baseURLProviderFactory);
        inject(handler, "tokenStore", tokenStore);
        inject(handler, "authorizationService", authorizationService);
        inject(handler, "providerSettingsFactory", providerSettingsFactory);
        inject(handler, "clientRegistrationStore", clientRegistrationStore);
        inject(handler, "resourceOwnerSessionValidator", resourceOwnerSessionValidator);
        inject(handler, "csrfProtection", csrfProtection);
        inject(handler, "consentPageRenderer", new ConsentPageRenderer(templateRenderer, xuiState,
                baseURLProviderFactory, csrfProtection));
    }

    /**
     * ⚠ <strong>R-5b2.3, finding 14 -- the row nothing else in this migration can make.</strong>
     *
     * <p>The handler seeds the device code onto the request attributes and then throws. If the base's
     * {@code @ExceptionHandler} built a <em>fresh</em> {@code ChfOAuth2Request} instead of recovering the cached
     * one, its {@code getParameter("state")} would fall through the (empty) attributes to the query and echo the
     * wire's value -- so every device-flow error would carry the wrong {@code state}, or none, and D3's seeding
     * would evaporate at exactly the moment it is needed.
     *
     * <p>The two states are deliberately different, and the redirect is deliberately reached: {@code state} is
     * the one seeded value with an observable of its own, and {@code page/error.ftl} does not print it -- only
     * the redirect's query does. The {@code redirect_uri} comes off the wire because a device code stores none.
     */
    @Test
    public void theErrorMapperReadsTheDeviceCodesStateThroughTheRequestCache() throws Exception {
        when(authorizationService.authorize(any()))
                .thenThrow(new InvalidScopeException("Unknown scope", UrlLocation.QUERY));

        Response response = through(get("user_code=" + USER_CODE + "&state=wire-state"
                + "&redirect_uri=" + CLIENT_URI));

        assertThat(response.getStatus().getCode()).isEqualTo(302);
        assertThat(response.getHeaders().getFirst("Location"))
                .startsWith(CLIENT_URI + "?")
                .contains("error=invalid_scope")
                .contains("state=" + DEVICE_STATE)
                .doesNotContain("wire-state");
    }

    /** The filter keys on {@code >= 400}; the login 301 must reach the browser with its Location intact. */
    @Test
    public void theLoginRedirectSurvivesTheFilterUntouched() throws Exception {
        consentImplied();
        when(resourceOwnerSessionValidator.validate(any()))
                .thenThrow(new ResourceOwnerAuthenticationRequired(URI.create(LOGIN_URI)));

        Response response = through(get("user_code=" + USER_CODE));

        assertThat(response.getStatus().getCode()).isEqualTo(301);
        assertThat(response.getHeaders().getFirst("Location")).isEqualTo(LOGIN_URI);
        assertThat(response.getEntity().getString()).isEmpty();
    }

    /**
     * The CSRF refusal is a 400 the handler <strong>returns</strong> rather than throws, so it reaches
     * {@link OAuth2ErrorFilter} through the plain response path. The filter rewrites any {@code >= 400} body it
     * recognises as JSON; this page must come through as markup, or a refused consent post becomes a blank page.
     */
    @Test
    public void theCsrfErrorPageIsNotRewrittenIntoAJsonBody() throws Exception {
        when(csrfProtection.isCsrfAttack(any())).thenReturn(true);

        Response response = through(post("user_code=" + USER_CODE + "&decision=allow&csrf=stale"));

        assertThat(response.getStatus().getCode()).isEqualTo(400);
        assertThat(response.getHeaders().getFirst("Content-Type")).isEqualTo("text/html; charset=UTF-8");
        assertThat(response.getEntity().getString())
                .contains("message: \"bad_request\"")
                .doesNotContain("\"error\":");
        // No Location: bad_request is redirectable, so a thrown one would have gone to an unvalidated wire URI.
        assertThat(response.getHeaders().getFirst("Location")).isNull();
    }

    /**
     * Risk #21 for the <em>consent</em> page, which {@link AuthorizeRouteCompositionIT} does not cover: its
     * UTF-8 row goes through the error page. The templates are ASCII, so only the model can carry non-ASCII into
     * the bytes -- here the resource owner's display name.
     *
     * <p>Decoding the wire bytes as UTF-8 is what discriminates: an ISO-8859-1 encode would have substituted one
     * {@code '?'} per unmappable character, and those bytes cannot decode back into the name.
     */
    @Test
    public void aNonAsciiConsentPageReachesTheWireAsUtf8() throws Exception {
        when(authorizationService.authorize(any())).thenThrow(consentRequired());

        Response response = through(post("user_code=" + USER_CODE));

        assertThat(response.getStatus().getCode()).isEqualTo(200);
        assertThat(response.getHeaders().getFirst("Content-Type")).isEqualTo("text/html; charset=UTF-8");
        String wire = new String(response.getEntity().getBytes(), UTF_8);
        assertThat(wire).contains("userName: \"" + RendererFixtures.NON_ASCII_USER_NAME + "\"");
        // The consent page is HTML at 200, and stays HTML: the filter must not touch it.
        assertThat(wire).contains("pageData").doesNotContain("\"error\":");
    }

    /**
     * D2 end to end, which is the reason 5b-2b touched {@link ConsentPageRenderer} at all: on the device
     * flow the consent model has <strong>no query to come from</strong>. Every one of these values reaches the
     * page only by being seeded onto the request attributes from the stored device code and then read back by
     * phase 1 -- and a key missing from {@code MODEL_KEYS} does not fail, it silently turns the template's
     * {@code <#if x??>} false and drops the field (finding 2 / R-5b1.2).
     *
     * <p>The unit rows assert the model map; this asserts the rendered page, through the real seeding, the real
     * renderer and the real template.
     */
    @Test
    public void theDeviceConsentPageIsBuiltFromTheSeededDeviceCode() throws Exception {
        when(authorizationService.authorize(any())).thenThrow(consentRequired());

        String page = through(post("user_code=" + USER_CODE)).getEntity().getString();

        assertThat(page)
                .contains("clientId: \"test_client_app\"")
                .contains("scope: \"openid profile\"")
                .contains("state: \"" + DEVICE_STATE + "\"")
                .contains("nonce: \"n-0S6_WzA2Mj\"")
                .contains("responseType: \"code\"")
                // ?js_string escapes the slash, so the realm reaches the page as \/alpha.
                .contains("realm: \"\\/alpha\"")
                // ui_locales wins over the request's Accept-Language, as the template's <#elseif> requires.
                .contains("locale: \"fr\"")
                .contains("userCode: \"" + USER_CODE + "\"");
    }

    /**
     * D8, narrowed by D10, on this endpoint: the handler declares {@code @Get} and {@code @Post} only, so a
     * {@code PUT} is the framework's 405, whose body the filter rewrites to {@code method_not_allowed} -- the
     * value live Restlet emits. The cache headers come from {@link OAuth2NoCacheFilter}, since no endpoint
     * method runs to set them.
     */
    @Test
    public void anUnsupportedVerbIsTheFrameworks405RewrittenToMethodNotAllowed() throws Exception {
        Response response = through(new Request().setMethod("PUT").setUri(PATH));

        assertThat(response.getStatus().getCode()).isEqualTo(405);
        assertThat(bodyOf(response)).containsEntry("error", "method_not_allowed");
        assertThat(response.getHeaders().getFirst("Cache-Control")).isEqualTo("no-store");
        assertThat(response.getHeaders().getFirst("Pragma")).isEqualTo("no-cache");
    }

    /**
     * The device consent form posts back {@code decision}, {@code save_consent} and {@code csrf} in a form body,
     * and {@code ChfOAuth2Request} reads that body <em>after</em> the audit filter already has. CHF entities are
     * buffered, so both reads see it -- but "buffered" is a property of the entity implementation, not of the
     * contract, and if it stopped holding, every consent decision would silently read as absent (the no-decision
     * branch) instead of failing. Asserted from both ends: the auditor's view of the body, and the handler's.
     */
    @Test
    public void aFormPostSurvivesAnAuditShapedBufferedRead() throws Exception {
        JsonValue[] audited = new JsonValue[1];
        Handler chain = Handlers.chainOf(Endpoints.from(handler), auditShapedRead(audited),
                new OAuth2NoCacheFilter(), new OAuth2ErrorFilter());

        Response response = chain.handle(context(), post("user_code=" + USER_CODE + "&decision=allow"))
                .getOrThrowUninterruptibly();

        assertThat(audited[0].get("decision").asString()).isEqualTo("allow");
        // The handler read the same body: "allow" authorises the code, an unread body would have rendered
        // the consent page instead.
        verify(tokenStore).updateDeviceCode(any(DeviceCode.class), any());
        assertThat(response.getStatus().getCode()).isEqualTo(200);
        assertThat(response.getHeaders().getFirst("Content-Type")).isEqualTo("text/html; charset=UTF-8");
        assertThat(response.getEntity().getString()).contains("done: true");
    }

    // --- helpers ----------------------------------------------------------------------------------

    /** What {@code OAuth2HttpAccessAuditFilter} does to a form endpoint: read the request body, then the response's. */
    private static Filter auditShapedRead(JsonValue[] audited) {
        return new Filter() {
            @Override
            public Promise<Response, NeverThrowsException> filter(Context context, Request request, Handler next) {
                try {
                    audited[0] = HttpBodyAuditor.formAuditor("user_code", "decision").apply(request.getEntity());
                } catch (AuditException e) {
                    throw new IllegalStateException(e);
                }
                return next.handle(context, request).then(response -> {
                    try {
                        response.getEntity().getString();
                    } catch (IOException e) {
                        throw new IllegalStateException(e);
                    }
                    return response;
                });
            }
        };
    }

    private Response through(Request request) throws Exception {
        return Handlers.chainOf(Endpoints.from(handler), new OAuth2NoCacheFilter(), new OAuth2ErrorFilter())
                .handle(context(), request)
                .getOrThrowUninterruptibly();
    }

    /** The one context requirement of the real factory: it caches the request on the {@link AttributesContext}. */
    private static Context context() {
        return new AttributesContext(new RootContext());
    }

    private static Request get(String query) throws Exception {
        return new Request().setMethod("GET").setUri(PATH + "?" + query);
    }

    private static Request post(String formBody) throws Exception {
        Request request = new Request().setMethod("POST").setUri(PATH);
        request.getHeaders().put(ContentTypeHeader.valueOf(FORM_TYPE));
        request.getEntity().setString(formBody);
        return request;
    }

    private void consentImplied() throws Exception {
        when(providerSettings.clientsCanSkipConsent()).thenReturn(true);
        when(clientRegistration.isConsentImplied()).thenReturn(true);
    }

    private static DeviceCode deviceCode() {
        Set<String> scope = new LinkedHashSet<>(List.of("openid", "profile"));
        return new DeviceCode("dev-code-id", USER_CODE, "demo", "test_client_app", "n-0S6_WzA2Mj", "code",
                DEVICE_STATE, "urn:mace:incommon:iap:silver", "consent", "fr", "demo@example.com", 300, "{}",
                1893456000L, scope, "/alpha", "challenge", "S256", "audit-id");
    }

    private static ResourceOwnerConsentRequired consentRequired() {
        Map<String, String> scopeDescriptions = new LinkedHashMap<>();
        scopeDescriptions.put("profile", "View your profile");
        return new ResourceOwnerConsentRequired("Demo & Co", "A demo client", scopeDescriptions, Map.of(),
                new UserInfoClaims(Map.of(), Map.of()), RendererFixtures.NON_ASCII_USER_NAME, true);
    }

    private static BaseURLProviderFactory baseURLProviderFactory() {
        BaseURLProvider provider = mock(BaseURLProvider.class);
        when(provider.getRootURL(ArgumentMatchers.<HttpServletRequest>any())).thenReturn(BASE_URL);
        BaseURLProviderFactory factory = mock(BaseURLProviderFactory.class);
        when(factory.get(anyString())).thenReturn(provider);
        return factory;
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> bodyOf(Response response) throws Exception {
        return (Map<String, Object>) response.getEntity().getJson();
    }

    private static void inject(Object target, String name, Object value) throws Exception {
        for (Class<?> c = target.getClass(); c != null; c = c.getSuperclass()) {
            try {
                Field f = c.getDeclaredField(name);
                f.setAccessible(true);
                f.set(target, value);
                return;
            } catch (NoSuchFieldException keepWalking) {
                // field is declared on a superclass
            }
        }
        throw new NoSuchFieldException(name);
    }
}
