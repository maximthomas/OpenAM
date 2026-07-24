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

import static java.util.Collections.singletonList;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.util.Date;
import java.util.LinkedHashMap;
import java.util.Map;

import jakarta.servlet.http.HttpServletRequest;

import com.sun.identity.authentication.util.ISAuthConstants;

import org.forgerock.http.protocol.Request;
import org.forgerock.http.protocol.Response;
import org.forgerock.http.routing.UriRouterContext;
import org.forgerock.json.jose.builders.JwtBuilderFactory;
import org.forgerock.json.jose.jws.JwsAlgorithm;
import org.forgerock.json.jose.jws.SigningManager;
import org.forgerock.json.jose.jws.handlers.SigningHandler;
import org.forgerock.json.jose.jwt.JwtClaimsSet;
import org.forgerock.oauth2.core.ClientAuthenticator;
import org.forgerock.oauth2.core.OAuth2Request;
import org.forgerock.oauth2.core.OAuth2RequestFactory;
import org.forgerock.oauth2.core.OAuth2Uris;
import org.forgerock.oauth2.core.exceptions.ClientAuthenticationFailureFactory;
import org.forgerock.oauth2.core.exceptions.InvalidClientException;
import org.forgerock.oauth2.core.OAuth2ProviderSettings;
import org.forgerock.oauth2.core.OAuth2ProviderSettingsFactory;
import org.forgerock.openam.core.realms.Realm;
import org.forgerock.openam.core.realms.RealmTestHelper;
import org.forgerock.openam.http.annotations.Endpoints;
import org.forgerock.openam.oauth2.OAuth2Constants;
import org.forgerock.openam.oauth2.OAuth2UrisFactory;
import org.forgerock.openam.rest.RealmContext;
import org.forgerock.openam.services.baseurl.BaseURLProviderFactory;
import org.forgerock.openam.utils.RealmNormaliser;
import org.forgerock.openidconnect.OpenIdConnectClientRegistration;
import org.forgerock.openidconnect.OpenIdConnectClientRegistrationStore;
import org.forgerock.services.context.AttributesContext;
import org.forgerock.services.context.RootContext;
import org.openidentityplatform.openam.oauth2.core.ChfOAuth2Request;
import org.mockito.ArgumentCaptor;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

/**
 * Unit suite for {@link IdTokenInfoHandler} ({@code /idtokeninfo}). POST only. The centrepiece is a real-context test
 * (D3): a real {@link ChfOAuth2Request} over {@code RootContext -> AttributesContext -> RealmContext ->
 * UriRouterContext} proves the id_token's realm claim (not the URL realm) reaches the three collaborators that read the
 * plain request, plus the servlet attribute -- a mocked request would make {@code setRealmOnRequest} a no-op and hide
 * the regression. Also pins the two non-base error mappings and the UTF-8 String->Map conversion (finding 6).
 */
public class IdTokenInfoHandlerTest {

    private static final String HMAC_SECRET = "0123456789abcdef0123456789abcdef";   // 256-bit for HS256
    private static final String URL_REALM = "/alpha";
    private static final String TOKEN_REALM = "/beta";

    private RealmTestHelper realmTestHelper;
    private OAuth2RequestFactory requestFactory;
    private OpenIdConnectClientRegistrationStore clientRegistrationStore;
    private ClientAuthenticator clientAuthenticator;
    private OAuth2UrisFactory urisFactory;
    private OAuth2ProviderSettingsFactory providerSettingsFactory;
    private OAuth2ProviderSettings providerSettings;
    private HttpServletRequest servletRequest;
    private IdTokenInfoHandler handler;

    /** Mints real InvalidClientExceptions (package-private ctors) the way production does. */
    private final ClientAuthenticationFailureFactory failures = new ClientAuthenticationFailureFactory() {
        @Override protected boolean hasAuthorizationHeader(OAuth2Request request) { return false; }
        @Override protected String getRealm(OAuth2Request request) { return TOKEN_REALM; }
    };

    @BeforeMethod
    public void setup() throws Exception {
        realmTestHelper = new RealmTestHelper();
        realmTestHelper.setupRealmClass();

        requestFactory = mock(OAuth2RequestFactory.class);
        clientRegistrationStore = mock(OpenIdConnectClientRegistrationStore.class);
        clientAuthenticator = mock(ClientAuthenticator.class);
        urisFactory = mock(OAuth2UrisFactory.class);
        providerSettingsFactory = mock(OAuth2ProviderSettingsFactory.class);
        providerSettings = mock(OAuth2ProviderSettings.class);
        servletRequest = mock(HttpServletRequest.class);
        when(providerSettingsFactory.get(any(OAuth2Request.class))).thenReturn(providerSettings);

        OAuth2ErrorResponseFactory errorResponseFactory = new OAuth2ErrorResponseFactory(
                mock(FreemarkerTemplateRenderer.class), mock(BaseURLProviderFactory.class),
                mock(RealmNormaliser.class));

        handler = new IdTokenInfoHandler();
        inject(handler, "requestFactory", requestFactory);
        inject(handler, "errorResponseFactory", errorResponseFactory);
        inject(handler, "clientRegistrationStore", clientRegistrationStore);
        inject(handler, "clientAuthenticator", clientAuthenticator);
        inject(handler, "urisFactory", urisFactory);
        inject(handler, "providerSettingsFactory", providerSettingsFactory);
    }

    @AfterMethod
    public void tearDown() {
        realmTestHelper.tearDownRealmClass();
    }

    // --- guard ------------------------------------------------------------------------------------

    @Test
    public void missingIdTokenReturns400BadRequest() throws Exception {
        OAuth2Request o2 = mock(OAuth2Request.class);
        when(o2.getParameter(OAuth2Constants.JWTTokenParams.ID_TOKEN)).thenReturn(null);

        Response response = dispatch(o2);

        assertThat(response.getStatus().getCode()).isEqualTo(400);
        assertThat(bodyOf(response)).containsEntry("error", "bad_request");
    }

    // --- D3 real-context: the token realm wins and reaches everything ------------------------------

    @Test
    public void tokenRealmClaimReachesCollaboratorsServletAndRoundTripsUtf8() throws Exception {
        realmTestHelper.mockRealm("beta");   // token realm must resolve for Realm.of(TOKEN_REALM)
        Map<String, Object> extraClaims = new LinkedHashMap<>();
        extraClaims.put("name", "Ñoño");   // non-ASCII -> guards the UTF-8 String->Map conversion (finding 6)
        ChfOAuth2Request o2 = realRequest(buildIdToken("myclient", TOKEN_REALM, extraClaims, false));

        OpenIdConnectClientRegistration registration = mock(OpenIdConnectClientRegistration.class);
        when(clientRegistrationStore.get(eq("myclient"), any())).thenReturn(registration);
        when(registration.getIDTokenSignedResponseAlgorithm()).thenReturn("HS256");   // HMAC -> urisFactory path
        when(registration.verifyJwtIdentity(any())).thenReturn(true);
        when(providerSettings.isIdTokenInfoClientAuthenticationEnabled()).thenReturn(true);
        OAuth2Uris uris = mock(OAuth2Uris.class);
        when(urisFactory.get(any(OAuth2Request.class))).thenReturn(uris);
        when(uris.getTokenEndpoint()).thenReturn("https://host/oauth2/access_token");

        Response response = dispatch(o2);

        assertThat(response.getStatus().getCode()).isEqualTo(200);
        assertThat(response.getHeaders().getFirst("Content-Type")).isEqualTo("application/json; charset=UTF-8");
        Map<String, Object> body = bodyOf(response);
        assertThat(body).containsEntry("name", "Ñoño")   // UTF-8 survived
                .containsEntry("realm", TOKEN_REALM);

        // The token realm (/beta) overrode the URL realm (/alpha) on the request the collaborators read.
        assertThat(o2.<String>getParameter(OAuth2Constants.Custom.REALM)).isEqualTo(TOKEN_REALM);
        assertThat(o2.<Realm>getParameter(OAuth2Constants.Custom.REALM_OBJECT).asPath()).isEqualTo(TOKEN_REALM);
        verify(providerSettingsFactory).get(o2);
        verify(urisFactory).get(o2);
        verify(servletRequest).setAttribute(ISAuthConstants.REALM_PARAM, TOKEN_REALM);

        // The client-registration lookup saw the token realm through the wrapper (not the URL realm).
        ArgumentCaptor<OAuth2Request> wrapper = ArgumentCaptor.forClass(OAuth2Request.class);
        verify(clientRegistrationStore).get(eq("myclient"), wrapper.capture());
        assertThat(wrapper.getValue().<String>getParameter(OAuth2Constants.JWTTokenParams.REALM)).isEqualTo(TOKEN_REALM);
    }

    // --- non-base error mappings ------------------------------------------------------------------

    /** An invalid realm claim (RealmLookupException, not an OAuth2Exception) becomes a 400 "Invalid realm". */
    @Test
    public void invalidRealmClaimReturns400InvalidRealm() throws Exception {
        realmTestHelper.mockInvalidRealm("bad");   // Realm.of("/bad") throws
        ChfOAuth2Request o2 = realRequest(buildIdToken("myclient", "/bad", new LinkedHashMap<>(), false));

        Response response = dispatch(o2);

        assertThat(response.getStatus().getCode()).isEqualTo(400);
        assertThat(bodyOf(response)).containsEntry("error", "Invalid realm");
    }

    /** An unknown audience (InvalidClientException) is remapped to 400 with the fixed message. */
    @Test
    public void unknownClientRemappedTo400WithFixedMessage() throws Exception {
        realmTestHelper.mockRealm("beta");
        ChfOAuth2Request o2 = realRequest(buildIdToken("ghost", TOKEN_REALM, new LinkedHashMap<>(), false));
        when(clientRegistrationStore.get(eq("ghost"), any()))
                .thenThrow((InvalidClientException) failures.getException("no such client"));

        Response response = dispatch(o2);

        assertThat(response.getStatus().getCode()).isEqualTo(400);
        Map<String, Object> body = bodyOf(response);
        assertThat(body).containsEntry("error", "invalid_client")
                .containsEntry("error_description", "no registered client matches audience of id_token");
    }

    // --- helpers ----------------------------------------------------------------------------------

    /** A real ChfOAuth2Request over the full context chain, carrying the id_token as a query parameter. */
    private ChfOAuth2Request realRequest(String idToken) throws Exception {
        RootContext root = new RootContext();
        AttributesContext attributes = new AttributesContext(root);
        attributes.getAttributes().put(HttpServletRequest.class.getName(), servletRequest);
        RealmContext realmContext = new RealmContext(attributes, realmTestHelper.mockRealm("alpha"));   // URL realm /alpha
        UriRouterContext uriContext = new UriRouterContext(realmContext, "idtokeninfo", "", new LinkedHashMap<>());
        Request request = new Request().setMethod("POST").setUri("/oauth2/idtokeninfo?id_token=" + idToken);
        return new ChfOAuth2Request(uriContext, request);
    }

    private String buildIdToken(String audience, String realmClaim, Map<String, Object> extraClaims, boolean expired) {
        long skew = expired ? -60_000L : 60_000L;
        JwtClaimsSet claims = new JwtBuilderFactory().claims()
                .aud(singletonList(audience))
                .exp(new Date(System.currentTimeMillis() + skew))
                .iat(new Date())
                .build();
        claims.setClaim(OAuth2Constants.JWTTokenParams.REALM, realmClaim);
        extraClaims.forEach(claims::setClaim);
        SigningHandler signer = new SigningManager().newHmacSigningHandler(HMAC_SECRET.getBytes());
        return new JwtBuilderFactory().jws(signer).headers().alg(JwsAlgorithm.HS256).done().claims(claims).build();
    }

    private Response dispatch(OAuth2Request o2) throws Exception {
        when(requestFactory.create(any(), any(Request.class))).thenReturn(o2);
        return Endpoints.from(handler).handle(new RootContext(), new Request().setMethod("POST"))
                .getOrThrowUninterruptibly();
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> bodyOf(Response response) throws Exception {
        return (Map<String, Object>) response.getEntity().getJson();
    }

    private static void inject(Object target, String name, Object value) throws Exception {
        for (Class<?> c = target.getClass(); c != null; c = c.getSuperclass()) {
            try {
                java.lang.reflect.Field f = c.getDeclaredField(name);
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
