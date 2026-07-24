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
import static org.forgerock.json.JsonValue.array;
import static org.forgerock.json.JsonValue.field;
import static org.forgerock.json.JsonValue.json;
import static org.forgerock.json.JsonValue.object;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.lang.reflect.Field;
import java.util.Map;

import org.forgerock.http.protocol.Request;
import org.forgerock.http.protocol.Response;
import org.forgerock.json.JsonValue;
import org.forgerock.oauth2.core.ClientAuthenticator;
import org.forgerock.oauth2.core.ClientRegistration;
import org.forgerock.oauth2.core.OAuth2Request;
import org.forgerock.oauth2.core.OAuth2RequestFactory;
import org.forgerock.oauth2.core.TokenStore;
import org.forgerock.oauth2.core.exceptions.ClientAuthenticationFailureFactory;
import org.forgerock.openam.cts.api.fields.OAuthTokenField;
import org.forgerock.openam.http.annotations.Endpoints;
import org.forgerock.openam.oauth2.OAuth2Constants;
import org.forgerock.openam.oauth2.OAuth2RealmResolver;
import org.forgerock.openam.services.baseurl.BaseURLProviderFactory;
import org.forgerock.openam.utils.RealmNormaliser;
import org.forgerock.services.context.RootContext;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

/**
 * Unit suite for {@link TokenRevocationHandler} ({@code /token/revoke}). POST only. Pins the empty {@code {}} 200,
 * the access-token and refresh-token cascade deletes, the ownership check, and the {@code WWW-Authenticate} challenge
 * the base emits from a bare {@code InvalidClientAuthZHeaderException} (D4). No cache headers.
 */
public class TokenRevocationHandlerTest {

    private static final String REALM = "/myrealm";
    private static final String CLIENT_ID = "myclient";
    private static final String TOKEN_NAME_KEY = OAuth2Constants.CoreTokenParams.TOKEN_NAME;
    private static final String CLIENT_ID_KEY = OAuthTokenField.CLIENT_ID.getOAuthField();
    private static final String USER_NAME_KEY = OAuthTokenField.USER_NAME.getOAuthField();
    private static final String ID_KEY = OAuthTokenField.ID.getOAuthField();
    private static final String AUTH_GRANT_ID_KEY = OAuth2Constants.CoreTokenParams.AUTH_GRANT_ID;

    private OAuth2RequestFactory requestFactory;
    private ClientAuthenticator clientAuthenticator;
    private TokenStore tokenStore;
    private OAuth2RealmResolver realmResolver;
    private OAuth2Request o2;
    private TokenRevocationHandler handler;

    /** Mints real InvalidClient(AuthZHeader)Exceptions the way production does (see TokenIntrospectionHandlerTest). */
    private final ClientAuthenticationFailureFactory failures = new ClientAuthenticationFailureFactory() {
        @Override protected boolean hasAuthorizationHeader(OAuth2Request request) { return true; }
        @Override protected String getRealm(OAuth2Request request) { return REALM; }
    };

    @BeforeMethod
    public void setup() throws Exception {
        requestFactory = mock(OAuth2RequestFactory.class);
        clientAuthenticator = mock(ClientAuthenticator.class);
        tokenStore = mock(TokenStore.class);
        realmResolver = mock(OAuth2RealmResolver.class);
        o2 = mock(OAuth2Request.class);
        when(requestFactory.create(any(), any(Request.class))).thenReturn(o2);
        when(realmResolver.resolveFrom(o2)).thenReturn(REALM);

        OAuth2ErrorResponseFactory errorResponseFactory = new OAuth2ErrorResponseFactory(
                mock(FreemarkerTemplateRenderer.class), mock(BaseURLProviderFactory.class),
                mock(RealmNormaliser.class));

        handler = new TokenRevocationHandler();
        inject(handler, "requestFactory", requestFactory);
        inject(handler, "errorResponseFactory", errorResponseFactory);
        inject(handler, "clientAuthenticator", clientAuthenticator);
        inject(handler, "tokenStore", tokenStore);
        inject(handler, "realmResolver", realmResolver);
    }

    // --- guards / success ------------------------------------------------------------------------

    @Test
    public void missingTokenReturns400InvalidRequest() throws Exception {
        when(o2.getParameter("token")).thenReturn(null);

        Response response = dispatch();

        assertThat(response.getStatus().getCode()).isEqualTo(400);
        assertThat(bodyOf(response)).containsEntry("error", "invalid_request");
    }

    @Test
    public void revokeAccessTokenReturns200EmptyBodyAndDeletes() throws Exception {
        stubAuthenticatedClient();
        when(o2.getParameter("token")).thenReturn("at-1");
        when(tokenStore.read("at-1")).thenReturn(json(object(
                field(TOKEN_NAME_KEY, OAuth2Constants.Params.ACCESS_TOKEN),
                field(CLIENT_ID_KEY, CLIENT_ID))));

        Response response = dispatch();

        assertThat(response.getStatus().getCode()).isEqualTo(200);
        assertThat(response.getHeaders().getFirst("Content-Type")).isEqualTo("application/json; charset=UTF-8");
        assertThat(response.getHeaders().getFirst("Cache-Control")).isNull();
        assertThat(bodyOf(response)).isEmpty();
        verify(tokenStore).delete(REALM, "at-1");
    }

    /** A refresh token deletes itself and every access token sharing its user + auth-grant. */
    @Test
    public void revokeRefreshTokenCascadeDeletesAllRelatedTokens() throws Exception {
        stubAuthenticatedClient();
        when(o2.getParameter("token")).thenReturn("rt-1");
        when(tokenStore.read("rt-1")).thenReturn(json(object(
                field(TOKEN_NAME_KEY, OAuth2Constants.Params.REFRESH_TOKEN),
                field(CLIENT_ID_KEY, CLIENT_ID),
                field(USER_NAME_KEY, "alice"),
                field(AUTH_GRANT_ID_KEY, "grant-9"))));
        when(tokenStore.queryForToken(eq(REALM), any())).thenReturn(json(array(
                object(field(ID_KEY, "at-a")),
                object(field(ID_KEY, "at-b")),
                object(field(ID_KEY, "rt-1")))));

        Response response = dispatch();

        assertThat(response.getStatus().getCode()).isEqualTo(200);
        assertThat(bodyOf(response)).isEmpty();
        verify(tokenStore, times(3)).delete(eq(REALM), any());
        verify(tokenStore).delete(REALM, "at-a");
        verify(tokenStore).delete(REALM, "at-b");
        verify(tokenStore).delete(REALM, "rt-1");
    }

    /** A token owned by a different client is rejected before any delete (ownership check). */
    @Test
    public void tokenOwnedByAnotherClientReturns400InvalidGrant() throws Exception {
        stubAuthenticatedClient();
        when(o2.getParameter("token")).thenReturn("at-1");
        when(tokenStore.read("at-1")).thenReturn(json(object(
                field(TOKEN_NAME_KEY, OAuth2Constants.Params.ACCESS_TOKEN),
                field(CLIENT_ID_KEY, "someone-else"))));

        Response response = dispatch();

        assertThat(response.getStatus().getCode()).isEqualTo(400);
        assertThat(bodyOf(response)).containsEntry("error", "invalid_grant");
        verify(tokenStore, times(0)).delete(any(), any());
    }

    // --- challenge (D4) ---------------------------------------------------------------------------

    /** A bare InvalidClientAuthZHeaderException -> the base emits WWW-Authenticate (Restlet decoration dropped). */
    @Test
    public void invalidClientAuthZHeaderEmitsChallenge() throws Exception {
        when(o2.getParameter("token")).thenReturn("at-1");
        when(clientAuthenticator.authenticate(o2, null))
                .thenThrow(failures.getException(o2, "client authentication failed"));

        Response response = dispatch();

        assertThat(response.getStatus().getCode()).isEqualTo(401);
        assertThat(bodyOf(response)).containsEntry("error", "invalid_client");
        assertThat(response.getHeaders().getFirst("WWW-Authenticate")).isEqualTo("Basic realm=\"" + REALM + "\"");
    }

    // --- helpers ----------------------------------------------------------------------------------

    private void stubAuthenticatedClient() throws Exception {
        ClientRegistration client = mock(ClientRegistration.class);
        when(client.getClientId()).thenReturn(CLIENT_ID);
        when(clientAuthenticator.authenticate(o2, null)).thenReturn(client);
    }

    private Response dispatch() throws Exception {
        Request request = new Request().setMethod("POST");
        return Endpoints.from(handler).handle(new RootContext(), request).getOrThrowUninterruptibly();
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
