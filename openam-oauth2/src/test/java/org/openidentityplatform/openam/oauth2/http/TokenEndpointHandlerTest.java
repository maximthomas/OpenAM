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
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.lang.reflect.Field;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;

import org.forgerock.http.protocol.Request;
import org.forgerock.http.protocol.Response;
import org.forgerock.oauth2.core.AccessToken;
import org.forgerock.oauth2.core.AccessTokenService;
import org.forgerock.oauth2.core.OAuth2Request;
import org.forgerock.oauth2.core.OAuth2RequestFactory;
import org.forgerock.oauth2.core.exceptions.ClientAuthenticationFailureFactory;
import org.forgerock.oauth2.core.exceptions.InvalidClientException;
import org.forgerock.oauth2.core.exceptions.InvalidGrantException;
import org.forgerock.openam.http.annotations.Endpoints;
import org.forgerock.openam.services.baseurl.BaseURLProviderFactory;
import org.forgerock.openam.utils.RealmNormaliser;
import org.forgerock.services.context.RootContext;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

/**
 * Unit suite for {@link TokenEndpointHandler}, driven through the real {@code Endpoints.from} framework so the
 * base {@link AbstractOAuth2HttpJsonEndpoint#onError} maps thrown exceptions to the JSON error body -- as it
 * will at 5d-1. Collaborators are mocked; {@link OAuth2ErrorResponseFactory} is the real one (its
 * {@code toJsonResponse} needs no renderer), so the error body and {@code WWW-Authenticate} are the production
 * shapes.
 */
public class TokenEndpointHandlerTest {

    private static final String FORM = "application/x-www-form-urlencoded";
    private static final String BODY = "grant_type=authorization_code";   // non-empty; params are mocked, so content is moot

    private static final Map<String, Object> TOKEN_MAP = new LinkedHashMap<>();
    static {
        TOKEN_MAP.put("access_token", "abc123");
        TOKEN_MAP.put("token_type", "Bearer");
        TOKEN_MAP.put("expires_in", 3599);
        TOKEN_MAP.put("scope", "read");
    }

    private OAuth2RequestFactory requestFactory;
    private AccessTokenService accessTokenService;
    private ChfTokenRequestHook hook;
    private OAuth2Request o2;
    private AccessToken token;
    private TokenEndpointHandler handler;

    /** Mints real InvalidClient(AuthZHeader)Exceptions the way production does. */
    private final ClientAuthenticationFailureFactory failures = new ClientAuthenticationFailureFactory() {
        @Override protected boolean hasAuthorizationHeader(OAuth2Request request) { return true; }
        @Override protected String getRealm(OAuth2Request request) { return "/myrealm"; }
    };

    @BeforeMethod
    public void setup() throws Exception {
        requestFactory = mock(OAuth2RequestFactory.class);
        accessTokenService = mock(AccessTokenService.class);
        hook = mock(ChfTokenRequestHook.class);
        o2 = mock(OAuth2Request.class);
        token = mock(AccessToken.class);
        when(token.toMap()).thenReturn(TOKEN_MAP);
        when(requestFactory.create(any(), any(Request.class))).thenReturn(o2);

        OAuth2ErrorResponseFactory errorResponseFactory = new OAuth2ErrorResponseFactory(
                mock(FreemarkerTemplateRenderer.class), mock(BaseURLProviderFactory.class),
                mock(RealmNormaliser.class));

        handler = new TokenEndpointHandler();
        inject(handler, "requestFactory", requestFactory);
        inject(handler, "errorResponseFactory", errorResponseFactory);
        inject(handler, "accessTokenService", accessTokenService);
        inject(handler, "hooks", Collections.singleton(hook));
    }

    // --- success + grant routing ------------------------------------------------------------------

    @Test
    public void successReturnsTokenBodyWithCacheHeadersAndRunsHookOnce() throws Exception {
        grant("authorization_code");
        when(accessTokenService.requestAccessToken(o2)).thenReturn(token);

        Response response = post(FORM);

        assertThat(response.getStatus().getCode()).isEqualTo(200);
        assertThat(bodyOf(response)).isEqualTo(TOKEN_MAP);
        assertThat(response.getHeaders().getFirst("Content-Type")).isEqualTo("application/json; charset=UTF-8");
        assertThat(response.getHeaders().getFirst("Cache-Control")).isEqualTo("no-store");
        assertThat(response.getHeaders().getFirst("Pragma")).isEqualTo("no-cache");
        verify(hook, times(1)).afterTokenHandling(o2);
    }

    @DataProvider
    public Object[][] accessGrants() {
        return new Object[][]{
                {"authorization_code"}, {"client_credentials"}, {"password"},
                {"urn:ietf:params:oauth:grant-type:device_code"},
                {"urn:ietf:params:oauth:grant-type:jwt-bearer"},
                {"urn:ietf:params:oauth:grant-type:saml2-bearer"},
        };
    }

    @Test(dataProvider = "accessGrants")
    public void accessGrantsRouteToRequestAccessToken(String grant) throws Exception {
        grant(grant);
        when(accessTokenService.requestAccessToken(o2)).thenReturn(token);

        Response response = post(FORM);

        assertThat(response.getStatus().getCode()).isEqualTo(200);
        verify(accessTokenService).requestAccessToken(o2);
        verify(accessTokenService, never()).refreshToken(o2);
        verify(hook, times(1)).afterTokenHandling(o2);
    }

    @Test
    public void refreshTokenRoutesToRefreshAndSkipsHooks() throws Exception {
        grant("refresh_token");
        when(accessTokenService.refreshToken(o2)).thenReturn(token);

        Response response = post(FORM);

        assertThat(response.getStatus().getCode()).isEqualTo(200);
        assertThat(bodyOf(response)).isEqualTo(TOKEN_MAP);
        verify(accessTokenService).refreshToken(o2);
        verify(accessTokenService, never()).requestAccessToken(o2);
        verify(hook, never()).afterTokenHandling(o2);   // RefreshTokenResource never ran the hooks.
    }

    // --- the two-map gate -------------------------------------------------------------------------

    @Test
    public void emptyGrantTypeIsInvalidRequest() throws Exception {
        grant(null);

        Response response = post(FORM);

        assertThat(response.getStatus().getCode()).isEqualTo(400);
        assertThat(bodyOf(response)).containsEntry("error", "invalid_request")
                .containsEntry("error_description", "Grant type is not set");
    }

    /** The load-bearing row: the finder's gate makes an unknown grant unsupported_grant_type, not invalid_grant. */
    @Test
    public void unknownGrantTypeIsUnsupportedGrantType() throws Exception {
        grant("something_unknown");

        Response response = post(FORM);

        assertThat(response.getStatus().getCode()).isEqualTo(400);
        assertThat(bodyOf(response)).containsEntry("error", "unsupported_grant_type");
        verify(accessTokenService, never()).requestAccessToken(o2);
    }

    // --- content type -----------------------------------------------------------------------------

    @Test
    public void formBodyWithCharsetSuffixIsAccepted() throws Exception {
        grant("authorization_code");
        when(accessTokenService.requestAccessToken(o2)).thenReturn(token);

        Response response = post(FORM + ";charset=UTF-8", BODY);   // the §7 charset trap

        assertThat(response.getStatus().getCode()).isEqualTo(200);
    }

    /** Media types are case-insensitive (RFC 7231); Restlet's MediaType.equals accepted mixed case, so we must too. */
    @Test
    public void mixedCaseFormContentTypeIsAccepted() throws Exception {
        grant("authorization_code");
        when(accessTokenService.requestAccessToken(o2)).thenReturn(token);

        Response response = post("Application/X-WWW-Form-Urlencoded", BODY);

        assertThat(response.getStatus().getCode()).isEqualTo(200);
    }

    @Test
    public void noContentTypeIsAccepted() throws Exception {
        grant("authorization_code");
        when(accessTokenService.requestAccessToken(o2)).thenReturn(token);

        Response response = post(null, BODY);   // body present, no Content-Type header -> type == null -> allowed

        assertThat(response.getStatus().getCode()).isEqualTo(200);
    }

    /** A non-form content type is rejected only when the body is non-empty (TokenEndpointFilter's entity check). */
    @Test
    public void jsonContentTypeWithBodyIsInvalidRequest() throws Exception {
        grant("authorization_code");

        Response response = post("application/json", BODY);

        assertThat(response.getStatus().getCode()).isEqualTo(400);
        assertThat(bodyOf(response)).containsEntry("error", "invalid_request")
                .containsEntry("error_description", "Invalid Content Type");
    }

    /** Finding 4: an empty body is never content-type-checked, so a non-form type falls through to the grant gate. */
    @Test
    public void emptyBodyWithNonFormContentTypeSkipsCheck() throws Exception {
        grant(null);   // fails at the grant gate, proving the CT check was skipped rather than firing first

        Response response = post("application/json");   // no body

        assertThat(response.getStatus().getCode()).isEqualTo(400);
        assertThat(bodyOf(response)).containsEntry("error", "invalid_request")
                .containsEntry("error_description", "Grant type is not set");
    }

    /** Finding 1: the OAuth2Filter added no-store/no-cache to EVERY response -- error responses included. */
    @Test
    public void errorResponseCarriesCacheHeaders() throws Exception {
        grant(null);   // -> 400 invalid_request via the base onError

        Response response = post(FORM);

        assertThat(response.getStatus().getCode()).isEqualTo(400);
        assertThat(response.getHeaders().getFirst("Cache-Control")).isEqualTo("no-store");
        assertThat(response.getHeaders().getFirst("Pragma")).isEqualTo("no-cache");
    }

    // --- WWW-Authenticate (finding 4) -------------------------------------------------------------

    @Test
    public void invalidClientAuthZHeaderCarriesChallenge() throws Exception {
        grant("authorization_code");
        when(accessTokenService.requestAccessToken(o2))
                .thenThrow(failures.getException(o2, "client authentication failed"));

        Response response = post(FORM);

        assertThat(response.getStatus().getCode()).isEqualTo(401);
        assertThat(bodyOf(response)).containsEntry("error", "invalid_client");
        assertThat(response.getHeaders().getFirst("WWW-Authenticate")).isEqualTo("Basic realm=\"/myrealm\"");
    }

    /** No Authorization header: a plain invalid_client is 400 with no challenge (RFC 6749 5.2), not the 401. */
    @Test
    public void plainInvalidClientIs400WithNoChallenge() throws Exception {
        grant("authorization_code");
        when(accessTokenService.requestAccessToken(o2))
                .thenThrow((InvalidClientException) failures.getException("no authorization header"));

        Response response = post(FORM);

        assertThat(response.getStatus().getCode()).isEqualTo(400);
        assertThat(bodyOf(response)).containsEntry("error", "invalid_client");
        assertThat(response.getHeaders().getFirst("WWW-Authenticate")).isNull();
    }

    // --- D2 + state -------------------------------------------------------------------------------

    @Test
    public void illegalArgumentBecomesInvalidRequest() throws Exception {
        grant("refresh_token");
        when(accessTokenService.refreshToken(o2)).thenThrow(new IllegalArgumentException("Missing parameter"));

        Response response = post(FORM);

        assertThat(response.getStatus().getCode()).isEqualTo(400);
        assertThat(bodyOf(response)).containsEntry("error", "invalid_request")
                .containsEntry("error_description", "Missing parameter");
    }

    /** Finding 2: RefreshTokenResource masks the InvalidGrantException cause to "grant is invalid". */
    @Test
    public void refreshInvalidGrantIsMaskedToGrantIsInvalid() throws Exception {
        grant("refresh_token");
        when(accessTokenService.refreshToken(o2)).thenThrow(new InvalidGrantException("token reuse detected"));

        Response response = post(FORM);

        assertThat(response.getStatus().getCode()).isEqualTo(400);
        assertThat(bodyOf(response)).containsEntry("error", "invalid_grant")
                .containsEntry("error_description", "grant is invalid");
    }

    /** ...but the access-grant path (TokenEndpointResource) leaves the InvalidGrantException message raw. */
    @Test
    public void accessGrantInvalidGrantKeepsRawMessage() throws Exception {
        grant("authorization_code");
        when(accessTokenService.requestAccessToken(o2)).thenThrow(new InvalidGrantException("auth code expired"));

        Response response = post(FORM);

        assertThat(response.getStatus().getCode()).isEqualTo(400);
        assertThat(bodyOf(response)).containsEntry("error", "invalid_grant")
                .containsEntry("error_description", "auth code expired");
    }

    @Test
    public void stateIsEchoedIntoErrorBody() throws Exception {
        grant(null);
        when(o2.<String>getParameter("state")).thenReturn("xyz");

        Response response = post(FORM);

        assertThat(bodyOf(response)).containsEntry("state", "xyz");
    }

    // --- helpers ----------------------------------------------------------------------------------

    private void grant(String grantType) {
        when(o2.<String>getParameter("grant_type")).thenReturn(grantType);
    }

    private Response post(String contentType) throws Exception {
        return post(contentType, null);
    }

    private Response post(String contentType, String body) throws Exception {
        Request request = new Request().setMethod("POST");
        if (body != null) {
            request.getEntity().setString(body);   // setString sets only Content-Length, so the header below wins
        }
        if (contentType != null) {
            request.getHeaders().put("Content-Type", contentType);
        }
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
