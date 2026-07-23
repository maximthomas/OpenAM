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

import static java.util.Arrays.asList;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.entry;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.util.HashSet;
import java.util.Map;

import org.forgerock.http.Handler;
import org.forgerock.http.protocol.Request;
import org.forgerock.http.protocol.Response;
import org.forgerock.http.protocol.Status;
import org.forgerock.oauth2.core.AccessToken;
import org.forgerock.oauth2.core.OAuth2Request;
import org.forgerock.oauth2.core.OAuth2RequestFactory;
import org.forgerock.oauth2.core.TokenStore;
import org.forgerock.oauth2.core.exceptions.InvalidGrantException;
import org.forgerock.oauth2.core.exceptions.NotFoundException;
import org.forgerock.oauth2.core.exceptions.ServerException;
import org.forgerock.services.context.Context;
import org.forgerock.services.context.RootContext;
import org.forgerock.util.promise.Promises;
import org.openidentityplatform.openam.oauth2.core.ChfOAuth2Request;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

/**
 * Parity oracle: the Restlet {@code org.forgerock.openam.oauth2.AccessTokenProtectionFilter}. Each exit
 * status (401/403/404/500) and the success token-stash mirror its {@code beforeHandle}, and the failure
 * bodies reproduce the CREST {@code {code,reason,message}} the app's {@code StatusFilter} rendered for its
 * bare error status -- with no OAuth2 {@code error} field and no {@code WWW-Authenticate} (D5).
 */
public class ChfAccessTokenProtectionFilterTest {

    private static final String SCOPE = "uma_protection";
    private static final String INVALID_TOKEN_MESSAGE =
            "The access token provided is expired, revoked, malformed, or invalid for other reasons.";

    private final Context context = new RootContext();

    private TokenStore tokenStore;
    private OAuth2RequestFactory requestFactory;
    private Handler next;
    private Response nextResponse;

    private Request request;
    private OAuth2Request oAuth2Request;

    @BeforeMethod
    public void setUp() {
        tokenStore = mock(TokenStore.class);
        requestFactory = mock(OAuth2RequestFactory.class);
        nextResponse = new Response(Status.OK);
        next = mock(Handler.class);
        when(next.handle(any(), any())).thenReturn(Promises.newResultPromise(nextResponse));
    }

    // --- success ----------------------------------------------------------------------------

    @Test
    public void aValidTokenWithTheRequiredScopeIsStashedAndNextIsCalled() throws Exception {
        givenBearer("tok");
        AccessToken token = accessToken(false, SCOPE);
        when(tokenStore.readAccessToken(oAuth2Request, "tok")).thenReturn(token);

        Response response = run(SCOPE);

        assertThat(response).isSameAs(nextResponse);
        // The token is stashed on the same cached OAuth2Request the endpoint downstream will read.
        assertThat(oAuth2Request.getToken(AccessToken.class)).isSameAs(token);
        verify(next).handle(context, request);
    }

    @Test
    public void aNullRequiredScopeSkipsTheScopeCheck() throws Exception {
        givenBearer("tok");
        AccessToken token = accessToken(false, "some_other_scope");
        when(tokenStore.readAccessToken(oAuth2Request, "tok")).thenReturn(token);

        Response response = run(null);

        assertThat(response).isSameAs(nextResponse);
        assertThat(oAuth2Request.getToken(AccessToken.class)).isSameAs(token);
        verify(next).handle(context, request);
    }

    // --- 401 --------------------------------------------------------------------------------

    @Test
    public void noBearerHeaderYields401CrestBodyAndDoesNotCallNext() throws Exception {
        givenBearer(null);

        Response response = run(SCOPE);

        assertThat(response.getStatus().getCode()).isEqualTo(401);
        assertThat(response.getHeaders().getFirst("Content-Type")).isEqualTo("application/json; charset=UTF-8");
        assertThat(bodyOf(response)).containsOnlyKeys("code", "reason", "message")
                .contains(entry("code", 401), entry("reason", "Unauthorized"),
                        entry("message", INVALID_TOKEN_MESSAGE));
        // D5: no OAuth2 error field, no bearer challenge.
        assertThat(bodyOf(response)).doesNotContainKey("error");
        assertThat(response.getHeaders().getFirst("WWW-Authenticate")).isNull();
        verify(next, never()).handle(any(), any());
        verify(tokenStore, never()).readAccessToken(any(), any());
    }

    @Test
    public void aNullTokenYields401() throws Exception {
        givenBearer("tok");
        when(tokenStore.readAccessToken(oAuth2Request, "tok")).thenReturn(null);

        Response response = run(SCOPE);

        assertThat(response.getStatus().getCode()).isEqualTo(401);
        assertThat(bodyOf(response)).containsEntry("message", INVALID_TOKEN_MESSAGE);
        verify(next, never()).handle(any(), any());
    }

    @Test
    public void anExpiredTokenYields401() throws Exception {
        givenBearer("tok");
        AccessToken expired = accessToken(true, SCOPE);
        when(tokenStore.readAccessToken(oAuth2Request, "tok")).thenReturn(expired);

        Response response = run(SCOPE);

        assertThat(response.getStatus().getCode()).isEqualTo(401);
        assertThat(bodyOf(response)).containsEntry("message", INVALID_TOKEN_MESSAGE);
        verify(next, never()).handle(any(), any());
    }

    @Test
    public void anInvalidGrantExceptionYields401WithTheInvalidTokenMessage() throws Exception {
        givenBearer("tok");
        when(tokenStore.readAccessToken(oAuth2Request, "tok")).thenThrow(new InvalidGrantException("grant boom"));

        Response response = run(SCOPE);

        // The grant message is discarded: the oracle substitutes InvalidTokenException for the body.
        assertThat(response.getStatus().getCode()).isEqualTo(401);
        assertThat(bodyOf(response)).containsEntry("message", INVALID_TOKEN_MESSAGE);
        verify(next, never()).handle(any(), any());
    }

    // --- 403 / 404 / 500 --------------------------------------------------------------------

    @Test
    public void aTokenMissingTheRequiredScopeYields403() throws Exception {
        givenBearer("tok");
        AccessToken wrongScope = accessToken(false, "other_scope");
        when(tokenStore.readAccessToken(oAuth2Request, "tok")).thenReturn(wrongScope);

        Response response = run(SCOPE);

        assertThat(response.getStatus().getCode()).isEqualTo(403);
        assertThat(bodyOf(response)).contains(entry("reason", "Forbidden"),
                entry("message", "The resource requested requires scope: " + SCOPE));
        assertThat(bodyOf(response)).doesNotContainKey("error");
        verify(next, never()).handle(any(), any());
    }

    @Test
    public void aNotFoundExceptionYields404WithTheCaughtMessage() throws Exception {
        givenBearer("tok");
        when(tokenStore.readAccessToken(oAuth2Request, "tok")).thenThrow(new NotFoundException("no such token"));

        Response response = run(SCOPE);

        assertThat(response.getStatus().getCode()).isEqualTo(404);
        assertThat(bodyOf(response)).contains(entry("reason", "Not Found"), entry("message", "no such token"));
        verify(next, never()).handle(any(), any());
    }

    @Test
    public void aServerExceptionYields500WithTheCaughtMessage() throws Exception {
        givenBearer("tok");
        when(tokenStore.readAccessToken(oAuth2Request, "tok")).thenThrow(new ServerException("boom"));

        Response response = run(SCOPE);

        assertThat(response.getStatus().getCode()).isEqualTo(500);
        assertThat(bodyOf(response)).contains(entry("reason", "Internal Server Error"), entry("message", "boom"));
        verify(next, never()).handle(any(), any());
    }

    // --- helpers ----------------------------------------------------------------------------

    private void givenBearer(String token) throws Exception {
        request = new Request().setMethod("POST").setUri("http://host/uma/permission_request");
        if (token != null) {
            request.getHeaders().put("Authorization", "Bearer " + token);
        }
        // A real ChfOAuth2Request so the bearer parse and the setToken/getToken stash round-trip for real.
        oAuth2Request = new ChfOAuth2Request(context, request);
        when(requestFactory.create(context, request)).thenReturn(oAuth2Request);
    }

    private Response run(String requiredScope) {
        return new ChfAccessTokenProtectionFilter(requiredScope, tokenStore, requestFactory)
                .filter(context, request, next).getOrThrowUninterruptibly();
    }

    private AccessToken accessToken(boolean expired, String... scopes) {
        AccessToken token = mock(AccessToken.class);
        when(token.isExpired()).thenReturn(expired);
        when(token.getScope()).thenReturn(new HashSet<>(asList(scopes)));
        return token;
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> bodyOf(Response response) throws Exception {
        return (Map<String, Object>) response.getEntity().getJson();
    }
}
