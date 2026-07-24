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
import static org.mockito.Mockito.when;

import java.lang.reflect.Field;
import java.util.Map;

import org.forgerock.http.protocol.Request;
import org.forgerock.http.protocol.Response;
import org.forgerock.json.JsonValue;
import org.forgerock.oauth2.core.OAuth2Request;
import org.forgerock.oauth2.core.OAuth2RequestFactory;
import org.forgerock.oauth2.core.TokenIntrospectionService;
import org.forgerock.oauth2.core.exceptions.ClientAuthenticationFailureFactory;
import org.forgerock.oauth2.core.exceptions.InvalidClientException;
import org.forgerock.openam.http.annotations.Endpoints;
import org.forgerock.openam.services.baseurl.BaseURLProviderFactory;
import org.forgerock.openam.utils.RealmNormaliser;
import org.forgerock.services.context.RootContext;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

/**
 * Unit suite for {@link TokenIntrospectionHandler} ({@code /introspect}). The single {@code @Get @Post} method
 * must answer <strong>both</strong> verbs (5a-2 D2 / finding 2). Because the service authenticates the client,
 * an auth-header failure ({@code InvalidClientAuthZHeaderException}) makes the base emit a {@code WWW-Authenticate}
 * the Restlet resource never sent -- a deliberate, RFC 6749 5.2-compliant 5d-1 divergence (R-5a2.4). No cache headers.
 */
public class TokenIntrospectionHandlerTest {

    private OAuth2RequestFactory requestFactory;
    private TokenIntrospectionService tokenIntrospectionService;
    private OAuth2Request o2;
    private TokenIntrospectionHandler handler;

    /** Mints real InvalidClient(AuthZHeader)Exceptions the way production does (see TokenEndpointHandlerTest). */
    private final ClientAuthenticationFailureFactory failures = new ClientAuthenticationFailureFactory() {
        @Override protected boolean hasAuthorizationHeader(OAuth2Request request) { return true; }
        @Override protected String getRealm(OAuth2Request request) { return "/myrealm"; }
    };

    @BeforeMethod
    public void setup() throws Exception {
        requestFactory = mock(OAuth2RequestFactory.class);
        tokenIntrospectionService = mock(TokenIntrospectionService.class);
        o2 = mock(OAuth2Request.class);
        when(requestFactory.create(any(), any(Request.class))).thenReturn(o2);

        OAuth2ErrorResponseFactory errorResponseFactory = new OAuth2ErrorResponseFactory(
                mock(FreemarkerTemplateRenderer.class), mock(BaseURLProviderFactory.class),
                mock(RealmNormaliser.class));

        handler = new TokenIntrospectionHandler();
        inject(handler, "requestFactory", requestFactory);
        inject(handler, "errorResponseFactory", errorResponseFactory);
        inject(handler, "tokenIntrospectionService", tokenIntrospectionService);
    }

    // --- dual-verb dispatch (D2): one method answers both GET and POST ----------------------------

    @Test
    public void getDispatchesToIntrospect() throws Exception {
        Map<String, Object> result = Map.of("active", true, "client_id", "myclient");
        when(tokenIntrospectionService.introspect(o2)).thenReturn(new JsonValue(result));

        Response response = dispatch("GET");

        assertThat(response.getStatus().getCode()).isEqualTo(200);
        assertThat(bodyOf(response)).isEqualTo(result);
        assertThat(response.getHeaders().getFirst("Content-Type")).isEqualTo("application/json; charset=UTF-8");
        assertThat(response.getHeaders().getFirst("Cache-Control")).isNull();
        assertThat(response.getHeaders().getFirst("Pragma")).isNull();
    }

    @Test
    public void postDispatchesToSameIntrospectMethod() throws Exception {
        Map<String, Object> result = Map.of("active", false);
        when(tokenIntrospectionService.introspect(o2)).thenReturn(new JsonValue(result));

        Response response = dispatch("POST");

        assertThat(response.getStatus().getCode()).isEqualTo(200);
        assertThat(bodyOf(response)).isEqualTo(result);
    }

    // --- client-auth error shapes -----------------------------------------------------------------

    /** DIVERGENCE (R-5a2.4): auth-header failure -> 401 invalid_client + WWW-Authenticate the Restlet resource omitted. */
    @Test
    public void invalidClientAuthZHeaderEmitsChallenge() throws Exception {
        when(tokenIntrospectionService.introspect(o2))
                .thenThrow(failures.getException(o2, "client authentication failed"));

        Response response = dispatch("POST");

        assertThat(response.getStatus().getCode()).isEqualTo(401);
        assertThat(bodyOf(response)).containsEntry("error", "invalid_client");
        assertThat(response.getHeaders().getFirst("WWW-Authenticate")).isEqualTo("Basic realm=\"/myrealm\"");
        assertThat(response.getHeaders().getFirst("Cache-Control")).isNull();
    }

    /** No Authorization header: a plain invalid_client is 400 with no challenge (RFC 6749 5.2) -- parity. */
    @Test
    public void plainInvalidClientIs400WithNoChallenge() throws Exception {
        when(tokenIntrospectionService.introspect(o2))
                .thenThrow((InvalidClientException) failures.getException("no authorization header"));

        Response response = dispatch("POST");

        assertThat(response.getStatus().getCode()).isEqualTo(400);
        assertThat(bodyOf(response)).containsEntry("error", "invalid_client");
        assertThat(response.getHeaders().getFirst("WWW-Authenticate")).isNull();
    }

    // --- helpers ----------------------------------------------------------------------------------

    private Response dispatch(String method) throws Exception {
        Request request = new Request().setMethod(method);
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
