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
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.lang.reflect.Field;
import java.util.Map;

import jakarta.servlet.http.HttpServletRequest;

import org.forgerock.http.protocol.Request;
import org.forgerock.http.protocol.Response;
import org.forgerock.json.JsonValue;
import org.forgerock.oauth2.core.OAuth2Request;
import org.forgerock.oauth2.core.OAuth2RequestFactory;
import org.forgerock.openidconnect.exceptions.InvalidClientMetadata;
import org.forgerock.openam.http.annotations.Endpoints;
import org.forgerock.openam.oauth2.OAuth2Constants;
import org.forgerock.openam.oauth2.OAuth2Utils;
import org.forgerock.openam.services.baseurl.BaseURLProviderFactory;
import org.forgerock.openam.utils.RealmNormaliser;
import org.forgerock.openidconnect.OpenIdConnectClientRegistrationService;
import org.forgerock.services.context.RootContext;
import org.mockito.ArgumentCaptor;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

/**
 * Unit suite for {@link ConnectClientRegistrationHandler} ({@code /connect/register}). Two methods, one per verb
 * (5a-2 D5): {@code @Post createClient} -> 201, {@code @Get getClient} -> 200. Pins the raw deployment-URL
 * reconstruction (finding 5 / concern C2) and the neutral Bearer read that turns the Restlet GET-without-header NPE
 * into a graceful null. No cache headers.
 */
public class ConnectClientRegistrationHandlerTest {

    private OAuth2RequestFactory requestFactory;
    private OpenIdConnectClientRegistrationService clientRegistrationService;
    private OAuth2Request o2;
    private ConnectClientRegistrationHandler handler;

    @BeforeMethod
    public void setup() throws Exception {
        requestFactory = mock(OAuth2RequestFactory.class);
        clientRegistrationService = mock(OpenIdConnectClientRegistrationService.class);
        o2 = mock(OAuth2Request.class);
        when(requestFactory.create(any(), any(Request.class))).thenReturn(o2);

        OAuth2ErrorResponseFactory errorResponseFactory = new OAuth2ErrorResponseFactory(
                mock(FreemarkerTemplateRenderer.class), mock(BaseURLProviderFactory.class),
                mock(RealmNormaliser.class));

        handler = new ConnectClientRegistrationHandler();
        inject(handler, "requestFactory", requestFactory);
        inject(handler, "errorResponseFactory", errorResponseFactory);
        inject(handler, "clientRegistrationService", clientRegistrationService);
        inject(handler, "oAuth2Utils", new OAuth2Utils());   // real: exercises the actual URL reconstruction
    }

    // --- POST createClient -> 201 -----------------------------------------------------------------

    @Test
    public void postCreatesClientReturns201WithReconstructedDeploymentUrl() throws Exception {
        Map<String, Object> registration = Map.of("client_id", "abc", "client_secret", "s3cr3t");
        when(clientRegistrationService.createRegistration(any(), any(), any(OAuth2Request.class)))
                .thenReturn(new JsonValue(registration));
        when(o2.getAuthorizationBearerToken()).thenReturn("reg-tok");
        HttpServletRequest servletRequest = servletRequest("https", "host", 8443, "/openam/oauth2/connect/register");
        when(o2.getHttpServletRequest()).thenReturn(servletRequest);

        Response response = dispatch("POST");

        assertThat(response.getStatus().getCode()).isEqualTo(201);
        assertThat(bodyOf(response)).isEqualTo(registration);
        assertThat(response.getHeaders().getFirst("Content-Type")).isEqualTo("application/json; charset=UTF-8");
        assertThat(response.getHeaders().getFirst("Cache-Control")).isNull();

        ArgumentCaptor<String> token = ArgumentCaptor.forClass(String.class);
        ArgumentCaptor<String> url = ArgumentCaptor.forClass(String.class);
        verify(clientRegistrationService).createRegistration(token.capture(), url.capture(), eq(o2));
        assertThat(token.getValue()).isEqualTo("reg-tok");
        // C2: deployment URL is scheme://host:port/<first-URI-segment> -- the segment "openam", not any contextPath.
        assertThat(url.getValue()).isEqualTo("https://host:8443/openam");
    }

    // --- GET getClient -> 200 ---------------------------------------------------------------------

    @Test
    public void getReturnsRegistrationWith200() throws Exception {
        Map<String, Object> registration = Map.of("client_id", "abc");
        when(o2.<String>getParameter(OAuth2Constants.OAuth2Client.CLIENT_ID)).thenReturn("abc");
        when(o2.getAuthorizationBearerToken()).thenReturn("reg-tok");
        when(clientRegistrationService.getRegistration("abc", "reg-tok", o2)).thenReturn(new JsonValue(registration));

        Response response = dispatch("GET");

        assertThat(response.getStatus().getCode()).isEqualTo(200);
        assertThat(bodyOf(response)).isEqualTo(registration);
        assertThat(response.getHeaders().getFirst("Content-Type")).isEqualTo("application/json; charset=UTF-8");
        assertThat(response.getHeaders().getFirst("Cache-Control")).isNull();
    }

    /**
     * DIVERGENCE (5d-1): the Restlet GET read the token unguarded and NPEd (500) on a missing header. The neutral
     * {@code getAuthorizationBearerToken()} returns {@code null}, which flows to the service's own auth check.
     */
    @Test
    public void getWithoutAuthorizationHeaderReadsNullTokenWithoutNpe() throws Exception {
        when(o2.<String>getParameter(OAuth2Constants.OAuth2Client.CLIENT_ID)).thenReturn("abc");
        when(o2.getAuthorizationBearerToken()).thenReturn(null);   // no Authorization header
        when(clientRegistrationService.getRegistration("abc", null, o2)).thenReturn(new JsonValue(Map.of()));

        Response response = dispatch("GET");

        assertThat(response.getStatus().getCode()).isEqualTo(200);
        verify(clientRegistrationService).getRegistration("abc", null, o2);
    }

    /** A service {@link org.forgerock.oauth2.core.exceptions.OAuth2Exception} maps to the JSON error body (base). */
    @Test
    public void serviceExceptionMapsToJsonError() throws Exception {
        HttpServletRequest servletRequest = servletRequest("https", "host", 8443, "/openam/oauth2/connect/register");
        when(o2.getHttpServletRequest()).thenReturn(servletRequest);
        when(clientRegistrationService.createRegistration(any(), any(), any(OAuth2Request.class)))
                .thenThrow(new InvalidClientMetadata());

        Response response = dispatch("POST");

        assertThat(response.getStatus().getCode()).isEqualTo(400);
        assertThat(bodyOf(response)).containsEntry("error", "invalid_client_metadata");
    }

    // --- helpers ----------------------------------------------------------------------------------

    private static HttpServletRequest servletRequest(String scheme, String host, int port, String uri) {
        HttpServletRequest request = mock(HttpServletRequest.class);
        when(request.getScheme()).thenReturn(scheme);
        when(request.getServerName()).thenReturn(host);
        when(request.getServerPort()).thenReturn(port);
        when(request.getRequestURI()).thenReturn(uri);
        return request;
    }

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
