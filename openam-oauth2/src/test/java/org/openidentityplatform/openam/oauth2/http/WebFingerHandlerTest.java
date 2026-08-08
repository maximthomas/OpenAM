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
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.lang.reflect.Field;
import java.util.Map;

import jakarta.servlet.http.HttpServletRequest;

import org.forgerock.http.protocol.Request;
import org.forgerock.http.protocol.Response;
import org.forgerock.oauth2.core.OAuth2Request;
import org.forgerock.oauth2.core.OAuth2RequestFactory;
import org.forgerock.oauth2.core.exceptions.BadRequestException;
import org.forgerock.oauth2.core.exceptions.NotFoundException;
import org.forgerock.openam.http.annotations.Endpoints;
import org.forgerock.openam.oauth2.OAuth2Constants;
import org.forgerock.openam.services.baseurl.BaseURLProvider;
import org.forgerock.openam.services.baseurl.BaseURLProviderFactory;
import org.forgerock.openam.utils.RealmNormaliser;
import org.forgerock.openidconnect.OpenIDConnectProviderDiscovery;
import org.forgerock.services.context.RootContext;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

/**
 * Unit suite for {@link WebFingerHandler} (the {@code /.well-known/webfinger} endpoint), driven through the
 * real {@code Endpoints.from} framework so the base {@code @ExceptionHandler} runs. The two error rows are
 * the ones that prove polymorphic handler dispatch: neither {@link BadRequestException} nor
 * {@link NotFoundException} has a handler of its own.
 */
public class WebFingerHandlerTest {

    private static final String RESOURCE = "acct:joe@example.com";
    private static final String REL = "http://openid.net/specs/connect/1.0/issuer";
    private static final String REALM = "/subrealm";
    private static final String ROOT_URL = "https://op.example:8443/openam";

    private OAuth2RequestFactory requestFactory;
    private OpenIDConnectProviderDiscovery providerDiscovery;
    private BaseURLProviderFactory baseUrlProviderFactory;
    private BaseURLProvider baseUrlProvider;
    private HttpServletRequest servletRequest;
    private OAuth2Request o2;
    private WebFingerHandler handler;

    @BeforeMethod
    public void setup() throws Exception {
        requestFactory = mock(OAuth2RequestFactory.class);
        providerDiscovery = mock(OpenIDConnectProviderDiscovery.class);
        baseUrlProviderFactory = mock(BaseURLProviderFactory.class);
        baseUrlProvider = mock(BaseURLProvider.class);
        servletRequest = mock(HttpServletRequest.class);
        o2 = mock(OAuth2Request.class);

        when(requestFactory.create(any(), any(Request.class))).thenReturn(o2);
        when(o2.getHttpServletRequest()).thenReturn(servletRequest);
        when(o2.<String>getParameter(OAuth2Constants.Custom.REALM)).thenReturn(REALM);
        when(o2.<String>getParameter("resource")).thenReturn(RESOURCE);
        when(o2.<String>getParameter("rel")).thenReturn(REL);
        when(baseUrlProviderFactory.get(REALM)).thenReturn(baseUrlProvider);
        when(baseUrlProvider.getRootURL(servletRequest)).thenReturn(ROOT_URL);

        OAuth2ErrorResponseFactory errorResponseFactory = new OAuth2ErrorResponseFactory(
                mock(FreemarkerTemplateRenderer.class), mock(BaseURLProviderFactory.class),
                mock(RealmNormaliser.class));

        handler = new WebFingerHandler();
        inject(handler, "requestFactory", requestFactory);
        inject(handler, "errorResponseFactory", errorResponseFactory);
        inject(handler, "providerDiscovery", providerDiscovery);
        inject(handler, "baseUrlProviderFactory", baseUrlProviderFactory);
    }

    @Test
    public void getReturnsTheJrdWithTheRealmsDeploymentUrl() throws Exception {
        Map<String, Object> jrd = Map.of("subject", RESOURCE,
                "links", Map.of("rel", REL, "href", ROOT_URL + "/oauth2"));
        when(providerDiscovery.discover(RESOURCE, REL, ROOT_URL, o2)).thenReturn(jrd);

        Response response = get();

        assertThat(response.getStatus().getCode()).isEqualTo(200);
        assertThat(bodyOf(response)).isEqualTo(jrd);
        assertThat(response.getHeaders().getFirst("Content-Type")).isEqualTo("application/json; charset=UTF-8");
        // the realm from the request picked the provider, and that provider's root URL fed discover
        verify(baseUrlProviderFactory).get(REALM);
        verify(baseUrlProvider).getRootURL(servletRequest);
        verify(providerDiscovery).discover(RESOURCE, REL, ROOT_URL, o2);
    }

    @Test
    public void noServletRequestIsNamedRatherThanNpe() throws Exception {
        when(o2.getHttpServletRequest()).thenReturn(null);

        Response response = get();

        assertThat(response.getStatus().getCode()).isEqualTo(400);
        assertThat(bodyOf(response)).containsEntry("error", "server_error");
        assertThat(bodyOf(response)).containsEntry("error_description",
                "Cannot determine the deployment URL: no servlet request on the context");
    }

    @Test
    public void badRequestMapsToJsonErrorThroughTheBaseHandler() throws Exception {
        when(providerDiscovery.discover(RESOURCE, REL, ROOT_URL, o2))
                .thenThrow(new BadRequestException("No resource provided in discovery."));

        Response response = get();

        assertThat(response.getStatus().getCode()).isEqualTo(400);
        assertThat(bodyOf(response)).containsEntry("error", "bad_request");
        assertThat(bodyOf(response)).containsEntry("error_description", "No resource provided in discovery.");
    }

    @Test
    public void notFoundMapsToJsonErrorThroughTheBaseHandler() throws Exception {
        when(providerDiscovery.discover(RESOURCE, REL, ROOT_URL, o2))
                .thenThrow(new NotFoundException("Invalid parameters."));

        Response response = get();

        assertThat(response.getStatus().getCode()).isEqualTo(404);
        assertThat(bodyOf(response)).containsEntry("error", "not_found");
        assertThat(bodyOf(response)).containsEntry("error_description", "Invalid parameters.");
    }

    // --- helpers ----------------------------------------------------------------------------------

    private Response get() throws Exception {
        Request request = new Request().setMethod("GET");
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
