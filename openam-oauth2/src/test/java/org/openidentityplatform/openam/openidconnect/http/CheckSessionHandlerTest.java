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
package org.openidentityplatform.openam.openidconnect.http;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.lang.reflect.Field;
import java.util.Map;
import java.util.NoSuchElementException;

import jakarta.servlet.http.HttpServletRequest;

import org.forgerock.http.protocol.Request;
import org.forgerock.http.protocol.Response;
import org.forgerock.oauth2.core.OAuth2Request;
import org.forgerock.oauth2.core.OAuth2RequestFactory;
import org.forgerock.oauth2.core.exceptions.UnauthorizedClientException;
import org.forgerock.openam.http.annotations.Endpoints;
import org.forgerock.openam.services.baseurl.BaseURLProvider;
import org.forgerock.openam.services.baseurl.BaseURLProviderFactory;
import org.forgerock.openam.utils.RealmNormaliser;
import org.forgerock.openidconnect.CheckSession;
import org.forgerock.services.context.RootContext;
import org.mockito.ArgumentCaptor;
import org.openidentityplatform.openam.oauth2.http.FreemarkerTemplateRenderer;
import org.openidentityplatform.openam.oauth2.http.OAuth2ErrorResponseFactory;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

/**
 * Unit coverage for the CHF {@code /oauth2/connect/checkSession} port.
 *
 * <p>Uses the <strong>real</strong> {@link FreemarkerTemplateRenderer} rather than a mock, because half of
 * what this endpoint has to get right is the model contract of {@code page/checkSession.ftl} -- notably that
 * {@code valid_session} stays a {@code String}, since the template emits it <em>unquoted</em> into JavaScript
 * and a {@code Boolean} would render identically here while diverging in the golden.
 *
 * <p>Every error row asserts {@code application/json}: R-5b2.1 is that this endpoint on the browser base would
 * answer an HTML page instead, and a test written against the wrong base would simply assert the page.
 */
public class CheckSessionHandlerTest {

    private static final String REALM = "/";
    private static final String BASE_URL = "https://openam.example/openam";
    private static final String CLIENT_URI = "https://rp.example";

    private OAuth2RequestFactory requestFactory;
    private CheckSession checkSession;
    private BaseURLProviderFactory baseURLProviderFactory;
    private OAuth2Request o2;
    private HttpServletRequest servletRequest;
    private CheckSessionHandler handler;

    @BeforeMethod
    public void setUp() throws Exception {
        requestFactory = mock(OAuth2RequestFactory.class);
        checkSession = mock(CheckSession.class);
        baseURLProviderFactory = mock(BaseURLProviderFactory.class);
        o2 = mock(OAuth2Request.class);
        servletRequest = mock(HttpServletRequest.class);

        when(requestFactory.create(any(), any(Request.class))).thenReturn(o2);
        when(o2.getHttpServletRequest()).thenReturn(servletRequest);
        when(o2.<String>getParameter("realm")).thenReturn(REALM);
        when(checkSession.getCookieName()).thenReturn("iPlanetDirectoryPro");
        when(checkSession.getClientSessionURI(servletRequest)).thenReturn(CLIENT_URI);
        when(checkSession.getValidSession(servletRequest)).thenReturn(true);

        BaseURLProvider baseURLProvider = mock(BaseURLProvider.class);
        when(baseURLProvider.getRootURL(servletRequest)).thenReturn(BASE_URL);
        when(baseURLProviderFactory.get(anyString())).thenReturn(baseURLProvider);

        OAuth2ErrorResponseFactory errorResponseFactory = new OAuth2ErrorResponseFactory(
                mock(FreemarkerTemplateRenderer.class), mock(BaseURLProviderFactory.class),
                mock(RealmNormaliser.class));

        handler = new CheckSessionHandler();
        inject(handler, "requestFactory", requestFactory);
        inject(handler, "errorResponseFactory", errorResponseFactory);
        inject(handler, "renderer", new FreemarkerTemplateRenderer());
        inject(handler, "checkSession", checkSession);
        inject(handler, "baseURLProviderFactory", baseURLProviderFactory);
    }

    // --- the page ---------------------------------------------------------------------------------

    @Test
    public void theIframePageIsRenderedAsUtf8Html() throws Exception {
        Response response = dispatch("GET");

        assertThat(response.getStatus().getCode()).isEqualTo(200);
        assertThat(response.getHeaders().getFirst("Content-Type")).isEqualTo("text/html; charset=UTF-8");
        assertThat(response.getEntity().getString())
                .contains(BASE_URL + "/js/sha256.js")
                .contains("var clientURI = \"" + CLIENT_URI + "\";")
                .contains("iPlanetDirectoryPro");
    }

    /**
     * ⚠ {@code valid_session} must reach the model as a {@code String}. {@code page/checkSession.ftl} emits it
     * <strong>unquoted</strong> -- {@code var validSession = ${valid_session?js_string};} -- so a
     * {@code String} yields the bare literal {@code true} that the template's {@code !validSession} guard
     * needs. This is also the exact bug the shipping JSP has on the bare path, where the quoted {@code "false"}
     * makes that guard dead; the FTL is the correct leg and the port must keep it correct.
     */
    @Test
    public void validSessionIsRenderedAsABareBooleanLiteralNotAQuotedString() throws Exception {
        when(checkSession.getValidSession(servletRequest)).thenReturn(false);

        String html = dispatch("GET").getEntity().getString();

        assertThat(html).contains("var validSession = false;");
        assertThat(html).doesNotContain("var validSession = \"false\";");
    }

    /** Both verbs delegate to the same body, as the Restlet's {@code @Get}/{@code @Post} pair did. */
    @Test
    public void getAndPostProduceIdenticalBytes() throws Exception {
        String get = dispatch("GET").getEntity().getString();
        String post = dispatch("POST").getEntity().getString();

        assertThat(post).isEqualTo(get);
    }

    /**
     * Risk #21. The templates are pure ASCII, so only a non-ASCII <em>model</em> can catch an ISO-8859-1
     * encode on the way to the wire -- and {@code client_uri} is the one model value an RP controls.
     */
    @Test
    public void aNonAsciiClientUriSurvivesAsUtf8() throws Exception {
        when(checkSession.getClientSessionURI(servletRequest)).thenReturn("https://пример.test");

        Response response = dispatch("GET");

        assertThat(response.getEntity().getString()).contains("https://пример.test");
    }

    /** No cache headers on this endpoint, ever: it was never wrapped by the Restlet {@code OAuth2Filter}. */
    @Test
    public void noCacheHeadersAreSet() throws Exception {
        Response response = dispatch("GET");

        assertThat(response.getHeaders().getFirst("Cache-Control")).isNull();
        assertThat(response.getHeaders().getFirst("Pragma")).isNull();
    }

    // --- D5: ?display= ----------------------------------------------------------------------------

    /**
     * D5, gated on and confirmed by 5-E3 row 7. {@code checkSession.ftl} exists only under {@code page/}, so
     * every other display is a 400 on live Restlet -- by three different mechanisms (missing template for
     * {@code touch}/{@code wap}, a failed render for {@code popup}, {@code Enum.valueOf} for an unknown one)
     * that all land on the same status. The port collapses them to one {@code ServerException}.
     */
    @Test
    public void aNonPageDisplayIs400ServerErrorJson() throws Exception {
        for (String display : new String[] {"touch", "wap", "popup", "bogus"}) {
            when(o2.<String>getParameter("display")).thenReturn(display);

            Response response = dispatch("GET");

            assertThat(response.getStatus().getCode()).as(display).isEqualTo(400);
            assertThat(response.getHeaders().getFirst("Content-Type")).as(display)
                    .isEqualTo("application/json; charset=UTF-8");
            assertThat(bodyOf(response)).as(display).containsEntry("error", "server_error");
        }
    }

    /** {@code ?display=} and {@code ?display=page} both mean the default folder, and both must render. */
    @Test
    public void anEmptyOrPageDisplayStillRenders() throws Exception {
        for (String display : new String[] {"", "page", "PAGE"}) {
            when(o2.<String>getParameter("display")).thenReturn(display);

            assertThat(dispatch("GET").getStatus().getCode()).as(display).isEqualTo(200);
        }
    }

    // --- D7: the client-reachable unchecked throws -------------------------------------------------

    /**
     * D7 row 3. {@code CheckSession.getClientSessionURI:111-115} guards {@code clientRegistration != null} for
     * the validity check and then dereferences it unconditionally, and {@code getClientRegistration} returns
     * null exactly when the id_token carries no {@code aud}. A pre-existing product bug, reproduced as the
     * 400 Restlet gave (5-E3 row 6d) rather than allowed to become the framework's 500.
     */
    @Test
    public void anNpeFromGetClientSessionUriIs400ServerErrorNot500() throws Exception {
        when(checkSession.getClientSessionURI(servletRequest)).thenThrow(new NullPointerException());

        Response response = dispatch("GET");

        assertThat(response.getStatus().getCode()).isEqualTo(400);
        assertThat(response.getHeaders().getFirst("Content-Type")).isEqualTo("application/json; charset=UTF-8");
        assertThat(bodyOf(response)).containsEntry("error", "server_error");
    }

    /**
     * D7's fourth wrap, added by 5-E3. {@code OpenAMClientRegistration.getClientSessionURI:426-434} ends in
     * {@code set.iterator().next()} with no emptiness guard, and the admin API leaves the attribute empty on
     * every client it creates -- so this is not an edge case but the endpoint's own happy path for a
     * default-configured client (5-E3 row 6e). Same call as the row above, hence the same wrap.
     */
    @Test
    public void aNoSuchElementFromAnEmptyClientSessionUriIs400ServerErrorNot500() throws Exception {
        when(checkSession.getClientSessionURI(servletRequest)).thenThrow(new NoSuchElementException());

        Response response = dispatch("GET");

        assertThat(response.getStatus().getCode()).isEqualTo(400);
        assertThat(bodyOf(response)).containsEntry("error", "server_error");
    }

    /**
     * A declared {@code OAuth2Exception} keeps its own error code -- it is not swallowed into
     * {@code server_error} by the D7 wrap. {@code getClientSessionURI} declares three of them
     * ({@code UnauthorizedClientException}, {@code InvalidClientException}, {@code NotFoundException}); this
     * uses the one with a public constructor, the distinction being the wrap's behaviour, not the type.
     */
    @Test
    public void anOAuth2ExceptionFromGetClientSessionUriKeepsItsOwnErrorAndStaysJson() throws Exception {
        when(checkSession.getClientSessionURI(servletRequest))
                .thenThrow(new UnauthorizedClientException("not allowed"));

        Response response = dispatch("GET");

        assertThat(response.getHeaders().getFirst("Content-Type")).isEqualTo("application/json; charset=UTF-8");
        assertThat(bodyOf(response)).containsEntry("error", "unauthorized_client");
    }

    // --- the model --------------------------------------------------------------------------------

    /**
     * The four keys and their types, asserted at the seam rather than through the rendered page, because the
     * {@code String}-vs-{@code Boolean} distinction on {@code valid_session} is invisible in the output of
     * this template but not in others.
     */
    @Test
    public void theModelCarriesTheFourKeysWithTheRestletsTypes() throws Exception {
        FreemarkerTemplateRenderer renderer = mock(FreemarkerTemplateRenderer.class);
        when(renderer.renderForDisplay(any(), eq("checkSession.ftl"), any())).thenReturn("<html/>");
        inject(handler, "renderer", renderer);

        dispatch("GET");

        @SuppressWarnings("unchecked")
        ArgumentCaptor<Map<String, Object>> model = ArgumentCaptor.forClass(Map.class);
        verify(renderer).renderForDisplay(any(), eq("checkSession.ftl"), model.capture());
        assertThat(model.getValue())
                .containsEntry("cookie_name", "iPlanetDirectoryPro")
                .containsEntry("client_uri", CLIENT_URI)
                .containsEntry("baseUrl", BASE_URL)
                .containsEntry("valid_session", "true");
        assertThat(model.getValue().get("valid_session")).isInstanceOf(String.class);
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
