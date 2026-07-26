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
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.io.IOException;
import java.lang.reflect.Field;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.Set;

import jakarta.servlet.http.HttpServletRequest;

import org.forgerock.http.Handler;
import org.forgerock.http.handler.Handlers;
import org.forgerock.http.protocol.Request;
import org.forgerock.http.protocol.Response;
import org.forgerock.oauth2.core.AuthorizationService;
import org.forgerock.oauth2.core.AuthorizationToken;
import org.forgerock.oauth2.core.OAuth2Request;
import org.forgerock.oauth2.core.OAuth2RequestFactory;
import org.forgerock.oauth2.core.RedirectUriResolver;
import org.forgerock.oauth2.core.UserInfoClaims;
import org.forgerock.oauth2.core.exceptions.InvalidScopeException;
import org.forgerock.oauth2.core.exceptions.OAuth2Exception;
import org.forgerock.oauth2.core.exceptions.RedirectUriMismatchException;
import org.forgerock.oauth2.core.exceptions.ResourceOwnerAuthenticationRequired;
import org.forgerock.oauth2.core.exceptions.ResourceOwnerConsentRequired;
import org.forgerock.openam.http.annotations.Endpoints;
import org.forgerock.openam.http.annotations.Get;
import org.forgerock.openam.http.annotations.Post;
import org.forgerock.openam.oauth2.OAuth2Constants.UrlLocation;
import org.forgerock.openam.services.baseurl.BaseURLProvider;
import org.forgerock.openam.services.baseurl.BaseURLProviderFactory;
import org.forgerock.openam.utils.RealmNormaliser;
import org.forgerock.services.context.RootContext;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

/**
 * Composition guard for {@link AbstractOAuth2HttpBrowserEndpoint}: the browser base is the first thing in this
 * migration whose contract is a <strong>3xx, or an HTML body, produced by an {@code @ExceptionHandler}</strong>
 * and then flowing through {@link OAuth2ErrorFilter}. A unit test drives the mapper; only real composition can
 * show what survives the framework and the filter.
 *
 * <p>Four claims that a unit test structurally cannot make, each of which would be a silent, total failure of
 * {@code /authorize} at 5d-1 if it were false:
 * <ul>
 * <li>a 301 and a 302 pass the filter <em>untouched</em> -- it keys on {@code >= 400}, so a 3xx must fall
 *     through. Pinned, not assumed;
 * <li>the HTML error page is not rewritten into an OAuth2 JSON body (the filter guards on
 *     {@code Content-Type} before parsing -- the one interaction that would silently destroy the page);
 * <li>a non-ASCII page reaches the wire as UTF-8 bytes (risk #21: the templates are ASCII, so only a
 *     non-ASCII <em>model</em> can catch an ISO-8859-1 encode);
 * <li>{@code PUT} against a {@code @Get}/{@code @Post}-only handler gives the framework 405, rewritten by the
 *     filter to {@code invalid_request} -- the {@code D8} body divergence from live Restlet's
 *     {@code method_not_allowed}, pinned here in process so 5d-1 only has to confirm it.
 * </ul>
 *
 * <p>A second group drives the <strong>real</strong> {@link AuthorizeHandler} rather than the stand-in, for the
 * claims a fixture cannot make: that {@code /authorize} really is a two-verb endpoint (so the D8 405 divergence
 * is about the real thing); that a 400 HTML page and a 302 the handler <em>returns</em> -- rather than ones the
 * framework builds from a thrown exception -- survive the filter just as well, the render fault being the case
 * that takes that path; and that D7's {@code invalid_request} page still reaches the browser as markup now that
 * the policy lives on the base rather than in this handler's method bodies.
 *
 * <h2>Name trap</h2>
 * {@code *IT.java} is bound to failsafe: {@code mvn -pl openam-oauth2 test} does <strong>not</strong> run this
 * class. It needs {@code mvn -pl openam-oauth2 verify}. CI runs {@code verify} on all nine legs.
 */
public class AuthorizeRouteCompositionIT {

    private static final String LOGIN_URI = "https://openam.example/openam/UI/Login?realm=%2F&goto=abc";
    private static final String CLIENT_URI = "https://client.example/cb";
    /** Cyrillic: the templates are ASCII, so only the model can carry non-ASCII into the bytes. */
    private static final String NON_ASCII = "Доступ запрещён";

    private OAuth2Request o2;
    private OAuth2RequestFactory requestFactory;
    private OAuth2ErrorResponseFactory errorResponseFactory;
    private AuthorizationService authorizationService;
    private BrowserEndpoint endpoint;

    /** Stands in for {@code AuthorizeHandler}: two verbs, and every error left to the base mapper. */
    public static class BrowserEndpoint extends AbstractOAuth2HttpBrowserEndpoint {

        OAuth2Exception toThrow;

        @Get
        public Response get() throws OAuth2Exception {
            throw toThrow;
        }

        @Post
        public Response post() throws OAuth2Exception {
            throw toThrow;
        }
    }

    @BeforeMethod
    public void setUp() throws Exception {
        o2 = mock(OAuth2Request.class);
        when(o2.getHttpServletRequest()).thenReturn(mock(HttpServletRequest.class));
        requestFactory = mock(OAuth2RequestFactory.class);
        when(requestFactory.create(any(), any(Request.class))).thenReturn(o2);

        BaseURLProvider provider = mock(BaseURLProvider.class);
        when(provider.getRootURL(org.mockito.ArgumentMatchers.<HttpServletRequest>any()))
                .thenReturn("https://openam.example/openam");
        BaseURLProviderFactory baseURLProviderFactory = mock(BaseURLProviderFactory.class);
        when(baseURLProviderFactory.get(anyString())).thenReturn(provider);
        RealmNormaliser realmNormaliser = mock(RealmNormaliser.class);
        when(realmNormaliser.normalise(anyString())).thenAnswer(call -> call.getArgument(0));

        errorResponseFactory = new OAuth2ErrorResponseFactory(new FreemarkerTemplateRenderer(),
                baseURLProviderFactory, realmNormaliser);
        endpoint = new BrowserEndpoint();
        inject(endpoint, "requestFactory", requestFactory);
        inject(endpoint, "errorResponseFactory", errorResponseFactory);
    }

    /** The filter keys on {@code >= 400}; a 301 must reach the browser with its Location intact. */
    @Test
    public void theLoginRedirectSurvivesTheFilterUntouched() throws Exception {
        Response response = through(new ResourceOwnerAuthenticationRequired(URI.create(LOGIN_URI)), "GET");

        assertThat(response.getStatus().getCode()).isEqualTo(301);
        assertThat(response.getHeaders().getFirst("Location")).isEqualTo(LOGIN_URI);
        assertThat(response.getEntity().getString()).isEmpty();
    }

    @Test
    public void theErrorRedirectSurvivesTheFilterUntouched() throws Exception {
        when(o2.<String>getParameter("redirect_uri")).thenReturn(CLIENT_URI);
        when(o2.<String>getParameter("state")).thenReturn("xyz");

        Response response = through(new InvalidScopeException("Unknown scope", UrlLocation.FRAGMENT), "GET");

        assertThat(response.getStatus().getCode()).isEqualTo(302);
        assertThat(response.getHeaders().getFirst("Location"))
                .startsWith(CLIENT_URI + "#")
                .contains("error=invalid_scope")
                .contains("state=xyz");
    }

    /**
     * The filter would rewrite any {@code >= 400} body it recognises as JSON. The page must come through as
     * markup, or every {@code /authorize} error becomes a blank page for a human.
     */
    @Test
    public void theHtmlErrorPageIsNotRewrittenIntoAJsonBody() throws Exception {
        Response response = through(new RedirectUriMismatchException(), "GET");

        assertThat(response.getStatus().getCode()).isEqualTo(400);
        assertThat(response.getHeaders().getFirst("Content-Type")).isEqualTo("text/html; charset=UTF-8");
        assertThat(response.getEntity().getString())
                .contains("message: \"redirect_uri_mismatch\"")
                .doesNotContain("\"error\":");
    }

    /**
     * Risk #21: the bytes on the wire, not the {@code String} -- an ISO-8859-1 encode is invisible to
     * {@code getString()}.
     *
     * <p>Asserted as a byte subsequence rather than by decoding: {@code new String(wire, ISO_8859_1)} maps
     * every byte into U+0000..U+00FF and so can never contain a Cyrillic character whatever the encoding was,
     * making that form of the "not ISO-8859-1" check vacuous. Searching for the UTF-8 bytes, and for the
     * {@code '?'} an ISO-8859-1 encoder substitutes for them, is what actually distinguishes the two.
     */
    @Test
    public void aNonAsciiErrorPageReachesTheWireAsUtf8() throws Exception {
        Response response = through(new InvalidScopeException(NON_ASCII, UrlLocation.QUERY), "GET");

        assertThat(response.getHeaders().getFirst("Content-Type")).isEqualTo("text/html; charset=UTF-8");
        byte[] wire = readBytes(response);
        assertThat(indexOf(wire, NON_ASCII.getBytes(StandardCharsets.UTF_8)))
                .as("UTF-8 bytes of the non-ASCII description are on the wire").isNotNegative();
        // What an ISO-8859-1 encode would have left behind instead: one '?' per unmappable character.
        assertThat(indexOf(wire, "???".getBytes(StandardCharsets.US_ASCII)))
                .as("no ISO-8859-1 replacement run").isNegative();
    }

    /** @return the index of {@code needle} in {@code haystack}, or -1. */
    private static int indexOf(byte[] haystack, byte[] needle) {
        outer:
        for (int i = 0; i <= haystack.length - needle.length; i++) {
            for (int j = 0; j < needle.length; j++) {
                if (haystack[i + j] != needle[j]) {
                    continue outer;
                }
            }
            return i;
        }
        return -1;
    }

    /**
     * D8: the handler declares no verb check, so an unsupported verb is the framework's 405 -- and the filter
     * rewrites its body code to {@code invalid_request}, where live Restlet's filter said
     * {@code method_not_allowed}. A recorded body divergence at 5d-1, not a status one.
     *
     * <p>⚠ The cache headers on this response are the reason {@link OAuth2NoCacheFilter} exists, and this row
     * is what proves it works. The framework's 405 is not a thrown {@code OAuth2Exception}, so it never reaches
     * {@link AbstractOAuth2HttpBrowserEndpoint#onError} -- the only caller of {@code withErrorHeaders} -- and no
     * endpoint method runs to call {@code noCache} either. Until 2026-07-26 this row asserted the two headers
     * <em>absent</em>, recording the gap for the 5d-1 smoke matrix; live Restlet sent them (5-E2 row 7) because
     * its filter wrapped the resource rather than being invoked by it, so the gap is now closed by a filter that
     * does the same, and the assertion is inverted. The same fix covers the framework's 404 and its 500 for a
     * non-{@code OAuth2Exception} throw, none of which enter a handler either.
     */
    @Test
    public void anUnsupportedVerbIsTheFrameworks405RewrittenToInvalidRequest() throws Exception {
        Response response = through(new RedirectUriMismatchException(), "PUT");

        assertThat(response.getStatus().getCode()).isEqualTo(405);
        assertThat(bodyOf(response)).containsEntry("error", "invalid_request");
        assertThat(response.getHeaders().getFirst("Cache-Control")).isEqualTo("no-store");
        assertThat(response.getHeaders().getFirst("Pragma")).isEqualTo("no-cache");
    }

    /** The POST verb reaches the same mapper -- the collapse is per-endpoint, not per-verb. */
    @Test
    public void thePostVerbUsesTheSameMapper() throws Exception {
        when(o2.<String>getParameter("redirect_uri")).thenReturn(CLIENT_URI);

        Response response = through(new InvalidScopeException("Unknown scope", UrlLocation.QUERY), "POST");

        assertThat(response.getStatus().getCode()).isEqualTo(302);
        assertThat(response.getHeaders().getFirst("Location")).startsWith(CLIENT_URI + "?");
    }

    // --- the real handler, for the claims a stand-in cannot make ----------------------------------

    /**
     * The rows above prove what the framework and the filter do to a two-verb endpoint. This one proves that
     * {@code /authorize} <em>is</em> that endpoint -- the stand-in's verb set is a fixture, the real handler's
     * is the contract, and a third {@code @}-annotated verb appearing there would silently retire the D8
     * divergence this migration has recorded.
     */
    @Test
    public void theRealHandlerAnswersPutWithTheFrameworks405() throws Exception {
        Response response = throughReal(realHandler(), "PUT");

        assertThat(response.getStatus().getCode()).isEqualTo(405);
        assertThat(bodyOf(response)).containsEntry("error", "invalid_request");
        // On the real endpoint too, not just the stand-in: the stand-in's verb set is a fixture.
        assertThat(response.getHeaders().getFirst("Cache-Control")).isEqualTo("no-store");
        assertThat(response.getHeaders().getFirst("Pragma")).isEqualTo("no-cache");
    }

    /**
     * A 400 HTML page the handler <strong>returns</strong>, rather than one the framework builds from a thrown
     * exception. {@link OAuth2ErrorFilter} sees only a status and a body either way, so if its
     * {@code Content-Type} guard were keyed on how the response was produced rather than on what it contains,
     * this would reach the browser as a blank page.
     *
     * <p>The render fault is the case that takes this path. D7's {@code invalid_request} page used to as well;
     * since D7 moved onto {@link AbstractOAuth2HttpBrowserEndpoint#onIllegalArgument} it is produced by the
     * framework's exception route instead, and is covered by the row below.
     */
    @Test
    public void aReturnedErrorPageIsNotRewrittenIntoAJsonBody() throws Exception {
        AuthorizeHandler authorizeHandler = realHandler();
        when(authorizationService.authorize(o2)).thenThrow(new ResourceOwnerConsentRequired("c", "d",
                Map.of("profile", "View your profile"), Map.of(), new UserInfoClaims(Map.of(), Map.of()),
                "demo", true));
        inject(authorizeHandler, "consentPageRenderer", failingConsentRenderer());

        Response response = throughReal(authorizeHandler, "GET");

        assertThat(response.getStatus().getCode()).isEqualTo(400);
        assertThat(response.getHeaders().getFirst("Content-Type")).isEqualTo("text/html; charset=UTF-8");
        assertThat(response.getEntity().getString())
                .contains("message: \"server_error\"")
                .doesNotContain("\"error\":");
        assertThat(response.getHeaders().getFirst("Cache-Control")).isEqualTo("no-store");
    }

    /**
     * D7 through the whole stack: an {@code IllegalArgumentException} the endpoint method throws is mapped by
     * the base's second {@code @ExceptionHandler} and must survive the filter as markup. This is the row that
     * would have caught the policy going missing when it moved off the handler.
     */
    @Test
    public void theIllegalArgumentPageSurvivesTheFilterAsMarkup() throws Exception {
        AuthorizeHandler authorizeHandler = realHandler();
        when(o2.<String>getParameter("redirect_uri")).thenReturn(CLIENT_URI);
        when(authorizationService.authorize(o2)).thenThrow(new IllegalArgumentException("Missing parameter scope"));

        Response response = throughReal(authorizeHandler, "GET");

        assertThat(response.getStatus().getCode()).isEqualTo(400);
        assertThat(response.getHeaders().getFirst("Location")).isNull();
        assertThat(response.getHeaders().getFirst("Content-Type")).isEqualTo("text/html; charset=UTF-8");
        assertThat(response.getEntity().getString())
                .contains("message: \"invalid_request\"")
                .doesNotContain("\"error\":");
        assertThat(response.getHeaders().getFirst("Cache-Control")).isEqualTo("no-store");
    }

    private static ConsentPageRenderer failingConsentRenderer() throws Exception {
        ConsentPageRenderer renderer = mock(ConsentPageRenderer.class);
        when(renderer.render(any(), any(), any())).thenThrow(new IOException("template missing"));
        return renderer;
    }

    /** A 3xx the handler returns, rather than one an {@code @ExceptionHandler} built, also passes untouched. */
    @Test
    public void theSuccessRedirectSurvivesTheFilterUntouched() throws Exception {
        AuthorizeHandler authorizeHandler = realHandler();
        when(authorizationService.authorize(o2))
                .thenReturn(new AuthorizationToken(Map.of("code", "abc"), false));

        Response response = throughReal(authorizeHandler, "GET");

        assertThat(response.getStatus().getCode()).isEqualTo(302);
        assertThat(response.getHeaders().getFirst("Location")).isEqualTo(CLIENT_URI + "?code=abc");
        assertThat(response.getEntity().getString()).isEmpty();
    }

    private AuthorizeHandler realHandler() throws Exception {
        authorizationService = mock(AuthorizationService.class);
        RedirectUriResolver redirectUriResolver = mock(RedirectUriResolver.class);
        when(redirectUriResolver.resolve(o2)).thenReturn(CLIENT_URI);

        AuthorizeHandler authorizeHandler = new AuthorizeHandler();
        inject(authorizeHandler, "requestFactory", requestFactory);
        inject(authorizeHandler, "errorResponseFactory", errorResponseFactory);
        inject(authorizeHandler, "authorizationService", authorizationService);
        inject(authorizeHandler, "redirectUriResolver", redirectUriResolver);
        inject(authorizeHandler, "consentPageRenderer", mock(ConsentPageRenderer.class));
        inject(authorizeHandler, "templateRenderer", new FreemarkerTemplateRenderer());
        inject(authorizeHandler, "hooks", Set.<ChfAuthorizeRequestHook>of());
        return authorizeHandler;
    }

    private static Response throughReal(AuthorizeHandler authorizeHandler, String method) throws Exception {
        return Handlers.chainOf(Endpoints.from(authorizeHandler), new OAuth2NoCacheFilter(), new OAuth2ErrorFilter())
                .handle(new RootContext(), new Request().setMethod(method).setUri("/oauth2/authorize"))
                .getOrThrowUninterruptibly();
    }

    // --- helpers ----------------------------------------------------------------------------------

    private Response through(OAuth2Exception e, String method) throws Exception {
        endpoint.toThrow = e;
        Handler handler = Handlers.chainOf(Endpoints.from(endpoint), new OAuth2NoCacheFilter(),
                new OAuth2ErrorFilter());
        return handler.handle(new RootContext(),
                        new Request().setMethod(method).setUri("/oauth2/authorize"))
                .getOrThrowUninterruptibly();
    }

    private static byte[] readBytes(Response response) throws IOException {
        return response.getEntity().getBytes();
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
