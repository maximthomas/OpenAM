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

import java.lang.reflect.Field;
import java.net.URI;

import jakarta.servlet.http.HttpServletRequest;

import org.forgerock.http.protocol.Request;
import org.forgerock.http.protocol.Response;
import org.forgerock.oauth2.core.OAuth2Request;
import org.forgerock.oauth2.core.OAuth2RequestFactory;
import org.forgerock.oauth2.core.exceptions.ClientAuthenticationFailureFactory;
import org.forgerock.oauth2.core.exceptions.CsrfException;
import org.forgerock.oauth2.core.exceptions.DuplicateRequestParameterException;
import org.forgerock.oauth2.core.exceptions.InvalidScopeException;
import org.forgerock.oauth2.core.exceptions.OAuth2Exception;
import org.forgerock.oauth2.core.exceptions.OAuth2ProviderNotFoundException;
import org.forgerock.oauth2.core.exceptions.RedirectUriMismatchException;
import org.forgerock.oauth2.core.exceptions.ResourceOwnerAuthenticationRequired;
import org.forgerock.openam.http.annotations.Endpoints;
import org.forgerock.openam.http.annotations.Get;
import org.forgerock.openam.oauth2.OAuth2Constants.UrlLocation;
import org.forgerock.openam.services.baseurl.BaseURLProvider;
import org.forgerock.openam.services.baseurl.BaseURLProviderFactory;
import org.forgerock.openam.utils.RealmNormaliser;
import org.forgerock.services.context.RootContext;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

/**
 * Unit suite for the browser {@code @ExceptionHandler}, driven through the real {@code Endpoints.from} so the
 * base mapper genuinely runs -- the same scaffolding the JSON endpoints use, one level deeper.
 *
 * <p>The renderer is the <strong>real</strong> {@link FreemarkerTemplateRenderer}, so the HTML branch is
 * exercised against the shipping {@code templates/page/error.ftl}; a stub would make the page rows assert
 * nothing.
 *
 * <p>Covers the two corrections {@code D2} makes to the umbrella's pseudocode: {@code redirectingTo} takes the
 * parameter location as its second argument (a test that passes with it dropped is not testing this), and the
 * three branches fall out of a single {@code toResponse} call.
 */
public class AbstractOAuth2HttpBrowserEndpointTest {

    private static final String LOGIN_URI = "https://openam.example/openam/UI/Login?realm=%2F&goto=abc";
    private static final String CLIENT_URI = "https://client.example/cb";

    private OAuth2Request o2;
    private TestBrowserEndpoint handler;

    /** A handler whose only job is to throw whatever the row under test needs. */
    public static class TestBrowserEndpoint extends AbstractOAuth2HttpBrowserEndpoint {

        OAuth2Exception toThrow;
        RuntimeException toThrowUnchecked;

        @Get
        public Response get() throws OAuth2Exception {
            if (toThrowUnchecked != null) {
                throw toThrowUnchecked;
            }
            throw toThrow;
        }
    }

    /** {@code /authorize} overrides {@code withErrorHeaders}; this proves the seam still reaches the base. */
    public static class NoCacheBrowserEndpoint extends TestBrowserEndpoint {

        @Override
        protected Response withErrorHeaders(Response response) {
            return noCache(response);
        }
    }

    @BeforeMethod
    public void setUp() throws Exception {
        o2 = mock(OAuth2Request.class);
        when(o2.getHttpServletRequest()).thenReturn(mock(HttpServletRequest.class));
        OAuth2RequestFactory requestFactory = mock(OAuth2RequestFactory.class);
        when(requestFactory.create(any(), any(Request.class))).thenReturn(o2);

        handler = new TestBrowserEndpoint();
        inject(handler, "requestFactory", requestFactory);
        inject(handler, "errorResponseFactory", errorResponseFactory());
    }

    // --- the login redirect (D13: the target is pinned by the exception) -------------------------

    @Test
    public void authenticationRequiredRedirectsToTheLoginPageWith301() throws Exception {
        Response response = handle(new ResourceOwnerAuthenticationRequired(URI.create(LOGIN_URI)));

        assertThat(response.getStatus().getCode()).isEqualTo(301);
        assertThat(response.getHeaders().getFirst("Location")).isEqualTo(LOGIN_URI);
    }

    /**
     * The adversarial row: an attacker-supplied {@code redirect_uri} must not retarget the login redirect.
     * {@code ResourceOwnerAuthenticationRequired} is in {@code NEVER_REDIRECT} <em>and</em> its target is
     * pinned, so both guards would have to fail.
     */
    @Test
    public void authenticationRequiredIgnoresAnAttackersRedirectUri() throws Exception {
        when(o2.<String>getParameter("redirect_uri")).thenReturn("https://evil.example/");

        Response response = handle(new ResourceOwnerAuthenticationRequired(URI.create(LOGIN_URI)));

        assertThat(response.getStatus().getCode()).isEqualTo(301);
        assertThat(response.getHeaders().getFirst("Location")).isEqualTo(LOGIN_URI);
    }

    /** The login redirect carries the user to a login page, not an error -- no error parameters on it. */
    @Test
    public void authenticationRequiredCarriesNoErrorParameters() throws Exception {
        when(o2.<String>getParameter("state")).thenReturn("xyz");

        Response response = handle(new ResourceOwnerAuthenticationRequired(URI.create(LOGIN_URI)));

        assertThat(response.getHeaders().getFirst("Location")).doesNotContain("error").doesNotContain("state=xyz");
    }

    // --- the error redirect, and where its parameters go -----------------------------------------

    @Test
    public void redirectableErrorGoesToTheClientWithParametersInTheQuery() throws Exception {
        when(o2.<String>getParameter("redirect_uri")).thenReturn(CLIENT_URI);
        when(o2.<String>getParameter("state")).thenReturn("xyz");

        Response response = handle(new InvalidScopeException("Unknown scope", UrlLocation.QUERY));

        assertThat(response.getStatus().getCode()).isEqualTo(302);
        String location = response.getHeaders().getFirst("Location");
        assertThat(location).startsWith(CLIENT_URI + "?").doesNotContain("#");
        assertThat(location).contains("error=invalid_scope").contains("state=xyz");
    }

    /**
     * R-5b1.3: the error location comes from the exception's own {@code parameterLocation}. Dropping the
     * second argument of {@code redirectingTo} would send this to the query and break implicit-flow clients.
     */
    @Test
    public void redirectableErrorHonoursTheExceptionsFragmentLocation() throws Exception {
        when(o2.<String>getParameter("redirect_uri")).thenReturn(CLIENT_URI);
        when(o2.<String>getParameter("state")).thenReturn("xyz");

        Response response = handle(new InvalidScopeException("Unknown scope", UrlLocation.FRAGMENT));

        assertThat(response.getStatus().getCode()).isEqualTo(302);
        String location = response.getHeaders().getFirst("Location");
        assertThat(location).startsWith(CLIENT_URI + "#");
        assertThat(location).contains("error=invalid_scope").contains("state=xyz");
    }

    /** No target to redirect to leaves only the page, even for a redirectable type. */
    @Test
    public void redirectableErrorWithoutARedirectUriRendersThePage() throws Exception {
        Response response = handle(new InvalidScopeException("Unknown scope", UrlLocation.QUERY));

        assertThat(response.getStatus().getCode()).isEqualTo(400);
        assertThat(response.getHeaders().getFirst("Location")).isNull();
        assertThat(response.getHeaders().getFirst("Content-Type")).isEqualTo("text/html; charset=UTF-8");
    }

    /** An empty redirect_uri is not a target -- Headers.put(name, null) would emit a Location-less 302. */
    @Test
    public void redirectableErrorWithAnEmptyRedirectUriRendersThePage() throws Exception {
        when(o2.<String>getParameter("redirect_uri")).thenReturn("");

        Response response = handle(new InvalidScopeException("Unknown scope", UrlLocation.QUERY));

        assertThat(response.getStatus().getCode()).isEqualTo(400);
        assertThat(response.getHeaders().getFirst("Location")).isNull();
    }

    // --- the never-redirect types render the page even with a target ------------------------------

    @DataProvider(name = "neverRedirect")
    public Object[][] neverRedirect() {
        return new Object[][] {
                {new RedirectUriMismatchException(), 400, "redirect_uri_mismatch"},
                // 404 not_found, inherited from NotFoundException. On POST this is the D6 behaviour change:
                // Restlet let it fall to the generic catch and redirect to an unvalidated redirect_uri.
                {new OAuth2ProviderNotFoundException("no provider"), 404, "not_found"},
                {new DuplicateRequestParameterException("duplicate"), 400, "invalid_request"},
                {new CsrfException(), 400, "bad_request"},
        };
    }

    @Test(dataProvider = "neverRedirect")
    public void neverRedirectTypesRenderThePageDespiteARedirectUri(OAuth2Exception e, int status, String error)
            throws Exception {
        when(o2.<String>getParameter("redirect_uri")).thenReturn(CLIENT_URI);

        Response response = handle(e);

        assertThat(response.getStatus().getCode()).isEqualTo(status);
        assertThat(response.getHeaders().getFirst("Location")).isNull();
        assertThat(response.getHeaders().getFirst("Content-Type")).isEqualTo("text/html; charset=UTF-8");
        assertThat(response.getEntity().getString()).contains(error);
    }

    /**
     * The challenge is orthogonal to the three branches -- {@code withChallenge} runs <em>after</em> the
     * branch is chosen -- and the branch a 401 {@code invalid_client} lands in is the page, which has no
     * redirect. Without this row nothing sends a challenge-carrying exception through the browser mapper.
     */
    @Test
    public void anAuthHeaderClientFailureRendersThePageAndKeepsItsChallenge() throws Exception {
        when(o2.<String>getParameter("redirect_uri")).thenReturn(CLIENT_URI);
        ClientAuthenticationFailureFactory failures = new ClientAuthenticationFailureFactory() {
            @Override protected boolean hasAuthorizationHeader(OAuth2Request request) {
                return true;
            }
            @Override protected String getRealm(OAuth2Request request) {
                return "/myrealm";
            }
        };

        Response response = handle(failures.getException(o2, "bad secret"));

        assertThat(response.getStatus().getCode()).isEqualTo(401);
        assertThat(response.getHeaders().getFirst("Location")).isNull();
        assertThat(response.getHeaders().getFirst("Content-Type")).isEqualTo("text/html; charset=UTF-8");
        assertThat(response.getHeaders().getFirst("WWW-Authenticate")).contains("realm=\"/myrealm\"");
    }

    // --- D7: the IllegalArgumentException mapper (on the base, so every subclass inherits it) -----

    /**
     * The whole point of D7 living here rather than in each handler's method body: a subclass gets the policy
     * without doing anything, so 5b-2's device-flow handler and every later browser endpoint cannot forget it.
     * Before the move, forgetting meant a framework CREST JSON 500 rendered to a human, with no compile-time
     * or test-time signal.
     */
    @Test
    public void anIllegalArgumentBecomesANonRedirecting400InvalidRequest() throws Exception {
        when(o2.<String>getParameter("redirect_uri")).thenReturn(CLIENT_URI);
        when(o2.<String>getParameter("state")).thenReturn("xyz");

        Response response = handleUnchecked(new IllegalArgumentException("Missing parameter scope"));

        assertThat(response.getStatus().getCode()).isEqualTo(400);
        // The redirect_uri is stubbed precisely so this line can fail: InvalidRequestException, the type this
        // would naturally be converted to, is NOT in NEVER_REDIRECT, so a mapper that routed the IAE through
        // OAuth2Error.of(OAuth2Exception) would emit a 302 to an unvalidated target.
        assertThat(response.getHeaders().getFirst("Location")).isNull();
        assertThat(response.getHeaders().getFirst("Content-Type")).isEqualTo("text/html; charset=UTF-8");
        assertThat(response.getEntity().getString()).contains("invalid_request").contains("Missing parameter scope");
    }

    /** The unknown-{@code ?display=} source: {@code renderForDisplay}'s IAE reaches the same mapper. */
    @Test
    public void theTwoMappersCoexistAndDispatchOnType() throws Exception {
        when(o2.<String>getParameter("redirect_uri")).thenReturn(CLIENT_URI);

        // The same endpoint, one type each: disjoint, so mostSpecificExceptionHandler has no ambiguity.
        assertThat(handleUnchecked(new IllegalArgumentException("No enum constant DisplayType.BOGUS"))
                .getStatus().getCode()).isEqualTo(400);
        assertThat(handle(new InvalidScopeException("Unknown scope", UrlLocation.QUERY))
                .getStatus().getCode()).isEqualTo(302);
    }

    /** An overriding subclass stamps the cache headers on this branch too -- it is one withErrorHeaders call. */
    @Test
    public void theIllegalArgumentPageAlsoGoesThroughWithErrorHeaders() throws Exception {
        handler = new NoCacheBrowserEndpoint();
        OAuth2RequestFactory requestFactory = mock(OAuth2RequestFactory.class);
        when(requestFactory.create(any(), any(Request.class))).thenReturn(o2);
        inject(handler, "requestFactory", requestFactory);
        inject(handler, "errorResponseFactory", errorResponseFactory());

        Response response = handleUnchecked(new IllegalArgumentException("boom"));

        assertThat(response.getHeaders().getFirst("Cache-Control")).isEqualTo("no-store");
        assertThat(response.getHeaders().getFirst("Pragma")).isEqualTo("no-cache");
    }

    // --- the withErrorHeaders seam ---------------------------------------------------------------

    /** The base adds no cache headers of its own: only /access_token and /authorize sent them. */
    @Test
    public void theBaseAddsNoCacheHeaders() throws Exception {
        when(o2.<String>getParameter("redirect_uri")).thenReturn(CLIENT_URI);

        Response response = handle(new InvalidScopeException("Unknown scope", UrlLocation.QUERY));

        assertThat(response.getHeaders().getFirst("Cache-Control")).isNull();
        assertThat(response.getHeaders().getFirst("Pragma")).isNull();
    }

    /** An overriding subclass stamps them -- the seam /authorize uses. */
    @Test
    public void anOverridingSubclassStampsCacheHeaders() throws Exception {
        handler = new NoCacheBrowserEndpoint();
        OAuth2RequestFactory requestFactory = mock(OAuth2RequestFactory.class);
        when(requestFactory.create(any(), any(Request.class))).thenReturn(o2);
        inject(handler, "requestFactory", requestFactory);
        inject(handler, "errorResponseFactory", errorResponseFactory());

        Response response = handle(new ResourceOwnerAuthenticationRequired(URI.create(LOGIN_URI)));

        assertThat(response.getHeaders().getFirst("Cache-Control")).isEqualTo("no-store");
        assertThat(response.getHeaders().getFirst("Pragma")).isEqualTo("no-cache");
    }

    // --- helpers ----------------------------------------------------------------------------------

    /** The unchecked twin of {@link #handle}: the test endpoint throws whatever it is given. */
    private Response handleUnchecked(RuntimeException e) throws Exception {
        handler.toThrowUnchecked = e;
        try {
            return Endpoints.from(handler)
                    .handle(new RootContext(), new Request().setMethod("GET").setUri("/oauth2/authorize"))
                    .getOrThrowUninterruptibly();
        } finally {
            handler.toThrowUnchecked = null;
        }
    }

    private Response handle(OAuth2Exception e) throws Exception {
        handler.toThrow = e;
        return Endpoints.from(handler)
                .handle(new RootContext(), new Request().setMethod("GET").setUri("/oauth2/authorize"))
                .getOrThrowUninterruptibly();
    }

    private static OAuth2ErrorResponseFactory errorResponseFactory() throws Exception {
        BaseURLProvider provider = mock(BaseURLProvider.class);
        when(provider.getRootURL(org.mockito.ArgumentMatchers.<HttpServletRequest>any()))
                .thenReturn("https://openam.example/openam");
        BaseURLProviderFactory baseURLProviderFactory = mock(BaseURLProviderFactory.class);
        when(baseURLProviderFactory.get(anyString())).thenReturn(provider);
        RealmNormaliser realmNormaliser = mock(RealmNormaliser.class);
        when(realmNormaliser.normalise(anyString())).thenAnswer(call -> call.getArgument(0));
        return new OAuth2ErrorResponseFactory(new FreemarkerTemplateRenderer(), baseURLProviderFactory,
                realmNormaliser);
    }

    private static void inject(Object target, String name, Object value) throws Exception {
        for (Class<?> c = target.getClass(); c != null; c = c.getSuperclass()) {
            try {
                Field f = c.getDeclaredField(name);
                f.setAccessible(true);
                f.set(target, value);
                return;
            } catch (NoSuchFieldException keepWalking) {
                // field is declared on a superclass -- now two levels up, not one
            }
        }
        throw new NoSuchFieldException(name);
    }
}
