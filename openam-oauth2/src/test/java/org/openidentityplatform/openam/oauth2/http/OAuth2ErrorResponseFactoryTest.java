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
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.assertj.core.api.Assertions.entry;
import static org.forgerock.openam.oauth2.OAuth2Constants.UrlLocation.FRAGMENT;
import static org.forgerock.openam.oauth2.OAuth2Constants.UrlLocation.QUERY;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.net.URI;
import java.util.Map;

import jakarta.servlet.http.HttpServletRequest;

import org.forgerock.http.protocol.Response;
import org.forgerock.http.protocol.Status;
import org.forgerock.json.resource.NotFoundException;
import org.forgerock.oauth2.core.OAuth2Request;
import org.forgerock.oauth2.core.exceptions.InvalidRequestException;
import org.forgerock.oauth2.core.exceptions.ResourceOwnerAuthenticationRequired;
import org.forgerock.oauth2.core.exceptions.ServerException;
import org.forgerock.openam.services.baseurl.BaseURLProvider;
import org.forgerock.openam.services.baseurl.BaseURLProviderFactory;
import org.forgerock.openam.utils.RealmNormaliser;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

/**
 * Unit coverage for the three-branch error dispatcher.
 * <p>
 * The renderer is the real one, so the HTML branch is exercised against the shipping
 * {@code templates/page/error.ftl} rather than a stub -- which is what makes the D9 null-realm row mean
 * anything, since the defect it fixes is that the template dereferences {@code ${realm}} with no default
 * and FreeMarker treats a Java {@code null} as missing.
 */
public class OAuth2ErrorResponseFactoryTest {

    private static final String LOGIN_URI = "https://openam.example/openam/UI/Login?goto=abc";
    private static final String BASE_URL = "https://openam.example/openam";

    private OAuth2ErrorResponseFactory factory;
    private OAuth2Request request;

    @BeforeMethod
    public void setUp() throws Exception {
        BaseURLProvider provider = mock(BaseURLProvider.class);
        when(provider.getRootURL(org.mockito.ArgumentMatchers.<HttpServletRequest>any())).thenReturn(BASE_URL);
        BaseURLProviderFactory baseURLProviderFactory = mock(BaseURLProviderFactory.class);
        when(baseURLProviderFactory.get(anyString())).thenReturn(provider);
        factory = new OAuth2ErrorResponseFactory(new FreemarkerTemplateRenderer(), baseURLProviderFactory,
                identityNormaliser());

        request = mock(OAuth2Request.class);
        when(request.<String>getParameter("realm")).thenReturn("/subrealm");
        when(request.getHttpServletRequest()).thenReturn(mock(HttpServletRequest.class));
    }

    /** Stands in for a deployment where every realm asked for exists. */
    private static RealmNormaliser identityNormaliser() throws Exception {
        RealmNormaliser realmNormaliser = mock(RealmNormaliser.class);
        when(realmNormaliser.normalise(anyString())).thenAnswer(call -> call.getArgument(0));
        return realmNormaliser;
    }

    // --------------------------------------------------- branch 1: the 301 login redirect

    @Test
    public void anAuthenticationRequiredErrorIsA301ToTheLoginPage() {
        OAuth2Error error = OAuth2Error.of(new ResourceOwnerAuthenticationRequired(URI.create(LOGIN_URI)))
                .withState("xyz");

        Response response = factory.toResponse(request, error);

        // 301, not the exception's own 307 -- Restlet's MODE_CLIENT_PERMANENT is what the wire has always
        // seen. And asMap() is not applied: no error parameters and no state on a cacheable redirect.
        assertThat(response.getStatus().getCode()).isEqualTo(301);
        assertThat(response.getHeaders().getFirst("Location")).isEqualTo(LOGIN_URI);
    }

    /**
     * D13. The carrier pins the login URI, so even an error that also names a client redirect target -- the
     * shape a generic "opt everything into redirecting" mapper produces -- lands on the login page.
     */
    @Test
    public void theLoginRedirectIsNotRetargetedByAClientRedirectUri() {
        OAuth2Error error = OAuth2Error.of(new ResourceOwnerAuthenticationRequired(URI.create(LOGIN_URI)))
                .redirectingTo("https://evil.example/steal", QUERY);

        Response response = factory.toResponse(request, error);

        assertThat(response.getStatus().getCode()).isEqualTo(301);
        assertThat(response.getHeaders().getFirst("Location")).isEqualTo(LOGIN_URI);
    }

    // ------------------------------------------------------ branch 2: the 302 error redirect

    @Test
    public void anErrorWithARedirectUriIsA302CarryingTheErrorInTheQuery() {
        OAuth2Error error = OAuth2Error.of(400, "invalid_scope", "unknown scope")
                .withState("xyz")
                .redirectingTo("https://app.example/cb?a=1", QUERY);

        Response response = factory.toResponse(request, error);

        // 302, never the error's own status: ExceptionHandler:119 wrote the status and the Redirector then
        // overwrote it, so that write was always dead. Not reproduced.
        assertThat(response.getStatus().getCode()).isEqualTo(302);
        assertThat(response.getHeaders().getFirst("Location"))
                .isEqualTo("https://app.example/cb?a=1&error=invalid_scope"
                        + "&error_description=unknown%20scope&state=xyz");
        assertThat(response.getEntity().isDecodedContentEmpty()).isTrue();
    }

    @Test
    public void aFragmentLocatedErrorIsA302CarryingTheErrorInTheFragment() {
        OAuth2Error error = OAuth2Error.of(400, "invalid_scope", null)
                .redirectingTo("https://app.example/cb#stale", FRAGMENT);

        Response response = factory.toResponse(request, error);

        assertThat(response.getStatus().getCode()).isEqualTo(302);
        assertThat(response.getHeaders().getFirst("Location"))
                .isEqualTo("https://app.example/cb#error=invalid_scope");
    }

    // ---------------------------------------------------------- branch 3: the HTML error page

    @Test
    public void anErrorWithNoRedirectUriRendersTheErrorPage() throws Exception {
        OAuth2Error error = OAuth2Error.of(new InvalidRequestException("missing response_type"));

        Response response = factory.toResponse(request, error);

        assertThat(response.getStatus().getCode()).isEqualTo(400);
        assertThat(response.getHeaders().getFirst("Content-Type")).isEqualTo("text/html; charset=UTF-8");
        assertThat(response.getEntity().getString())
                // ?js_string escapes a leading slash, which is why these are not the raw values.
                .contains("realm : \"\\/subrealm\"")
                .contains("baseUrl: \"" + BASE_URL + "/XUI\"")
                .contains("message: \"invalid_request\"")
                .contains("description: \"missing response_type\"");
    }

    @Test
    public void theErrorPageOmitsUnsetOptionalFields() throws Exception {
        String html = factory.toHtmlErrorResponse(Status.BAD_REQUEST,
                OAuth2Error.of(400, "invalid_request", null), "/", BASE_URL).getEntity().getString();

        assertThat(html).contains("message: \"invalid_request\"").doesNotContain("description:").doesNotContain("uri:");
    }

    /**
     * D9. {@code page/error.ftl} dereferences {@code ${realm?js_string}} with no {@code !} default, and
     * FreeMarker treats a Java {@code null} as missing -- so a request without a realm parameter rendered a
     * FreeMarker error rather than an error page.
     */
    @Test
    public void aNullRealmDefaultsToRoot() throws Exception {
        when(request.<String>getParameter("realm")).thenReturn(null);

        Response response = factory.toResponse(request, OAuth2Error.of(400, "invalid_request", "bad"));

        assertThat(response.getStatus().getCode()).isEqualTo(400);
        assertThat(response.getEntity().getString()).contains("realm : \"\\/\"");
    }

    /**
     * Finding 8: the {@code HttpContext} overload of {@code getRootURL} is unreachable from an
     * {@code Endpoints.from} route, so the servlet-request overload is the only one usable -- and Grizzly
     * and unit contexts have no servlet request at all.
     */
    @Test
    public void aMissingServletRequestStillRendersAPage() throws Exception {
        when(request.getHttpServletRequest()).thenReturn(null);

        Response response = factory.toResponse(request, OAuth2Error.of(400, "invalid_request", "bad"));

        assertThat(response.getStatus().getCode()).isEqualTo(400);
        assertThat(response.getEntity().getString()).contains("message: \"invalid_request\"");
    }

    // ------------------------------------------------------------------------ the JSON entry

    @Test
    @SuppressWarnings("unchecked")
    public void toJsonResponseCarriesTheErrorMapAtTheErrorsStatus() throws Exception {
        OAuth2Error error = OAuth2Error.of(400, "invalid_grant", "expired").withState("xyz");

        Response response = factory.toJsonResponse(error);

        assertThat(response.getStatus().getCode()).isEqualTo(400);
        assertThat(response.getHeaders().getFirst("Content-Type")).isEqualTo("application/json; charset=UTF-8");
        assertThat((Map<String, Object>) response.getEntity().getJson()).containsExactly(
                entry("error", "invalid_grant"),
                entry("error_description", "expired"),
                entry("state", "xyz"));
    }

    // -------------------------------------------------------------- D14: WWW-Authenticate

    @Test
    public void aChallengeBearingErrorEmitsWwwAuthenticateOnTheJsonBranch() {
        OAuth2Error error = OAuth2Error.of(401, "invalid_client", "bad secret")
                .withChallenge("Basic", "/subrealm");

        assertThat(factory.toJsonResponse(error).getHeaders().getFirst("WWW-Authenticate"))
                .isEqualTo("Basic realm=\"/subrealm\"");
    }

    /**
     * The header is applied once, after the branch is chosen, rather than per branch: today's producers set
     * the challenge on the response before any error shape is picked, so a header that depends on which
     * branch ran is how it goes missing when Phase 5a ports a different endpoint.
     */
    @Test
    public void theChallengeSurvivesEveryBranchOfToResponse() {
        OAuth2Error base = OAuth2Error.of(401, "invalid_client", "bad secret")
                .withChallenge("Basic", "/subrealm");

        assertThat(factory.toResponse(request, base).getHeaders().getFirst("WWW-Authenticate"))
                .isEqualTo("Basic realm=\"/subrealm\"");
        assertThat(factory.toResponse(request, base.redirectingTo("https://app.example/cb", QUERY))
                .getHeaders().getFirst("WWW-Authenticate")).isEqualTo("Basic realm=\"/subrealm\"");
        OAuth2Error loginRedirect = OAuth2Error.of(new ResourceOwnerAuthenticationRequired(URI.create(LOGIN_URI)))
                .withChallenge("Basic", "/subrealm");
        assertThat(factory.toResponse(request, loginRedirect).getHeaders().getFirst("WWW-Authenticate"))
                .isEqualTo("Basic realm=\"/subrealm\"");
    }

    /**
     * The challenge realm reaches here from {@code getRealm(request)}, which reads the {@code realm} request
     * parameter and falls back to the un-normalised value when normalisation fails -- so it is
     * client-controlled, and interpolating it raw would let a quote break out of the quoted-string.
     */
    @Test
    public void aRealmContainingQuotesOrControlCharactersCannotBreakTheHeader() {
        OAuth2Error injected = OAuth2Error.of(401, "invalid_client", "bad secret")
                .withChallenge("Basic", "evil\", error=\"x");

        assertThat(factory.toJsonResponse(injected).getHeaders().getFirst("WWW-Authenticate"))
                .isEqualTo("Basic realm=\"evil\\\", error=\\\"x\"");

        OAuth2Error withControls = OAuth2Error.of(401, "invalid_client", "bad secret")
                .withChallenge("Basic", "a\r\nSet-Cookie: b=c");

        assertThat(factory.toJsonResponse(withControls).getHeaders().getFirst("WWW-Authenticate"))
                .isEqualTo("Basic realm=\"aSet-Cookie: b=c\"");
    }

    /**
     * A header value is octets and CHF applies no encoding, so a realm above {@code 0x7F} would reach the
     * container as each character truncated to its low byte -- or be rejected, turning the handled 401 into
     * a container 500. RFC 7235 gives the realm no encoding mechanism, so the characters are dropped.
     */
    @Test
    public void aNonAsciiRealmIsReducedToWhatAHeaderCanCarry() {
        OAuth2Error error = OAuth2Error.of(401, "invalid_client", "bad secret")
                .withChallenge("Basic", "/тест-realm");

        assertThat(factory.toJsonResponse(error).getHeaders().getFirst("WWW-Authenticate"))
                .isEqualTo("Basic realm=\"/-realm\"");
    }

    // ------------------------------------------------------------ degenerate errors

    /**
     * CHF's {@code Headers.put(name, null)} *removes* the header, so dispatching on the 307 status alone
     * would have produced a 301 with no {@code Location} at all -- silently, and with nothing logged.
     * <p>
     * The page renders, but <strong>not at 307</strong>: a redirect status with nothing to point at is a
     * shape no specification defines, and the HTML branch has no more of a target than the JSON one does.
     * Both entry points reduce it to a 500 through {@code deliverableStatusOf}; that they once disagreed
     * about the same degenerate error is how the broken shape survived on this branch.
     */
    @Test
    public void aStatus307WithNoTargetRendersTheErrorPageAtA500() throws Exception {
        Response response = factory.toResponse(request,
                OAuth2Error.of(307, "redirection_temporary", "no target"));

        assertThat(response.getStatus().getCode()).isEqualTo(500);
        assertThat(response.getHeaders().getFirst("Location")).isNull();
        assertThat(response.getEntity().getString()).contains("message: \"redirection_temporary\"");
    }

    /**
     * The branch is chosen by where the target came from, not by the status. An error that merely
     * <em>has</em> status 307 and a client {@code redirect_uri} must be a 302 carrying the error, never a
     * cacheable 301 to that URI with the parameters silently dropped.
     */
    @Test
    public void aClientTargetAtStatus307IsStillAnErrorRedirect() {
        OAuth2Error error = OAuth2Error.of(307, "redirection_temporary", "nope")
                .withState("xyz")
                .redirectingTo("https://app.example/cb", QUERY);

        Response response = factory.toResponse(request, error);

        assertThat(response.getStatus().getCode()).isEqualTo(302);
        assertThat(response.getHeaders().getFirst("Location"))
                .isEqualTo("https://app.example/cb?error=redirection_temporary"
                        + "&error_description=nope&state=xyz");
    }

    /**
     * The JSON entry point has no page to fall back to, so a redirect status it cannot honour is a fault,
     * not a response. Emitting the bare 3xx would hand the client a redirect with nowhere to go.
     */
    @Test
    @SuppressWarnings("unchecked")
    public void aRedirectStatusWithNoTargetIsReportedAsA500OnTheJsonBranch() throws Exception {
        Response response = factory.toJsonResponse(OAuth2Error.of(307, "redirection_temporary", "no target"));

        assertThat(response.getStatus().getCode()).isEqualTo(500);
        assertThat(response.getHeaders().getFirst("Location")).isNull();
        assertThat((Map<String, Object>) response.getEntity().getJson())
                .containsEntry("error", "redirection_temporary");
    }

    /**
     * With a target it is honoured: a JSON client still has to be told where the redirect points. A pinned
     * target is the login page, so it goes out bare -- {@code asMap()} is no more applied here than on the
     * 301 branch.
     */
    @Test
    public void aRedirectStatusWithATargetCarriesLocationOnTheJsonBranch() {
        Response response = factory.toJsonResponse(
                OAuth2Error.of(new ResourceOwnerAuthenticationRequired(URI.create(LOGIN_URI))));

        assertThat(response.getStatus().getCode()).isEqualTo(307);
        assertThat(response.getHeaders().getFirst("Location")).isEqualTo(LOGIN_URI);
    }

    /**
     * A client-supplied target is composed, exactly as {@link OAuth2ErrorResponseFactory#toResponse} would
     * compose it. Sending the bare callback would be worse than sending nothing: the client follows a URL
     * carrying neither {@code error} nor {@code state} and cannot tell the request failed, while the CSRF
     * token it is holding never comes back.
     */
    @Test
    public void aClientTargetIsComposedIntoTheLocationOnTheJsonBranch() {
        OAuth2Error error = OAuth2Error.of(302, "access_denied", "nope")
                .withState("xyz")
                .redirectingTo("https://app.example/cb?a=1", QUERY);

        Response response = factory.toJsonResponse(error);

        assertThat(response.getStatus().getCode()).isEqualTo(302);
        assertThat(response.getHeaders().getFirst("Location"))
                .isEqualTo("https://app.example/cb?a=1&error=access_denied"
                        + "&error_description=nope&state=xyz");
    }

    /** A target is not a redirect. Only the status decides whether this response promises a {@code Location}. */
    @Test
    public void aNonRedirectStatusCarriesNoLocationEvenWithATarget() {
        OAuth2Error error = OAuth2Error.of(400, "invalid_scope", "nope")
                .redirectingTo("https://app.example/cb", QUERY);

        assertThat(factory.toJsonResponse(error).getHeaders().getFirst("Location")).isNull();
    }

    /**
     * BaseURLProviderFactory caches a provider under every realm DN it is asked for and never evicts, so
     * the raw parameter must not reach it -- an unauthenticated {@code ?realm=<random>} would otherwise
     * grow that map without bound. The page's own realm stays what the client sent.
     */
    @Test
    public void onlyANormalisedRealmReachesTheBaseUrlLookup() throws Exception {
        BaseURLProvider provider = mock(BaseURLProvider.class);
        when(provider.getRootURL(org.mockito.ArgumentMatchers.<HttpServletRequest>any())).thenReturn(BASE_URL);
        BaseURLProviderFactory baseUrls = mock(BaseURLProviderFactory.class);
        when(baseUrls.get(anyString())).thenReturn(provider);
        RealmNormaliser rejecting = mock(RealmNormaliser.class);
        when(rejecting.normalise(anyString())).thenThrow(new NotFoundException("no such realm"));
        when(request.<String>getParameter("realm")).thenReturn("/does-not-exist");

        Response response = new OAuth2ErrorResponseFactory(new FreemarkerTemplateRenderer(), baseUrls,
                rejecting).toResponse(request, OAuth2Error.of(400, "invalid_request", "bad"));

        verify(baseUrls).get("/");
        assertThat(response.getEntity().getString()).contains("realm : \"\\/does-not-exist\"");
    }

    @Test
    public void theRedirectEntryPointsRejectAMissingTarget() {
        OAuth2Error targetless = OAuth2Error.of(400, "invalid_scope", "no");

        assertThatThrownBy(() -> factory.toLoginRedirectResponse(targetless))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> factory.toRedirectResponse(targetless))
                .isInstanceOf(IllegalArgumentException.class);
    }

    /** {@code UmaException} takes a caller-supplied status, so not every code reaching here is a literal. */
    @Test
    public void anOutOfRangeStatusIsReportedAsA500RatherThanThrowing() {
        assertThat(factory.toJsonResponse(OAuth2Error.of(0, "server_error", "bad code"))
                .getStatus().getCode()).isEqualTo(500);
    }

    /**
     * The render fallback has to cover the data model too: {@code realm} is unnormalised client input and is
     * handed straight to {@code BaseURLProviderFactory.get}.
     */
    @Test
    @SuppressWarnings("unchecked")
    public void aFailureResolvingTheBaseUrlFallsBackToJsonRatherThanEscaping() throws Exception {
        BaseURLProviderFactory exploding = mock(BaseURLProviderFactory.class);
        when(exploding.get(anyString())).thenThrow(new IllegalStateException("no such realm"));
        OAuth2ErrorResponseFactory factoryWithBadBaseUrl = new OAuth2ErrorResponseFactory(
                new FreemarkerTemplateRenderer(), exploding, identityNormaliser());

        Response response = factoryWithBadBaseUrl.toResponse(request,
                OAuth2Error.of(400, "invalid_request", "bad"));

        assertThat(response.getStatus().getCode()).isEqualTo(400);
        assertThat((Map<String, Object>) response.getEntity().getJson())
                .containsEntry("error", "invalid_request");
    }

    // ------------------------------------------------------------ D8: the mask on every wire branch

    /**
     * The HTML branch builds its data model from {@code asMap()}, so the mask reaches the page too. Measured
     * post-flip, this page carried the FreeMarker fault verbatim -- template name, loader class and base
     * package -- to an unauthenticated browser.
     */
    @Test
    public void theErrorPageCarriesTheMaskRatherThanTheThrowablesMessage() throws Exception {
        OAuth2Error error = OAuth2Error.of(new ServerException(new java.io.IOException(
                "Template not found for name \"templates/popup/checkSession.ftl\".")));

        String html = factory.toResponse(request, error).getEntity().getString();

        assertThat(html).doesNotContain("checkSession.ftl").doesNotContain("Template not found")
                .contains("description: \"" + OAuth2Error.RESTLET_INTERNAL_ERROR + "\"");
    }

    /**
     * And the redirect branch, which is the worse leak of the two: the exception text would travel to the
     * client's callback URL, into its access log and its {@code Referer}.
     */
    @Test
    public void theErrorRedirectCarriesTheMaskRatherThanTheThrowablesMessage() {
        OAuth2Error error = OAuth2Error.of(new ServerException(new NullPointerException(
                        "Cannot invoke \"ClientRegistration.getClientSessionURI()\" because it is null")))
                .withState("xyz")
                .redirectingTo("https://app.example/cb", QUERY);

        String location = factory.toResponse(request, error).getHeaders().getFirst("Location");

        assertThat(location).doesNotContain("ClientRegistration").doesNotContain("Cannot%20invoke")
                .isEqualTo("https://app.example/cb?error=server_error&error_description=Internal%20Server"
                        + "%20Error%20(500)%20-%20The%20server%20encountered%20an%20unexpected%20condition"
                        + "%20which%20prevented%20it%20from%20fulfilling%20the%20request&state=xyz");
    }

    @Test
    public void anErrorWithoutAChallengeEmitsNoWwwAuthenticateHeader() {
        OAuth2Error error = OAuth2Error.of(400, "invalid_request", "bad");

        assertThat(factory.toJsonResponse(error).getHeaders().getFirst("WWW-Authenticate")).isNull();
        assertThat(factory.toResponse(request, error).getHeaders().getFirst("WWW-Authenticate")).isNull();
    }
}
