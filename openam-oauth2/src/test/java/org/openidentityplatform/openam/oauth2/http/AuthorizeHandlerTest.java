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
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.same;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.io.IOException;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.net.URI;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;

import jakarta.servlet.http.HttpServletRequest;

import org.forgerock.http.protocol.Request;
import org.forgerock.http.protocol.Response;
import org.forgerock.http.protocol.Status;
import org.forgerock.oauth2.core.AuthorizationService;
import org.forgerock.oauth2.core.AuthorizationToken;
import org.forgerock.oauth2.core.OAuth2Request;
import org.forgerock.oauth2.core.OAuth2RequestFactory;
import org.forgerock.oauth2.core.RedirectUriResolver;
import org.forgerock.oauth2.core.UserInfoClaims;
import org.forgerock.oauth2.core.exceptions.AccessDeniedException;
import org.forgerock.oauth2.core.exceptions.ClientAuthenticationFailureFactory;
import org.forgerock.oauth2.core.exceptions.CsrfException;
import org.forgerock.oauth2.core.exceptions.DuplicateRequestParameterException;
import org.forgerock.oauth2.core.exceptions.InvalidScopeException;
import org.forgerock.oauth2.core.exceptions.OAuth2Exception;
import org.forgerock.oauth2.core.exceptions.OAuth2ProviderNotFoundException;
import org.forgerock.oauth2.core.exceptions.RedirectUriMismatchException;
import org.forgerock.oauth2.core.exceptions.ResourceOwnerAuthenticationRequired;
import org.forgerock.oauth2.core.exceptions.ResourceOwnerConsentRequired;
import org.forgerock.openam.http.annotations.Endpoints;
import org.forgerock.openam.oauth2.OAuth2Constants.UrlLocation;
import org.forgerock.openam.services.baseurl.BaseURLProvider;
import org.forgerock.openam.services.baseurl.BaseURLProviderFactory;
import org.forgerock.openam.utils.RealmNormaliser;
import org.forgerock.services.context.RootContext;
import org.mockito.InOrder;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

/**
 * Unit suite for {@link AuthorizeHandler}, driven through the real {@code Endpoints.from} so the framework
 * dispatch and the inherited browser {@code @ExceptionHandler} genuinely run.
 *
 * <h2>What this suite has to prove that the Restlet resource never asserted</h2>
 * {@code AuthorizeResource} spread fourteen catch clauses over two verbs, and the two lists had drifted. The
 * collapse onto one mapper is only safe if every one of those clauses lands on the same {@code (status, error,
 * redirect-or-page)} it does today -- so {@link #collapseTable} carries one row per clause with the values read
 * off the Restlet source, not off this implementation. Exactly two rows are <em>meant</em> to differ, and both
 * are labelled: {@code OAuth2ProviderNotFoundException} on POST (D6) and every
 * {@code IllegalArgumentException} (D7).
 *
 * <h2>The renderers</h2>
 * {@link ConsentPageRenderer} is mocked -- it has its own suite, and what matters here is the interaction and
 * the status. {@link FreemarkerTemplateRenderer} and {@link OAuth2ErrorResponseFactory} are <strong>real</strong>,
 * so the form-post page and the HTML error page are exercised against the shipping templates; stubbing them
 * would leave the two rows that assert page content asserting nothing.
 */
public class AuthorizeHandlerTest {

    private static final String CLIENT_URI = "https://client.example/cb";
    private static final String LOGIN_URI = "https://openam.example/openam/UI/Login?realm=%2F&goto=abc";
    private static final String CODE = "g0ZGZmNjVmOWI";
    private static final String STATE = "af0ifjsldkj";

    private OAuth2Request o2;
    private OAuth2RequestFactory requestFactory;
    private AuthorizationService authorizationService;
    private RedirectUriResolver redirectUriResolver;
    private ConsentPageRenderer consentPageRenderer;
    private ChfAuthorizeRequestHook hook;
    private AuthorizeHandler handler;

    @BeforeMethod
    public void setUp() throws Exception {
        o2 = mock(OAuth2Request.class);
        when(o2.getHttpServletRequest()).thenReturn(mock(HttpServletRequest.class));
        requestFactory = mock(OAuth2RequestFactory.class);
        when(requestFactory.create(any(), any(Request.class))).thenReturn(o2);

        authorizationService = mock(AuthorizationService.class);
        redirectUriResolver = mock(RedirectUriResolver.class);
        when(redirectUriResolver.resolve(o2)).thenReturn(CLIENT_URI);
        consentPageRenderer = mock(ConsentPageRenderer.class);
        hook = mock(ChfAuthorizeRequestHook.class);

        handler = new AuthorizeHandler();
        inject(handler, "requestFactory", requestFactory);
        inject(handler, "errorResponseFactory", errorResponseFactory());
        inject(handler, "authorizationService", authorizationService);
        inject(handler, "redirectUriResolver", redirectUriResolver);
        inject(handler, "consentPageRenderer", consentPageRenderer);
        inject(handler, "templateRenderer", new FreemarkerTemplateRenderer());
        inject(handler, "hooks", Set.of(hook));
    }

    // --- the success tail -------------------------------------------------------------------------

    @Test
    public void successRedirectsWithTheTokenParametersInTheQuery() throws Exception {
        when(authorizationService.authorize(o2)).thenReturn(token(false));

        Response response = get("");

        assertThat(response.getStatus().getCode()).isEqualTo(302);
        assertThat(response.getHeaders().getFirst("Location"))
                .isEqualTo(CLIENT_URI + "?code=" + CODE + "&state=" + STATE);
    }

    /**
     * R-5b1.3/R-5.4: the success location comes from {@code AuthorizationToken.isFragment()}, and a fragment
     * <em>replaces</em> whatever the target already had. Reading the exception's parameter location here
     * instead would break implicit and hybrid flows with nothing to catch it at compile time.
     */
    @Test
    public void successHonoursIsFragmentAndReplacesAnExistingFragment() throws Exception {
        when(redirectUriResolver.resolve(o2)).thenReturn(CLIENT_URI + "#stale");
        when(authorizationService.authorize(o2)).thenReturn(token(true));

        Response response = get("");

        assertThat(response.getHeaders().getFirst("Location"))
                .isEqualTo(CLIENT_URI + "#code=" + CODE + "&state=" + STATE);
    }

    /**
     * Finding 7 pinned as a test rather than as prose: {@code RedirectUris}' documented "empty params leaves
     * the target untouched" divergence is unreachable on the success path, because an
     * {@code AuthorizationToken} always carries at least the code or the access token. A one-entry map is the
     * smallest thing the issuer can produce, and it still composes.
     */
    @Test
    public void aSingleEntryTokenMapStillComposes() throws Exception {
        when(authorizationService.authorize(o2)).thenReturn(
                new AuthorizationToken(Map.of("code", CODE), false));

        Response response = get("");

        assertThat(response.getHeaders().getFirst("Location")).isEqualTo(CLIENT_URI + "?code=" + CODE);
    }

    /** The OAuth2Filter stamped these on every /authorize response; D8 keeps them unconditional. */
    @Test
    public void theSuccessRedirectCarriesTheCacheHeaders() throws Exception {
        when(authorizationService.authorize(o2)).thenReturn(token(false));

        Response response = get("");

        assertThat(response.getHeaders().getFirst("Cache-Control")).isEqualTo("no-store");
        assertThat(response.getHeaders().getFirst("Pragma")).isEqualTo("no-cache");
    }

    /**
     * D9 step 2. {@code OAuth2Representation:164-165} composes the redirect reference <strong>before</strong>
     * branching on {@code response_mode}, so the form posts to the URI with the parameters already on it --
     * duplicating them into both the action URL and the hidden inputs. Reproduced, not cleaned up.
     */
    @Test
    public void formPostRendersThePageWithTheComposedTargetAsItsAction() throws Exception {
        when(o2.<String>getParameter("response_mode")).thenReturn("form_post");
        when(authorizationService.authorize(o2)).thenReturn(token(false));

        Response response = get("");

        assertThat(response.getStatus().getCode()).isEqualTo(200);
        assertThat(response.getHeaders().getFirst("Content-Type")).isEqualTo("text/html; charset=UTF-8");
        String html = response.getEntity().getString();
        // ?html escapes the separator, so the action carries "&amp;" -- exactly what the template emits today.
        assertThat(html).contains("action=\"" + CLIENT_URI + "?code=" + CODE + "&amp;state=" + STATE + "\"");
        assertThat(html).contains("name=\"code\" value=\"" + CODE + "\"");
        assertThat(html).contains("name=\"state\" value=\"" + STATE + "\"");
    }

    @Test
    public void formPostCarriesTheCacheHeadersToo() throws Exception {
        when(o2.<String>getParameter("response_mode")).thenReturn("form_post");
        when(authorizationService.authorize(o2)).thenReturn(token(false));

        Response response = get("");

        assertThat(response.getHeaders().getFirst("Cache-Control")).isEqualTo("no-store");
    }

    // --- the hooks (D4/D6) ------------------------------------------------------------------------

    @Test
    public void hooksRunBeforeTheServiceAndAfterTheRepresentation() throws Exception {
        when(authorizationService.authorize(o2)).thenReturn(token(false));

        get("");

        InOrder ordered = inOrder(hook, authorizationService, redirectUriResolver);
        ordered.verify(hook).beforeAuthorizeHandling(o2);
        ordered.verify(authorizationService).authorize(o2);
        ordered.verify(redirectUriResolver).resolve(o2);
        ordered.verify(hook).afterAuthorizeSuccess(o2);
    }

    /**
     * D4's caller contract: the same {@code OAuth2Request} instance must reach both hooks, because
     * {@code LoginHintHook.afterAuthorizeSuccess} recomputes from the request what its before-hook decided.
     * One {@code create} call per request is also what the 5d filters will share.
     */
    @Test
    public void theRequestIsBuiltOnceAndSharedByBothHooks() throws Exception {
        when(authorizationService.authorize(o2)).thenReturn(token(false));

        get("");

        verify(requestFactory).create(any(), any(Request.class));
        verify(hook).beforeAuthorizeHandling(same(o2));
        verify(hook).afterAuthorizeSuccess(same(o2));
    }

    /** The before-hook is unconditional -- Restlet runs it outside the try; the after-hook is success-only. */
    @Test
    public void onlyTheBeforeHookRunsWhenTheRequestFails() throws Exception {
        when(authorizationService.authorize(o2)).thenThrow(new RedirectUriMismatchException());

        get("");

        verify(hook).beforeAuthorizeHandling(o2);
        verify(hook, never()).afterAuthorizeSuccess(any());
    }

    /** Nor after a consent page: Restlet returns the page from inside the catch, never reaching the hook. */
    @Test
    public void theAfterHookDoesNotRunOnTheConsentPage() throws Exception {
        when(authorizationService.authorize(o2)).thenThrow(consentRequired());
        when(consentPageRenderer.render(any(), any(), any())).thenReturn(consentPage());

        get("");

        verify(hook, never()).afterAuthorizeSuccess(any());
    }

    // --- the consent branch -----------------------------------------------------------------------

    @Test
    public void consentRequiredRendersTheConsentPageAt200() throws Exception {
        when(authorizationService.authorize(o2)).thenThrow(consentRequired());
        when(consentPageRenderer.render(any(), any(), any())).thenReturn(consentPage());

        Response response = get("");

        assertThat(response.getStatus().getCode()).isEqualTo(200);
        assertThat(response.getEntity().getString()).isEqualTo("<html>consent</html>");
        assertThat(response.getHeaders().getFirst("Cache-Control")).isEqualTo("no-store");
        verify(consentPageRenderer).render(any(ResourceOwnerConsentRequired.class), same(o2), any(Request.class));
    }

    /**
     * Finding 3's premise, pinned. {@code ResourceOwnerConsentRequired} is a plain {@code Exception}, so it
     * cannot reach the browser base -- the GET method catches it by hand. The POST method does not, and the
     * only thing making that safe is that the 3-arg {@code authorize} cannot raise it. If that ever changes,
     * the POST path leaks a framework CREST 500 to a browser, and this row is what says so.
     */
    @Test
    public void theThreeArgAuthorizeCannotRaiseConsentRequired() throws Exception {
        Method authorize = AuthorizationService.class.getMethod("authorize", OAuth2Request.class,
                boolean.class, boolean.class);

        assertThat(authorize.getExceptionTypes()).doesNotContain(ResourceOwnerConsentRequired.class);
    }

    /**
     * A missing template is a deployment fault, not a bug path, so it stays a contractual 400 error page
     * rather than becoming the framework's 500. ({@code D3} governs bug paths; the error page can still
     * describe this one.)
     */
    @Test
    public void aFailedConsentRenderBecomesTheServerErrorPage() throws Exception {
        // Same trap as the content-type row: ServerException is redirectable, so wrapping and throwing would
        // send a deployment fault -- template path included -- to the client's callback instead of showing it.
        when(o2.<String>getParameter("redirect_uri")).thenReturn(CLIENT_URI);
        when(authorizationService.authorize(o2)).thenThrow(consentRequired());
        when(consentPageRenderer.render(any(), any(), any())).thenThrow(new IOException("template missing"));

        Response response = get("");

        assertThat(response.getStatus().getCode()).isEqualTo(400);
        assertThat(response.getHeaders().getFirst("Location")).isNull();
        assertThat(response.getHeaders().getFirst("Content-Type")).isEqualTo("text/html; charset=UTF-8");
        assertThat(response.getEntity().getString()).contains("server_error").contains("template missing");
    }

    /** The form-post render is the second fault site, and it must not redirect either -- nor run the hooks. */
    @Test
    public void aFailedFormPostRenderBecomesTheServerErrorPageAndSkipsTheAfterHook() throws Exception {
        when(o2.<String>getParameter("redirect_uri")).thenReturn(CLIENT_URI);
        when(o2.<String>getParameter("response_mode")).thenReturn("form_post");
        when(authorizationService.authorize(o2)).thenReturn(token(false));
        inject(handler, "templateRenderer", new FreemarkerTemplateRenderer(
                new freemarker.cache.StringTemplateLoader()));       // every template is a miss

        Response response = get("");

        assertThat(response.getStatus().getCode()).isEqualTo(400);
        assertThat(response.getHeaders().getFirst("Location")).isNull();
        assertThat(response.getEntity().getString()).contains("server_error");
        verify(hook, never()).afterAuthorizeSuccess(any());
    }

    // --- POST: the consent decision ---------------------------------------------------------------

    @DataProvider(name = "decisions")
    public Object[][] decisions() {
        // Verbatim from AuthorizeResource:170-171 -- equalsIgnoreCase against "allow" and "on", so anything
        // else at all (including a missing parameter) is a refusal rather than a default-allow.
        return new Object[][] {
                {"allow", "on", true, true},
                {"ALLOW", "ON", true, true},
                {"allow", null, true, false},
                {"deny", "on", false, true},
                {null, null, false, false},
                {"", "yes", false, false},
        };
    }

    @Test(dataProvider = "decisions")
    public void postMapsTheDecisionAndSaveConsentParameters(String decision, String save, boolean consentGiven,
            boolean saveConsent) throws Exception {
        when(o2.<String>getParameter("decision")).thenReturn(decision);
        when(o2.<String>getParameter("save_consent")).thenReturn(save);
        when(authorizationService.authorize(o2, consentGiven, saveConsent)).thenReturn(token(false));

        // The body is inert here: both parameters are read through the stubbed OAuth2Request, not parsed
        // from these bytes. It exists only to make the request a form post.
        Response response = post(formRequest("decision=allow&save_consent=on"));

        assertThat(response.getStatus().getCode()).isEqualTo(302);
        verify(authorizationService).authorize(o2, consentGiven, saveConsent);
    }

    /** A refused consent surfaces as the service's own {@code AccessDeniedException}, which may redirect. */
    @Test
    public void aDeniedConsentRedirectsTheServiceError() throws Exception {
        when(o2.<String>getParameter("redirect_uri")).thenReturn(CLIENT_URI);
        when(authorizationService.authorize(any(), anyBoolean(), anyBoolean()))
                .thenThrow(new AccessDeniedException("Resource Owner did not authorize the request"));

        Response response = post(formRequest("decision=deny"));

        assertThat(response.getStatus().getCode()).isEqualTo(302);
        assertThat(response.getHeaders().getFirst("Location"))
                .startsWith(CLIENT_URI + "?").contains("error=access_denied");
    }

    // --- D8: content type and verb ----------------------------------------------------------------

    /**
     * Row 8 of the 5-E2 capture: live Restlet returns 400 invalid_request, so the check is reproduced.
     *
     * <p>⚠ The {@code redirect_uri} stub is the whole point of the row, not scenery. The natural way to write
     * this check -- {@code throw new InvalidRequestException("Invalid Content Type")} -- reaches the browser
     * mapper, and {@code InvalidRequestException} is <em>not</em> in {@code NEVER_REDIRECT}, so the 400 would
     * become a 302 to a {@code redirect_uri} nothing has validated: the request failed before the client was
     * ever resolved. Without this stub the row passes either way.
     *
     * <p>The body is <strong>JSON, not the HTML error page</strong>: the filter wrote a Jackson representation
     * and row 8 recorded {@code application/json} off the live container. And the request is rejected
     * <em>before</em> {@code requestFactory.create}, which is why {@code verifyNoInteractions} holds -- Restlet
     * rejected in {@code beforeHandle}, so the resource, and the client-registration lookup {@code create}
     * performs, never ran.
     */
    @Test
    public void aJsonBodiedPostIsRejected() throws Exception {
        when(o2.<String>getParameter("redirect_uri")).thenReturn(CLIENT_URI);
        Request request = new Request().setMethod("POST").setUri("/oauth2/authorize");
        request.getHeaders().put("Content-Type", "application/json");
        request.setEntity("{\"decision\":\"allow\"}");

        Response response = post(request);

        assertThat(response.getStatus().getCode()).isEqualTo(400);
        assertThat(response.getHeaders().getFirst("Location")).isNull();
        assertThat(response.getHeaders().getFirst("Content-Type")).startsWith("application/json");
        assertThat(response.getEntity().getString()).contains("invalid_request").contains("Invalid Content Type");
        assertThat(response.getHeaders().getFirst("Cache-Control")).isEqualTo("no-store");
        verify(requestFactory, never()).create(any(), any(Request.class));
        verify(authorizationService, never()).authorize(any(), anyBoolean(), anyBoolean());
    }

    /**
     * The row the content-type fix exists for, and the only one where a wrong answer is not a wrong status but
     * a wrong <strong>decision</strong>.
     *
     * <p>A consent POST carrying {@code decision=allow} with no {@code Content-Type} used to be accepted here.
     * It could not work: {@code ChfOAuth2Request.getParameter} reads a POST body only when the type is form, so
     * {@code decision} arrived as {@code null}, {@code consentGiven} became {@code false}, and the service was
     * told the resource owner had <em>refused</em> — the client got {@code access_denied} for an approval the
     * user actually gave, and nothing anywhere reported an error. Restlet answered 400
     * ({@code RestletContentTypeParityTest}), which is what this now asserts.
     */
    @Test
    public void aConsentPostWithNoContentTypeIsRejectedRatherThanReadAsARefusal() throws Exception {
        when(o2.<String>getParameter("redirect_uri")).thenReturn(CLIENT_URI);
        Request request = new Request().setMethod("POST").setUri("/oauth2/authorize");
        request.setEntity("decision=allow&save_consent=on");

        Response response = post(request);

        assertThat(response.getStatus().getCode()).isEqualTo(400);
        assertThat(response.getHeaders().getFirst("Location")).isNull();
        assertThat(response.getHeaders().getFirst("Content-Type")).startsWith("application/json");
        assertThat(response.getEntity().getString()).contains("invalid_request").contains("Invalid Content Type");
        assertThat(response.getHeaders().getFirst("Cache-Control")).isEqualTo("no-store");
        verify(requestFactory, never()).create(any(), any(Request.class));
        // The decisive assertion: the service is never told anything about a decision it cannot have.
        verify(authorizationService, never()).authorize(any(), anyBoolean(), anyBoolean());
    }

    /** The charset-safe parse: a bare string compare against the raw header would reject this. */
    @Test
    public void aFormPostWithACharsetParameterIsAccepted() throws Exception {
        when(authorizationService.authorize(any(), anyBoolean(), anyBoolean())).thenReturn(token(false));
        Request request = new Request().setMethod("POST").setUri("/oauth2/authorize");
        request.getHeaders().put("Content-Type", "application/x-www-form-urlencoded; charset=UTF-8");
        request.setEntity("decision=allow");

        assertThat(post(request).getStatus().getCode()).isEqualTo(302);
    }

    /**
     * {@code OAuth2Filter.beforeHandle:59-62} runs the check on every method, not just the one with a body, so
     * a GET carrying a JSON entity is a 400 today. Checking only the POST would have widened that silently --
     * and no row anywhere else in this suite would have noticed.
     */
    @Test
    public void aJsonBodiedGetIsRejectedToo() throws Exception {
        when(o2.<String>getParameter("redirect_uri")).thenReturn(CLIENT_URI);
        Request request = new Request().setMethod("GET").setUri("/oauth2/authorize");
        request.getHeaders().put("Content-Type", "application/json");
        request.setEntity("{}");

        Response response = dispatch(request);

        assertThat(response.getStatus().getCode()).isEqualTo(400);
        assertThat(response.getHeaders().getFirst("Location")).isNull();
        assertThat(response.getHeaders().getFirst("Content-Type")).startsWith("application/json");
        assertThat(response.getEntity().getString()).contains("invalid_request");
        verify(requestFactory, never()).create(any(), any(Request.class));
        verify(authorizationService, never()).authorize(any());
    }

    /** The filter only ever inspected a non-empty entity, so an empty body is never content-type checked. */
    @Test
    public void anEmptyBodyIsNotContentTypeChecked() throws Exception {
        when(authorizationService.authorize(any(), anyBoolean(), anyBoolean())).thenReturn(token(false));
        Request request = new Request().setMethod("POST").setUri("/oauth2/authorize");
        request.getHeaders().put("Content-Type", "application/json");

        assertThat(post(request).getStatus().getCode()).isEqualTo(302);
    }

    /**
     * D8: no verb check in the handler. Two {@code @}-annotated verbs mean PUT gets the framework's own 405,
     * whose body {@code OAuth2ErrorFilter} rewrites at 5d-1 -- a recorded body divergence from live Restlet's
     * {@code method_not_allowed}, not a status one. The composition IT pins the rewritten body; this row pins
     * that the handler itself never runs.
     */
    @Test
    public void anUnsupportedVerbIsTheFrameworks405() throws Exception {
        Response response = Endpoints.from(handler)
                .handle(new RootContext(), new Request().setMethod("PUT").setUri("/oauth2/authorize"))
                .getOrThrowUninterruptibly();

        assertThat(response.getStatus().getCode()).isEqualTo(405);
        verify(authorizationService, never()).authorize(any());
    }

    // --- the collapse table (finding 3) -----------------------------------------------------------

    /**
     * One row per Restlet catch clause, with the {@code (status, error)} pair read off {@code AuthorizeResource}
     * and the exception's own definition -- never off this implementation. {@code redirects} is where the two
     * differ from today, and both differences are decisions:
     * {@code OAuth2ProviderNotFoundException} redirected on POST (D6) and every IAE redirected on GET (D7).
     * <p>
     * {@code CsrfException} is <strong>not</strong> here: it is POST-only, and not by convention -- the 1-arg
     * {@code authorize} does not declare it, so the GET path cannot raise it at all. See
     * {@link #csrfIsRefusedOnThePostPath()}.
     */
    @DataProvider(name = "collapseTable")
    public Object[][] collapseTable() {
        return new Object[][] {
                {new RedirectUriMismatchException(), 400, "redirect_uri_mismatch", false},
                {new DuplicateRequestParameterException("duplicate scope"), 400, "invalid_request", false},
                // D6: on POST, Restlet let this fall to the generic catch and redirected to a redirect_uri
                // that -- there being no provider -- nothing had validated. Now it renders the page.
                {new OAuth2ProviderNotFoundException("no provider"), 404, "not_found", false},
                {new InvalidScopeException("Unknown scope", UrlLocation.QUERY), 400, "invalid_scope", true},
                {new AccessDeniedException("denied"), 400, "access_denied", true},
        };
    }

    @Test(dataProvider = "collapseTable")
    public void collapsedErrorsKeepTheirOwnStatusAndCodeOnGet(OAuth2Exception e, int status, String error,
            boolean redirects) throws Exception {
        when(o2.<String>getParameter("redirect_uri")).thenReturn(CLIENT_URI);
        when(o2.<String>getParameter("state")).thenReturn(STATE);
        when(authorizationService.authorize(o2)).thenThrow(e);

        assertCollapsed(get(""), status, error, redirects);
    }

    @Test(dataProvider = "collapseTable")
    public void collapsedErrorsKeepTheirOwnStatusAndCodeOnPost(OAuth2Exception e, int status, String error,
            boolean redirects) throws Exception {
        when(o2.<String>getParameter("redirect_uri")).thenReturn(CLIENT_URI);
        when(o2.<String>getParameter("state")).thenReturn(STATE);
        when(authorizationService.authorize(any(), anyBoolean(), anyBoolean())).thenThrow(e);

        assertCollapsed(post(formRequest("decision=allow")), status, error, redirects);
    }

    /** D13: the login redirect's target is the exception's, and an attacker's redirect_uri cannot retarget it. */
    @Test
    public void authenticationRequiredRedirectsToTheLoginPage() throws Exception {
        when(o2.<String>getParameter("redirect_uri")).thenReturn("https://evil.example/");
        when(authorizationService.authorize(o2)).thenThrow(
                new ResourceOwnerAuthenticationRequired(URI.create(LOGIN_URI)));

        Response response = get("");

        assertThat(response.getStatus().getCode()).isEqualTo(301);
        assertThat(response.getHeaders().getFirst("Location")).isEqualTo(LOGIN_URI);
    }

    /** The one exception carrying a challenge still renders the page and keeps it (D14). */
    @Test
    public void anInvalidClientRendersThePageAndKeepsItsChallenge() throws Exception {
        ClientAuthenticationFailureFactory failures = new ClientAuthenticationFailureFactory() {
            @Override protected boolean hasAuthorizationHeader(OAuth2Request request) {
                return true;
            }
            @Override protected String getRealm(OAuth2Request request) {
                return "/";
            }
        };
        when(o2.<String>getParameter("redirect_uri")).thenReturn(CLIENT_URI);
        when(authorizationService.authorize(o2)).thenThrow(failures.getException(o2, "bad client"));

        Response response = get("");

        assertThat(response.getStatus().getCode()).isEqualTo(401);
        assertThat(response.getHeaders().getFirst("Location")).isNull();
        assertThat(response.getHeaders().getFirst("WWW-Authenticate")).contains("realm=\"/\"");
    }

    /**
     * The CSRF check lives in the 3-arg {@code authorize}, so this is a POST-only clause -- and structurally
     * so: {@code CsrfException} is absent from the 1-arg method's {@code throws}, which is why the shared
     * table cannot carry it. The literal {@code (400, "bad_request")} Restlet's catch passed is the
     * exception's own pair, so the collapse leaves it unchanged.
     */
    @Test
    public void csrfIsRefusedOnThePostPath() throws Exception {
        when(o2.<String>getParameter("redirect_uri")).thenReturn(CLIENT_URI);
        when(o2.<String>getParameter("state")).thenReturn(STATE);
        when(authorizationService.authorize(any(), anyBoolean(), anyBoolean())).thenThrow(new CsrfException());

        assertCollapsed(post(formRequest("decision=allow")), 400, "bad_request", false);
    }

    /** The redirect branch echoes state -- it rides in {@code asMap()}, which becomes the query parameters. */
    @Test
    public void theErrorRedirectEchoesState() throws Exception {
        when(o2.<String>getParameter("redirect_uri")).thenReturn(CLIENT_URI);
        when(o2.<String>getParameter("state")).thenReturn(STATE);
        when(authorizationService.authorize(o2)).thenThrow(new InvalidScopeException("Unknown scope",
                UrlLocation.QUERY));

        assertThat(get("").getHeaders().getFirst("Location")).contains("state=" + STATE);
    }

    /**
     * The HTML branch does <strong>not</strong>, and that is legacy behaviour reproduced rather than an
     * omission here: {@code page/error.ftl} interpolates only {@code error} and {@code error_description}, so
     * the {@code state} the producer has always put in the model reaches no template. Pinned because the
     * obvious "state is echoed in every error body" reading of the contract is false, and a future change that
     * quietly started rendering it would be a wire change.
     */
    @Test
    public void theErrorPageDoesNotCarryState() throws Exception {
        when(o2.<String>getParameter("state")).thenReturn(STATE);
        when(authorizationService.authorize(o2)).thenThrow(new RedirectUriMismatchException());

        assertThat(get("").getEntity().getString()).doesNotContain(STATE);
    }

    @Test
    public void theErrorPathCarriesTheCacheHeaders() throws Exception {
        when(authorizationService.authorize(o2)).thenThrow(new RedirectUriMismatchException());

        Response response = get("");

        assertThat(response.getHeaders().getFirst("Cache-Control")).isEqualTo("no-store");
        assertThat(response.getHeaders().getFirst("Pragma")).isEqualTo("no-cache");
    }

    // --- D7: every IllegalArgumentException, one answer --------------------------------------------

    /**
     * The three inputs that have three different answers today: the service's IAE with and without
     * {@code client_id} in the message (400 {@code invalid_request} + an open redirect, or the error page),
     * and the unknown {@code ?display=} (400 {@code server_error} page, because Restlet raised it inside a
     * sibling {@code catch}). All three become one non-redirecting 400 {@code invalid_request}.
     */
    @Test
    public void anIllegalArgumentFromTheServiceIsANonRedirectingInvalidRequest() throws Exception {
        when(o2.<String>getParameter("redirect_uri")).thenReturn(CLIENT_URI);
        when(o2.<String>getParameter("state")).thenReturn(STATE);
        when(authorizationService.authorize(o2)).thenThrow(new IllegalArgumentException("Missing parameter scope"));

        Response response = get("");

        assertThat(response.getStatus().getCode()).isEqualTo(400);
        assertThat(response.getHeaders().getFirst("Location")).isNull();
        // The message survives onto the page; state does not -- see theErrorPageDoesNotCarryState.
        assertThat(response.getEntity().getString()).contains("invalid_request").contains("Missing parameter scope");
    }

    /** The {@code client_id} branch was the only one Restlet already refused to redirect; same answer now. */
    @Test
    public void anIllegalArgumentMentioningClientIdIsTheSameAnswer() throws Exception {
        when(o2.<String>getParameter("redirect_uri")).thenReturn(CLIENT_URI);
        when(authorizationService.authorize(o2)).thenThrow(new IllegalArgumentException("Missing client_id"));

        Response response = get("");

        assertThat(response.getStatus().getCode()).isEqualTo(400);
        assertThat(response.getHeaders().getFirst("Location")).isNull();
        assertThat(response.getEntity().getString()).contains("invalid_request");
    }

    /**
     * Finding 9: the display IAE is raised <em>inside</em> the consent branch, and a sibling catch does not
     * protect a catch body -- which is exactly why Restlet leaked it to {@code doCatch} as a
     * {@code server_error}. The catch has to sit one level out, and this row is what proves it does.
     */
    @Test
    public void anUnknownDisplayIsAlsoInvalidRequest() throws Exception {
        when(o2.<String>getParameter("redirect_uri")).thenReturn(CLIENT_URI);
        when(authorizationService.authorize(o2)).thenThrow(consentRequired());
        when(consentPageRenderer.render(any(), any(), any()))
                .thenThrow(new IllegalArgumentException("No enum constant DisplayType.BOGUS"));

        Response response = get("");

        assertThat(response.getStatus().getCode()).isEqualTo(400);
        assertThat(response.getHeaders().getFirst("Location")).isNull();
        assertThat(response.getEntity().getString()).contains("invalid_request");
    }

    /** POST reaches the same answer, where Restlet gave it a 400 {@code server_error} through doCatch. */
    @Test
    public void anIllegalArgumentOnPostIsInvalidRequestToo() throws Exception {
        when(o2.<String>getParameter("redirect_uri")).thenReturn(CLIENT_URI);
        when(authorizationService.authorize(any(), anyBoolean(), anyBoolean()))
                .thenThrow(new IllegalArgumentException("Missing parameter scope"));

        Response response = post(formRequest("decision=allow"));

        assertThat(response.getStatus().getCode()).isEqualTo(400);
        assertThat(response.getHeaders().getFirst("Location")).isNull();
        assertThat(response.getEntity().getString()).contains("invalid_request");
    }

    @Test
    public void theIllegalArgumentPageCarriesTheCacheHeaders() throws Exception {
        when(authorizationService.authorize(o2)).thenThrow(new IllegalArgumentException("boom"));

        Response response = get("");

        assertThat(response.getHeaders().getFirst("Cache-Control")).isEqualTo("no-store");
        assertThat(response.getHeaders().getFirst("Pragma")).isEqualTo("no-cache");
    }

    // --- helpers ----------------------------------------------------------------------------------

    private static void assertCollapsed(Response response, int status, String error, boolean redirects)
            throws Exception {
        if (redirects) {
            assertThat(response.getStatus().getCode()).isEqualTo(302);
            assertThat(response.getHeaders().getFirst("Location"))
                    .startsWith(CLIENT_URI + "?").contains("error=" + error).contains("state=" + STATE);
        } else {
            assertThat(response.getStatus().getCode()).isEqualTo(status);
            assertThat(response.getHeaders().getFirst("Location")).isNull();
            assertThat(response.getHeaders().getFirst("Content-Type")).isEqualTo("text/html; charset=UTF-8");
            assertThat(response.getEntity().getString()).contains(error);
        }
    }

    private Response get(String query) throws Exception {
        return Endpoints.from(handler)
                .handle(new RootContext(), new Request().setMethod("GET").setUri("/oauth2/authorize" + query))
                .getOrThrowUninterruptibly();
    }

    private Response post(Request request) {
        return dispatch(request);
    }

    private Response dispatch(Request request) {
        return Endpoints.from(handler).handle(new RootContext(), request).getOrThrowUninterruptibly();
    }

    private static Request formRequest(String body) throws Exception {
        Request request = new Request().setMethod("POST").setUri("/oauth2/authorize");
        request.getHeaders().put("Content-Type", "application/x-www-form-urlencoded");
        request.setEntity(body);
        return request;
    }

    private static AuthorizationToken token(boolean fragment) {
        Map<String, String> tokens = new LinkedHashMap<>();
        tokens.put("code", CODE);
        tokens.put("state", STATE);
        return new AuthorizationToken(tokens, fragment);
    }

    private static Response consentPage() {
        return FreemarkerTemplateRenderer.toHtmlResponse(Status.OK, "<html>consent</html>");
    }

    private static ResourceOwnerConsentRequired consentRequired() {
        return new ResourceOwnerConsentRequired("Demo & Co", "A demo client", Map.of("profile", "View your profile"),
                Map.of(), new UserInfoClaims(Map.of(), Map.of()), "demo", true);
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
                // the shared members live two levels up, on AbstractOAuth2HttpEndpoint
            }
        }
        throw new NoSuchFieldException(name);
    }
}
