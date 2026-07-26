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

import static org.forgerock.openam.oauth2.OAuth2Constants.Custom.DECISION;
import static org.forgerock.openam.oauth2.OAuth2Constants.Custom.FORM_POST;
import static org.forgerock.openam.oauth2.OAuth2Constants.Custom.RESPONSE_MODE;
import static org.forgerock.openam.oauth2.OAuth2Constants.Custom.SAVE_CONSENT;
import static org.forgerock.openam.oauth2.OAuth2Constants.Params.STATE;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

import jakarta.inject.Inject;

import freemarker.template.TemplateException;

import org.forgerock.http.header.LocationHeader;
import org.forgerock.http.protocol.Request;
import org.forgerock.http.protocol.Response;
import org.forgerock.http.protocol.Status;
import org.forgerock.oauth2.core.AuthorizationService;
import org.forgerock.oauth2.core.AuthorizationToken;
import org.forgerock.oauth2.core.OAuth2Request;
import org.forgerock.oauth2.core.RedirectUriResolver;
import org.forgerock.oauth2.core.exceptions.OAuth2Exception;
import org.forgerock.oauth2.core.exceptions.ResourceOwnerConsentRequired;
import org.forgerock.oauth2.core.exceptions.ServerException;
import org.forgerock.openam.http.annotations.Contextual;
import org.forgerock.openam.http.annotations.Get;
import org.forgerock.openam.http.annotations.Post;
import org.forgerock.openam.oauth2.OAuth2Constants.UrlLocation;
import org.forgerock.services.context.Context;

/**
 * CHF authorize endpoint ({@code /oauth2/authorize}), collapsing the Restlet {@code AuthorizeEndpointFilter} +
 * {@code AuthorizeResource} + {@code OAuth2Representation.toRepresentation} into one handler.
 *
 * <p>Two verbs share one success tail. {@code GET} starts an authorization request; {@code POST} carries the
 * resource owner's decision back from the consent page. Everything after the service call is identical, which
 * is why {@link #succeed} exists rather than two near-copies.
 *
 * <p><strong>Fourteen catch clauses become one mapper.</strong> The Restlet resource caught eight exception
 * types on {@code GET} and six on {@code POST}, and the two lists had drifted apart; every
 * {@link OAuth2Exception} now rises to {@link AbstractOAuth2HttpBrowserEndpoint#onError}, which decides
 * redirect-or-page from the exception's type rather than from clause ordering. Each literal
 * {@code (status, error)} pair those clauses passed equals the exception's own, so the collapse is
 * byte-identical except for the two changes it is meant to make -- see D6 and D7.
 *
 * <p>No verb check: two annotated methods mean the framework answers {@code PUT}/{@code DELETE} with its own
 * 405, whose body {@code OAuth2ErrorFilter} rewrites (D8).
 */
public class AuthorizeHandler extends AbstractOAuth2HttpBrowserEndpoint {

    private static final String INVALID_REQUEST = "invalid_request";

    /** {@code OAuth2Representation:181} -- no display folder; the form-post page has only one form. */
    private static final String FORM_POST_TEMPLATE = "templates/FormPostResponse.ftl";

    @Inject
    private AuthorizationService authorizationService;
    @Inject
    private RedirectUriResolver redirectUriResolver;
    @Inject
    private ConsentPageRenderer consentPageRenderer;
    @Inject
    private FreemarkerTemplateRenderer templateRenderer;
    @Inject
    private Set<ChfAuthorizeRequestHook> hooks;

    /**
     * Starts an authorization request.
     *
     * @param ctx the request context.
     * @param request the CHF request.
     * @return the 302 to the client, the form-post page, or the consent page.
     * @throws OAuth2Exception mapped to a redirect or the HTML error page by the base handler.
     * @throws IllegalArgumentException from the service's parameter validation or from an unknown
     *     {@code ?display=}; mapped to the non-redirecting 400 page by the base handler (D7). Deliberately
     *     <strong>not</strong> caught here: {@code ?display=bogus} raises its IAE from inside the consent
     *     branch, and a sibling {@code catch} does not protect a {@code catch} body -- which is precisely how
     *     Restlet leaked it to {@code doCatch} as a {@code server_error}. Letting it leave the method is what
     *     makes the three IAE sources converge without any placement subtlety at all.
     */
    @Get
    public Response authorize(@Contextual Context ctx, @Contextual Request request) throws OAuth2Exception {
        // On the GET too: OAuth2Filter.beforeHandle:59-62 ran validateContentType on every method, so a GET
        // carrying a non-empty JSON body is a 400 today and checking only the POST would quietly widen that.
        // The ordinary bodyless GET is accepted without inspecting anything, so real traffic pays nothing.
        if (!OAuth2ContentTypes.isFormUrlEncoded(request)) {
            return invalidContentType();
        }
        OAuth2Request o2 = requestFactory.create(ctx, request);
        runBeforeHooks(o2);
        try {
            return succeed(authorizationService.authorize(o2), o2);
        } catch (ResourceOwnerConsentRequired e) {
            // Not an OAuth2Exception, so it cannot reach the base mapper -- and the POST path deliberately has
            // no equivalent, the 3-arg authorize being unable to raise it.
            try {
                return noCache(consentPageRenderer.render(e, o2, request));
            } catch (IOException | TemplateException renderFailed) {
                return serverErrorPage(o2, renderFailed);
            }
        }
    }

    /**
     * Carries the resource owner's decision back from the consent page.
     *
     * @param ctx the request context.
     * @param request the CHF request, whose form body carries {@code decision} and {@code save_consent}.
     * @return the 302 to the client or the form-post page.
     * @throws OAuth2Exception mapped to a redirect or the HTML error page by the base handler.
     * @throws IllegalArgumentException mapped to the non-redirecting 400 page by the base handler (D7), where
     *     Restlet's POST path had no catch at all and got a {@code server_error} from {@code doCatch}.
     */
    @Post
    public Response consent(@Contextual Context ctx, @Contextual Request request) throws OAuth2Exception {
        if (!OAuth2ContentTypes.isFormUrlEncoded(request)) {
            return invalidContentType();
        }
        OAuth2Request o2 = requestFactory.create(ctx, request);
        runBeforeHooks(o2);
        // Verbatim from AuthorizeResource:170-171: anything but these two literals is a refusal, so a missing
        // or misspelled decision can never be read as consent.
        boolean consentGiven = "allow".equalsIgnoreCase(o2.<String>getParameter(DECISION));
        boolean saveConsent = "on".equalsIgnoreCase(o2.<String>getParameter(SAVE_CONSENT));
        return succeed(authorizationService.authorize(o2, consentGiven, saveConsent), o2);
    }

    /** The OAuth2Filter stamped no-store/no-cache on this endpoint's error responses too (D8). */
    @Override
    protected Response withErrorHeaders(Response response) {
        return noCache(response);
    }

    /**
     * The shared success tail: compose the target, deliver it as a redirect or a self-submitting form, then
     * tell the hooks. Reproduces {@code OAuth2Representation.toRepresentation:148-173}, including its ordering
     * -- the reference is composed <strong>before</strong> the {@code response_mode} branch, so the form-post
     * page posts to a URI that already carries the parameters as well as repeating them as hidden inputs.
     */
    private Response succeed(AuthorizationToken token, OAuth2Request o2) throws OAuth2Exception {
        String target = RedirectUris.compose(redirectUriResolver.resolve(o2), token.getToken(),
                token.isFragment() ? UrlLocation.FRAGMENT : UrlLocation.QUERY);
        Response response;
        try {
            response = FORM_POST.equals(o2.getParameter(RESPONSE_MODE))
                    ? formPostPage(target, token)
                    : redirectTo(target);
        } catch (IOException | TemplateException renderFailed) {
            // Not a success, so the after-hooks do not run: D9 puts them after the representation is built,
            // and one that failed to build was not.
            return serverErrorPage(o2, renderFailed);
        }
        for (ChfAuthorizeRequestHook hook : hooks) {
            hook.afterAuthorizeSuccess(o2);
        }
        return noCache(response);
    }

    /** {@code Redirector(MODE_CLIENT_FOUND)} is a 302; the target is emitted verbatim (D11). */
    private static Response redirectTo(String target) {
        Response response = new Response(Status.FOUND);
        response.getHeaders().put(LocationHeader.NAME, target);
        return response;
    }

    private Response formPostPage(String target, AuthorizationToken token) throws IOException, TemplateException {
        Map<String, Object> dataModel = new HashMap<>();
        dataModel.put("redirectUri", target);
        dataModel.put("formValues", token.getToken());
        return FreemarkerTemplateRenderer.toHtmlResponse(Status.OK,
                templateRenderer.render(FORM_POST_TEMPLATE, dataModel));
    }

    private void runBeforeHooks(OAuth2Request o2) {
        for (ChfAuthorizeRequestHook hook : hooks) {
            hook.beforeAuthorizeHandling(o2);
        }
    }

    /**
     * ⚠ <strong>Every error this handler builds itself is built, not thrown.</strong> Both of the ones below
     * carry a status whose natural exception type ({@code InvalidRequestException}, {@code ServerException}) is
     * <em>redirectable</em>, and {@link AbstractOAuth2HttpBrowserEndpoint#onError} keys {@code mayRedirect} on
     * type -- so throwing either would send the error to a {@code redirect_uri} that, the request having failed
     * before the client was ever resolved, nothing has validated. Restlet built both with the 4-argument
     * {@code OAuth2RestletException} whose last parameter is {@code state}, leaving the redirect null, and so
     * always rendered the page ({@code OAuth2Filter:66-70}, {@code ExceptionHandler:86-89}). The third such
     * error, {@code IllegalArgumentException}, is built the same way one level up, by
     * {@link AbstractOAuth2HttpBrowserEndpoint#onIllegalArgument}.
     *
     * <p>A template fault stays a contractual 400 {@code server_error} page rather than the framework's 500: a
     * missing or broken template is a deployment fault, not one of the bug paths [D3] sends to the framework,
     * and the error page can still describe it.
     */
    private Response serverErrorPage(OAuth2Request o2, Exception renderFailed) {
        // of(OAuth2Exception) rather than of(int, String, String): identical wire shape -- ServerException is
        // 400 server_error carrying the cause's message -- but it also threads the CHAINED cause into
        // OAuth2Error, which is the only thing that puts a stack trace in the provider log. Without it the one
        // line recording a broken template names neither the template nor the frame that read it. It stays
        // non-redirecting because nothing calls redirectingTo on it.
        return withErrorHeaders(errorResponseFactory.toResponse(o2,
                OAuth2Error.of(new ServerException(renderFailed)).withState(o2.<String>getParameter(STATE))));
    }

    /**
     * The content-type refusal, as a <strong>JSON</strong> body and <strong>before</strong> the
     * {@code OAuth2Request} is built. Both halves are the recorded contract rather than preference:
     *
     * <ul>
     * <li>5-E2 row 8 captured live Restlet answering {@code 400 application/json}
     *     {@code {"error_description":"Invalid Content Type","error":"invalid_request"}} — the filter wrote a
     *     Jackson representation, never a page, so rendering the HTML error page here would have been a
     *     divergence introduced for no reason;
     * <li>{@code OAuth2Filter.beforeHandle} rejected in the filter, so the resource — and therefore
     *     {@code OAuth2RequestFactory.create}, which performs an unconditional
     *     {@code ClientRegistrationStore.get(client_id, …)} — never ran. Building the request first would let
     *     an unauthenticated flood of malformed posts cost one client-registration lookup each.
     * </ul>
     *
     * {@code toJsonResponse} needs no {@code OAuth2Request} at all, which is what makes that ordering possible.
     */
    private Response invalidContentType() {
        return withErrorHeaders(errorResponseFactory.toJsonResponse(
                OAuth2Error.of(400, INVALID_REQUEST, "Invalid Content Type")));
    }

}
