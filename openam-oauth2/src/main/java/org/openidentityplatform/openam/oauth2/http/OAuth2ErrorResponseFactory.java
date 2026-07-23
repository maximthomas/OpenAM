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

import java.io.IOException;
import java.util.LinkedHashMap;
import java.util.Map;

import jakarta.inject.Inject;
import jakarta.inject.Singleton;
import jakarta.servlet.http.HttpServletRequest;

import org.forgerock.http.header.HeaderUtil;
import org.forgerock.http.header.LocationHeader;
import org.forgerock.http.protocol.Response;
import org.forgerock.http.protocol.Status;
import org.forgerock.json.resource.NotFoundException;
import org.forgerock.oauth2.core.OAuth2Request;
import org.forgerock.openam.oauth2.OAuth2Constants;
import org.forgerock.openam.services.baseurl.BaseURLProviderFactory;
import org.forgerock.openam.utils.RealmNormaliser;
import org.forgerock.util.annotations.VisibleForTesting;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import freemarker.template.TemplateException;

/**
 * Turns an {@link OAuth2Error} into the CHF {@code Response} the OAuth2 provider has always emitted for it.
 * <p>
 * This is the transport-neutral replacement for {@code org.forgerock.oauth2.restlet.ExceptionHandler}. Phase
 * 5b's handlers reach it through {@link #toResponse}, which reproduces that class's three ordered branches;
 * Phase 5a's JSON endpoints reach it through {@link #toJsonResponse}, which is the separate entry point
 * {@code ExceptionHandler.handle(Throwable, Response)} was.
 * <p>
 * {@code JacksonRepresentationFactory} does not survive the port: CHF's {@code Entity.setEntity(Map)} routes
 * to {@code setJson}, which writes both the body and {@code Content-Type: application/json; charset=UTF-8}.
 */
@Singleton
public class OAuth2ErrorResponseFactory {

    private static final Logger LOGGER = LoggerFactory.getLogger("OAuth2Provider");

    /**
     * Hardcoded, exactly as {@code ExceptionHandler:137} hardcodes the {@code "page"} display. There is no
     * {@code error.ftl} outside {@code page/}, so honouring {@code ?display=} here would resolve a template
     * that does not exist.
     */
    private static final String ERROR_TEMPLATE = "templates/page/error.ftl";

    /** {@code Realm.root().asPath()}. The error template dereferences {@code realm} with no default. */
    private static final String ROOT_REALM = "/";

    /** CHF ships no header class for this one, unlike {@link LocationHeader}. */
    private static final String WWW_AUTHENTICATE = "WWW-Authenticate";

    private final FreemarkerTemplateRenderer renderer;
    private final BaseURLProviderFactory baseURLProviderFactory;
    private final RealmNormaliser realmNormaliser;

    /**
     * @param renderer renders the HTML error page.
     * @param baseURLProviderFactory supplies the deployment's root URL for that page's data model.
     * @param realmNormaliser bounds what reaches that factory; see {@link #baseUrlOf}.
     */
    @Inject
    public OAuth2ErrorResponseFactory(FreemarkerTemplateRenderer renderer,
            BaseURLProviderFactory baseURLProviderFactory, RealmNormaliser realmNormaliser) {
        this.renderer = renderer;
        this.baseURLProviderFactory = baseURLProviderFactory;
        this.realmNormaliser = realmNormaliser;
    }

    /**
     * The browser-facing dispatcher, reproducing {@code ExceptionHandler.handle}'s three ordered branches.
     *
     * @param request the request the error arose from; supplies {@code realm} and the servlet request.
     * @param error the error to render.
     * @return a 301 to the login page, a 302 to the client's redirect target, or the HTML error page.
     */
    public Response toResponse(OAuth2Request request, OAuth2Error error) {
        // Both redirect branches require a target. Testing hasRedirectUri() first is not belt-and-braces:
        // CHF's Headers.put(name, null) *removes* the header, so a targetless redirect would otherwise emit
        // a 301 with no Location at all -- a blank page, silently and with nothing logged.
        //
        // Which redirect it is turns on where the target came from, not on the status. Those agree today,
        // ResourceOwnerAuthenticationRequired being the only 307, but only one of them is the actual
        // question: an error given status 307 *and* a client redirect_uri must not become a cacheable 301
        // to that URI with the error parameters dropped.
        if (error.hasRedirectUri()) {
            Response redirect = error.isRedirectUriFromException()
                    ? toLoginRedirectResponse(error)
                    : toRedirectResponse(error);
            return withChallenge(redirect, error);
        }
        return withChallenge(toHtmlErrorResponse(request, error), error);
    }

    /**
     * The API-facing entry point: the error as a JSON body at its own status.
     *
     * @param error the error to render.
     * @return the response.
     */
    public Response toJsonResponse(OAuth2Error error) {
        log(error);
        Status status = deliverableStatusOf(error);
        Response response = new Response(status);
        // A JSON client still has to be told where a redirect status points, and this entry point is the one
        // an endpoint reaches for when it has no browser to render a page to. Where it points is the same
        // question toResponse asks: the bare target when the error pinned it, the composed one when the
        // request supplied it. Emitting the bare client target instead would send the user agent to the
        // callback with no `error` and no `state` -- a failure the client cannot tell from a success.
        //
        // Only on a redirection. deliverableStatusOf has already ruled out a 3xx with nothing to point at,
        // so this branch implies a target; the converse -- a target on a 400 -- is not a redirect and must
        // not claim to be one.
        if (status.isRedirection()) {
            response.getHeaders().put(LocationHeader.NAME, error.isRedirectUriFromException()
                    ? error.getRedirectUri()
                    : RedirectUris.compose(error.getRedirectUri(), error.asMap(),
                            error.getParameterLocation()));
        }
        response.setEntity(error.asMap());
        return withChallenge(response, error);
    }

    /**
     * The authentication-required redirect.
     * <p>
     * A <strong>301</strong>, not the 307 the exception carries: Restlet's {@code MODE_CLIENT_PERMANENT} is
     * what the wire has always seen, so the code is reproduced rather than corrected. The error parameters
     * are deliberately not applied -- the target is the login page, and this is the one OAuth2 redirect a
     * user agent may cache.
     * <p>
     * Package-private: every <em>public</em> entry point logs the error exactly once, and a builder reachable
     * from outside would be a way to deliver one with no provider-log line at all. {@link #toResponse} is how
     * a handler asks for this branch.
     *
     * @param error the error, whose pinned target is the login page.
     * @return the response.
     */
    @VisibleForTesting
    Response toLoginRedirectResponse(OAuth2Error error) {
        log(error);
        requireTarget(error.getRedirectUri(), "a login redirect needs a login URI");
        Response response = new Response(Status.MOVED_PERMANENTLY);
        response.getHeaders().put(LocationHeader.NAME, error.getRedirectUri());
        return response;
    }

    /**
     * The error redirect: a <strong>302</strong> carrying {@link OAuth2Error#asMap()} in the query or the
     * fragment.
     * <p>
     * The status is always 302. {@code ExceptionHandler:119} set the error's own status first and the
     * {@code Redirector} then overwrote it, so that write was always dead; it is not reproduced.
     * <p>
     * Package-private for the same reason as {@link #toLoginRedirectResponse}.
     *
     * @param error the error, which must have a redirect target.
     * @return the response.
     */
    @VisibleForTesting
    Response toRedirectResponse(OAuth2Error error) {
        log(error);
        requireTarget(error.getRedirectUri(), "an error redirect needs a redirect_uri");
        Response response = new Response(Status.FOUND);
        response.getHeaders().put(LocationHeader.NAME,
                RedirectUris.compose(error.getRedirectUri(), error.asMap(), error.getParameterLocation()));
        return response;
    }

    /**
     * Renders {@code templates/page/error.ftl} at the error's own status.
     * <p>
     * <strong>Gathering the data model is inside the guard, not before it.</strong> {@code realm} comes
     * straight off the request unnormalised, and it is handed to {@code BaseURLProviderFactory.get} -- so a
     * lookup that throws for an unknown realm would escape the error path entirely and turn a handled 400
     * into an unhandled 500. The fallback exists to keep this path alive; it has to cover the inputs too,
     * not just the render.
     *
     * @param request the request the error arose from.
     * @param error the error to render.
     * @return the rendered page, or a JSON body if anything about producing it failed.
     */
    private Response toHtmlErrorResponse(OAuth2Request request, OAuth2Error error) {
        log(error);
        Status status = deliverableStatusOf(error);
        try {
            String realm = realmOf(request);
            return toHtmlErrorResponse(status, error, realm, baseUrlOf(request, realm));
        } catch (Exception e) {
            // The page is presentation; the error itself is the contract. Falling back to the JSON body
            // keeps the status and the error code truthful rather than serving a blank page, which is what
            // the legacy handler did when TemplateFactory returned null.
            LOGGER.warn("Could not render the OAuth2 error page; falling back to a JSON body", e);
            Response response = new Response(status);
            response.setEntity(error.asMap());
            return response;
        }
    }

    /**
     * The pure half: renders the page from values already resolved.
     * <p>
     * Package-private and taking its request-derived values as arguments, so the render tests need no
     * {@code BaseURLProviderFactory} -- which needs a {@code ServletContext}. The status is passed in rather
     * than re-derived, so that a clamped one is resolved, and logged, exactly once per response.
     *
     * @param status the response status, already validated by {@link #statusOf}.
     * @param error the error to render.
     * @param realm the realm, never {@code null}.
     * @param baseUrl the deployment root URL, never {@code null}.
     * @return the rendered page.
     * @throws IOException if the template cannot be found or read.
     * @throws TemplateException if the template fails to render.
     */
    @VisibleForTesting
    Response toHtmlErrorResponse(Status status, OAuth2Error error, String realm, String baseUrl)
            throws IOException, TemplateException {
        Map<String, Object> dataModel = new LinkedHashMap<>(error.asMap());
        dataModel.put("realm", realm);
        dataModel.put("baseUrl", baseUrl);
        return FreemarkerTemplateRenderer.toHtmlResponse(status, renderer.render(ERROR_TEMPLATE, dataModel));
    }

    /** D9: the template dereferences {@code realm} with no default, and the parameter can be absent. */
    private String realmOf(OAuth2Request request) {
        String realm = request.getParameter(OAuth2Constants.Custom.REALM);
        return realm == null || realm.isEmpty() ? ROOT_REALM : realm;
    }

    /**
     * {@code Status.valueOf} rejects anything outside {@code 100..999} with an {@code IllegalArgumentException},
     * and not every status reaching here is a hardcoded constructor literal -- {@code UmaException} takes a
     * caller-supplied code. A bad code must not turn the error path into a second error.
     */
    private static Status statusOf(OAuth2Error error) {
        int code = error.getStatusCode();
        if (code < 100 || code > 999) {
            LOGGER.warn("OAuth2 error carried an out-of-range status {}; reporting it as 500", code);
            return Status.INTERNAL_SERVER_ERROR;
        }
        return Status.valueOf(code);
    }

    /**
     * {@link #statusOf}, plus the rule that a status must be one this response can actually honour.
     * <p>
     * A redirect status is a promise of a {@code Location}, and neither non-redirecting branch has one to
     * give: the JSON entry point has no page to fall back to, and the HTML branch is by construction the
     * branch with no target. Emitting the bare 3xx would hand the user agent a redirect with nowhere to go --
     * behaviour no specification defines, so what the client does with it is the client's guess.
     * <p>
     * Both branches share this because the input is the same degenerate error, and the pair disagreeing about
     * it was how the broken shape survived on one of them.
     */
    private static Status deliverableStatusOf(OAuth2Error error) {
        Status status = statusOf(error);
        if (status.isRedirection() && !error.hasRedirectUri()) {
            LOGGER.warn("OAuth2 error carried redirect status {} with no target; reporting it as 500",
                    status.getCode());
            return Status.INTERNAL_SERVER_ERROR;
        }
        return status;
    }

    /** Turns a javadoc-only precondition into an enforced one, since both redirect methods are public. */
    private static void requireTarget(String redirectUri, String message) {
        if (redirectUri == null || redirectUri.isEmpty()) {
            throw new IllegalArgumentException(message);
        }
    }

    /**
     * Finding 8: {@code BaseURLProvider}'s other {@code getRootURL} overload takes a CREST
     * {@code HttpContext}, which an {@code Endpoints.from} route never has at any depth, so the servlet
     * request is the only usable source -- and Grizzly and unit contexts have none. The template
     * dereferences {@code baseUrl} outside any guard, so this must not return {@code null}.
     */
    private String baseUrlOf(OAuth2Request request, String realm) {
        HttpServletRequest servletRequest = request.getHttpServletRequest();
        if (servletRequest == null) {
            return "";
        }
        String rootUrl = baseURLProviderFactory.get(normalised(realm)).getRootURL(servletRequest);
        return rootUrl == null ? "" : rootUrl;
    }

    /**
     * {@code BaseURLProviderFactory} caches a provider under every realm DN it is ever asked for and never
     * evicts, so handing it the raw parameter -- as {@code ExceptionHandler:136} did -- lets an
     * unauthenticated {@code ?realm=<random>} on the error page grow that map without bound, one SMS lookup
     * and one retained provider per distinct value. Normalising first bounds it to realms that exist, and
     * also fixes the lookup for a realm spelled in a non-canonical form. Only the base-URL lookup is
     * normalised: the page's own {@code realm} stays what the client sent, as before.
     */
    private String normalised(String realm) {
        try {
            return realmNormaliser.normalise(realm);
        } catch (NotFoundException noSuchRealm) {
            return ROOT_REALM;
        }
    }

    /**
     * RFC 6749 section 5.2 requires the challenge on an {@code invalid_client} 401. Applied once, after the
     * branch is chosen: today's producers decorate the response with the challenge <em>before</em> picking
     * an error shape, so it is orthogonal to the dispatch, and a header that depends on which branch ran is
     * how it goes missing when the next endpoint is ported.
     */
    private static Response withChallenge(Response response, OAuth2Error error) {
        if (error.getChallengeScheme() != null) {
            response.getHeaders().put(WWW_AUTHENTICATE, error.getChallengeScheme() + " realm="
                    + HeaderUtil.quote(printableAsciiOnly(error.getChallengeRealm())));
        }
        return response;
    }

    /**
     * Reduces the realm to what a header value can actually carry, leaving the quoting itself to
     * {@link HeaderUtil#quote}.
     * <p>
     * <strong>The realm is client-controlled.</strong> {@code ClientAuthenticationFailureFactory} builds the
     * challenge with {@code getRealm(request)}, and OpenAM's implementation reads the {@code realm} request
     * parameter and, when normalisation fails, deliberately falls back to the <em>un-normalised</em> value.
     * Two ranges have to go, for different reasons:
     * <ul>
     * <li><strong>C0 and DEL.</strong> {@code HeaderUtil.quote} handles {@code "} and {@code \}, but not CR
     *     or LF, which would leave header framing to whatever the container happens to reject;
     * <li><strong>everything above {@code 0x7F}.</strong> A header value is octets, and CHF applies no
     *     encoding, so {@code ?realm=/&#1090;&#1077;&#1089;&#1090;} either reaches the wire as each character truncated to
     *     its low byte -- mojibake -- or is rejected outright, turning the handled 401 into a container 500.
     *     RFC 7235 gives the realm no encoding mechanism, so dropping is the only lossless-looking option
     *     available; it is also the predictable one.
     * </ul>
     * Restlet's {@code HttpBasicHelper} filtered neither; that is not a reason to carry it forward.
     */
    private static String printableAsciiOnly(String value) {
        if (value == null) {
            return "";
        }
        StringBuilder stripped = new StringBuilder(value.length());
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            if (c >= 0x20 && c < 0x7F) {
                stripped.append(c);
            }
        }
        return stripped.toString();
    }

    /**
     * {@code ExceptionHandler:151-153} logged every error at WARN with a stack trace, so a client typo in a
     * {@code grant_type} produced a warning. Nothing here is client-observable; it is the difference between
     * a usable and an unusable provider log.
     * <p>
     * Severity is not the status, though. {@code ServerException} is the core's wrap-any-bug path and D2
     * gives it a <strong>400</strong>, so an internal fault would otherwise be a one-line debug message --
     * and the framework's own {@code DEBUG.error(…, t)} never runs for it, because a handler caught the
     * exception before the framework saw it. What an internal fault does say, whatever its status, is
     * {@code server_error}. The exception goes to the logger as the throwable so the stack survives with it.
     */
    private static void log(OAuth2Error error) {
        Throwable cause = error.getCause();
        if (error.getStatusCode() >= 500 || "server_error".equals(error.getError())) {
            LOGGER.warn("OAuth2 error {}: {} - {}", error.getStatusCode(), error.getError(),
                    error.getDescription(), cause);
        } else if (LOGGER.isDebugEnabled()) {
            LOGGER.debug("OAuth2 error {}: {} - {}", error.getStatusCode(), error.getError(),
                    error.getDescription(), cause);
        }
    }
}
