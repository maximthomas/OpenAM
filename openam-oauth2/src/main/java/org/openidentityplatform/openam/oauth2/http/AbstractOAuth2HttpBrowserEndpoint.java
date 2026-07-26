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

import static org.forgerock.oauth2.core.Utils.isEmpty;

import org.forgerock.http.protocol.Request;
import org.forgerock.http.protocol.Response;
import org.forgerock.oauth2.core.OAuth2Request;
import org.forgerock.oauth2.core.exceptions.OAuth2Exception;
import org.forgerock.openam.http.annotations.Contextual;
import org.forgerock.openam.http.annotations.ExceptionHandler;
import org.forgerock.openam.oauth2.OAuth2Constants;
import org.forgerock.services.context.Context;

/**
 * Base for the CHF OAuth2 <em>browser</em> endpoints -- those whose errors a human sees. It carries the one
 * {@link ExceptionHandler} they share, collapsing what Restlet's {@code AuthorizeResource} spread over
 * fourteen catch clauses across two verbs into a single mapper driven by data rather than by clause ordering.
 *
 * <p>Three outcomes fall out of one {@code toResponse} call, which dispatches on where the target came from:
 * a <strong>301</strong> to the login page (target pinned by the exception), a <strong>302</strong> to the
 * client's {@code redirect_uri} carrying the error parameters, or the <strong>HTML error page</strong> when
 * there is no target or the exception type may never redirect.
 *
 * <p>A <strong>second</strong> mapper covers {@link IllegalArgumentException} -- which the Restlet
 * {@code AuthorizeResource} also caught, and which {@code FreemarkerTemplateRenderer.renderForDisplay} raises
 * for an unknown {@code ?display=}. It is a separate method rather than a branch of {@link #onError} because
 * its policy is "never redirect" while the OAuth2 type it would naturally be converted to
 * ({@code InvalidRequestException}) <em>is</em> redirectable: routing it through {@link OAuth2Error#mayRedirect}
 * would send a malformed request's error to a {@code redirect_uri} that, the client never having been
 * resolved, nothing has validated. Building the error instead of throwing it removes the question -- see
 * {@link #onIllegalArgument}.
 *
 * <p>Sibling of {@link AbstractOAuth2HttpJsonEndpoint}, not its subclass: the framework would find only the
 * override and Java drops annotations onto overrides, so a forgotten {@code @ExceptionHandler} would silently
 * turn every OAuth2 error into a framework 500. Shared members live on {@link AbstractOAuth2HttpEndpoint}.
 * ⚠ Subclasses must <strong>not</strong> override {@link #onError} <em>or</em> {@link #onIllegalArgument}:
 * both mappers are found by annotation, both lose that annotation on an override, and both then fall through
 * to a CREST-JSON 500 rendered to a human. The second one is the newer trap and the easier to reach, since
 * tweaking a validation message is a plausible reason to want to override it.
 */
public abstract class AbstractOAuth2HttpBrowserEndpoint extends AbstractOAuth2HttpEndpoint {

    /**
     * @param e the exception the endpoint method threw (handed over directly by the framework, not wrapped).
     * @param ctx the request context, used to recover the cached request.
     * @param request the CHF request, whose {@code state} is echoed into the error.
     * @return the login redirect, the error redirect, or the error page.
     */
    @ExceptionHandler
    public Response onError(OAuth2Exception e, @Contextual Context ctx, @Contextual Request request) {
        OAuth2Request o2 = requestFactory.create(ctx, request);
        OAuth2Error error = OAuth2Error.of(e).withState(o2.<String>getParameter(OAuth2Constants.Params.STATE));
        String redirectUri = o2.getParameter(OAuth2Constants.Params.REDIRECT_URI);
        if (OAuth2Error.mayRedirect(e) && !isEmpty(redirectUri)) {
            // The location is the exception's own: an implicit-flow error belongs in the fragment. Passing it
            // is a no-op today -- redirectingTo would keep the value of() already set -- but the parameter is
            // NOT optional, and its null branch defaults to QUERY, so the alternatives a future edit reaches
            // for (`null`, or a hardcoded QUERY) both silently move every implicit-flow error to the query
            // string. Written explicitly so that edit has to be deliberate.
            error = error.redirectingTo(redirectUri, error.getParameterLocation());
        }
        return withErrorHeaders(errorResponseFactory.toResponse(o2, error));
    }

    /**
     * D7: every {@link IllegalArgumentException} becomes one non-redirecting 400 {@code invalid_request} page.
     *
     * <p>Restlet had three answers for the same class of fault -- {@code AuthorizeResource}'s GET caught it and
     * <em>redirected</em> to the raw {@code redirect_uri} (unless the message mentioned {@code client_id}), its
     * POST did not catch it at all and got a 400 {@code server_error} page from {@code doCatch}, and the
     * {@code ?display=} case reached {@code doCatch} too because it was raised inside a sibling {@code catch}.
     * This is the safe union of the three: the answer POST already gave, with the page GET already gave for
     * half its inputs. It closes the open redirect the GET path had, since a request that failed parameter
     * validation never had its {@code redirect_uri} checked against the client's registered set.
     *
     * <p><strong>Built, never thrown.</strong> {@link OAuth2Error#of(int, String, String)} carries no redirect
     * target, so {@code toResponse} takes the page branch by construction rather than by a rule someone has to
     * remember -- and living on the base means no subclass has to remember it at all.
     *
     * <p>⚠ This maps only what an endpoint <em>method</em> threw. The framework routes its own plumbing
     * failures through a different branch ({@code AnnotatedMethod:104}, the non-{@code InvocationTargetException}
     * catch), so a reflective {@code IllegalArgumentException} still becomes the framework's 500 rather than
     * being disguised as a client error.
     *
     * @param e the exception the endpoint method threw.
     * @param ctx the request context, used to recover the cached request.
     * @param request the CHF request, whose {@code state} is echoed into the error.
     * @return the 400 error page.
     */
    @ExceptionHandler
    public Response onIllegalArgument(IllegalArgumentException e, @Contextual Context ctx,
            @Contextual Request request) {
        OAuth2Request o2 = requestFactory.create(ctx, request);
        // The four-argument of(): the throwable is kept for the log, never for the wire. Most exceptions
        // arriving here are client-caused (a bad parameter, an unknown ?display=) and stay at debug, but the
        // ones that are not are internal faults wearing a 400, and without the cause the single line recording
        // one names neither the frame that threw nor the fault.
        return withErrorHeaders(errorResponseFactory.toResponse(o2,
                OAuth2Error.of(400, "invalid_request", e.getMessage(), e)
                        .withState(o2.<String>getParameter(OAuth2Constants.Params.STATE))));
    }
}
