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

import jakarta.inject.Inject;

import org.forgerock.http.protocol.Request;
import org.forgerock.http.protocol.Response;
import org.forgerock.oauth2.core.OAuth2Request;
import org.forgerock.oauth2.core.OAuth2RequestFactory;
import org.forgerock.oauth2.core.exceptions.OAuth2Exception;
import org.forgerock.openam.http.annotations.Contextual;
import org.forgerock.openam.http.annotations.ExceptionHandler;
import org.forgerock.services.context.Context;

/**
 * Base for the CHF OAuth2 JSON endpoints, carrying the one {@link ExceptionHandler} they all share so any
 * {@link OAuth2Exception} a handler method throws becomes the OAuth2 JSON error body.
 *
 * <p>Sibling of {@code AbstractUmaHttpEndpoint}, differing in two ways: it catches {@link OAuth2Exception}
 * (not {@code Throwable}), because {@code OAuth2Error.of} requires one -- a genuinely unexpected throwable
 * falls to the framework's CREST 500; and it field-injects its collaborators, since
 * {@link OAuth2ErrorResponseFactory} is {@code @Inject}-constructed (the UMA factory is static).
 *
 * <p>The framework discovers {@code @ExceptionHandler} on inherited methods, so declaring it once here
 * covers every subclass. ⚠ Subclasses must <strong>not</strong> override {@link #onError} -- Java does not
 * carry an annotation onto an override, so an overriding method would silently lose the mapper.
 */
public abstract class AbstractOAuth2HttpJsonEndpoint {

    @Inject
    protected OAuth2RequestFactory requestFactory;
    @Inject
    protected OAuth2ErrorResponseFactory errorResponseFactory;

    /**
     * @param e the exception the endpoint method threw (handed over directly by the framework, not wrapped).
     * @param ctx the request context, used to recover the cached request.
     * @param request the CHF request, whose {@code state} is echoed into the error body.
     * @return the OAuth2 JSON error response.
     */
    @ExceptionHandler
    public Response onError(OAuth2Exception e, @Contextual Context ctx, @Contextual Request request) {
        OAuth2Request o2 = requestFactory.create(ctx, request);
        Response response = errorResponseFactory.toJsonResponse(
                OAuth2Error.of(e).withState(o2.<String>getParameter("state")));
        return withErrorHeaders(response);
    }

    /**
     * Endpoint-specific headers for the error response. Default: none -- most OAuth2 JSON endpoints add no cache
     * headers on their error path. Only {@code /access_token} (and {@code /authorize}) did, via the Restlet
     * {@code OAuth2Filter}; {@code TokenEndpointHandler} overrides this to {@link #noCache}.
     */
    protected Response withErrorHeaders(Response response) {
        return response;
    }

    /**
     * Stamps {@code Cache-Control: no-store} + {@code Pragma: no-cache} -- the directives the Restlet
     * {@code OAuth2Filter} added to every {@code /access_token} (and {@code /authorize}) response, success and
     * error. Only those two endpoints inherited it; the other OAuth2 JSON endpoints set their own cache header
     * (or none), so this is opt-in per handler, not a base default.
     */
    protected static Response noCache(Response response) {
        response.getHeaders().put("Cache-Control", "no-store");
        response.getHeaders().put("Pragma", "no-cache");
        return response;
    }
}
