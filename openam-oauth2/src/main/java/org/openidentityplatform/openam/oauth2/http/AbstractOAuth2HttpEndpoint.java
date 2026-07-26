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

import org.forgerock.http.protocol.Response;
import org.forgerock.oauth2.core.OAuth2RequestFactory;
import org.forgerock.openam.http.annotations.ExceptionHandler;

/**
 * Everything the CHF OAuth2 endpoints share regardless of how they render an error: the injected
 * collaborators, the {@link #withErrorHeaders} hook and the {@link #noCache} header helper.
 *
 * <p>Deliberately carries <strong>no</strong> {@link ExceptionHandler}. The two error renderings are
 * siblings, not an override chain -- Java drops annotations on an override, so an overriding {@code onError}
 * would silently lose the mapper:
 *
 * <pre>
 * AbstractOAuth2HttpEndpoint            (this class)
 * |-- AbstractOAuth2HttpJsonEndpoint    &#64;ExceptionHandler -&gt; OAuth2 JSON error body
 * \-- AbstractOAuth2HttpBrowserEndpoint &#64;ExceptionHandler -&gt; redirect or HTML error page
 * </pre>
 *
 * <p>The framework discovers {@code @ExceptionHandler} on inherited public methods, so a mapper declared on
 * either sibling covers every one of its subclasses.
 */
public abstract class AbstractOAuth2HttpEndpoint {

    @Inject
    protected OAuth2RequestFactory requestFactory;
    @Inject
    protected OAuth2ErrorResponseFactory errorResponseFactory;

    /**
     * Endpoint-specific headers for the error response. Default: none -- most OAuth2 endpoints add no cache
     * headers on their error path. Only {@code /access_token} and {@code /authorize} did, via the Restlet
     * {@code OAuth2Filter}; those two handlers override this to {@link #noCache}.
     */
    protected Response withErrorHeaders(Response response) {
        return response;
    }

    /**
     * Stamps {@code Cache-Control: no-store} + {@code Pragma: no-cache} -- the directives the Restlet
     * {@code OAuth2Filter} added to every {@code /access_token} and {@code /authorize} response, success and
     * error. Only those two endpoints inherited it; the others set their own cache header (or none), so this is
     * opt-in per handler, not a base default.
     */
    protected static Response noCache(Response response) {
        response.getHeaders().put("Cache-Control", "no-store");
        response.getHeaders().put("Pragma", "no-cache");
        return response;
    }
}
