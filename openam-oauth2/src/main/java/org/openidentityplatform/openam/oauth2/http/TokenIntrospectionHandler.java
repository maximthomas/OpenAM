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
import org.forgerock.http.protocol.Status;
import org.forgerock.oauth2.core.OAuth2Request;
import org.forgerock.oauth2.core.TokenIntrospectionService;
import org.forgerock.oauth2.core.exceptions.OAuth2Exception;
import org.forgerock.openam.http.annotations.Contextual;
import org.forgerock.openam.http.annotations.Get;
import org.forgerock.openam.http.annotations.Post;
import org.forgerock.services.context.Context;

/**
 * CHF token introspection endpoint ({@code /oauth2/introspect}), porting the Restlet {@code TokenIntrospectionResource}.
 * <p>
 * One {@code @Get @Post} method serves both verbs -- the framework resolves it for each verb independently
 * (5a-2 finding 2), so no delegation is needed. The service authenticates the client, so an auth-header failure
 * ({@code InvalidClientAuthZHeaderException}) yields a {@code WWW-Authenticate} via the base -- a deliberate,
 * RFC 6749 5.2-compliant divergence from the Restlet resource (R-5a2.4). No cache headers (5a-2 finding 1).
 */
public class TokenIntrospectionHandler extends AbstractOAuth2HttpJsonEndpoint {

    @Inject
    private TokenIntrospectionService tokenIntrospectionService;

    /**
     * @param ctx the request context.
     * @param request the CHF request (GET or POST).
     * @return 200 with the introspection result as JSON.
     * @throws OAuth2Exception mapped to the JSON error body by the base handler.
     */
    @Get
    @Post
    public Response introspect(@Contextual Context ctx, @Contextual Request request) throws OAuth2Exception {
        OAuth2Request o2 = requestFactory.create(ctx, request);
        return new Response(Status.valueOf(200))
                .setEntity(tokenIntrospectionService.introspect(o2).asMap());
    }
}
