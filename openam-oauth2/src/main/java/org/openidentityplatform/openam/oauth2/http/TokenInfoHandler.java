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
import org.forgerock.oauth2.core.TokenInfoService;
import org.forgerock.oauth2.core.exceptions.OAuth2Exception;
import org.forgerock.openam.http.annotations.Contextual;
import org.forgerock.openam.http.annotations.Get;
import org.forgerock.services.context.Context;

/**
 * CHF tokeninfo endpoint ({@code /oauth2/tokeninfo}), porting the Restlet {@code ValidationServerResource}.
 * <p>
 * Unlike the other 5a-2 endpoints this one carries a cache header, but a different one from {@code /access_token}:
 * {@code Cache-Control: no-cache, no-store} (no {@code Pragma}), and only on the success path -- the error path
 * (base {@link AbstractOAuth2HttpJsonEndpoint#onError}) carries none (5a-2 finding 1).
 */
public class TokenInfoHandler extends AbstractOAuth2HttpJsonEndpoint {

    @Inject
    private TokenInfoService tokenInfoService;

    /**
     * @param ctx the request context.
     * @param request the CHF request.
     * @return 200 with the token info as JSON, plus the success-path cache header.
     * @throws OAuth2Exception mapped to the JSON error body by the base handler.
     */
    @Get
    public Response getTokenInfo(@Contextual Context ctx, @Contextual Request request) throws OAuth2Exception {
        OAuth2Request o2 = requestFactory.create(ctx, request);
        Response response = new Response(Status.valueOf(200)).setEntity(tokenInfoService.getTokenInfo(o2).asMap());
        response.getHeaders().put("Cache-Control", "no-cache, no-store");   // the resource's own header (ValidationServerResource:81-82)
        return response;
    }
}
