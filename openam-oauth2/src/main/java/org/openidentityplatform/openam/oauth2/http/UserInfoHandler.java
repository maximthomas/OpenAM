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
import org.forgerock.oauth2.core.exceptions.OAuth2Exception;
import org.forgerock.openam.http.annotations.Contextual;
import org.forgerock.openam.http.annotations.Get;
import org.forgerock.openam.http.annotations.Post;
import org.forgerock.openidconnect.UserInfoService;
import org.forgerock.services.context.Context;

/**
 * CHF OpenID Connect userinfo endpoint ({@code /oauth2/userinfo}), porting the Restlet {@code UserInfo}.
 * <p>
 * One {@code @Get @Post} method serves both verbs (5a-2 finding 2). An {@code InvalidTokenException} carries no
 * challenge scheme, so there is no {@code WWW-Authenticate} (parity with Restlet). No cache headers (5a-2 finding 1).
 */
public class UserInfoHandler extends AbstractOAuth2HttpJsonEndpoint {

    @Inject
    private UserInfoService userInfoService;

    /**
     * @param ctx the request context.
     * @param request the CHF request (GET or POST).
     * @return 200 with the user info as JSON.
     * @throws OAuth2Exception mapped to the JSON error body by the base handler.
     */
    @Get
    @Post
    public Response getUserInfo(@Contextual Context ctx, @Contextual Request request) throws OAuth2Exception {
        OAuth2Request o2 = requestFactory.create(ctx, request);
        return new Response(Status.valueOf(200))
                .setEntity(userInfoService.getUserInfo(o2).asMap());
    }
}
