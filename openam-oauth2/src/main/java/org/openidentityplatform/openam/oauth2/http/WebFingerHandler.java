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
import jakarta.servlet.http.HttpServletRequest;

import org.forgerock.http.protocol.Request;
import org.forgerock.http.protocol.Response;
import org.forgerock.http.protocol.Status;
import org.forgerock.oauth2.core.OAuth2Request;
import org.forgerock.oauth2.core.exceptions.OAuth2Exception;
import org.forgerock.oauth2.core.exceptions.ServerException;
import org.forgerock.openam.http.annotations.Contextual;
import org.forgerock.openam.http.annotations.Get;
import org.forgerock.openam.oauth2.OAuth2Constants;
import org.forgerock.openam.services.baseurl.BaseURLProviderFactory;
import org.forgerock.openidconnect.OpenIDConnectProviderDiscovery;
import org.forgerock.services.context.Context;

/**
 * CHF WebFinger endpoint ({@code /.well-known/webfinger}), porting the Restlet {@code OpenIDConnectDiscovery}:
 * the RFC 7033 JRD naming the issuer for a resource. No cache headers.
 *
 * <p>{@code HEAD} needs no method of its own -- {@code Endpoints} maps it onto the {@code GET}. The
 * {@link org.forgerock.oauth2.core.exceptions.BadRequestException} and
 * {@link org.forgerock.oauth2.core.exceptions.NotFoundException} that {@link OpenIDConnectProviderDiscovery}
 * throws need no handler of their own either: {@code @ExceptionHandler} dispatch is polymorphic, so the base
 * class's {@code OAuth2Exception} mapper catches both.
 */
public class WebFingerHandler extends AbstractOAuth2HttpJsonEndpoint {

    @Inject
    private OpenIDConnectProviderDiscovery providerDiscovery;
    @Inject
    private BaseURLProviderFactory baseUrlProviderFactory;

    /**
     * @param ctx the request context.
     * @param request the CHF request.
     * @return 200 with the JRD as JSON.
     * @throws OAuth2Exception mapped to the JSON error body by the base handler.
     */
    @Get
    public Response discover(@Contextual Context ctx, @Contextual Request request) throws OAuth2Exception {
        OAuth2Request o2 = requestFactory.create(ctx, request);
        HttpServletRequest servletRequest = o2.getHttpServletRequest();
        if (servletRequest == null) {
            // Unreachable behind the CHF servlet, but the Restlet incumbent NPE'd here on every request;
            // naming the failure the way OAuth2UrisFactory does costs one branch and never lies about it.
            throw new ServerException("Cannot determine the deployment URL: no servlet request on the context");
        }
        String realm = o2.getParameter(OAuth2Constants.Custom.REALM);
        String deploymentUrl = baseUrlProviderFactory.get(realm).getRootURL(servletRequest);
        return new Response(Status.valueOf(200)).setEntity(providerDiscovery.discover(
                o2.<String>getParameter("resource"), o2.<String>getParameter("rel"), deploymentUrl, o2));
    }
}
