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
import org.forgerock.openam.oauth2.OAuth2Constants;
import org.forgerock.openam.oauth2.OAuth2Utils;
import org.forgerock.openidconnect.OpenIdConnectClientRegistrationService;
import org.forgerock.services.context.Context;

/**
 * CHF OpenID Connect dynamic client registration endpoint ({@code /oauth2/connect/register}), porting the Restlet
 * {@code ConnectClientRegistration}.
 * <p>
 * Two methods -- {@code @Post createClient} (201) and {@code @Get getClient} (200) -- because register and read are
 * genuinely different calls, not one shared body (5a-2 D5). No cache headers (5a-2 finding 1).
 * <p>
 * <strong>Bearer token (both verbs):</strong> {@link OAuth2Request#getAuthorizationBearerToken()} returns {@code null}
 * gracefully when no {@code Authorization} header is present, so the service's own auth check yields a proper 401. The
 * Restlet resource read the GET token <em>unguarded</em> ({@code getChallengeResponse().getRawValue()}) and NPEd to a
 * 500 on a missing header -- fixing that is a deliberate, documented 5d-1 divergence.
 * <p>
 * <strong>Deployment URL (POST):</strong> reconstructed raw from the servlet request via
 * {@link OAuth2Utils#getDeploymentURL} ({@code scheme://host:port/<first-segment>}, e.g. {@code https://host:8443/openam})
 * -- byte-parity with the Restlet resource's {@code getHostRef() + "/" + getResourceRef().getSegments().get(0)}, not the
 * <em>configured</em> {@code BaseURLProviderFactory} root URL (which can diverge under a forwarded-header/fixed-value
 * provider config). {@code OAuth2Utils.getDeploymentURL} already produces that exact shape, so it is reused rather than
 * re-derived (5a-2 finding 5).
 */
public class ConnectClientRegistrationHandler extends AbstractOAuth2HttpJsonEndpoint {

    @Inject
    private OpenIdConnectClientRegistrationService clientRegistrationService;
    @Inject
    private OAuth2Utils oAuth2Utils;

    /**
     * @param ctx the request context.
     * @param request the CHF POST request carrying the client-registration metadata.
     * @return 201 with the created client registration as JSON.
     * @throws OAuth2Exception mapped to the JSON error body by the base handler.
     */
    @Post
    public Response createClient(@Contextual Context ctx, @Contextual Request request) throws OAuth2Exception {
        OAuth2Request o2 = requestFactory.create(ctx, request);
        String accessToken = o2.getAuthorizationBearerToken();
        String deploymentUrl = oAuth2Utils.getDeploymentURL(o2.getHttpServletRequest());
        return new Response(Status.valueOf(201))
                .setEntity(clientRegistrationService.createRegistration(accessToken, deploymentUrl, o2).asMap());
    }

    /**
     * @param ctx the request context.
     * @param request the CHF GET request; the {@code client_id} query parameter selects the registration.
     * @return 200 with the client registration as JSON.
     * @throws OAuth2Exception mapped to the JSON error body by the base handler.
     */
    @Get
    public Response getClient(@Contextual Context ctx, @Contextual Request request) throws OAuth2Exception {
        OAuth2Request o2 = requestFactory.create(ctx, request);
        String clientId = o2.getParameter(OAuth2Constants.OAuth2Client.CLIENT_ID);
        String accessToken = o2.getAuthorizationBearerToken();
        return new Response(Status.valueOf(200))
                .setEntity(clientRegistrationService.getRegistration(clientId, accessToken, o2).asMap());
    }
}
