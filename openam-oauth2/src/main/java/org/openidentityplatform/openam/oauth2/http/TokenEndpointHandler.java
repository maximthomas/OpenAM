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
import static org.forgerock.openam.oauth2.OAuth2Constants.Params.GRANT_TYPE;
import static org.forgerock.openam.oauth2.OAuth2Constants.TokenEndpoint.AUTHORIZATION_CODE;
import static org.forgerock.openam.oauth2.OAuth2Constants.TokenEndpoint.CLIENT_CREDENTIALS;
import static org.forgerock.openam.oauth2.OAuth2Constants.TokenEndpoint.DEVICE_CODE;
import static org.forgerock.openam.oauth2.OAuth2Constants.TokenEndpoint.JWT_BEARER;
import static org.forgerock.openam.oauth2.OAuth2Constants.TokenEndpoint.PASSWORD;
import static org.forgerock.openam.oauth2.OAuth2Constants.TokenEndpoint.REFRESH_TOKEN;
import static org.forgerock.openam.oauth2.OAuth2Constants.TokenEndpoint.SAML2_BEARER;

import java.util.Set;

import jakarta.inject.Inject;

import org.forgerock.http.header.ContentTypeHeader;
import org.forgerock.http.protocol.Request;
import org.forgerock.http.protocol.Response;
import org.forgerock.http.protocol.Status;
import org.forgerock.oauth2.core.AccessToken;
import org.forgerock.oauth2.core.AccessTokenService;
import org.forgerock.oauth2.core.OAuth2Request;
import org.forgerock.oauth2.core.exceptions.InvalidGrantException;
import org.forgerock.oauth2.core.exceptions.InvalidRequestException;
import org.forgerock.oauth2.core.exceptions.OAuth2Exception;
import org.forgerock.oauth2.core.exceptions.UnsupportedGrantTypeException;
import org.forgerock.openam.http.annotations.Contextual;
import org.forgerock.openam.http.annotations.Post;
import org.forgerock.services.context.Context;

/**
 * CHF token endpoint ({@code /oauth2/access_token}), collapsing the Restlet {@code TokenEndpointFilter} +
 * {@code AccessTokenFlowFinder} + {@code TokenEndpointResource}/{@code RefreshTokenResource} into one handler.
 * <p>
 * A single {@code @Post} means GET/PUT/DELETE get a framework 405 without a verb check. Every failure path
 * <em>returns</em> (no Restlet CONTINUE fall-through): an {@link OAuth2Exception} rises to the base
 * {@link AbstractOAuth2HttpJsonEndpoint#onError} for the JSON error body -- including {@code WWW-Authenticate},
 * which rides on the exception and is never re-derived here.
 */
public class TokenEndpointHandler extends AbstractOAuth2HttpJsonEndpoint {

    private static final String FORM_URLENCODED = "application/x-www-form-urlencoded";

    /** The finder's known access grants -- everything it routes to {@code requestAccessToken}. */
    private static final Set<String> ACCESS_GRANTS = Set.of(
            AUTHORIZATION_CODE, CLIENT_CREDENTIALS, PASSWORD, DEVICE_CODE, JWT_BEARER, SAML2_BEARER);

    @Inject
    private AccessTokenService accessTokenService;
    @Inject
    private Set<ChfTokenRequestHook> hooks;

    /**
     * @param ctx the request context.
     * @param request the CHF request carrying the form body.
     * @return 200 with the {@code {access_token, token_type, expires_in, ...}} body on success.
     * @throws OAuth2Exception mapped to the JSON error body by the base handler.
     */
    @Post
    public Response token(@Contextual Context ctx, @Contextual Request request) throws OAuth2Exception {
        OAuth2Request o2 = requestFactory.create(ctx, request);
        validateContentType(request);
        AccessToken token = issue(o2.<String>getParameter(GRANT_TYPE), o2);
        // setEntity(Map) -> setJson -> application/json; charset=UTF-8. noCache() adds the OAuth2Filter's
        // no-store/no-cache after the entity write so it does not clobber them (error path: base onError).
        Response response = new Response(Status.valueOf(200)).setEntity(token.toMap());
        return noCache(response);
    }

    /** Reproduces the finder's gate + the two resources' service call; hooks only on the access-grant path. */
    private AccessToken issue(String grantType, OAuth2Request o2) throws OAuth2Exception {
        if (isEmpty(grantType)) {
            throw new InvalidRequestException("Grant type is not set");
        }
        boolean refresh = REFRESH_TOKEN.equals(grantType);
        if (!refresh && !ACCESS_GRANTS.contains(grantType)) {
            throw new UnsupportedGrantTypeException("Grant type is not supported");
        }
        AccessToken token;
        try {
            token = refresh ? accessTokenService.refreshToken(o2) : accessTokenService.requestAccessToken(o2);
        } catch (InvalidGrantException e) {
            // RefreshTokenResource masks the cause to "grant is invalid"; TokenEndpointResource leaves it raw.
            throw refresh ? new InvalidGrantException("grant is invalid") : e;
        } catch (IllegalArgumentException e) {
            throw new InvalidRequestException(e.getMessage());   // D2: contractual 400, not the framework's 500
        }
        if (!refresh) {   // TokenEndpointResource runs the hooks; RefreshTokenResource does not.
            for (ChfTokenRequestHook hook : hooks) {
                hook.afterTokenHandling(o2);
            }
        }
        return token;
    }

    /**
     * Reproduces {@code TokenEndpointFilter.validateContentType}: an <em>empty body</em> is never checked (the
     * filter only inspected a non-empty entity), and a null/empty content type is allowed; otherwise the type must
     * be {@code application/x-www-form-urlencoded}, matched case-insensitively (media types are, per RFC 7231, and
     * the Restlet {@code MediaType.equals} was). The charset-safe parse ({@code getType()} strips any
     * {@code ;charset=...}) is why a bare string compare against the raw header would wrongly reject a
     * {@code ;charset=UTF-8} body.
     */
    private void validateContentType(Request request) throws InvalidRequestException {
        if (request.getEntity().isRawContentEmpty()) {
            return;
        }
        String type = ContentTypeHeader.valueOf(request).getType();
        if (type != null && !type.isEmpty() && !FORM_URLENCODED.equalsIgnoreCase(type)) {
            throw new InvalidRequestException("Invalid Content Type");
        }
    }
}
