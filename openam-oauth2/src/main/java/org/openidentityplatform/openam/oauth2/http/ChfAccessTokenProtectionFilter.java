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

import static org.forgerock.util.promise.Promises.newResultPromise;

import org.forgerock.http.Filter;
import org.forgerock.http.Handler;
import org.forgerock.http.protocol.Request;
import org.forgerock.http.protocol.Response;
import org.forgerock.http.protocol.Status;
import org.forgerock.json.resource.ResourceException;
import org.forgerock.oauth2.core.AccessToken;
import org.forgerock.oauth2.core.OAuth2Request;
import org.forgerock.oauth2.core.OAuth2RequestFactory;
import org.forgerock.oauth2.core.TokenStore;
import org.forgerock.oauth2.core.exceptions.InsufficientScopeException;
import org.forgerock.oauth2.core.exceptions.InvalidGrantException;
import org.forgerock.oauth2.core.exceptions.InvalidTokenException;
import org.forgerock.oauth2.core.exceptions.NotFoundException;
import org.forgerock.oauth2.core.exceptions.ServerException;
import org.forgerock.services.context.Context;
import org.forgerock.util.promise.NeverThrowsException;
import org.forgerock.util.promise.Promise;

import com.sun.identity.shared.debug.Debug;

/**
 * A CHF {@link Filter} that fetches a bearer access token from the {@code Authorization} header and
 * verifies it against the internal token store, enforcing an optional required scope.
 *
 * <p>The CHF counterpart of the Restlet {@code AccessTokenProtectionFilter}. Shared by {@code /uma}
 * (Phase 4) and, later, {@code /oauth2/resource_set} (Phase 5c).
 */
public class ChfAccessTokenProtectionFilter implements Filter {

    private final Debug debug = Debug.getInstance("UmaProvider");
    private final String requiredScope;
    private final TokenStore tokenStore;
    private final OAuth2RequestFactory requestFactory;

    /**
     * @param requiredScope The scope the access token must carry; {@code null} skips the scope check.
     * @param tokenStore The token store the bearer token is read from.
     * @param requestFactory Builds (and caches) the {@link org.forgerock.oauth2.core.OAuth2Request}.
     */
    public ChfAccessTokenProtectionFilter(String requiredScope, TokenStore tokenStore,
            OAuth2RequestFactory requestFactory) {
        this.requiredScope = requiredScope;
        this.tokenStore = tokenStore;
        this.requestFactory = requestFactory;
    }

    @Override
    public Promise<Response, NeverThrowsException> filter(Context context, Request request, Handler next) {
        // The same cached instance the audit filter and the endpoint see, so the token stash below is
        // visible downstream via getToken(AccessToken.class).
        OAuth2Request oAuth2Request = requestFactory.create(context, request);
        String tokenId = oAuth2Request.getAuthorizationBearerToken();
        if (tokenId == null) {
            return crestError(401, new InvalidTokenException());
        }
        try {
            AccessToken accessToken = tokenStore.readAccessToken(oAuth2Request, tokenId);
            if (accessToken == null || accessToken.isExpired()) {
                return crestError(401, new InvalidTokenException());
            }
            if (requiredScope != null && !accessToken.getScope().contains(requiredScope)) {
                return crestError(403, new InsufficientScopeException(requiredScope));
            }
            oAuth2Request.setToken(AccessToken.class, accessToken);
        } catch (ServerException e) {
            return crestError(500, e);
        } catch (NotFoundException e) {
            debug.message("Error loading token with id: " + tokenId, e);
            return crestError(404, e);
        } catch (InvalidGrantException e) {
            debug.message("Error loading token with id: " + tokenId, e);
            return crestError(401, new InvalidTokenException());
        }
        return next.handle(context, request);
    }

    /**
     * Reproduces the CREST {@code {code, reason, message}} body the Restlet {@code StatusFilter} rendered
     * for the filter's bare error status -- deliberately no OAuth2 {@code error} field and no
     * {@code WWW-Authenticate} (D5). {@code setEntity(Map)} supplies {@code application/json; charset=UTF-8}.
     */
    private Promise<Response, NeverThrowsException> crestError(int code, Exception exception) {
        Response response = new Response(Status.valueOf(code));
        response.setEntity(ResourceException.newResourceException(code, exception.getMessage()).toJsonValue().getObject());
        return newResultPromise(response);
    }
}
