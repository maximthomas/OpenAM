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
import static org.forgerock.openam.cts.api.fields.OAuthTokenField.*;
import static org.forgerock.openam.oauth2.OAuth2Constants.CoreTokenParams.TOKEN_NAME;
import static org.forgerock.openam.oauth2.OAuth2Constants.Params.ACCESS_TOKEN;
import static org.forgerock.openam.oauth2.OAuth2Constants.Params.REFRESH_TOKEN;
import static org.forgerock.util.query.QueryFilter.and;
import static org.forgerock.util.query.QueryFilter.equalTo;

import java.util.Collections;

import jakarta.inject.Inject;

import org.forgerock.http.protocol.Request;
import org.forgerock.http.protocol.Response;
import org.forgerock.http.protocol.Status;
import org.forgerock.json.JsonValue;
import org.forgerock.oauth2.core.ClientAuthenticator;
import org.forgerock.oauth2.core.ClientRegistration;
import org.forgerock.oauth2.core.OAuth2Request;
import org.forgerock.oauth2.core.TokenStore;
import org.forgerock.oauth2.core.exceptions.InvalidGrantException;
import org.forgerock.oauth2.core.exceptions.InvalidRequestException;
import org.forgerock.oauth2.core.exceptions.NotFoundException;
import org.forgerock.oauth2.core.exceptions.OAuth2Exception;
import org.forgerock.oauth2.core.exceptions.ServerException;
import org.forgerock.openam.http.annotations.Contextual;
import org.forgerock.openam.http.annotations.Post;
import org.forgerock.openam.oauth2.OAuth2Constants.CoreTokenParams;
import org.forgerock.openam.oauth2.OAuth2RealmResolver;
import org.forgerock.openam.tokens.CoreTokenField;
import org.forgerock.openam.utils.CollectionUtils;
import org.forgerock.services.context.Context;
import org.forgerock.util.query.QueryFilter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * CHF token revocation endpoint ({@code /oauth2/token/revoke}), porting the Restlet {@code TokenRevocationResource}.
 * <p>
 * POST only. Authenticates the client, verifies token ownership, and cascade-deletes (a single access token, or a
 * refresh token plus all its access tokens), returning an empty {@code {}} at 200. No cache headers (5a-2 finding 1).
 * <p>
 * <strong>Challenge (D4):</strong> an {@code InvalidClientAuthZHeaderException} is thrown bare -- the base
 * {@code onError} copies its challenge and emits {@code WWW-Authenticate: Basic realm="…"}; the Restlet's manual
 * {@code ChallengeRequest} decoration is dropped.
 * <p>
 * <strong>No {@code CoreTokenException} catch:</strong> the Restlet caught it, but {@link TokenStore#read(String)}
 * throws only the OAuth2 {@code ServerException}/{@code NotFoundException} and nothing else in the flow throws
 * {@code CoreTokenException} -- the Restlet catch was unreachable dead code (its {@code getToken} merely over-declared
 * {@code throws CoreTokenException}). Omitting it is byte-parity-safe. (D4 as written aimed to keep that path at 500 via
 * {@code new ServerException}, but {@code ServerException} is 400 and no OAuth2 exception maps to 500 -- moot here.)
 */
public class TokenRevocationHandler extends AbstractOAuth2HttpJsonEndpoint {

    private final Logger logger = LoggerFactory.getLogger("OAuth2Provider");

    @Inject
    private ClientAuthenticator clientAuthenticator;
    @Inject
    private TokenStore tokenStore;
    @Inject
    private OAuth2RealmResolver realmResolver;

    /**
     * @param ctx the request context.
     * @param request the CHF POST request; the {@code token} parameter names the token to revoke.
     * @return 200 with an empty JSON object.
     * @throws OAuth2Exception mapped to the JSON error body (challenge included where present) by the base handler.
     */
    @Post
    public Response revoke(@Contextual Context ctx, @Contextual Request request) throws OAuth2Exception {
        OAuth2Request o2 = requestFactory.create(ctx, request);
        String realm = realmResolver.resolveFrom(o2);
        String tokenId = o2.getParameter("token");

        if (isEmpty(tokenId)) {
            throw new InvalidRequestException("Missing parameter: token");
        }
        String clientId = clientAuthenticator.authenticate(o2, null).getClientId();
        JsonValue token = getToken(clientId, tokenId);
        if (token != null) {
            String tokenName = getAttributeValue(token, TOKEN_NAME);
            switch (tokenName) {
                case ACCESS_TOKEN:
                    deleteAccessToken(realm, tokenId);
                    break;
                case REFRESH_TOKEN:
                    deleteRefreshTokenAndAccessTokens(realm, token, clientId);
                    break;
                default:
                    throw new InvalidRequestException("Invalid token name: " + tokenName);
            }
        }
        return new Response(Status.valueOf(200)).setEntity(Collections.emptyMap());
    }

    private void deleteAccessToken(String realm, String tokenId) throws ServerException, NotFoundException {
        try {
            tokenStore.delete(realm, tokenId);
        } catch (ServerException e) {
            logger.error("Failed to delete access token with id :" + tokenId, e);
            throw new ServerException("Failed to revoke access token");
        }
    }

    private void deleteRefreshTokenAndAccessTokens(String realm, JsonValue token, String clientId)
            throws ServerException, NotFoundException {
        String userName = getAttributeValue(token, USER_NAME.getOAuthField());
        String authGrantId = getAttributeValue(token, CoreTokenParams.AUTH_GRANT_ID);
        int deletedTokens = 0;
        try {
            JsonValue userTokens = getTokens(realm, clientId, userName, authGrantId);
            String tokenId = null;
            for (JsonValue userToken : userTokens) {
                try {
                    tokenId = getAttributeValue(userToken, ID.getOAuthField());
                    tokenStore.delete(realm, tokenId);
                    deletedTokens++;
                } catch (ServerException e) {
                    logger.error("Failed to delete token with id :" + tokenId, e);
                }
            }
            int allTokens = userTokens.size();
            if (deletedTokens < allTokens) {
                logger.error("Failed to revoke " + (allTokens - deletedTokens) + " from " + allTokens + " tokens");
            }
        } catch (ServerException | NotFoundException e) {
            logger.error("Failed to fetch all the related tokens for the client :"
                    + clientId + "and user name :" + userName, e);
            throw new ServerException("Failed to revoke refresh and access tokens");
        }
    }

    private JsonValue getTokens(String realm, String clientId, String userName, String authGrantId)
            throws ServerException, NotFoundException {
        QueryFilter<CoreTokenField> allTokensQuery = and(equalTo(USER_NAME.getField(), userName),
                equalTo(CLIENT_ID.getField(), clientId), equalTo(AUTH_GRANT_ID.getField(), authGrantId));
        return tokenStore.queryForToken(realm, allTokensQuery);
    }

    private JsonValue getToken(String clientId, String tokenId)
            throws InvalidGrantException, ServerException, NotFoundException {
        JsonValue token = tokenStore.read(tokenId);
        if (token != null) {
            String tokenClientId = getAttributeValue(token, CLIENT_ID.getOAuthField());
            if (!clientId.equals(tokenClientId)) {
                throw new InvalidGrantException("The provided token id : "
                        + tokenId + " belongs to different access grant.");
            }
        }
        return token;
    }

    private String getAttributeValue(JsonValue token, String attributeName) {
        String value = null;
        JsonValue jsonValue = token.get(attributeName);
        if (jsonValue.isString()) {
            value = jsonValue.asString();
        } else if (jsonValue.isCollection()) {
            value = CollectionUtils.getFirstItem(jsonValue.asCollection(String.class));
        }
        return value;
    }
}
