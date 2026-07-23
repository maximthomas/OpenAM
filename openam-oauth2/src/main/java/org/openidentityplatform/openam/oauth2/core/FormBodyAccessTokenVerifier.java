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
 * Copyright 2014-2016 ForgeRock AS.
 * Portions copyright 2025-2026 3A Systems LLC.
 */
package org.openidentityplatform.openam.oauth2.core;

import jakarta.inject.Inject;
import jakarta.inject.Singleton;

import org.forgerock.oauth2.core.AccessTokenVerifier;
import org.forgerock.oauth2.core.OAuth2Request;
import org.forgerock.oauth2.core.TokenStore;
import org.forgerock.openam.oauth2.OAuth2Constants;

/**
 * Verifies that an OAuth2 request made to one of the protected endpoints on the OAuth2 provider
 * (i.e. tokeninfo, userinfo) contains a valid access token specified in the request body.
 */
@Singleton
public class FormBodyAccessTokenVerifier extends AccessTokenVerifier {

    @Inject
    public FormBodyAccessTokenVerifier(TokenStore tokenStore) {
        super(tokenStore);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    protected String obtainTokenId(OAuth2Request request) {
        final String tokenId = request.getFormParameter(OAuth2Constants.Params.ACCESS_TOKEN);

        if (tokenId == null) {
            logger.debug("Request form is absent or does not contain access_token.");
        }

        return tokenId;
    }
}
