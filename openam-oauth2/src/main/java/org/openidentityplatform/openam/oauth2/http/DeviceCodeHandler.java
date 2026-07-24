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

import static org.forgerock.openam.oauth2.OAuth2Constants.Custom.*;
import static org.forgerock.openam.oauth2.OAuth2Constants.DeviceCode.*;
import static org.forgerock.openam.oauth2.OAuth2Constants.Params.*;
import static org.forgerock.openam.utils.StringUtils.isEmpty;

import java.util.HashMap;
import java.util.Map;

import jakarta.inject.Inject;
import jakarta.servlet.http.HttpServletRequest;

import org.forgerock.http.protocol.Request;
import org.forgerock.http.protocol.Response;
import org.forgerock.http.protocol.Status;
import org.forgerock.oauth2.core.ClientRegistrationStore;
import org.forgerock.oauth2.core.DeviceCode;
import org.forgerock.oauth2.core.OAuth2ProviderSettings;
import org.forgerock.oauth2.core.OAuth2ProviderSettingsFactory;
import org.forgerock.oauth2.core.OAuth2Request;
import org.forgerock.oauth2.core.TokenStore;
import org.forgerock.oauth2.core.exceptions.BadRequestException;
import org.forgerock.oauth2.core.exceptions.OAuth2Exception;
import org.forgerock.openam.http.annotations.Contextual;
import org.forgerock.openam.http.annotations.Post;
import org.forgerock.openam.oauth2.OAuth2Constants;
import org.forgerock.openam.oauth2.OAuth2Utils;
import org.forgerock.openam.services.baseurl.BaseURLProviderFactory;
import org.forgerock.openam.utils.StringUtils;
import org.forgerock.services.context.Context;

/**
 * CHF device authorization endpoint ({@code /oauth2/device/code}), porting the Restlet {@code DeviceCodeResource}.
 * <p>
 * POST only. Missing {@code client_id}/{@code scope}/{@code response_type} &rarr; 400 {@code bad_request} (byte-parity
 * with the Restlet resource -- <em>not</em> {@code invalid_request}). No cache headers (5a-2 finding 1).
 * <p>
 * The {@code verification_uri} fallback uses the <em>configured</em> {@code getRootURL} (finding 5, line 167):
 * unlike {@link ConnectClientRegistrationHandler}'s raw reconstruction, this endpoint deliberately keeps the
 * base-URL-provider derivation the Restlet resource used -- the two derivations are not unified.
 */
public class DeviceCodeHandler extends AbstractOAuth2HttpJsonEndpoint {

    @Inject
    private TokenStore tokenStore;
    @Inject
    private ClientRegistrationStore clientRegistrationStore;
    @Inject
    private OAuth2ProviderSettingsFactory providerSettingsFactory;
    @Inject
    private BaseURLProviderFactory baseURLProviderFactory;
    @Inject
    private OAuth2Utils oAuth2Utils;

    /**
     * @param ctx the request context.
     * @param request the CHF POST request carrying the device-authorization parameters.
     * @return 200 with {@code device_code}/{@code user_code}/{@code expires_in}/{@code interval}/{@code verification_uri}.
     * @throws OAuth2Exception mapped to the JSON error body (with {@code state} echoed) by the base handler.
     */
    @Post
    public Response issueCode(@Contextual Context ctx, @Contextual Request request) throws OAuth2Exception {
        OAuth2Request o2 = requestFactory.create(ctx, request);

        // client_id, scope and response_type are required; all other parameters are optional.
        String clientId = o2.getParameter(CLIENT_ID);
        String scope = o2.getParameter(SCOPE);
        String responseType = o2.getParameter(RESPONSE_TYPE);
        if (isEmpty(clientId) || isEmpty(scope) || isEmpty(responseType)) {
            throw new BadRequestException("client_id, scope and response_type are required parameters");
        }
        clientRegistrationStore.get(clientId, o2);   // fails fast if the client is unknown

        String maxAge = o2.getParameter(MAX_AGE);
        DeviceCode code = tokenStore.createDeviceCode(
                oAuth2Utils.split(scope, " "),
                null,
                clientId,
                o2.<String>getParameter(NONCE),
                o2.<String>getParameter(RESPONSE_TYPE),
                o2.<String>getParameter(STATE),
                o2.<String>getParameter(ACR_VALUES),
                o2.<String>getParameter(PROMPT),
                o2.<String>getParameter(UI_LOCALES),
                o2.<String>getParameter(LOGIN_HINT),
                maxAge == null ? null : Integer.valueOf(maxAge),
                o2.<String>getParameter(CLAIMS),
                o2,
                o2.<String>getParameter(CODE_CHALLENGE),
                o2.<String>getParameter(CODE_CHALLENGE_METHOD));

        OAuth2ProviderSettings providerSettings = providerSettingsFactory.get(o2);
        Map<String, Object> result = new HashMap<>();
        result.put(DEVICE_CODE, code.getDeviceCode());
        result.put(USER_CODE, code.getUserCode());
        result.put(EXPIRES_IN, providerSettings.getDeviceCodeLifetime());
        result.put(INTERVAL, providerSettings.getDeviceCodePollInterval());

        String verificationUrl = providerSettings.getVerificationUrl();
        if (StringUtils.isBlank(verificationUrl)) {
            HttpServletRequest servletRequest = o2.getHttpServletRequest();
            String realm = o2.getParameter(OAuth2Constants.Custom.REALM);
            verificationUrl = baseURLProviderFactory.get(realm).getRootURL(servletRequest) + "/oauth2/device/user";
        }
        result.put(VERIFICATION_URI, verificationUrl);

        return new Response(Status.valueOf(200)).setEntity(result);
    }
}
