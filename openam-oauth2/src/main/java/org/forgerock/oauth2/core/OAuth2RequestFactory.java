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
 * Portions copyright 2025 3A Systems LLC.
 */

package org.forgerock.oauth2.core;

import jakarta.inject.Inject;
import jakarta.inject.Singleton;
import jakarta.servlet.http.HttpServletRequest;

import java.util.Map;

import org.forgerock.oauth2.core.exceptions.InvalidClientException;
import org.forgerock.oauth2.core.exceptions.NotFoundException;
import org.forgerock.openam.oauth2.OAuth2Constants;
import org.forgerock.openam.rest.representations.JacksonRepresentationFactory;
import org.forgerock.openam.utils.StringUtils;
import org.forgerock.services.context.AttributesContext;
import org.forgerock.services.context.Context;
import org.restlet.Request;
import org.forgerock.openam.rest.jakarta.servlet.ServletUtils;

import com.sun.identity.shared.debug.Debug;

/**
 * A factory for creating OAuth2Request instances.
 *
 * @since 12.0.0
 */
@Singleton
public class OAuth2RequestFactory {

    private final Debug logger = Debug.getInstance("OAuth2Provider");

    private static final String OAUTH2_REQ_ATTR = "OAUTH2_REQ_ATTR";
    private final JacksonRepresentationFactory jacksonRepresentationFactory;
    private final ClientRegistrationStore clientRegistrationStore;

    /**
     * Guice injection constructor.
     * @param jacksonRepresentationFactory The factory for {@code JacksonRepresentation} instances.
     * @param clientRegistrationStore The OAuth2 providers store for all client registrations.
     */
    @Inject
    public OAuth2RequestFactory(JacksonRepresentationFactory jacksonRepresentationFactory,
            ClientRegistrationStore clientRegistrationStore) {
        this.jacksonRepresentationFactory = jacksonRepresentationFactory;
        this.clientRegistrationStore = clientRegistrationStore;
    }

    /**
     * Creates a new OAuth2Request for the underlying HTTP request.
     *
     * @param request The underlying request.
     * @return The OAuth2Request.
     */
    public OAuth2Request create(Request request) {
        HttpServletRequest httpRequest = ServletUtils.getRequest(request);
        OAuth2Request o2request = getOAuth2Request(httpRequest);
        if (o2request == null) {
            o2request = new RestletOAuth2Request(jacksonRepresentationFactory, request);
            addClientRegistrationToOAuth2Request(httpRequest, o2request);
            setOauth2RequestAttributeOnHttpRequest(httpRequest, o2request);
        }
        return o2request;
    }

    /**
     * Creates a new OAuth2Request for the underlying CHF request, caching it on the request's
     * {@link AttributesContext} so that the collaborators of a single request share one instance.
     *
     * @param context The CHF context.
     * @param request The CHF request.
     * @return The OAuth2Request.
     */
    public OAuth2Request create(Context context, org.forgerock.http.protocol.Request request) {
        Map<String, Object> attributes = context.asContext(AttributesContext.class).getAttributes();
        OAuth2Request o2request = (OAuth2Request) attributes.get(OAUTH2_REQ_ATTR);
        if (o2request == null) {
            o2request = new ChfOAuth2Request(context, request);
            // Publish before resolving the registration: the store is handed this same request.
            attributes.put(OAUTH2_REQ_ATTR, o2request);
            addClientRegistrationToOAuth2Request(o2request);
        }
        return o2request;
    }

    private OAuth2Request getOAuth2Request(HttpServletRequest httpRequest) {
        return httpRequest == null ? null : (OAuth2Request) httpRequest.getAttribute(OAUTH2_REQ_ATTR);
    }

    private void addClientRegistrationToOAuth2Request(HttpServletRequest httpRequest, OAuth2Request o2request) {
        if (httpRequest == null) {
            return;
        }

        setClientRegistration(o2request, httpRequest.getParameter(OAuth2Constants.Params.CLIENT_ID));
    }

    private void addClientRegistrationToOAuth2Request(OAuth2Request o2request) {
        setClientRegistration(o2request, o2request.<String>getParameter(OAuth2Constants.Params.CLIENT_ID));
    }

    private void setClientRegistration(OAuth2Request o2request, String clientId) {
        if (StringUtils.isNotBlank(clientId)) {
            try {
                ClientRegistration clientRegistration = clientRegistrationStore.get(clientId, o2request);
                o2request.setClientRegistration(clientRegistration);
            } catch (InvalidClientException | NotFoundException e) {
                logger.error("Unable to get Client Registration for client_Id = " + clientId, e);
            }
        }
    }

    private void setOauth2RequestAttributeOnHttpRequest(HttpServletRequest httpRequest, OAuth2Request o2request) {
        if (httpRequest != null) {
            httpRequest.setAttribute(OAUTH2_REQ_ATTR, o2request);
        }
    }
}
