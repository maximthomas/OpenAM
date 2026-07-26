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
 * Copyright 2015-2016 ForgeRock AS.
 * Portions copyright 2025-2026 3A Systems LLC.
 */

package org.forgerock.openam.uma;

import jakarta.inject.Inject;
import jakarta.servlet.http.HttpServletRequest;
import java.net.URI;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import com.google.inject.Singleton;
import org.forgerock.json.resource.http.HttpContext;
import org.forgerock.oauth2.core.OAuth2Request;
import org.forgerock.oauth2.core.RestletOAuth2Request;
import org.forgerock.oauth2.core.OAuth2Uris;
import org.forgerock.oauth2.core.exceptions.NotFoundException;
import org.forgerock.oauth2.core.exceptions.ServerException;
import org.forgerock.openam.core.realms.Realm;
import org.forgerock.openam.oauth2.OAuth2UrisFactory;
import org.forgerock.openam.rest.representations.JacksonRepresentationFactory;
import org.forgerock.openam.rest.service.RestletRealmRouter;
import org.forgerock.openam.services.baseurl.BaseURLProvider;
import org.forgerock.openam.services.baseurl.BaseURLProviderFactory;
import org.forgerock.openam.services.baseurl.InvalidBaseUrlException;
import org.forgerock.services.context.Context;
import org.openidentityplatform.openam.http.ChfContexts;
import org.restlet.Request;

/**
 * <p>A factory for creating/retrieving UmaUris instances.</p>
 *
 * @since 13.0.0
 */
@Singleton
public class UmaUrisFactory {

    // Concurrent, not plain: the lookups below read this map outside getUmaUris' monitor, and /uma/.well-known
    // /uma-configuration is public, so two cold requests can race a resize. OAuth2UrisFactory already does this.
    private final Map<String, UmaUris> urisMap = new ConcurrentHashMap<>();
    private final OAuth2UrisFactory oAuth2UriFactory;
    private final UmaProviderSettingsFactory umaProviderSettingsFactory;
    private final BaseURLProviderFactory baseURLProviderFactory;
    private final JacksonRepresentationFactory jacksonRepresentationFactory;

    /**
     * Constructs a new UmaUrisFactory.
     *
     * @param oAuth2UriFactory An instance of the OAuth2UrisFactory.
     * @param umaProviderSettingsFactory An instance of the UmaProviderSettingsFactory.
     * @param baseURLProviderFactory An instance of the BaseURLProviderFactory.
     */
    @Inject
    UmaUrisFactory(OAuth2UrisFactory oAuth2UriFactory, UmaProviderSettingsFactory umaProviderSettingsFactory,
            BaseURLProviderFactory baseURLProviderFactory, JacksonRepresentationFactory jacksonRepresentationFactory) {
        this.oAuth2UriFactory = oAuth2UriFactory;
        this.umaProviderSettingsFactory = umaProviderSettingsFactory;
        this.baseURLProviderFactory = baseURLProviderFactory;
        this.jacksonRepresentationFactory = jacksonRepresentationFactory;
    }

    /**
     * Gets a UmaUris instance.
     *
     * @param req The Restlet request.
     * @return A UmaProviderSettings instance.
     */
    UmaUris get(Request req) throws NotFoundException, ServerException {
        return get(new RestletOAuth2Request(jacksonRepresentationFactory, req));
    }

    public UmaUris get(OAuth2Request request) throws NotFoundException, ServerException {
        Realm realm = request.getParameter(RestletRealmRouter.REALM_OBJECT);
        return get(request, realm);
    }

    /**
     * <p>Gets the instance of the UmaUris.</p>
     *
     * <p>Cache each provider settings on the realm it was created for.</p>
     *
     * @param oAuth2Request The request instance from which the base URL can be deduced.
     * @param realm The realm.
     * @return The OAuth2ProviderSettings instance.
     */
    public UmaUris get(OAuth2Request oAuth2Request, Realm realm) throws NotFoundException, ServerException {

        String baseUrl;
        HttpServletRequest request = oAuth2Request.getHttpServletRequest();
        try {
            baseUrl = baseURLProviderFactory.get(realm.asPath()).getRealmURL(request, "/uma", realm);
        } catch (InvalidBaseUrlException e) {
            throw new ServerException("Configuration error");
        }
        UmaUris uris = urisMap.get(baseUrl);
        if (uris == null) {
            OAuth2Uris oAuth2Uris = oAuth2UriFactory.get(oAuth2Request, realm);
            uris = getUmaUris(realm.asPath(), oAuth2Uris, baseUrl);
        }
        return uris;
    }

    /**
     * <p>Gets the instance of the UmaProviderSettings.</p>
     *
     * <p>Cache each provider settings on the realm it was created for.</p>
     *
     * @param context The context instance from which the base URL can be deduced.
     * @param realm The realm.
     * @return The OAuth2ProviderSettings instance.
     */
    public UmaUris get(Context context, Realm realm) throws NotFoundException, ServerException {
        String baseUrl;
        try {
            BaseURLProvider baseUrlProvider = baseURLProviderFactory.get(realm.asPath());
            // A plain CHF chain (HttpFrameworkServlet -> Endpoints.from) carries NO CREST HttpContext -- only
            // the servlet request, in the AttributesContext. Asking for HttpContext unconditionally is what
            // made /uma/.well-known/uma-configuration a 500 after the phase-4 flip. Prefer the servlet
            // request; fall back to HttpContext so a CREST-routed caller keeps working. If a chain offers
            // neither, say so: letting asContext raise IllegalArgumentException reproduces exactly the
            // opaque 500 this method was fixed to stop producing.
            HttpServletRequest servletRequest = ChfContexts.servletRequest(context);
            if (servletRequest != null) {
                baseUrl = baseUrlProvider.getRealmURL(servletRequest, "/uma", realm);
            } else if (context.containsContext(HttpContext.class)) {
                baseUrl = baseUrlProvider.getRealmURL(context.asContext(HttpContext.class), "/uma", realm);
            } else {
                throw new ServerException("Cannot determine the base URL: the request carries neither a "
                        + "servlet request nor an HttpContext");
            }
        } catch (InvalidBaseUrlException e) {
            throw new ServerException("Configuration error");
        }
        UmaUris uris = urisMap.get(baseUrl);
        if (uris == null) {
            OAuth2Uris oAuth2Uris = oAuth2UriFactory.get(context, realm);
            uris = get(realm.asPath(), oAuth2Uris, baseUrl);
        }
        return uris;
    }

    private UmaUris get(String absoluteRealm, OAuth2Uris oAuth2Uris, String baseUrlPattern) throws NotFoundException {
        UmaUris uris = urisMap.get(baseUrlPattern);
        if (uris == null) {
            uris = getUmaUris(absoluteRealm, oAuth2Uris, baseUrlPattern);
        }
        return uris;
    }

    private synchronized UmaUris getUmaUris(String absoluteRealm, OAuth2Uris oAuth2Uris, String baseUrlPattern)
            throws NotFoundException {
        UmaUris uris = urisMap.get(baseUrlPattern);
        if (uris != null) {
            return uris;
        }
        UmaProviderSettings umaProviderSettings = umaProviderSettingsFactory.get(absoluteRealm);
        UmaUris providerSettings = new UmaUrisImpl(baseUrlPattern, umaProviderSettings, oAuth2Uris);
        urisMap.put(baseUrlPattern, providerSettings);
        return providerSettings;
    }

    static final class UmaUrisImpl implements UmaUris {

        private final UmaProviderSettings umaProviderSettings;
        private final OAuth2Uris oauth2Uris;
        private final String baseUrl;

        UmaUrisImpl(String deploymentUrl, UmaProviderSettings umaProviderSettings,
                OAuth2Uris oauth2Uris) throws NotFoundException {
            this.umaProviderSettings = umaProviderSettings;
            this.oauth2Uris = oauth2Uris;
            this.baseUrl = deploymentUrl;
        }

        @Override
        public boolean isEnabled() {
            return umaProviderSettings.isEnabled();
        }

        @Override
        public URI getIssuer() throws ServerException {
            return URI.create(oauth2Uris.getIssuer());
        }

        @Override
        public URI getTokenEndpoint() {
            return URI.create(oauth2Uris.getTokenEndpoint());
        }

        @Override
        public URI getAuthorizationEndpoint() {
            return URI.create(oauth2Uris.getAuthorizationEndpoint());
        }

        @Override
        public URI getTokenIntrospectionEndpoint() {
            return URI.create(oauth2Uris.getIntrospectionEndpoint());
        }

        @Override
        public URI getResourceSetRegistrationEndpoint() {
            return URI.create(oauth2Uris.getResourceSetRegistrationEndpoint());
        }

        @Override
        public URI getPermissionRegistrationEndpoint() {
            return URI.create(baseUrl + "/permission_request");
        }

        @Override
        public URI getRPTEndpoint() {
            return URI.create(baseUrl + "/authz_request");
        }

        @Override
        public URI getDynamicClientEndpoint() {
            return URI.create(oauth2Uris.getClientRegistrationEndpoint());
        }

        /**
         * OpenAM currently does not support requesting party claims so no endpoint isEnabled.
         *
         * @return {@code null}.
         */
        @Override
        public URI getRequestingPartyClaimsEndpoint() {
            return null;
        }

    }
}
