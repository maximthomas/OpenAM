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

import java.util.Locale;
import java.util.Set;

import jakarta.inject.Inject;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import com.sun.identity.authentication.util.ISAuthConstants;

import org.forgerock.http.protocol.Request;
import org.forgerock.http.protocol.Response;
import org.forgerock.http.protocol.Status;
import org.forgerock.json.JsonValue;
import org.forgerock.json.jose.exceptions.InvalidJwtException;
import org.forgerock.json.jose.jws.JwsAlgorithm;
import org.forgerock.json.jose.jws.JwsAlgorithmType;
import org.forgerock.json.jose.jwt.JwtClaimsSet;
import org.forgerock.oauth2.core.ClientAuthenticator;
import org.forgerock.oauth2.core.OAuth2Jwt;
import org.forgerock.oauth2.core.OAuth2ProviderSettingsFactory;
import org.forgerock.oauth2.core.OAuth2Request;
import org.forgerock.oauth2.core.exceptions.BadRequestException;
import org.forgerock.oauth2.core.exceptions.InvalidClientException;
import org.forgerock.oauth2.core.exceptions.OAuth2Exception;
import org.forgerock.openam.core.realms.Realm;
import org.forgerock.openam.core.realms.RealmLookupException;
import org.forgerock.openam.http.annotations.Contextual;
import org.forgerock.openam.http.annotations.Post;
import org.forgerock.openam.oauth2.OAuth2Constants;
import org.forgerock.openam.oauth2.OAuth2UrisFactory;
import org.forgerock.openam.utils.CollectionUtils;
import org.forgerock.openam.utils.JsonValueBuilder;
import org.forgerock.openam.utils.StringUtils;
import org.forgerock.openidconnect.OpenIdConnectClientRegistration;
import org.forgerock.openidconnect.OpenIdConnectClientRegistrationStore;
import org.forgerock.openidconnect.OpenIdConnectToken;
import org.forgerock.services.context.Context;
import org.openidentityplatform.openam.oauth2.core.BasicAuthHeader;

/**
 * CHF id_token validation endpoint ({@code /oauth2/idtokeninfo}), porting the Restlet {@code IdTokenInfo}.
 * <p>
 * POST only. The operative realm comes from the id_token's {@code realm} claim (not the URL), and is injected back
 * onto the request so the three downstream collaborators that read the plain request see it (D3). No cache headers.
 * <p>
 * Two non-base error mappings kept from the Restlet: an {@link InvalidClientException} (audience/client-auth failure)
 * is remapped to 400 with the fixed message {@code "no registered client matches audience of id_token"}, and a
 * {@link RealmLookupException} (not an {@code OAuth2Exception}, so the base could not map it) becomes a 400
 * {@code Invalid realm}. Both are reproduced via {@link BadRequestException} -- {@code InvalidClientException} has no
 * public message constructor, and no {@code OAuth2Exception} maps to 500, so {@code BadRequestException(error, message)}
 * ({@code super(400, …)}) is the byte-parity vehicle for both.
 */
public class IdTokenInfoHandler extends AbstractOAuth2HttpJsonEndpoint {

    @Inject
    private OpenIdConnectClientRegistrationStore clientRegistrationStore;
    @Inject
    private ClientAuthenticator clientAuthenticator;
    @Inject
    private OAuth2UrisFactory urisFactory;
    @Inject
    private OAuth2ProviderSettingsFactory providerSettingsFactory;

    /**
     * @param ctx the request context.
     * @param request the CHF POST request carrying the id_token to validate.
     * @return 200 with the (optionally filtered) id_token claims as JSON.
     * @throws OAuth2Exception mapped to the JSON error body by the base handler.
     */
    @Post
    public Response validateIdToken(@Contextual Context ctx, @Contextual Request request) throws OAuth2Exception {
        OAuth2Request o2 = requestFactory.create(ctx, request);
        try {
            OAuth2Jwt idToken = validateIdToken(o2);
            // build() yields a JSON String; convert to a Map so setEntity uses UTF-8 JSON, not ISO-8859-1 (finding 6).
            return new Response(Status.valueOf(200))
                    .setEntity(JsonValueBuilder.toJsonValue(filterClaims(idToken, o2).build()).asMap());
        } catch (InvalidClientException e) {
            throw new BadRequestException(e.getError(), "no registered client matches audience of id_token");
        } catch (RealmLookupException e) {
            throw new BadRequestException("Invalid realm", "Invalid realm: " + e.getRealm());
        }
    }

    private OAuth2Jwt validateIdToken(OAuth2Request request) throws OAuth2Exception, RealmLookupException {
        String jwt = request.getParameter(OAuth2Constants.JWTTokenParams.ID_TOKEN);
        if (StringUtils.isBlank(jwt)) {
            throw new BadRequestException("no id_token in request");
        }
        OAuth2Jwt idToken;
        try {
            idToken = OAuth2Jwt.create(jwt);
        } catch (InvalidJwtException e) {
            throw new BadRequestException("invalid id_token: " + e.getMessage());
        }

        request.setToken(OpenIdConnectToken.class, new OpenIdConnectToken(idToken.getSignedJwt().getClaimsSet()));

        String clientId = CollectionUtils.getFirstItem(idToken.getSignedJwt().getClaimsSet().getAudience());
        String realm = idToken.getSignedJwt().getClaimsSet().get(OAuth2Constants.JWTTokenParams.REALM)
                .defaultTo("/")
                .asString();

        setRealmOnRequest(request, realm);

        OpenIdConnectClientRegistration clientRegistration = clientRegistrationStore.get(clientId,
                new ValidateIdTokenRequest(request, realm));
        JwsAlgorithm algorithm = JwsAlgorithm.valueOf(clientRegistration.getIDTokenSignedResponseAlgorithm());
        boolean requiresClientAuthentication =
                providerSettingsFactory.get(request).isIdTokenInfoClientAuthenticationEnabled();

        if (requiresClientAuthentication && algorithm.getAlgorithmType().equals(JwsAlgorithmType.HMAC)) {
            clientAuthenticator.authenticate(request, urisFactory.get(request).getTokenEndpoint());
        }

        if (idToken.isExpired()) {
            throw new BadRequestException("id_token has expired");
        }

        if (!clientRegistration.verifyJwtIdentity(idToken)) {
            throw new BadRequestException("invalid id_token");
        }

        return idToken;
    }

    /** Injects the token's realm so the collaborators that read the plain request (and the servlet) resolve it. */
    private void setRealmOnRequest(OAuth2Request request, String realm) throws RealmLookupException {
        // ChfOAuth2Request.getParameter reads attributes first, so this overrides the URL-seeded realm.
        request.setAttribute(OAuth2Constants.Custom.REALM, realm);
        // Load-bearing: urisFactory.get(request) reads REALM_OBJECT via getParameter with no fallback.
        request.setAttribute(OAuth2Constants.Custom.REALM_OBJECT, Realm.of(realm));
        request.getHttpServletRequest().setAttribute(ISAuthConstants.REALM_PARAM, realm);
    }

    private JwtClaimsSet filterClaims(OAuth2Jwt idToken, OAuth2Request request) {
        String requestedClaims = request.getParameter(OAuth2Constants.Custom.CLAIMS);
        JwtClaimsSet claims = idToken.getSignedJwt().getClaimsSet();
        if (requestedClaims != null) {
            JwtClaimsSet newClaims = new JwtClaimsSet();
            for (String claimName : requestedClaims.split(",")) {
                if (claims.isDefined(claimName)) {
                    newClaims.setClaim(claimName, claims.getClaim(claimName));
                }
            }
            return newClaims;
        }
        return claims;
    }

    /**
     * Delegating {@link OAuth2Request} that reports the id_token's realm claim instead of the request's, passed to the
     * client-registration lookup. Ported from the Restlet inner class minus its {@code getRequest()} override (that
     * returned a {@code Restlet} request; nothing on the CHF path calls it).
     */
    private static class ValidateIdTokenRequest extends OAuth2Request {
        private final OAuth2Request delegate;
        private final String realm;

        ValidateIdTokenRequest(OAuth2Request delegate, String realm) {
            this.delegate = delegate;
            this.realm = realm;
        }

        @Override
        @SuppressWarnings("unchecked")
        public <T> T getParameter(String name) {
            if (OAuth2Constants.JWTTokenParams.REALM.equals(name)) {
                return (T) realm;
            }
            return delegate.getParameter(name);
        }

        @Override
        public int getParameterCount(String name) {
            return delegate.getParameterCount(name);
        }

        @Override
        public Set<String> getParameterNames() {
            return delegate.getParameterNames();
        }

        @Override
        public JsonValue getBody() {
            return delegate.getBody();
        }

        @Override
        public Locale getLocale() {
            return delegate.getLocale();
        }

        @Override
        public String getEndpointPath() {
            return delegate.getEndpointPath();
        }

        @Override
        public HttpServletRequest getHttpServletRequest() {
            return delegate.getHttpServletRequest();
        }

        @Override
        public HttpServletResponse getHttpServletResponse() {
            return delegate.getHttpServletResponse();
        }

        @Override
        public BasicAuthHeader getBasicAuthCredentials() {
            return delegate.getBasicAuthCredentials();
        }

        @Override
        public String getAuthorizationBearerToken() {
            return delegate.getAuthorizationBearerToken();
        }

        @Override
        public String getQueryParameter(String name) {
            return delegate.getQueryParameter(name);
        }

        @Override
        public String getFormParameter(String name) {
            return delegate.getFormParameter(name);
        }

        @Override
        public Object getAttribute(String name) {
            return delegate.getAttribute(name);
        }

        @Override
        public void setAttribute(String name, Object value) {
            delegate.setAttribute(name, value);
        }

        @Override
        public String getRequestUrl() {
            return delegate.getRequestUrl();
        }

        @Override
        public void setQueryParameter(String name, String value) {
            delegate.setQueryParameter(name, value);
        }

        @Override
        public void removeQueryParameterValue(String name, String value) {
            delegate.removeQueryParameterValue(name, value);
        }
    }
}
