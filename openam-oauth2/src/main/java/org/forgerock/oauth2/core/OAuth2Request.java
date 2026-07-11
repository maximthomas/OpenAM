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
 * Portions Copyrighted 2018 Open Source Solution Technology Corporation
 * Portions copyright 2025-2026 3A Systems LLC.
 */

package org.forgerock.oauth2.core;

import java.util.Collection;
import java.util.Locale;
import java.util.Set;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import com.google.common.collect.ClassToInstanceMap;
import com.google.common.collect.MutableClassToInstanceMap;
import org.forgerock.json.JsonValue;
import org.forgerock.openam.oauth2.OAuth2Constants.EndpointType;
import org.restlet.Request;

/**
 * An abstraction of the actual request so as to allow the core of the OAuth2 provider to be agnostic of the library
 * used to translate the HTTP request.
 *
 * <p>Concrete transports are {@link RestletOAuth2Request} and {@link ChfOAuth2Request}. The
 * transport-neutral accessors below are what the shared OAuth2 collaborators are allowed to use;
 * {@link #getRequest()} exists only for the Restlet endpoints that have not been migrated yet.
 *
 * @since 12.0.0
 */
public abstract class OAuth2Request {

    private final ClassToInstanceMap<Token> tokens = MutableClassToInstanceMap.create();
    private String sessionId;
    private ClientRegistration clientRegistration;

    /**
     * Gets the actual underlying Restlet request.
     *
     * @return The underlying request.
     * @deprecated Only {@link RestletOAuth2Request} is backed by a Restlet request. Use the
     * transport-neutral accessors on this class instead.
     */
    @Deprecated
    public Request getRequest() {
        throw new UnsupportedOperationException("Not backed by a Restlet request");
    }

    /**
     * Gets the specified parameter from the request.
     * <br/>
     * It is up to the implementation to determine how and where it gets the parameter from on the request, i.e.
     * query parameters, request attributes, etc.
     *
     * @param name The name of the parameter.
     * @param <T> The type of the parameter.
     * @return The parameter value.
     */
    public abstract <T> T getParameter(String name);

    /**
     * Gets the count of the parameter present in the request query string with the given name.
     *
     * @param name The name of the parameter.
     * @return The count of the parameter with the given name.
     */
    public abstract int getParameterCount(String name);

    /**
     * Gets the name of the parameters in the current request.
     *
     * @return The parameter names in the request.
     */
    public abstract Set<String> getParameterNames();

    /**
     * Gets the body of the request.
     * <br/>
     * Note: reading of the body maybe a one time only operation, so the implementation needs to cache the content
     * of the body so multiple calls to this method do not behave differently.
     * <br/>
     * This method should only ever be called for access and refresh token request and requests to the userinfo and
     * tokeninfo endpoints.
     *
     * @return The body of the request.
     */
    public abstract JsonValue getBody();

    /**
     * Get the request locale.
     *
     * @return The Locale object.
     */
    public abstract Locale getLocale();

    /**
     * Gets the request path relative to the OAuth2 provider's realm base, with a leading slash and
     * with any {@literal /realms/{realm}} segments removed, e.g. {@literal /access_token}.
     *
     * @return The endpoint path, or {@code null} if it cannot be determined.
     */
    public abstract String getEndpointPath();

    /**
     * Get the type of the endpoint this request was made against.
     *
     * @return The EndpointType, or {@code null} if the request was not made against a known endpoint.
     */
    public EndpointType getEndpointType() {
        return EndpointType.get(getEndpointPath());
    }

    /**
     * Gets the servlet request underlying this request.
     *
     * @return The servlet request, may be {@code null}.
     */
    public HttpServletRequest getHttpServletRequest() {
        throw new UnsupportedOperationException("No servlet request for this OAuth2Request");
    }

    /**
     * Gets the servlet response underlying this request.
     *
     * @return The servlet response, may be {@code null}.
     */
    public HttpServletResponse getHttpServletResponse() {
        throw new UnsupportedOperationException("No servlet response for this OAuth2Request");
    }

    /**
     * Gets the credentials carried by the request's {@code Authorization} header.
     *
     * @return The credentials, or {@code null} if the request carries no {@code Authorization} header.
     */
    public BasicAuthHeader getBasicAuthCredentials() {
        throw new UnsupportedOperationException("No Authorization header for this OAuth2Request");
    }

    /**
     * Gets a per-request attribute.
     *
     * @param name The attribute name.
     * @return The attribute value, may be {@code null}.
     */
    public Object getAttribute(String name) {
        throw new UnsupportedOperationException("No attributes for this OAuth2Request");
    }

    /**
     * Sets a per-request attribute.
     *
     * @param name The attribute name.
     * @param value The attribute value.
     */
    public void setAttribute(String name, Object value) {
        throw new UnsupportedOperationException("No attributes for this OAuth2Request");
    }

    /**
     * Gets the full URL of the request, including its query string.
     *
     * <p>The URL reflects any modification made through {@link #setQueryParameter} and
     * {@link #removeQueryParameterValue}.
     *
     * @return The request URL.
     */
    public String getRequestUrl() {
        throw new UnsupportedOperationException("No request URL for this OAuth2Request");
    }

    /**
     * Sets a query parameter on the request URL, replacing the first existing value if the parameter
     * is already present.
     *
     * @param name The parameter name.
     * @param value The parameter value.
     */
    public void setQueryParameter(String name, String value) {
        throw new UnsupportedOperationException("No request URL for this OAuth2Request");
    }

    /**
     * Removes a value from the first occurrence of a query parameter on the request URL. The
     * parameter itself is retained; its value is lowercased, the given value stripped out and the
     * remainder trimmed.
     *
     * @param name The parameter name.
     * @param value The value to remove.
     */
    public void removeQueryParameterValue(String name, String value) {
        throw new UnsupportedOperationException("No request URL for this OAuth2Request");
    }

    /**
     * Set a Token that is in play for this request.
     * @param tokenClass The token type.
     * @param token The token instance.
     * @param <T> The type of token.
     */
    public <T extends Token> void setToken(Class<T> tokenClass, T token) {
        tokens.putInstance(tokenClass, token);
    }

    /**
     * Get a Token that is in play for this request.
     * @param tokenClass The token type.
     * @param <T> The type of token.
     * @return The token instance.
     */
    public <T extends Token> T getToken(Class<T> tokenClass) {
        return tokens.getInstance(tokenClass);
    }

    /**
     * Get all the tokens that have been used in this request.
     * @return The token instances.
     */
    public Collection<Token> getTokens() {
        return tokens.values();
    }

    /**
     * Sets the user's session for this request.
     *
     * @param sessionId The user's session.
     */
    public void setSession(String sessionId) {
        this.sessionId = sessionId;
    }

    /**
     * Gets the user's session for this request.
     *
     * @return The user's session.
     */
    public String getSession() {
        return sessionId;
    }

    /**
     * Get the OAuth2 client registration of the request.
     *
     * @return The client registration.
     */
    public ClientRegistration getClientRegistration() {
        return clientRegistration;
    }

    /**
     * Set the OAuth2 client registration.
     *
     * @param clientRegistration The client registration.
     */
    public void setClientRegistration(ClientRegistration clientRegistration) {
        this.clientRegistration = clientRegistration;
    }

    /**
     * Creates an {@code OAuth2Request} which holds the provided realm only.
     *
     * @param realm The request realm.
     * @return An {@code OAuth2Request}.
     */
    public static OAuth2Request forRealm(String realm) {
        return new RealmOnlyOAuth2Request(realm);
    }

    private static class RealmOnlyOAuth2Request extends OAuth2Request {

        private final String realm;

        private RealmOnlyOAuth2Request(String realm) {
            this.realm = realm;
        }

        @Override
        public <T> T getParameter(String name) {
            if ("realm".equals(name)) {
                return (T) realm;
            }
            throw new UnsupportedOperationException("Realm parameter only OAuth2Request");
        }

        @Override
        public JsonValue getBody() {
            return null;
        }

        @Override
        public int getParameterCount(String name)  { throw new UnsupportedOperationException(); }

        @Override
        public Set<String> getParameterNames() { throw new UnsupportedOperationException(); }

        @Override
        public Locale getLocale() {
            throw new UnsupportedOperationException();
        }

        @Override
        public String getEndpointPath() {
            throw new UnsupportedOperationException("Realm parameter only OAuth2Request");
        }
    }
}
