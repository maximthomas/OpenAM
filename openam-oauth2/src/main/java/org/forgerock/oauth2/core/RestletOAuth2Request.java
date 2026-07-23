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

import java.io.IOException;
import java.util.Collections;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.forgerock.json.JsonValue;
import org.forgerock.openam.rest.jakarta.servlet.ServletUtils;
import org.forgerock.openam.rest.representations.JacksonRepresentationFactory;
import org.forgerock.openam.rest.service.RestletRealmRouter;
import org.openidentityplatform.openam.oauth2.core.BasicAuthHeader;
import org.restlet.Request;
import org.restlet.Response;
import org.restlet.data.ChallengeResponse;
import org.restlet.data.ChallengeScheme;
import org.restlet.data.Form;
import org.restlet.data.Header;
import org.restlet.data.MediaType;
import org.restlet.data.Method;
import org.restlet.data.Parameter;
import org.restlet.engine.adapter.HttpRequest;
import org.restlet.engine.header.HeaderConstants;
import org.restlet.ext.jackson.JacksonRepresentation;
import org.restlet.representation.Representation;
import org.restlet.util.Series;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * An {@link OAuth2Request} backed by a Restlet request.
 *
 * @since 15.2.0
 */
public class RestletOAuth2Request extends OAuth2Request {

    private static final String REALMS_PREFIX = "/realms/";

    private final Logger logger = LoggerFactory.getLogger("OAuth2Provider");
    private final Request request;
    private final JacksonRepresentationFactory jacksonRepresentationFactory;
    private JsonValue body;

    /**
     * Constructs a new RestletOAuth2Request.
     *
     * @param jacksonRepresentationFactory The factory class for {@link JacksonRepresentation}.
     * @param request The Restlet request.
     */
    public RestletOAuth2Request(JacksonRepresentationFactory jacksonRepresentationFactory,
            Request request) {
        this.jacksonRepresentationFactory = jacksonRepresentationFactory;
        this.request = request;
    }

    @Override
    public Request getRequest() {
        return request;
    }

    @Override
    public <T> T getParameter(String name) {
        Object value = getAttribute(name);
        if (value != null) {
            return (T) value;
        }

        //query param priority over body
        String queryValue = getResourceRefQueryParameter(request, name);
        if (queryValue != null) {
            return (T) queryValue;
        }

        if (request.getMethod().equals(Method.POST)) {
            if (request.getEntity() != null) {
                if (MediaType.APPLICATION_WWW_FORM.equals(request.getEntity().getMediaType())) {
                    Form form = new Form(request.getEntity());
                    // restore the entity body
                    request.setEntity(form.getWebRepresentation());
                    return (T) form.getValuesMap().get(name);
                } else if (MediaType.APPLICATION_JSON.equals(request.getEntity().getMediaType())) {
                    return (T) getBody().get(name).getObject();
                }
            }
        }
        return null;
    }

    @Override
    public int getParameterCount(String name) {
        return request.getResourceRef().getQueryAsForm().subList(name).size();
    }

    @Override
    public Set<String> getParameterNames() {

        if (request.getMethod().equals(Method.GET)) {
            return request.getResourceRef().getQueryAsForm().getNames();
        } else if (request.getMethod().equals(Method.POST)) {
            if (request.getEntity() != null) {
                if (MediaType.APPLICATION_WWW_FORM.equals(request.getEntity().getMediaType())) {
                    Form form = new Form(request.getEntity());
                    // restore the entity body
                    request.setEntity(form.getWebRepresentation());
                    return  form.getNames();
                } else if (MediaType.APPLICATION_JSON.equals(request.getEntity().getMediaType())) {
                    return getBody().keys();
                }
            }
        }
        return Collections.emptySet();
    }

    @Override
    public JsonValue getBody() {
        if (body == null) {
            final JacksonRepresentation<Map> representation =
                    jacksonRepresentationFactory.create(request.getEntity(), Map.class);
            try {
                body = new JsonValue(representation.getObject());
            } catch (IOException e) {
                logger.error(e.getMessage());
                return JsonValue.json(JsonValue.object());
            }
        }
        return body;
    }

    @Override
    public Locale getLocale() {
        return ServletUtils.getRequest(request).getLocale();
    }

    @Override
    public String getEndpointPath() {
        String realmUrl = (String) request.getAttributes().get(RestletRealmRouter.REALM_URL);
        if (realmUrl == null) {
            return null;
        }
        String resourceUrl = request.getResourceRef().toString(false, false);
        if (!resourceUrl.startsWith(realmUrl)) {
            return null;
        }
        return stripRealmSegments(resourceUrl.substring(realmUrl.length()));
    }

    @Override
    public HttpServletRequest getHttpServletRequest() {
        return request == null ? null : ServletUtils.getRequest(request);
    }

    @Override
    public HttpServletResponse getHttpServletResponse() {
        Response response = Response.getCurrent();
        return response == null ? null : ServletUtils.getResponse(response);
    }

    @Override
    public BasicAuthHeader getBasicAuthCredentials() {
        ChallengeResponse challengeResponse = request.getChallengeResponse();
        if (challengeResponse == null) {
            return null;
        }
        return new BasicAuthHeader(challengeResponse.getIdentifier(), challengeResponse.getSecret());
    }

    @Override
    public String getAuthorizationBearerToken() {
        ChallengeResponse challengeResponse = bearerChallengeResponse();
        return challengeResponse == null ? null : challengeResponse.getRawValue();
    }

    @Override
    public String getQueryParameter(String name) {
        return request.getOriginalRef().getQueryAsForm().getFirstValue(name);
    }

    @Override
    public String getFormParameter(String name) {
        Representation body = request.getEntity();
        if (body == null || !MediaType.APPLICATION_WWW_FORM.equals(body.getMediaType())) {
            return null;
        }
        // Unlike getParameter above, this deliberately does not restore the entity after reading
        // it. The form body access token verifier this was ported from drains the entity, and
        // restoring it here would be a live-path behaviour change rather than a port.
        return new Form(body).getFirstValue(name);
    }

    /**
     * Ported from the Restlet header access token verifier. Two behaviours here are load-bearing
     * rather than incidental, and must survive until the Restlet path is deleted:
     *
     * <ul>
     * <li>the {@code HttpRequest} guard — the raw {@code Authorization} header is reachable only
     * through Restlet's server adapter, so a request built programmatically rather than dispatched
     * (as openam-uma builds them) would fail the cast;
     * <li>the {@code setChallengeResponse} write — a getter that mutates reads as a smell, but
     * {@code OpenAMClientAuthenticationFailureFactory#hasAuthorizationHeader} reads back that exact
     * field, so dropping the write would change the client authentication failure path.
     * </ul>
     */
    private ChallengeResponse bearerChallengeResponse() {
        if (request instanceof HttpRequest) {
            final Series<Header> headers = ((HttpRequest) request).getHttpCall().getRequestHeaders();
            final String authorization = headers.getValues(HeaderConstants.HEADER_AUTHORIZATION);

            if (authorization != null) {
                int space = authorization.indexOf(' ');

                if (space != -1) {
                    String scheme = authorization.substring(0, space);

                    if (scheme.equalsIgnoreCase("Bearer")) {
                        ChallengeResponse result = new ChallengeResponse(new ChallengeScheme("HTTP_"
                                + scheme, scheme));
                        result.setRawValue(authorization.substring(space + 1));
                        request.setChallengeResponse(result);
                        return result;
                    }
                }
            }
        }
        // A non-Bearer scheme, or a request that never went through the server adapter, falls back
        // to whatever ChallengeResponse is already set. For Basic that is a credential blob rather
        // than a token, which fails token lookup exactly as a null would.
        return request.getChallengeResponse();
    }

    @Override
    public Object getAttribute(String name) {
        return request.getAttributes().get(name);
    }

    @Override
    public void setAttribute(String name, Object value) {
        request.getAttributes().put(name, value);
    }

    @Override
    public String getRequestUrl() {
        return request.getResourceRef().toString();
    }

    @Override
    public void setQueryParameter(String name, String value) {
        Form query = request.getResourceRef().getQueryAsForm();
        Parameter param = query.getFirst(name);
        if (param == null) {
            query.add(new Parameter(name, value));
        } else {
            param.setValue(value);
        }
        request.getResourceRef().setQuery(query.getQueryString());
    }

    @Override
    public void removeQueryParameterValue(String name, String value) {
        Form query = request.getResourceRef().getQueryAsForm();
        Parameter param = query.getFirst(name);
        if (param != null && param.getValue() != null) {
            param.setValue(param.getValue().toLowerCase().replace(value, "").trim());
        }
        request.getResourceRef().setQuery(query.getQueryString());
    }

    /**
     * Removes the leading {@literal /realms/{realm}} segments left by the realm router, which
     * matches the endpoint below the realm base rather than above it.
     */
    private static String stripRealmSegments(String path) {
        String remainder = path;
        while (remainder.startsWith(REALMS_PREFIX)) {
            int nextSlash = remainder.indexOf('/', REALMS_PREFIX.length());
            remainder = nextSlash < 0 ? "" : remainder.substring(nextSlash);
        }
        return remainder;
    }

    /**
     * Reads the <em>resource</em> reference's query, which is the post-routing URI and reflects
     * writes made by {@link #setQueryParameter}. Deliberately distinct from the public
     * {@link #getQueryParameter(String)}, which reads the original, pre-routing reference.
     */
    private String getResourceRefQueryParameter(Request request, String name) {
        return request.getResourceRef().getQueryAsForm().getValuesMap().get(name);
    }
}
