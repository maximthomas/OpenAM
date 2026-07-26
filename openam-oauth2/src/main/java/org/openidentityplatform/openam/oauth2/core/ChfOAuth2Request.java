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

package org.openidentityplatform.openam.oauth2.core;

import java.io.IOException;
import java.util.ArrayDeque;
import java.util.Collections;
import java.util.Deque;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.forgerock.http.header.AcceptLanguageHeader;
import org.forgerock.http.header.ContentTypeHeader;
import org.forgerock.http.protocol.Form;
import org.forgerock.http.protocol.Request;
import org.forgerock.http.routing.UriRouterContext;
import org.forgerock.json.JsonValue;
import org.forgerock.oauth2.core.OAuth2Request;
import org.forgerock.openam.core.realms.Realm;
import org.forgerock.openam.oauth2.OAuth2Constants;
import org.forgerock.openam.rest.RealmContext;
import org.forgerock.services.context.Context;
import org.forgerock.util.i18n.PreferredLocales;
import org.openidentityplatform.openam.http.ChfContexts;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * An {@link OAuth2Request} backed by a Common HTTP Framework {@code Context} and {@code Request}.
 *
 * <p>Parameter resolution reproduces the Restlet precedence exactly: per-request attribute, then
 * query string, then — for {@code POST} only — an {@code application/x-www-form-urlencoded} body,
 * then a JSON body.
 */
public class ChfOAuth2Request extends OAuth2Request {

    private static final String POST = "POST";
    private static final String GET = "GET";
    private static final String FORM_CONTENT_TYPE = "application/x-www-form-urlencoded";
    private static final String JSON_CONTENT_TYPE = "application/json";
    private static final String AUTHORIZATION_HEADER = "Authorization";
    private static final String BEARER = "Bearer";

    private final Logger logger = LoggerFactory.getLogger("OAuth2Provider");
    private final Context context;
    private final Request request;

    private Map<String, Object> attributes;
    private Form queryForm;
    private Form formBody;
    private JsonValue body;

    /**
     * Constructs a new ChfOAuth2Request.
     *
     * @param context The CHF context of the request.
     * @param request The CHF request.
     */
    public ChfOAuth2Request(Context context, Request request) {
        this.context = context;
        this.request = request;
    }

    @Override
    public <T> T getParameter(String name) {
        Object value = getAttribute(name);
        if (value != null) {
            return (T) value;
        }

        //query param priority over body
        String queryValue = queryForm().getFirst(name);
        if (queryValue != null) {
            return (T) queryValue;
        }

        if (POST.equals(request.getMethod())) {
            if (isContentType(FORM_CONTENT_TYPE)) {
                return (T) formBody().getFirst(name);
            } else if (isContentType(JSON_CONTENT_TYPE)) {
                return (T) getBody().get(name).getObject();
            }
        }
        return null;
    }

    @Override
    public int getParameterCount(String name) {
        List<String> values = queryForm().get(name);
        return values == null ? 0 : values.size();
    }

    @Override
    public Set<String> getParameterNames() {
        // Return a copy, not the Form's live keySet: the Form is instance-cached, so handing back a
        // view would let a caller's mutation corrupt this request's parameter map.
        if (GET.equals(request.getMethod())) {
            return new LinkedHashSet<>(queryForm().keySet());
        } else if (POST.equals(request.getMethod())) {
            if (isContentType(FORM_CONTENT_TYPE)) {
                return new LinkedHashSet<>(formBody().keySet());
            } else if (isContentType(JSON_CONTENT_TYPE)) {
                return getBody().keys();
            }
        }
        return Collections.emptySet();
    }

    @Override
    public JsonValue getBody() {
        if (body == null) {
            try {
                body = new JsonValue(request.getEntity().getJson());
            } catch (IOException e) {
                logger.error(e.getMessage());
                return JsonValue.json(JsonValue.object());
            }
        }
        return body;
    }

    @Override
    public Locale getLocale() {
        String header = request.getHeaders().getFirst(AcceptLanguageHeader.NAME);
        if (header != null) {
            AcceptLanguageHeader acceptLanguage =
                    AcceptLanguageHeader.valueOf(new LinkedHashSet<>(Collections.singletonList(header)));
            if (acceptLanguage != null) {
                PreferredLocales locales = acceptLanguage.getLocales();
                if (locales != null && !locales.getLocales().isEmpty()) {
                    return locales.getPreferredLocale();
                }
            }
        }
        // HttpServletRequest#getLocale() falls back to the server default when the header is absent.
        return Locale.getDefault();
    }

    /**
     * {@inheritDoc}
     *
     * <p>The path is the concatenation of the URIs matched by the routers <em>below</em> the realm
     * router, which is the CHF equivalent of the {@literal realmUrl} request attribute the Restlet
     * realm router publishes. At the realm base itself (no endpoint segment below the realm router)
     * the path is the empty string, matching {@link org.forgerock.oauth2.core.RestletOAuth2Request#getEndpointPath()} rather
     * than a bare {@code "/"} — so {@link #getEndpointType()} resolves to {@code OTHER}, not
     * {@code null}, on both transports.
     */
    @Override
    public String getEndpointPath() {
        if (!context.containsContext(RealmContext.class)) {
            return null;
        }
        Deque<String> matched = new ArrayDeque<>();
        for (Context current = context; current != null; current = current.getParent()) {
            if (current instanceof RealmContext) {
                break;
            }
            if (current instanceof UriRouterContext) {
                String matchedUri = ((UriRouterContext) current).getMatchedUri();
                if (matchedUri != null && !matchedUri.isEmpty()) {
                    matched.addFirst(matchedUri);
                }
            }
        }
        return matched.isEmpty() ? "" : "/" + String.join("/", matched);
    }

    @Override
    public HttpServletRequest getHttpServletRequest() {
        return ChfContexts.servletRequest(context);
    }

    @Override
    public HttpServletResponse getHttpServletResponse() {
        return ChfContexts.servletResponse(context);
    }

    @Override
    public BasicAuthHeader getBasicAuthCredentials() {
        return BasicAuthHeader.parse(request.getHeaders().getFirst(AUTHORIZATION_HEADER));
    }

    @Override
    public String getAuthorizationBearerToken() {
        String authorization = request.getHeaders().getFirst(AUTHORIZATION_HEADER);
        if (authorization == null) {
            return null;
        }
        int space = authorization.indexOf(' ');
        if (space < 0 || !BEARER.equalsIgnoreCase(authorization.substring(0, space))) {
            return null;
        }
        return authorization.substring(space + 1);
    }

    @Override
    public String getQueryParameter(String name) {
        return queryForm().getFirst(name);
    }

    @Override
    public String getFormParameter(String name) {
        // formBody() is not itself content-type guarded — its other callers guard it — so a JSON
        // body would otherwise be parsed as a form string instead of yielding null.
        if (!isContentType(FORM_CONTENT_TYPE)) {
            return null;
        }
        return formBody().getFirst(name);
    }

    @Override
    public Object getAttribute(String name) {
        return attributes().get(name);
    }

    @Override
    public void setAttribute(String name, Object value) {
        attributes().put(name, value);
    }

    @Override
    public String getRequestUrl() {
        return request.getUri().toString();
    }

    @Override
    public void setQueryParameter(String name, String value) {
        Form query = new Form().fromRequestQuery(request);
        List<String> values = query.get(name);
        if (values == null || values.isEmpty()) {
            query.add(name, value);
        } else {
            values.set(0, value);
        }
        writeQuery(query);
    }

    @Override
    public void removeQueryParameterValue(String name, String value) {
        Form query = new Form().fromRequestQuery(request);
        List<String> values = query.get(name);
        if (values != null && !values.isEmpty() && values.get(0) != null) {
            values.set(0, values.get(0).toLowerCase().replace(value, "").trim());
        }
        writeQuery(query);
    }

    private void writeQuery(Form query) {
        query.toRequestQuery(request);
        // The cached query form is derived from the URI, so it must be rebuilt on next access.
        queryForm = null;
    }

    private Form queryForm() {
        if (queryForm == null) {
            queryForm = new Form().fromRequestQuery(request);
        }
        return queryForm;
    }

    private Form formBody() {
        if (formBody == null) {
            formBody = new Form();
            try {
                // The CHF entity is buffered, so reading it does not consume the body.
                formBody.fromFormString(request.getEntity().getString());
            } catch (IOException e) {
                logger.error(e.getMessage());
            }
        }
        return formBody;
    }

    /**
     * Compares the parsed media type rather than the raw header, so that a {@code charset}
     * parameter does not defeat the match.
     */
    private boolean isContentType(String mediaType) {
        return mediaType.equalsIgnoreCase(ContentTypeHeader.valueOf(request).getType());
    }

    private Map<String, Object> attributes() {
        if (attributes == null) {
            attributes = new HashMap<>();
            Deque<UriRouterContext> routerContexts = new ArrayDeque<>();
            for (Context current = context; current != null; current = current.getParent()) {
                if (current instanceof UriRouterContext) {
                    routerContexts.addFirst((UriRouterContext) current);
                }
            }
            // Outermost first, so that the innermost router's variables win.
            for (UriRouterContext routerContext : routerContexts) {
                attributes.putAll(routerContext.getUriTemplateVariables());
            }
            if (context.containsContext(RealmContext.class)) {
                Realm realm = RealmContext.getRealm(context);
                attributes.put(OAuth2Constants.Custom.REALM, realm.asPath());
                // The *UrisFactory.get(OAuth2Request) overloads read the Realm object directly, no fallback.
                attributes.put(OAuth2Constants.Custom.REALM_OBJECT, realm);
            }
        }
        return attributes;
    }
}
