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
package org.openidentityplatform.openam.openidconnect.http;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import java.util.NoSuchElementException;

import freemarker.template.TemplateException;

import jakarta.inject.Inject;
import jakarta.servlet.http.HttpServletRequest;

import org.forgerock.http.protocol.Request;
import org.forgerock.http.protocol.Response;
import org.forgerock.http.protocol.Status;
import org.forgerock.oauth2.core.OAuth2Request;
import org.forgerock.oauth2.core.exceptions.OAuth2Exception;
import org.forgerock.oauth2.core.exceptions.ServerException;
import org.forgerock.openam.http.annotations.Contextual;
import org.forgerock.openam.http.annotations.Get;
import org.forgerock.openam.http.annotations.Post;
import org.forgerock.openam.services.baseurl.BaseURLProviderFactory;
import org.forgerock.openidconnect.CheckSession;
import org.forgerock.services.context.Context;
import org.openidentityplatform.openam.oauth2.http.AbstractOAuth2HttpJsonEndpoint;
import org.openidentityplatform.openam.oauth2.http.FreemarkerTemplateRenderer;

/**
 * CHF OpenID Connect check-session endpoint ({@code /oauth2/connect/checkSession}), porting the Restlet
 * {@code OpenIDConnectCheckSessionEndpoint}. Serves the RP-facing session-management iframe.
 *
 * <p><strong>Reachable only on the realm-prefixed path</strong> (D6). {@code web.xml} maps the bare
 * {@code /oauth2/connect/checkSession} to a JSP as an <em>exact</em> mapping, which out-ranks {@code /oauth2/*}
 * under the servlet spec -- today and after the flip. So this handler mounts like any other route and the
 * container keeps the JSP on the bare path by itself; no web.xml edit, no conditional routing, and the JSP is
 * not deleted at 5d-2.
 *
 * <p><strong>JSON errors, not a page</strong> (D1): the Restlet's {@code doCatch} called the 2-arg
 * {@code ExceptionHandler.handle}. Hence {@link AbstractOAuth2HttpJsonEndpoint}, whose {@code onError} must not
 * be overridden. An HTML <em>success</em> page with JSON errors is an odd pairing but it is the recorded
 * contract (5-E3 rows 6d, 7).
 *
 * <p>⚠ The page differs from the shipping JSP in more than cosmetics: the JSP emits
 * {@code var validSession = "false"} -- a quoted string, so its {@code !validSession} guard is dead code --
 * while the FTL's {@code ?js_string} yields a bare boolean literal and the guard works. This handler inherits
 * the FTL, i.e. the correct leg. Recorded so the 5d-1 diff on the bare path is not misread as a regression.
 */
public class CheckSessionHandler extends AbstractOAuth2HttpJsonEndpoint {

    @Inject
    private FreemarkerTemplateRenderer renderer;
    @Inject
    private CheckSession checkSession;
    @Inject
    private BaseURLProviderFactory baseURLProviderFactory;

    /**
     * @param ctx the request context.
     * @param request the CHF GET request.
     * @return 200 carrying the session-management iframe.
     * @throws OAuth2Exception mapped to the JSON error body by the base handler.
     */
    @Get
    public Response checkSession(@Contextual Context ctx, @Contextual Request request) throws OAuth2Exception {
        return render(ctx, request);
    }

    /**
     * The Restlet declared {@code @Get} and {@code @Post} over one body, so both verbs answer identically.
     *
     * @param ctx the request context.
     * @param request the CHF POST request; its entity is not read, as the Restlet's was not.
     * @return 200 carrying the session-management iframe.
     * @throws OAuth2Exception mapped to the JSON error body by the base handler.
     */
    @Post
    public Response checkSessionPost(@Contextual Context ctx, @Contextual Request request)
            throws OAuth2Exception {
        return render(ctx, request);
    }

    private Response render(Context ctx, Request request) throws OAuth2Exception {
        OAuth2Request o2 = requestFactory.create(ctx, request);
        Map<String, Object> model = dataModel(o2);
        try {
            // D5 + D7, second half: the render. Two unchecked/checked types, both reachable from ?display=:
            //   - IOException -- ?display=touch|wap|popup, since checkSession.ftl exists only under page/;
            //   - IAE         -- ?display=<unknown>, from Enum.valueOf inside renderForDisplay.
            // Live Restlet answered 400 for every non-page display (5-E3 row 7); ServerException is the JSON
            // base's 400 server_error, byte-identical to its toOAuth2RestletException fallback.
            return FreemarkerTemplateRenderer.toHtmlResponse(Status.OK,
                    renderer.renderForDisplay(o2.getParameter("display"), "checkSession.ftl", model));
        } catch (IOException | TemplateException | IllegalArgumentException e) {
            throw new ServerException(e);
        }
    }

    private Map<String, Object> dataModel(OAuth2Request o2) throws OAuth2Exception {
        HttpServletRequest servletRequest = o2.getHttpServletRequest();
        Map<String, Object> data = new HashMap<>();
        data.put("cookie_name", checkSession.getCookieName());
        String clientSessionUri;
        try {
            // D7, first half. getClientSessionURI is the one call here that throws unchecked on client
            // input, and it does so two ways -- both out of the single exit at CheckSession:115:
            //   - NPE           -- no `aud` in the Referer's id_token, so getClientRegistration returns null
            //                      and :111-115 dereferences it unguarded (a pre-existing product bug);
            //   - NoSuchElement -- a REGISTERED client whose clientSessionURI is unset, which is the admin
            //                      API's default, from set.iterator().next() (5-E3 rows 6d and 6e).
            // Wrapped by type, not with a blanket catch: the other three collaborator calls in this method
            // take no client input, so a fault in them is a bug and must keep CHF's 500 (decisions.md D3).
            clientSessionUri = checkSession.getClientSessionURI(servletRequest);
        } catch (NullPointerException | NoSuchElementException e) {
            throw new ServerException(e);
        }
        data.put("client_uri", clientSessionUri);
        // A String, not a Boolean: page/checkSession.ftl emits it UNQUOTED into JavaScript
        // (`var validSession = ${valid_session?js_string};`), so the type is load-bearing.
        data.put("valid_session", Boolean.toString(checkSession.getValidSession(servletRequest)));
        data.put("baseUrl", baseURLProviderFactory.get(o2.<String>getParameter("realm"))
                .getRootURL(servletRequest));
        return data;
        // The Restlet seeded this map from the Restlet request attributes first
        // (OpenIDConnectCheckSessionEndpoint.getDataModel). Verified inert: those attributes hold the realm,
        // the realm object and router internals, and checkSession.ftl reads none of them. The golden is the
        // proof -- it is rendered from both legs.
    }
}
