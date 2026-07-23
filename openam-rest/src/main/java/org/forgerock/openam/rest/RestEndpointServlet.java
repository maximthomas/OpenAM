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
 * Copyright 2014-2015 ForgeRock AS.
 * Portions copyright 2025-2026 3A Systems LLC.
 */

package org.forgerock.openam.rest;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletRequestWrapper;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;

import org.forgerock.openam.rest.service.OAuth2ServiceEndpointApplication;
import org.forgerock.openam.rest.service.RestletServiceServlet;

/**
 * Root Servlet for the remaining Restlet REST Service endpoint requests, which are then passed onto the correct
 * underlying servlet for the requested service. {@literal /uma} moved to the CHF stack in Phase 4
 * ({@code UmaHttpRouteProvider}); {@literal /oauth2} remains here until Phase 5.
 *
 * @since 12.0.0
 */
public class RestEndpointServlet extends HttpServlet {

    private final RestletServiceServlet restletOAuth2ServiceServlet;

    /**
     * Constructs a new RestEndpointServlet.
     */
    public RestEndpointServlet() {
        this.restletOAuth2ServiceServlet = new RestletServiceServlet(this, OAuth2ServiceEndpointApplication.class,
                "oauth2RestletServiceServlet");
    }

    /**
     * Constructor for test use.
     *
     * @param restletOAuth2ServiceServlet An instance of a RestletServiceServlet.
     */
    RestEndpointServlet(RestletServiceServlet restletOAuth2ServiceServlet) {
        this.restletOAuth2ServiceServlet = restletOAuth2ServiceServlet;
    }

    /**
     * Delegates the request to the Restlet servlet for the requested service REST endpoint.
     *
     * @param request The HttpServletRequest.
     * @param response The HttpServletResponse.
     * @throws ServletException If the Restlet Servlet service() call fails.
     * @throws IOException If the Restlet Servlet service() call fails.
     */
    @Override
    protected void service(HttpServletRequest request, HttpServletResponse response) throws ServletException,
            IOException {
        if ("/oauth2".equals(request.getServletPath())) {
            restletOAuth2ServiceServlet.service(new HttpServletRequestWrapper(request), response);
        }
    }

    /**
     * Destroys the Restlet servlets.
     */
    @Override
    public void destroy() {
        restletOAuth2ServiceServlet.destroy();
    }
}
