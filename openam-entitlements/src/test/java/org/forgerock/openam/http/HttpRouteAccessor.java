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
 * Portions copyright 2026 3A Systems LLC.
 */

package org.forgerock.openam.http;

import org.forgerock.http.Handler;
import org.forgerock.http.routing.RoutingMode;

/**
 * Exposes {@link HttpRoute}'s package-private accessors to tests outside this package.
 *
 * <p>{@code HttpRoute} deliberately keeps them package-private so that only {@code HttpRouterProvider}
 * reads them in production. Tests that need to dispatch through a route without standing up the whole
 * {@code HttpApplication} need the same three values, hence this test-scoped shim.
 */
public final class HttpRouteAccessor {

    private HttpRouteAccessor() {
    }

    public static RoutingMode modeOf(HttpRoute route) {
        return route.getMode();
    }

    public static String uriTemplateOf(HttpRoute route) {
        return route.getUriTemplate();
    }

    public static Handler handlerOf(HttpRoute route) {
        return route.getHandler();
    }
}
