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

import org.forgerock.http.Filter;
import org.forgerock.http.Handler;
import org.forgerock.http.protocol.Request;
import org.forgerock.http.protocol.Response;
import org.forgerock.services.context.Context;
import org.forgerock.util.promise.NeverThrowsException;
import org.forgerock.util.promise.Promise;

/**
 * Stamps {@code Cache-Control: no-store} + {@code Pragma: no-cache} on <strong>every</strong> response,
 * restoring the one thing the Restlet {@code OAuth2Filter} did that a handler cannot do for itself.
 *
 * <h2>Why a filter and not more {@code noCache()} calls</h2>
 * {@code OAuth2Filter:72-77} added those directives after its try/catch, unconditionally -- so they landed on
 * responses that never reached the resource at all. The CHF ports moved the stamping into the handler methods,
 * which covers every response a handler <em>returns</em> and none of the ones the framework produces on its
 * own: an unsupported verb is answered by {@code AnnotatedMethod} before any endpoint method runs, so
 * {@code withErrorHeaders} is never called and the 405 goes out cacheable where 5-E2 row 7 recorded live
 * Restlet sending {@code no-store}. The same hole covers the framework's 404 and its 500 for a non-OAuth2
 * throw. No amount of care inside the handler closes it, because the handler is not on that path.
 *
 * <h2>Scope: exactly two routes</h2>
 * ⚠ Compose this on {@code /authorize} and {@code /access_token} <strong>only</strong>. Those are the two
 * resources {@code OAuth2Filter} wrapped; the other OAuth2 endpoints set their own cache header or none, so
 * applying it to the whole {@code /oauth2} application would be a widening rather than a restoration -- the
 * same reason {@link AbstractOAuth2HttpEndpoint#noCache} is opt-in per handler instead of a base default.
 *
 * <p>The two handlers keep their own {@code noCache} calls. Stamping twice is free ({@code Headers.put}
 * replaces), and it keeps every handler correct when driven directly -- which is how the unit suites drive it.
 */
public class OAuth2NoCacheFilter implements Filter {

    @Override
    public Promise<Response, NeverThrowsException> filter(Context context, Request request, Handler next) {
        return next.handle(context, request).then(AbstractOAuth2HttpEndpoint::noCache);
    }
}
