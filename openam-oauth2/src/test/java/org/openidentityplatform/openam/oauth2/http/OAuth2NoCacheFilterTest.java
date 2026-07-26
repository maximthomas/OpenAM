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

import static org.assertj.core.api.Assertions.assertThat;

import org.forgerock.http.Handler;
import org.forgerock.http.protocol.Request;
import org.forgerock.http.protocol.Response;
import org.forgerock.http.protocol.Status;
import org.forgerock.services.context.Context;
import org.forgerock.services.context.RootContext;
import org.forgerock.util.promise.NeverThrowsException;
import org.forgerock.util.promise.Promise;
import org.forgerock.util.promise.Promises;
import org.testng.annotations.Test;

/**
 * Unit rows for {@link OAuth2NoCacheFilter}. Its behaviour in the real chain -- which is the point of it, since
 * the response it was written for is one no handler produces -- is asserted by
 * {@code AuthorizeRouteCompositionIT}.
 */
public class OAuth2NoCacheFilterTest {

    /** Success responses were stamped too: {@code OAuth2Filter} added the directives after its try/catch. */
    @Test
    public void aSuccessIsStamped() throws Exception {
        Response response = through(new Response(Status.OK));

        assertThat(response.getHeaders().getFirst("Cache-Control")).isEqualTo("no-store");
        assertThat(response.getHeaders().getFirst("Pragma")).isEqualTo("no-cache");
    }

    /** The case it exists for: a response produced without any handler running. */
    @Test
    public void aFrameworkErrorIsStampedToo() throws Exception {
        Response response = through(new Response(Status.METHOD_NOT_ALLOWED));

        assertThat(response.getHeaders().getFirst("Cache-Control")).isEqualTo("no-store");
        assertThat(response.getHeaders().getFirst("Pragma")).isEqualTo("no-cache");
    }

    /**
     * The filter and the handlers both stamp, so the overlap must be idempotent rather than additive -- a
     * {@code Headers.add} would put {@code no-store, no-store} on every {@code /authorize} response.
     */
    @Test
    public void stampingTwiceDoesNotDuplicateTheDirective() throws Exception {
        Response alreadyStamped = new Response(Status.FOUND);
        alreadyStamped.getHeaders().put("Cache-Control", "no-store");

        Response response = through(alreadyStamped);

        assertThat(response.getHeaders().get("Cache-Control").getValues()).containsExactly("no-store");
    }

    private static Response through(Response response) throws Exception {
        Handler next = new Handler() {
            @Override
            public Promise<Response, NeverThrowsException> handle(Context context, Request request) {
                return Promises.newResultPromise(response);
            }
        };
        return new OAuth2NoCacheFilter().filter(new RootContext(), new Request(), next)
                .getOrThrowUninterruptibly();
    }
}
