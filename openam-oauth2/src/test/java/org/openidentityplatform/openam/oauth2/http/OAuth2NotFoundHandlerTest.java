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

import java.net.URI;
import java.util.Map;

import org.forgerock.http.handler.Handlers;
import org.forgerock.http.protocol.Request;
import org.forgerock.http.protocol.Response;
import org.forgerock.services.context.RootContext;
import org.testng.annotations.Test;

/**
 * Unit rows for {@link OAuth2NotFoundHandler} (5d-1 D5). Its placement -- the default route of both the endpoint
 * router and the nested {@code resource_set} one -- is asserted by {@code OAuth2RouterIT}.
 */
public class OAuth2NotFoundHandlerTest {

    @Test
    @SuppressWarnings("unchecked")
    public void anUnroutedPathIsA404InTheOAuth2Shape() throws Exception {
        Response response = handle();

        assertThat(response.getStatus().getCode()).isEqualTo(404);
        assertThat((Map<String, Object>) response.getEntity().getJson())
                .containsEntry("error", "not_found")
                .containsEntry("error_description", "Not Found");
    }

    /** {@code OAuth2ErrorFilter} guards on the declared type before parsing, so the body has to declare one. */
    @Test
    public void theBodyIsDeclaredJson() throws Exception {
        assertThat(handle().getHeaders().getFirst("Content-Type")).contains("application/json");
    }

    /**
     * D5: the handler writes the OAuth2 shape rather than a CREST body for the filter to rewrite, so the two
     * compose idempotently and this 404 does not depend on the filter being mounted.
     */
    @Test
    @SuppressWarnings("unchecked")
    public void theErrorFilterReturnsItUnchanged() throws Exception {
        Response response = Handlers.chainOf(new OAuth2NotFoundHandler(), new OAuth2ErrorFilter())
                .handle(new RootContext(), new Request().setMethod("GET").setUri(URI.create("/oauth2/nosuch")))
                .getOrThrowUninterruptibly();

        assertThat(response.getStatus().getCode()).isEqualTo(404);
        assertThat((Map<String, Object>) response.getEntity().getJson())
                .containsEntry("error", "not_found")
                .containsEntry("error_description", "Not Found");
    }

    private static Response handle() throws Exception {
        return new OAuth2NotFoundHandler()
                .handle(new RootContext(), new Request().setMethod("GET").setUri(URI.create("/oauth2/nosuch")))
                .getOrThrowUninterruptibly();
    }
}
