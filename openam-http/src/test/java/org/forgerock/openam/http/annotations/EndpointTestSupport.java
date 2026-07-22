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

package org.forgerock.openam.http.annotations;

import java.io.IOException;
import java.util.Map;

import org.forgerock.http.protocol.Request;
import org.forgerock.http.protocol.Response;
import org.forgerock.services.context.RootContext;

/** Shared helpers for driving an annotated endpoint through {@link Endpoints#from(Object)}. */
final class EndpointTestSupport {

    static Response get(Object endpoint) {
        return handle(endpoint, "GET");
    }

    static Response handle(Object endpoint, String verb) {
        return handle(endpoint, new Request().setMethod(verb));
    }

    static Response handle(Object endpoint, Request request) {
        return Endpoints.from(endpoint).handle(new RootContext(), request).getOrThrowUninterruptibly();
    }

    @SuppressWarnings("unchecked")
    static Map<String, Object> jsonBody(Response response) throws IOException {
        return (Map<String, Object>) response.getEntity().getJson();
    }

    private EndpointTestSupport() {
    }
}
