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

import static org.assertj.core.api.Assertions.assertThat;
import static org.forgerock.openam.http.annotations.EndpointTestSupport.handle;
import static org.forgerock.openam.http.annotations.EndpointTestSupport.jsonBody;

import java.io.IOException;

import org.forgerock.http.protocol.Request;
import org.forgerock.http.protocol.Response;
import org.forgerock.http.protocol.Status;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

/**
 * Characterization tests for {@link Endpoints} — request dispatch and the framework's own
 * error responses. These pin behaviour as it is <em>before</em> the F1–F4 fixes; rows that a
 * fix deliberately changes are replaced by that fix's commit.
 */
public class EndpointsTest {

    /** Handler with one annotated method per verb, each echoing its own verb name. */
    public static class AllVerbsHandler {
        @Get
        public Response onGet() {
            return new Response(Status.OK).setEntity("GET");
        }

        @Post
        public Response onPost() {
            return new Response(Status.OK).setEntity("POST");
        }

        @Put
        public Response onPut() {
            return new Response(Status.OK).setEntity("PUT");
        }

        @Delete
        public Response onDelete() {
            return new Response(Status.OK).setEntity("DELETE");
        }
    }

    /** Handler with a @Get only, so the other verbs resolve to the null-method sentinel. */
    public static class GetOnlyHandler {
        @Get
        public Response onGet() {
            return new Response(Status.OK).setEntity("GET");
        }
    }

    @DataProvider(name = "verbs")
    public Object[][] verbs() {
        return new Object[][] {{"GET"}, {"POST"}, {"PUT"}, {"DELETE"}};
    }

    @Test(dataProvider = "verbs")
    public void dispatchesEachVerbToItsAnnotatedMethod(String verb) throws IOException {
        Response response = handle(new AllVerbsHandler(), new Request().setMethod(verb));

        assertThat(response.getStatus()).isEqualTo(Status.OK);
        assertThat(response.getEntity().getString()).isEqualTo(verb);
    }

    @Test(dataProvider = "verbs")
    public void honoursXHttpMethodOverrideOnPost(String verb) throws IOException {
        Request request = new Request().setMethod("POST");
        request.getHeaders().put("X-HTTP-Method-Override", verb);

        Response response = handle(new AllVerbsHandler(), request);

        assertThat(response.getEntity().getString()).isEqualTo(verb);
    }

    @Test
    public void ignoresXHttpMethodOverrideOnNonPost() throws IOException {
        Request request = new Request().setMethod("GET");
        request.getHeaders().put("X-HTTP-Method-Override", "DELETE");

        Response response = handle(new AllVerbsHandler(), request);

        assertThat(response.getEntity().getString()).isEqualTo("GET");
    }

    /**
     * A verb the framework does not map at all never reaches an AnnotatedMethod: Endpoints
     * answers 405 with a NotSupportedException body, whose {@code code} is 501.
     */
    @Test
    public void unmappedVerbGives405WithA501Body() throws IOException {
        Response response = handle(new AllVerbsHandler(), new Request().setMethod("PATCH"));

        assertThat(response.getStatus()).isEqualTo(Status.METHOD_NOT_ALLOWED);
        assertThat(jsonBody(response))
                .containsEntry("code", 501)
                .containsEntry("reason", "Not Implemented")
                .containsEntry("message", "Not Implemented");
    }

    /**
     * A mapped verb with no matching method resolves to findMethod's sentinel, which answers
     * 405 with a matching 405 body — a different shape from the unmapped-verb case above.
     */
    @Test
    public void mappedVerbWithNoMethodGives405WithA405Body() throws IOException {
        Response response = handle(new GetOnlyHandler(), new Request().setMethod("DELETE"));

        assertThat(response.getStatus()).isEqualTo(Status.METHOD_NOT_ALLOWED);
        assertThat(jsonBody(response))
                .containsEntry("code", 405)
                .containsEntry("reason", "Method Not Allowed")
                .containsEntry("message", "Method Not Allowed");
    }
}
