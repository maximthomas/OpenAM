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
 * <p>
 * The rows marked <em>F5</em> are the exception: they pin the {@code HEAD} mapping and the
 * {@code Allow} header <em>after</em> that fix, against the live Restlet behaviour phase 5-E5
 * recorded.
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

    /** Handler with a @Post only, so HEAD resolves to the GET sentinel. */
    public static class PostOnlyHandler {
        @Post
        public Response onPost() {
            return new Response(Status.OK).setEntity("POST");
        }
    }

    /** Handler that answers 405 itself, advertising a verb the framework knows nothing about. */
    public static class OwnAllowHandler {
        @Get
        public Response onGet() {
            Response response = new Response(Status.METHOD_NOT_ALLOWED);
            response.getHeaders().put("Allow", "TRACE");
            return response;
        }
    }

    /**
     * Handler carrying no annotation at all: {@code findMethod}'s second pass matches it by method
     * name. Nothing an annotation scan could see, which is why the Allow list is derived from the
     * resolved method instead.
     */
    public static class NameConventionHandler {
        public Response get() {
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
     * A verb the framework does not map at all never reaches an AnnotatedMethod. Endpoints
     * answers 405 with a body whose {@code code} matches the 405 status line — the same shape
     * as the mapped-verb-with-no-method case below. (Previously this path emitted a
     * NotSupportedException body whose {@code code} was 501, contradicting the 405 status; that
     * status-line/body-code mismatch is now fixed.)
     */
    @Test
    public void unmappedVerbGives405WithA405Body() throws IOException {
        Response response = handle(new AllVerbsHandler(), new Request().setMethod("PATCH"));

        assertThat(response.getStatus()).isEqualTo(Status.METHOD_NOT_ALLOWED);
        assertThat(jsonBody(response))
                .containsEntry("code", 405)
                .containsEntry("reason", "Method Not Allowed")
                .containsEntry("message", "Method Not Allowed");
    }

    /**
     * A mapped verb with no matching method resolves to findMethod's sentinel, which answers
     * 405 with a matching 405 body — the same shape as the unmapped-verb case above.
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

    /**
     * F5. RFC 7231 §4.3.2 defines HEAD as GET without the body, and dropping the body is the
     * servlet container's job — so the @Get method runs and returns its entity here.
     */
    @Test
    public void headDispatchesToTheGetMethod() throws IOException {
        Response response = handle(new AllVerbsHandler(), new Request().setMethod("HEAD"));

        assertThat(response.getStatus()).isEqualTo(Status.OK);
        assertThat(response.getEntity().getString()).isEqualTo("GET");
    }

    /** F5. No @Get means HEAD resolves to the same sentinel GET does, so it 405s as before. */
    @Test
    public void headGives405WhenThereIsNoGetMethod() {
        Response response = handle(new PostOnlyHandler(), new Request().setMethod("HEAD"));

        assertThat(response.getStatus()).isEqualTo(Status.METHOD_NOT_ALLOWED);
        assertThat(allowOf(response)).isEqualTo("POST");
    }

    /** F5. RFC 7231 §6.5.5 makes Allow mandatory on a 405 — here from the unmapped-verb producer. */
    @Test
    public void unmappedVerb405CarriesAllow() {
        Response response = handle(new AllVerbsHandler(), new Request().setMethod("PATCH"));

        assertThat(allowOf(response)).isEqualTo("DELETE, GET, POST, PUT");
    }

    /** F5. The other 405 producer: AnnotatedMethod's null-method sentinel. */
    @Test
    public void sentinel405CarriesAllowListingOnlyTheSupportedVerbs() {
        Response response = handle(new GetOnlyHandler(), new Request().setMethod("DELETE"));

        assertThat(allowOf(response)).isEqualTo("GET");
    }

    /**
     * F5. HEAD is mapped but never advertised: Restlet answered HEAD while advertising the four
     * mapped verbs only, and [5-E4 row 11] asserts that set.
     */
    @Test
    public void allowNeverAdvertisesHead() {
        Response response = handle(new AllVerbsHandler(), new Request().setMethod("PROPFIND"));

        assertThat(allowOf(response)).doesNotContain("HEAD");
    }

    /**
     * F5. The Allow list is derived from the resolved AnnotatedMethod, not from an annotation
     * scan — findMethod's second pass matches by method name, and the two disagree here.
     */
    @Test
    public void allowCoversMethodsMatchedByNameRatherThanAnnotation() {
        Response response = handle(new NameConventionHandler(), new Request().setMethod("PATCH"));

        assertThat(allowOf(response)).isEqualTo("GET");
    }

    /** F5. The stamp is idempotent: a handler that answered 405 with its own Allow keeps it. */
    @Test
    public void handlersOwnAllowIsNotOverwritten() {
        Response response = handle(new OwnAllowHandler(), new Request().setMethod("GET"));

        assertThat(allowOf(response)).isEqualTo("TRACE");
    }

    /** F5. Allow belongs on a 405, and nowhere else. */
    @Test
    public void successfulResponseCarriesNoAllow() {
        Response response = handle(new AllVerbsHandler(), new Request().setMethod("GET"));

        assertThat(response.getStatus()).isEqualTo(Status.OK);
        assertThat(allowOf(response)).isNull();
    }

    private static String allowOf(Response response) {
        return response.getHeaders().getFirst("Allow");
    }
}
