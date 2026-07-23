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
import static org.assertj.core.api.Assertions.entry;
import static org.mockito.Mockito.mock;

import java.util.Map;

import org.forgerock.http.Handler;
import org.forgerock.http.handler.Handlers;
import org.forgerock.http.protocol.Request;
import org.forgerock.http.protocol.Response;
import org.forgerock.http.protocol.Status;
import org.forgerock.oauth2.core.exceptions.InvalidGrantException;
import org.forgerock.openam.http.annotations.Endpoints;
import org.forgerock.openam.http.annotations.Get;
import org.forgerock.openam.services.baseurl.BaseURLProviderFactory;
import org.forgerock.openam.utils.RealmNormaliser;
import org.forgerock.services.context.RootContext;
import org.testng.annotations.Test;

/**
 * Drives {@link OAuth2ErrorFilter} over the real {@code Endpoints.from} framework, in process.
 *
 * <h2>Why this exists when the filter already has a unit suite</h2>
 * A canned {@code Response} encodes the author's belief about what the framework emits, and this phase's
 * research found that belief wrong: {@code chf-patterns.md} said an uncaught {@code Throwable} yields a
 * CREST error map, when in fact a handler that <em>threw</em> produced a 500 with an empty body and no
 * {@code Content-Type} at all. No unit test with a hand-written response could have caught that, because the
 * hand-written response would have been wrong in the same way. Only real composition can.
 * <p>
 * Since then the framework has been fixed (F1-F4), so what these rows now verify is that the fix composes as
 * believed -- that a throwing handler really does reach this filter as a well-formed CREST body, and that
 * the two distinct 405 shapes really are what they are documented to be.
 *
 * <h2>Name trap</h2>
 * {@code *IT.java} is bound to failsafe, so {@code mvn -pl openam-oauth2 test} does <strong>not</strong>
 * run this class. It needs {@code mvn -pl openam-oauth2 verify}. CI runs {@code verify} on all nine legs.
 */
public class OAuth2ErrorRouteCompositionIT {

    /**
     * A handler that fails the way a Phase 5 handler would if it let something escape. The message carries
     * markup on purpose: {@code ResourceException.toJsonValue()} would HTML-escape it, and openam-http
     * deliberately does not, so this row is where that composes or does not.
     */
    public static class ThrowingEndpoint {
        @Get
        public Response get() throws Exception {
            throw new InvalidGrantException("the code for <client> expired & cannot be reused");
        }
    }

    /** Only {@code GET} is annotated, so {@code PUT} and {@code HEAD} take the two different 405 paths. */
    public static class GetOnlyEndpoint {
        @Get
        public Response get() {
            return new Response(Status.OK).setEntity(java.util.Collections.singletonMap("ok", true));
        }
    }

    /**
     * Phase 5b's shape: a business error rendered as the real HTML error page.
     * <p>
     * Built by {@link OAuth2ErrorResponseFactory} rather than by hand. A hand-written response would encode
     * this author's belief about what that class emits -- the same belief a canned unit fixture encodes,
     * and the reason this IT exists. The collaborators are mocks only because the render path does not
     * reach them; the template, the data model and the {@code Content-Type} are the production ones.
     */
    public static class HtmlErrorEndpoint {
        @Get
        public Response get() throws Exception {
            return new OAuth2ErrorResponseFactory(new FreemarkerTemplateRenderer(),
                    mock(BaseURLProviderFactory.class), mock(RealmNormaliser.class))
                    .toHtmlErrorResponse(Status.BAD_REQUEST,
                            OAuth2Error.of(400, "access_denied", "consent denied"), "/",
                            "https://openam.example/openam");
        }
    }

    /** Phase 5a's shape: an error the endpoint already rendered through the factory. */
    public static class OAuth2ErrorEndpoint {
        @Get
        public Response get() {
            Response response = new Response(Status.BAD_REQUEST);
            response.setEntity(OAuth2Error.of(400, "invalid_grant", "expired").withState("xyz").asMap());
            return response;
        }
    }

    private static Response through(Object endpoint, String method) throws Exception {
        Handler handler = Handlers.chainOf(Endpoints.from(endpoint), new OAuth2ErrorFilter());
        return handler.handle(new RootContext(), new Request().setMethod(method).setUri("/"))
                .getOrThrowUninterruptibly();
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> bodyOf(Response response) throws Exception {
        return (Map<String, Object>) response.getEntity().getJson();
    }

    /**
     * The row the whole class is for. Before F1 this produced a bodiless 500 with no {@code Content-Type},
     * which the filter would have had to guess at; it now arrives as a CREST body and is rewritten like any
     * other framework error.
     */
    @Test
    public void aThrowingHandlerBecomesAnOAuth2ShapedServerError() throws Exception {
        Response response = through(new ThrowingEndpoint(), "GET");

        assertThat(response.getStatus().getCode()).isEqualTo(500);
        assertThat(response.getHeaders().getFirst("Content-Type")).isEqualTo("application/json; charset=UTF-8");
        // Markup intact: the framework no longer HTML-escapes the message, so the filter has nothing to
        // undo and a client reading error_description sees what the handler actually said.
        assertThat(bodyOf(response)).containsExactly(
                entry("error", "server_error"),
                entry("error_description", "the code for <client> expired & cannot be reused"));
    }

    /** A mapped verb with no annotated method: {@code AnnotatedMethod}'s own 405. */
    @Test
    public void aMappedVerbWithNoAnnotatedMethodBecomesInvalidRequest() throws Exception {
        Response response = through(new GetOnlyEndpoint(), "PUT");

        assertThat(response.getStatus().getCode()).isEqualTo(405);
        assertThat(bodyOf(response)).containsEntry("error", "invalid_request");
    }

    /**
     * A verb that is not in the framework's map at all: {@code Endpoints}' fallback, whose body carries
     * {@code code: 501} against a 405 status. Both 405 paths must collapse to one client-visible shape,
     * which is only true because the filter derives the error from the wire status.
     */
    @Test
    public void anUnmappedVerbBecomesTheSameInvalidRequest() throws Exception {
        Response response = through(new GetOnlyEndpoint(), "HEAD");

        assertThat(response.getStatus().getCode()).isEqualTo(405);
        assertThat(bodyOf(response)).containsEntry("error", "invalid_request");
    }

    /** R-3c.5, through the real chain: the real error page must survive the filter intact. */
    @Test
    public void anHtmlErrorPageSurvivesTheChain() throws Exception {
        Response response = through(new HtmlErrorEndpoint(), "GET");

        assertThat(response.getStatus().getCode()).isEqualTo(400);
        assertThat(response.getHeaders().getFirst("Content-Type")).isEqualTo("text/html; charset=UTF-8");
        assertThat(response.getEntity().getString())
                .contains("message: \"access_denied\"")
                .contains("description: \"consent denied\"")
                .doesNotContain("\"error\":");     // not rewritten into the JSON shape
    }

    @Test
    public void anAlreadyOAuth2ShapedErrorSurvivesTheChain() throws Exception {
        Response response = through(new OAuth2ErrorEndpoint(), "GET");

        assertThat(response.getStatus().getCode()).isEqualTo(400);
        assertThat(bodyOf(response)).containsExactly(entry("error", "invalid_grant"),
                entry("error_description", "expired"), entry("state", "xyz"));
    }

    @Test
    public void aSuccessfulResponseSurvivesTheChain() throws Exception {
        Response response = through(new GetOnlyEndpoint(), "GET");

        assertThat(response.getStatus().getCode()).isEqualTo(200);
        assertThat(bodyOf(response)).containsExactly(entry("ok", true));
    }
}
