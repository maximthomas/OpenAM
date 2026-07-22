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
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.forgerock.openam.http.annotations.EndpointTestSupport.get;
import static org.forgerock.openam.http.annotations.EndpointTestSupport.handle;
import static org.forgerock.openam.http.annotations.EndpointTestSupport.jsonBody;

import java.io.IOException;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

import org.forgerock.http.header.ContentTypeHeader;
import org.forgerock.http.protocol.Request;
import org.forgerock.http.protocol.Response;
import org.forgerock.http.protocol.Status;
import org.forgerock.services.context.AttributesContext;
import org.testng.annotations.Test;

/**
 * Tests for {@link ExceptionHandler} — an endpoint's own method for turning a thrown exception
 * into a response, instead of the framework's default 500.
 */
public class ExceptionHandlerTest {

    /**
     * The feature was dead for a decade because the annotation defaulted to CLASS retention and
     * was therefore invisible to reflection. Asserted directly so it cannot regress silently.
     */
    @Test
    public void theAnnotationIsVisibleToReflectionAndAppliesToMethods() {
        assertThat(ExceptionHandler.class.getAnnotation(Retention.class).value())
                .isEqualTo(RetentionPolicy.RUNTIME);
        assertThat(ExceptionHandler.class.getAnnotation(Target.class).value())
                .containsExactly(ElementType.METHOD);
    }

    // ----- dispatch -----

    public static class MappedHandler {
        @Get
        public Response onGet() {
            throw new IllegalStateException("boom");
        }

        @ExceptionHandler
        public Response onError(IllegalStateException e) {
            return new Response(Status.BAD_REQUEST).setEntity("mapped:" + e.getMessage());
        }
    }

    @Test
    public void aMatchingExceptionHandlerProducesTheResponse() throws IOException {
        Response response = get(new MappedHandler());

        assertThat(response.getStatus()).isEqualTo(Status.BAD_REQUEST);
        assertThat(response.getEntity().getString()).isEqualTo("mapped:boom");
    }

    public static class SubtypeHandler {
        @Get
        public Response onGet() {
            throw new IllegalArgumentException("boom");
        }

        @ExceptionHandler
        public Response onRuntime(RuntimeException e) {
            return new Response(Status.OK).setEntity("runtime");
        }
    }

    /** Assignability, not identity: a supertype handler catches the subtype that was thrown. */
    @Test
    public void anExceptionHandlerMatchesSubtypesOfItsParameter() throws IOException {
        assertThat(get(new SubtypeHandler()).getEntity().getString()).isEqualTo("runtime");
    }

    public static class SpecificityHandler {
        @Get
        public Response onGet() {
            throw new IllegalArgumentException("boom");
        }

        @ExceptionHandler
        public Response onRuntime(RuntimeException e) {
            return new Response(Status.OK).setEntity("runtime");
        }

        @ExceptionHandler
        public Response onIllegalArgument(IllegalArgumentException e) {
            return new Response(Status.OK).setEntity("specific");
        }
    }

    @Test
    public void theMostSpecificMatchingExceptionHandlerWins() throws IOException {
        assertThat(get(new SpecificityHandler()).getEntity().getString()).isEqualTo("specific");
    }

    public static class UnmatchedHandler {
        @Get
        public Response onGet() {
            throw new IllegalStateException("unmapped");
        }

        @ExceptionHandler
        public Response onArithmetic(ArithmeticException e) {
            return new Response(Status.OK).setEntity("wrong one");
        }
    }

    /** An endpoint that maps one exception keeps sane behaviour for everything else. */
    @Test
    public void anUnmatchedExceptionFallsBackToTheDefault500() throws IOException {
        Response response = get(new UnmatchedHandler());

        assertThat(response.getStatus()).isEqualTo(Status.INTERNAL_SERVER_ERROR);
        assertThat(jsonBody(response)).containsEntry("message", "unmapped");
    }

    public static class FrameworkFailureHandler {
        @Get
        public Response onGet(@Contextual AttributesContext missing) {
            return new Response(Status.OK);
        }

        @ExceptionHandler
        public Response onError(IllegalArgumentException e) {
            return new Response(Status.OK).setEntity("mapped");
        }
    }

    /**
     * Only what the method threw is dispatched. Resolving a context the chain does not carry
     * fails inside the framework, and an endpoint mapping IllegalArgumentException must not be
     * able to turn that into a success — it would mask the misconfiguration indefinitely.
     */
    @Test
    public void aFrameworkFailureIsNotOfferedToTheExceptionHandler() throws IOException {
        Response response = get(new FrameworkFailureHandler());

        assertThat(response.getStatus()).isEqualTo(Status.INTERNAL_SERVER_ERROR);
        assertThat(jsonBody(response)).containsEntry("message",
                "No context of type org.forgerock.services.context.AttributesContext found.");
    }

    public static class ErrorHandlingBase {
        @ExceptionHandler
        public Response onError(IllegalStateException e) {
            return new Response(Status.OK).setEntity("inherited");
        }
    }

    public static class InheritingHandler extends ErrorHandlingBase {
        @Get
        public Response onGet() {
            throw new IllegalStateException("boom");
        }
    }

    /** Scanning uses getMethods(), so a handler declared on a superclass still applies. */
    @Test
    public void anInheritedExceptionHandlerApplies() throws IOException {
        assertThat(get(new InheritingHandler()).getEntity().getString()).isEqualTo("inherited");
    }

    public static class EveryVerbThrowsHandler {
        @Post
        public Response onPost() {
            throw new IllegalStateException("from post");
        }

        @ExceptionHandler
        public Response onError(IllegalStateException e) {
            return new Response(Status.BAD_REQUEST).setEntity(e.getMessage());
        }
    }

    /** One table serves all four verbs, not just the one the other tests happen to use. */
    @Test
    public void theExceptionHandlerAppliesToEveryVerb() throws IOException {
        Response response = handle(new EveryVerbThrowsHandler(), "POST");

        assertThat(response.getStatus()).isEqualTo(Status.BAD_REQUEST);
        assertThat(response.getEntity().getString()).isEqualTo("from post");
    }

    // ----- the exception handler is an annotated method like any other -----

    public static class ContextualErrorHandler {
        @Get
        public Response onGet() {
            throw new IllegalStateException("boom");
        }

        @ExceptionHandler
        public Response onError(IllegalStateException e, @Contextual Request request) {
            return new Response(Status.OK).setEntity(request.getMethod() + ":" + e.getMessage());
        }
    }

    @Test
    public void contextualParametersAreInjectedIntoTheExceptionHandler() throws IOException {
        assertThat(get(new ContextualErrorHandler()).getEntity().getString()).isEqualTo("GET:boom");
    }

    public static class StringReturningErrorHandler {
        @Get
        public Response onGet() {
            throw new IllegalStateException("boom");
        }

        @ExceptionHandler
        public String onError(IllegalStateException e) {
            return "as-text";
        }
    }

    /** Same return types as a verb method, through the same adapter — so a String means 200. */
    @Test
    public void anExceptionHandlerMayReturnAnySupportedType() throws IOException {
        Response response = get(new StringReturningErrorHandler());

        assertThat(response.getStatus()).isEqualTo(Status.OK);
        assertThat(response.getEntity().getString()).isEqualTo("as-text");
    }

    public static class ProblemDetailHandler {
        @Get
        public Response onGet() {
            throw new IllegalStateException("boom");
        }

        @ExceptionHandler
        @Produces("application/problem+json; charset=UTF-8")
        public String onError(IllegalStateException e) {
            return "{\"detail\":\"" + e.getMessage() + "\"}";
        }
    }

    /** An exception handler is wired like any other method, @Produces included. */
    @Test
    public void producesIsHonouredOnAnExceptionHandler() throws IOException {
        Response response = get(new ProblemDetailHandler());

        assertThat(response.getHeaders().getFirst(ContentTypeHeader.NAME))
                .isEqualTo("application/problem+json; charset=UTF-8");
        assertThat(response.getEntity().getString()).isEqualTo("{\"detail\":\"boom\"}");
    }

    // ----- the error path must not fault -----

    public static class FaultyErrorHandler {
        int dispatches;

        @Get
        public Response onGet() {
            throw new IllegalStateException("original");
        }

        @ExceptionHandler
        public Response onError(IllegalStateException e) {
            dispatches++;
            throw new IllegalStateException("the mapper itself failed");
        }
    }

    /**
     * An exception handler that throws must not be re-entered with its own exception. The
     * response describes the request's original failure; the mapper's is a server-side bug.
     */
    @Test
    public void anExceptionHandlerThatThrowsFallsBackWithoutRecursing() throws IOException {
        FaultyErrorHandler endpoint = new FaultyErrorHandler();

        Response response = get(endpoint);

        assertThat(endpoint.dispatches).isEqualTo(1);
        assertThat(response.getStatus()).isEqualTo(Status.INTERNAL_SERVER_ERROR);
        assertThat(jsonBody(response)).containsEntry("message", "original");
    }

    // ----- malformed declarations fail when the handler is mounted -----

    public static class DuplicateTypeHandler {
        @Get
        public Response onGet() {
            return new Response(Status.OK);
        }

        @ExceptionHandler
        public Response first(IllegalStateException e) {
            return new Response(Status.OK);
        }

        @ExceptionHandler
        public Response second(IllegalStateException e) {
            return new Response(Status.OK);
        }
    }

    /** Two handlers for one type have no defensible winner, so it is a wiring error. */
    @Test
    public void duplicateExceptionTypesAreRejectedWhenTheHandlerIsMounted() {
        assertThatThrownBy(() -> Endpoints.from(new DuplicateTypeHandler()))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("IllegalStateException");
    }

    public static class NonThrowableParameterHandler {
        @Get
        public Response onGet() {
            return new Response(Status.OK);
        }

        @ExceptionHandler
        public Response onError(String notAnException) {
            return new Response(Status.OK);
        }
    }

    @Test
    public void anExceptionParameterThatIsNotAThrowableIsRejected() {
        assertThatThrownBy(() -> Endpoints.from(new NonThrowableParameterHandler()))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("Throwable");
    }

    public static class NoExceptionParameterHandler {
        @Get
        public Response onGet() {
            return new Response(Status.OK);
        }

        @ExceptionHandler
        public Response onError(@Contextual Request request) {
            return new Response(Status.OK);
        }
    }

    public static class TwoExceptionParametersHandler {
        @Get
        public Response onGet() {
            return new Response(Status.OK);
        }

        @ExceptionHandler
        public Response onError(IllegalStateException first, IllegalArgumentException second) {
            return new Response(Status.OK);
        }
    }

    /** Only one of the two could ever be filled, so the declaration is a mistake, not a choice. */
    @Test
    public void moreThanOneExceptionParameterIsRejected() {
        assertThatThrownBy(() -> Endpoints.from(new TwoExceptionParametersHandler()))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("More than one Throwable parameter");
    }

    @Test
    public void anExceptionHandlerWithNoExceptionParameterIsRejected() {
        assertThatThrownBy(() -> Endpoints.from(new NoExceptionParameterHandler()))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("Throwable");
    }
}
