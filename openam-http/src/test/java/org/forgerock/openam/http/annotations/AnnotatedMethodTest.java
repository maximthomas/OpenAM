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

import static java.nio.charset.StandardCharsets.ISO_8859_1;
import static java.nio.charset.StandardCharsets.UTF_8;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.forgerock.json.JsonValue.field;
import static org.forgerock.json.JsonValue.json;
import static org.forgerock.json.JsonValue.object;
import static org.forgerock.openam.http.annotations.EndpointTestSupport.get;
import static org.forgerock.openam.http.annotations.EndpointTestSupport.handle;
import static org.forgerock.openam.http.annotations.EndpointTestSupport.jsonBody;
import static org.forgerock.util.promise.Promises.newResultPromise;

import java.io.IOException;

import org.forgerock.http.header.ContentTypeHeader;
import org.forgerock.http.protocol.Request;
import org.forgerock.http.protocol.Response;
import org.forgerock.http.protocol.Status;
import org.forgerock.json.JsonValue;
import org.forgerock.json.resource.ResourceException;
import org.forgerock.services.context.AttributesContext;
import org.forgerock.services.context.Context;
import org.forgerock.services.context.RootContext;
import org.forgerock.util.promise.NeverThrowsException;
import org.forgerock.util.promise.Promise;
import org.testng.annotations.Test;

/**
 * Characterization tests for {@link AnnotatedMethod} — how a method's signature is translated
 * into a response. Driven through {@link Endpoints#from(Object)} because that is the only way
 * the framework is used, and because several failures surface at wiring time rather than at
 * request time.
 */
public class AnnotatedMethodTest {

    // ----- supported return types -----

    public static class StringHandler {
        @Get
        public String onGet() {
            return "body";
        }
    }

    /**
     * Dispatch and status only: {@code Entity} caches the String it was given, so getString()
     * never exercises the encoding. The wire format is pinned on bytes, by the @Produces tests.
     */
    @Test
    public void stringReturnBecomesAnOkEntity() throws IOException {
        Response response = get(new StringHandler());

        assertThat(response.getStatus()).isEqualTo(Status.OK);
        assertThat(response.getEntity().getString()).isEqualTo("body");
    }

    public static class ByteArrayHandler {
        @Get
        public byte[] onGet() {
            return new byte[] {1, 2, 3};
        }
    }

    @Test
    public void byteArrayReturnBecomesAnOkEntity() throws IOException {
        Response response = get(new ByteArrayHandler());

        assertThat(response.getStatus()).isEqualTo(Status.OK);
        assertThat(response.getEntity().getBytes()).containsExactly(1, 2, 3);
    }

    public static class JsonValueHandler {
        @Get
        public JsonValue onGet() {
            return json(object(field("a", "b")));
        }
    }

    @Test
    public void jsonValueReturnIsUnwrappedToItsObject() throws IOException {
        Response response = get(new JsonValueHandler());

        assertThat(response.getStatus()).isEqualTo(Status.OK);
        assertThat(jsonBody(response)).containsEntry("a", "b");
    }

    public static class NullStringHandler {
        @Get
        public String onGet() {
            return null;
        }
    }

    /** A null entity means 204, not 200 — but the rule is not uniform, see the JsonValue case. */
    @Test
    public void nullReturnBecomesNoContent() {
        Response response = get(new NullStringHandler());

        assertThat(response.getStatus()).isEqualTo(Status.NO_CONTENT);
    }

    public static class NullJsonValueHandler {
        @Get
        public JsonValue onGet() {
            return null;
        }
    }

    /**
     * The JsonValue converter dereferences its argument, so a null JsonValue is a 500 where a
     * null String is a 204. The NPE's message varies by JDK, so only the code is asserted.
     */
    @Test
    public void nullJsonValueReturnGivesA500NotNoContent() throws IOException {
        Response response = get(new NullJsonValueHandler());

        assertThat(response.getStatus()).isEqualTo(Status.INTERNAL_SERVER_ERROR);
        assertThat(jsonBody(response)).containsEntry("code", 500);
    }

    public static class VoidHandler {
        @Get
        public Void onGet() {
            return null;
        }
    }

    @Test
    public void boxedVoidReturnIsSupportedAndGivesNoContent() throws IOException {
        Response response = get(new VoidHandler());

        assertThat(response.getStatus()).isEqualTo(Status.NO_CONTENT);
        assertThat(response.getHeaders().getFirst(ContentTypeHeader.NAME)).isNull();
        assertThat(response.getEntity().getBytes()).isEmpty();
    }

    public static class PromiseHandler {
        @Get
        public Promise<Response, NeverThrowsException> onGet() {
            return newResultPromise(new Response(Status.OK).setEntity("promised"));
        }
    }

    @Test
    public void promiseReturnIsPassedThroughUnchanged() throws IOException {
        Response response = get(new PromiseHandler());

        assertThat(response.getStatus()).isEqualTo(Status.OK);
        assertThat(response.getEntity().getString()).isEqualTo("promised");
    }

    public static class NullPromiseHandler {
        @Get
        public Promise<Response, NeverThrowsException> onGet() {
            return null;
        }
    }

    /** Same rule as a null entity from a content-producing method. */
    @Test
    public void nullPromiseBecomesNoContent() {
        assertThat(get(new NullPromiseHandler()).getStatus()).isEqualTo(Status.NO_CONTENT);
    }

    // ----- unsupported return types fail at wiring time, not at request time -----

    public static class WrongPromiseHandler {
        @Get
        public Promise<Response, ResourceException> onGet() {
            return newResultPromise(new Response(Status.OK));
        }
    }

    /**
     * Erasure hides the type arguments from getReturnType(), so this promise would cast-fail
     * at request time. The generic return type is checked when the handler is mounted instead.
     */
    @Test
    public void wronglyParameterisedPromiseIsRejectedWhenTheHandlerIsMounted() {
        assertThatThrownBy(() -> Endpoints.from(new WrongPromiseHandler()))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("Unsupported response type: ")
                .hasMessageContaining("ResourceException");
    }

    @SuppressWarnings("rawtypes")
    public static class RawPromiseHandler {
        @Get
        public Promise onGet() {
            return newResultPromise(new Response(Status.OK));
        }
    }

    /** A raw Promise carries no type arguments to check, so it is rejected too. */
    @Test
    public void rawPromiseIsRejectedWhenTheHandlerIsMounted() {
        assertThatThrownBy(() -> Endpoints.from(new RawPromiseHandler()))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("Unsupported response type: ");
    }

    public static class PrimitiveVoidHandler {
        @Get
        public void onGet() {
        }
    }

    /** {@code void} is not {@code Void}: the primitive is rejected where the box is accepted. */
    @Test
    public void primitiveVoidReturnIsRejectedWhenTheHandlerIsMounted() {
        assertThatThrownBy(() -> Endpoints.from(new PrimitiveVoidHandler()))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("Unsupported response type: void");
    }

    public static class IntegerHandler {
        @Get
        public Integer onGet() {
            return 1;
        }
    }

    @Test
    public void unsupportedReturnTypeIsRejectedWhenTheHandlerIsMounted() {
        assertThatThrownBy(() -> Endpoints.from(new IntegerHandler()))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageStartingWith("Unsupported response type: class java.lang.Integer");
    }

    // ----- the undocumented name-based fallback -----

    /** No annotation anywhere; the method is bound purely because it is named "get". */
    public static class NameOnlyHandler {
        public Response get() {
            return new Response(Status.OK).setEntity("by-name");
        }
    }

    @Test
    public void methodNamedAfterTheVerbIsBoundWithoutAnAnnotation() throws IOException {
        assertThat(get(new NameOnlyHandler()).getEntity().getString()).isEqualTo("by-name");
    }

    /** The annotated method wins over a same-verb method matched only by name. */
    public static class AnnotatedAndNamedHandler {
        @Get
        public Response annotated() {
            return new Response(Status.OK).setEntity("annotated");
        }

        public Response get() {
            return new Response(Status.OK).setEntity("by-name");
        }
    }

    @Test
    public void annotationTakesPrecedenceOverTheNameFallback() throws IOException {
        assertThat(get(new AnnotatedAndNamedHandler()).getEntity().getString()).isEqualTo("annotated");
    }

    public static class BaseHandler {
        @Get
        public Response onGet() {
            return new Response(Status.OK).setEntity("inherited");
        }
    }

    public static class SubclassHandler extends BaseHandler {
    }

    /**
     * The annotated method may be inherited rather than declared — findMethod scans
     * getMethods(). AuthenticationServiceV2 binds its POST exactly this way.
     */
    @Test
    public void annotatedMethodInheritedFromASuperclassIsFound() throws IOException {
        assertThat(get(new SubclassHandler()).getEntity().getString()).isEqualTo("inherited");
    }

    // ----- @Contextual parameter injection -----

    public static class ContextualHandler {
        @Get
        public Response onGet(@Contextual Context context, @Contextual Request request) {
            return new Response(Status.OK).setEntity(context.getClass().getSimpleName() + ":" + request.getMethod());
        }
    }

    @Test
    public void contextualContextAndRequestAreInjected() throws IOException {
        assertThat(get(new ContextualHandler()).getEntity().getString()).isEqualTo("RootContext:GET");
    }

    public static class SpecificContextHandler {
        @Get
        public Response onGet(@Contextual RootContext context) {
            return new Response(Status.OK).setEntity(context.getId());
        }
    }

    @Test
    public void aSpecificContextTypeIsResolvedFromTheContextChain() throws IOException {
        RootContext context = new RootContext();
        Response response = Endpoints.from(new SpecificContextHandler())
                .handle(context, new Request().setMethod("GET")).getOrThrowUninterruptibly();

        assertThat(response.getEntity().getString()).isEqualTo(context.getId());
    }

    public static class StrayParameterHandler {
        @Get
        public Response onGet(String stray) {
            return new Response(Status.OK).setEntity(String.valueOf(stray));
        }
    }

    /** A parameter the framework cannot fill is passed as null, not rejected. */
    @Test
    public void anUnannotatedParameterIsPassedAsNull() throws IOException {
        assertThat(get(new StrayParameterHandler()).getEntity().getString()).isEqualTo("null");
    }

    public static class MissingContextHandler {
        @Get
        public Response onGet(@Contextual AttributesContext context) {
            return new Response(Status.OK);
        }
    }

    /**
     * A context the chain does not carry fails the request with a CREST 500 carrying the
     * resolution failure's own message. F1 moves where this is caught, not what it produces.
     */
    @Test
    public void aMissingContextGivesACrest500() throws IOException {
        Response response = get(new MissingContextHandler());

        assertThat(response.getStatus()).isEqualTo(Status.INTERNAL_SERVER_ERROR);
        assertThat(jsonBody(response))
                .containsEntry("code", 500)
                .containsEntry("reason", "Internal Server Error")
                .containsEntry("message",
                        "No context of type org.forgerock.services.context.AttributesContext found.");
    }

    // ----- a handler that throws -----

    public static class ThrowingHandler {
        @Get
        public Response onGet() {
            throw new IllegalStateException("handler blew up");
        }

        @Post
        public Response onPost() throws Exception {
            throw new Exception("checked failure");
        }

        @Put
        public Response onPut() {
            throw new Error("not an Exception");
        }
    }

    /** The thrown exception becomes a CREST body, and stays on the response as its cause. */
    @Test
    public void aThrownExceptionGivesACrest500CarryingItsMessage() throws IOException {
        Response response = get(new ThrowingHandler());

        assertThat(response.getStatus()).isEqualTo(Status.INTERNAL_SERVER_ERROR);
        assertThat(response.getHeaders().getFirst(ContentTypeHeader.NAME))
                .isEqualTo("application/json; charset=UTF-8");
        assertThat(jsonBody(response))
                .containsEntry("code", 500)
                .containsEntry("reason", "Internal Server Error")
                .containsEntry("message", "handler blew up");
        assertThat(response.getCause()).isInstanceOf(IllegalStateException.class).hasMessage("handler blew up");
    }

    @Test
    public void aThrownCheckedExceptionTakesTheSamePath() throws IOException {
        Response response = handle(new ThrowingHandler(), "POST");

        assertThat(response.getStatus()).isEqualTo(Status.INTERNAL_SERVER_ERROR);
        assertThat(jsonBody(response)).containsEntry("message", "checked failure");
    }

    /** Not only Exception: an Error thrown by a handler is answered, not propagated. */
    @Test
    public void aThrownErrorTakesTheSamePath() throws IOException {
        Response response = handle(new ThrowingHandler(), "PUT");

        assertThat(response.getStatus()).isEqualTo(Status.INTERNAL_SERVER_ERROR);
        assertThat(jsonBody(response)).containsEntry("message", "not an Exception");
    }

    public static class MarkupThrowingHandler {
        @Get
        public Response onGet() {
            throw new IllegalStateException("<b>bad</b> & worse");
        }
    }

    /**
     * The message ships verbatim, HTML metacharacters included.
     * <p>
     * {@code ResourceException.toJsonValue()} would escape it -- a CREST body is also rendered into
     * HTML pages elsewhere -- but this framework writes JSON, so escaping here only corrupts the
     * value for JSON clients. Escaping belongs to whoever renders the message into markup, against
     * that renderer's own context. Reversed deliberately; see {@code AnnotatedMethod.crestBody}.
     */
    @Test
    public void aThrownExceptionsMessageKeepsItsMarkupCharacters() throws IOException {
        assertThat(jsonBody(get(new MarkupThrowingHandler())))
                .containsEntry("message", "<b>bad</b> & worse");
    }

    /** Latin-1-representable and not, so both mangling modes show up. */
    private static final String NON_ASCII = "héllo €";

    public static class NonAsciiStringHandler {
        @Get
        public String onGet() {
            return NON_ASCII;
        }
    }

    /**
     * A String body is UTF-8 and says so. The fixture must be non-ASCII: with an ASCII body this
     * test passes even when the body is written as ISO-8859-1.
     */
    @Test
    public void aStringBodyIsUtf8AndCarriesAContentType() throws IOException {
        Response response = get(new NonAsciiStringHandler());

        assertThat(response.getHeaders().getFirst(ContentTypeHeader.NAME)).isEqualTo("text/plain; charset=UTF-8");
        assertThat(response.getEntity().getBytes()).isEqualTo(NON_ASCII.getBytes(UTF_8));
        assertThat(response.getEntity().getBytes()).isNotEqualTo(NON_ASCII.getBytes(ISO_8859_1));
    }

    public static class HtmlHandler {
        @Get
        @Produces("text/html; charset=UTF-8")
        public String onGet() {
            return NON_ASCII;
        }
    }

    @Test
    public void producesOverridesTheDefaultContentType() throws IOException {
        Response response = get(new HtmlHandler());

        assertThat(response.getHeaders().getFirst(ContentTypeHeader.NAME)).isEqualTo("text/html; charset=UTF-8");
        assertThat(response.getEntity().getBytes()).isEqualTo(NON_ASCII.getBytes(UTF_8));
    }

    public static class Latin1Handler {
        @Get
        @Produces("text/plain; charset=ISO-8859-1")
        public String onGet() {
            return "héllo";
        }
    }

    /** The charset the header declares is the charset the body is written in. */
    @Test
    public void producesDecidesTheCharsetTheBodyIsEncodedWith() throws IOException {
        Response response = get(new Latin1Handler());

        assertThat(response.getEntity().getBytes()).isEqualTo("héllo".getBytes(ISO_8859_1));
    }

    public static class ProducesByteArrayHandler {
        @Get
        @Produces("application/octet-stream")
        public byte[] onGet() {
            return new byte[] {1, 2, 3};
        }
    }

    @Test
    public void producesIsHonouredForBytes() throws IOException {
        Response response = get(new ProducesByteArrayHandler());

        assertThat(response.getHeaders().getFirst(ContentTypeHeader.NAME)).isEqualTo("application/octet-stream");
        assertThat(response.getEntity().getBytes()).containsExactly(1, 2, 3);
    }

    public static class BareByteArrayHandler {
        @Get
        public byte[] onGet() {
            return new byte[] {1, 2, 3};
        }
    }

    /** Only String gets a default: the framework cannot guess what bytes are. */
    @Test
    public void bytesWithoutProducesGetNoContentType() {
        assertThat(get(new BareByteArrayHandler()).getHeaders().getFirst(ContentTypeHeader.NAME)).isNull();
    }

    /** Nothing to describe and nothing to send: no Content-Type, and no body either. */
    @Test
    public void aNoContentResponseIsEmptyAndUntyped() throws IOException {
        Response response = get(new NullStringHandler());

        assertThat(response.getStatus()).isEqualTo(Status.NO_CONTENT);
        assertThat(response.getHeaders().getFirst(ContentTypeHeader.NAME)).isNull();
        assertThat(response.getEntity().getBytes()).isEmpty();
    }

    public static class ContradictingProducesHandler {
        @Get
        @Produces("text/plain; charset=UTF-8")
        public JsonValue onGet() {
            return json(object(field("a", "b")));
        }
    }

    /**
     * A JsonValue entity writes its own application/json header, which would silently win.
     * Reject the contradiction rather than let the annotation look honoured when it is not.
     */
    @Test
    public void producesContradictingAJsonValueReturnIsRejected() {
        assertThatThrownBy(() -> Endpoints.from(new ContradictingProducesHandler()))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("application/json");
    }

    public static class CharsetlessHtmlHandler {
        @Get
        @Produces("text/html")
        public String onGet() {
            return NON_ASCII;
        }
    }

    /**
     * A text type declaring no charset would send the entity back to ISO-8859-1, reopening the
     * defect @Produces is here to fix. UTF-8 is filled in rather than assumed.
     */
    @Test
    public void producesWithoutACharsetStillEncodesTextAsUtf8() throws IOException {
        Response response = get(new CharsetlessHtmlHandler());

        assertThat(response.getHeaders().getFirst(ContentTypeHeader.NAME)).isEqualTo("text/html; charset=UTF-8");
        assertThat(response.getEntity().getBytes()).isEqualTo(NON_ASCII.getBytes(UTF_8));
    }

    public static class UppercaseJsonHandler {
        @Get
        @Produces("Application/JSON")
        public JsonValue onGet() {
            return json(object(field("a", "b")));
        }
    }

    /** Media types are case-insensitive, so this agrees with the JsonValue return rather than not. */
    @Test
    public void producesIsComparedCaseInsensitively() throws IOException {
        assertThat(jsonBody(get(new UppercaseJsonHandler()))).containsEntry("a", "b");
    }

    public static class JsonWithWrongCharsetHandler {
        @Get
        @Produces("application/json; charset=ISO-8859-1")
        public JsonValue onGet() {
            return json(object(field("a", "b")));
        }
    }

    /** The right type with the wrong charset is still a contradiction: the entity writes UTF-8. */
    @Test
    public void producesWithACharsetAJsonValueCannotHonourIsRejected() {
        assertThatThrownBy(() -> Endpoints.from(new JsonWithWrongCharsetHandler()))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("application/json");
    }

    public static class ProducesOnVoidHandler {
        @Get
        @Produces("text/html; charset=UTF-8")
        public Void onGet() {
            return null;
        }
    }

    /** A Void return has no content, so the annotation could only ever be ignored. */
    @Test
    public void producesOnAVoidReturnIsRejected() {
        assertThatThrownBy(() -> Endpoints.from(new ProducesOnVoidHandler()))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("never has content");
    }

    public static class EmptyProducesHandler {
        @Get
        @Produces("")
        public String onGet() {
            return "body";
        }
    }

    @Test
    public void anEmptyProducesIsRejected() {
        assertThatThrownBy(() -> Endpoints.from(new EmptyProducesHandler()))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("Empty @Produces");
    }

    public static class BadCharsetHandler {
        @Get
        @Produces("text/plain; charset=not-a-charset")
        public String onGet() {
            return "body";
        }
    }

    /** A typo fails when the endpoint is mounted, not on every request that hits it. */
    @Test
    public void producesWithAnUnknownCharsetIsRejected() {
        assertThatThrownBy(() -> Endpoints.from(new BadCharsetHandler()))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("not-a-charset");
    }

    public static class ProducesOnResponseHandler {
        @Get
        @Produces("text/html")
        public Response onGet() {
            return new Response(Status.OK).setEntity("body");
        }
    }

    /**
     * A method returning Response owns its headers, so @Produces there would be quietly
     * ignored - which is the defect F4 exists to fix. Say so at wiring time instead.
     */
    @Test
    public void producesOnAMethodThatReturnsItsOwnResponseIsRejected() {
        assertThatThrownBy(() -> Endpoints.from(new ProducesOnResponseHandler()))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("@Produces");
    }
}
