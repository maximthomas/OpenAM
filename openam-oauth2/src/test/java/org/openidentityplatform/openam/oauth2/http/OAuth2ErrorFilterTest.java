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

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.entry;

import java.util.LinkedHashMap;
import java.util.Map;

import org.forgerock.http.Handler;
import org.forgerock.http.protocol.Request;
import org.forgerock.http.protocol.Response;
import org.forgerock.http.protocol.Status;
import org.forgerock.json.resource.InternalServerErrorException;
import org.forgerock.json.resource.NotSupportedException;
import org.forgerock.json.resource.ResourceException;
import org.forgerock.services.context.Context;
import org.forgerock.services.context.RootContext;
import org.forgerock.util.promise.Promises;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

/**
 * Unit coverage for the error-shape unifier, built on {@code XacmlXmlErrorFilterTest}'s scaffold: canned
 * responses, no Guice, no container.
 * <p>
 * A canned response encodes the author's belief about what the framework emits, which is exactly the class
 * of belief that turned out to be wrong when this phase was planned. The rows here fix the filter's
 * <em>rules</em>; that the framework really produces these inputs is
 * {@code OAuth2ErrorRouteCompositionIT}'s job, and only real composition can prove it.
 */
public class OAuth2ErrorFilterTest {

    private final OAuth2ErrorFilter filter = new OAuth2ErrorFilter();
    private final Context context = new RootContext();
    private final Request request = new Request();

    private Response through(Response canned) {
        Handler next = (ctx, req) -> Promises.newResultPromise(canned);
        return filter.filter(context, request, next).getOrThrowUninterruptibly();
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> bodyOf(Response response) throws Exception {
        return (Map<String, Object>) response.getEntity().getJson();
    }

    // ------------------------------------------------------------ rewrite the CREST shape

    @Test
    public void aCrestServerErrorBecomesAnOAuth2ServerError() throws Exception {
        Response response = through(new Response(Status.INTERNAL_SERVER_ERROR)
                .setEntity(new InternalServerErrorException("boom").toJsonValue().getObject()));

        assertThat(response.getStatus().getCode()).isEqualTo(500);
        assertThat(bodyOf(response)).containsExactly(
                entry("error", "server_error"), entry("error_description", "boom"));
        assertThat(response.getHeaders().getFirst("Content-Type")).isEqualTo("application/json; charset=UTF-8");
    }

    /**
     * The OAuth2 error is derived from the wire status, not the body's {@code code}, so a 405 collapses to one
     * client-visible shape however its CREST body is coded. Both inputs here are 405 on the wire: one carries a
     * mismatched {@code code} of 501 (as the framework's unmapped-verb fallback once emitted, before it was
     * fixed to a 405-coded body), the other a matching 405 -- both must become {@code invalid_request}.
     */
    @Test
    public void bothFrameworkMethodNotAllowedBodiesBecomeInvalidRequest() throws Exception {
        Response unmappedVerb = through(new Response(Status.METHOD_NOT_ALLOWED)
                .setEntity(new NotSupportedException("no HEAD here").toJsonValue().getObject()));
        Response noAnnotatedMethod = through(new Response(Status.METHOD_NOT_ALLOWED)
                .setEntity(ResourceException.getException(405, "no PUT here").toJsonValue().getObject()));

        assertThat(unmappedVerb.getStatus().getCode()).isEqualTo(405);
        assertThat(bodyOf(unmappedVerb)).containsExactly(
                entry("error", "invalid_request"), entry("error_description", "no HEAD here"));
        assertThat(bodyOf(noAnnotatedMethod)).containsExactly(
                entry("error", "invalid_request"), entry("error_description", "no PUT here"));
    }

    /**
     * The statuses RFC 6749 and 6750 give a specific code to must get it. This filter exists to hand the
     * client the field it dispatches on, and a client told {@code invalid_request} for a 401 corrects its
     * request parameters and retries -- forever -- where {@code invalid_client} tells it to re-authenticate.
     */
    @DataProvider(name = "statusToError")
    public Object[][] statusToError() {
        return new Object[][] {
            {Status.UNAUTHORIZED, "invalid_client"},           // RFC 6749 5.2
            {Status.FORBIDDEN, "access_denied"},               // RFC 6749 4.1.2.1
            {Status.SERVICE_UNAVAILABLE, "temporarily_unavailable"},
            {Status.NOT_FOUND, "invalid_request"},
            {Status.BAD_REQUEST, "invalid_request"},
            {Status.INTERNAL_SERVER_ERROR, "server_error"},
        };
    }

    @Test(dataProvider = "statusToError")
    public void theErrorCodeFollowsTheWireStatus(Status status, String expected) throws Exception {
        Map<String, Object> crest = new LinkedHashMap<>();
        crest.put("code", status.getCode());
        crest.put("message", "nope");

        Response response = through(new Response(status).setEntity(crest));

        assertThat(response.getStatus().getCode()).isEqualTo(status.getCode());
        assertThat(bodyOf(response)).containsEntry("error", expected);
    }

    @Test
    public void aCrestBodyWithNoMessageStillYieldsAnErrorCode() throws Exception {
        Map<String, Object> crest = new LinkedHashMap<>();
        crest.put("code", 400);
        crest.put("reason", "Bad Request");

        Response response = through(new Response(Status.BAD_REQUEST).setEntity(crest));

        assertThat(bodyOf(response)).containsExactly(entry("error", "invalid_request"));
    }

    /**
     * The message is carried across byte for byte.
     * <p>
     * This filter used to reverse the HTML escaping {@code ResourceException.toJsonValue()} applies, which
     * was correct only for bodies that had actually been through it -- a distinction the filter cannot make.
     * openam-http now emits the message as the exception wrote it ({@code AnnotatedMethod.crestBody}), so
     * there is nothing to undo, and a body from anywhere else is no longer silently altered.
     */
    @Test
    public void aCrestMessageKeepsItsMarkupCharacters() throws Exception {
        Map<String, Object> crest = new LinkedHashMap<>();
        crest.put("code", 400);
        crest.put("message", "unknown response_type <foo> & \"bar\"");

        Response response = through(new Response(Status.BAD_REQUEST).setEntity(crest));

        assertThat(bodyOf(response)).containsEntry("error_description", "unknown response_type <foo> & \"bar\"");
    }

    // ---------------------------------------------------------------- leave everything else

    @Test
    public void anOAuth2ShapedBodyIsLeftUntouched() throws Exception {
        Map<String, Object> oauth2 = new LinkedHashMap<>();
        oauth2.put("error", "invalid_grant");
        oauth2.put("error_description", "expired");
        oauth2.put("state", "xyz");

        Response response = through(new Response(Status.BAD_REQUEST).setEntity(oauth2));

        // Idempotent: the filter is mounted across the whole /oauth2 application, so it sees the error
        // factory's own output as well as the framework's.
        assertThat(bodyOf(response)).containsExactly(entry("error", "invalid_grant"),
                entry("error_description", "expired"), entry("state", "xyz"));
    }

    /**
     * R-3c.5. Phase 5b returns a 400 carrying the rendered {@code page/error.ftl}. The Phase-2 filter this
     * one is modelled on survives that case only because {@code getJson()} happens to throw on non-JSON --
     * an accident, and here a load-bearing one, so the guard is explicit and tested directly.
     */
    @Test
    public void anHtmlErrorPageIsLeftUntouched() throws Exception {
        Response html = new Response(Status.BAD_REQUEST);
        html.getHeaders().put("Content-Type", "text/html; charset=UTF-8");
        html.setEntity("<html><body>error</body></html>".getBytes(UTF_8));

        Response response = through(html);

        assertThat(response.getHeaders().getFirst("Content-Type")).isEqualTo("text/html; charset=UTF-8");
        assertThat(response.getEntity().getString()).isEqualTo("<html><body>error</body></html>");
    }

    /**
     * Post-F1 no framework response reaches this filter without a {@code Content-Type}, so a bodiless,
     * header-less error is something the filter cannot classify -- and inventing a body for it would be
     * guessing.
     */
    @Test
    public void aResponseWithNoContentTypeIsLeftUntouched() {
        Response response = through(new Response(Status.INTERNAL_SERVER_ERROR));

        assertThat(response.getStatus().getCode()).isEqualTo(500);
        assertThat(response.getEntity().isDecodedContentEmpty()).isTrue();
        assertThat(response.getHeaders().getFirst("Content-Type")).isNull();
    }

    @Test
    public void aJsonBodyThatIsNeitherShapeIsLeftUntouched() throws Exception {
        Response response = through(new Response(Status.BAD_REQUEST)
                .setEntity(java.util.Collections.singletonMap("unexpected", "shape")));

        assertThat(bodyOf(response)).containsExactly(entry("unexpected", "shape"));
    }

    @Test
    public void aJsonBodyThatIsNotAMapIsLeftUntouched() throws Exception {
        Response response = through(new Response(Status.BAD_REQUEST)
                .setEntity(java.util.Arrays.asList("a", "b")));

        assertThat(response.getEntity().getString()).isEqualTo("[\"a\",\"b\"]");
    }

    @Test
    public void aSuccessfulResponseIsLeftUntouched() throws Exception {
        Response response = through(new Response(Status.OK)
                .setEntity(java.util.Collections.singletonMap("code", 200)));

        assertThat(bodyOf(response)).containsExactly(entry("code", 200));
    }

    /** The filter must never fail a request; a malformed JSON body is not its problem to solve. */
    @Test
    public void aMalformedJsonBodyIsLeftUntouched() throws Exception {
        Response malformed = new Response(Status.BAD_REQUEST);
        malformed.getHeaders().put("Content-Type", "application/json; charset=UTF-8");
        malformed.setEntity("{not json".getBytes(UTF_8));

        Response response = through(malformed);

        assertThat(response.getEntity().getString()).isEqualTo("{not json");
    }
}
