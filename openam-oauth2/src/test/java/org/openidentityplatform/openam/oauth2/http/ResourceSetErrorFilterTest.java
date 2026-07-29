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

import java.util.LinkedHashMap;
import java.util.Map;

import org.forgerock.http.Handler;
import org.forgerock.http.protocol.Request;
import org.forgerock.http.protocol.Response;
import org.forgerock.http.protocol.Status;
import org.forgerock.json.resource.NotSupportedException;
import org.forgerock.services.context.Context;
import org.forgerock.services.context.RootContext;
import org.forgerock.util.promise.Promises;
import org.testng.annotations.Test;

/**
 * Unit coverage for producer B's port -- the filter that gives {@code /oauth2/resource_set} the error
 * vocabulary draft-hardjono-oauth-resource-reg-04 3 defines, rather than the generic {@code /oauth2} one.
 * <p>
 * The status/body rows are measured (5-E4 rows 11, 13 and 14); the guard is read off the Restlet filter's
 * {@code entity == null} check. Canned responses, no Guice, no container -- that the framework really produces
 * these inputs is {@code ResourceSetRouteCompositionIT}'s job at 5c-2.
 */
public class ResourceSetErrorFilterTest {

    private final ResourceSetErrorFilter filter = new ResourceSetErrorFilter();
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

    /** What {@code Endpoints.from} hands this filter for an unmapped verb: a CREST body, not an empty one. */
    private static Object crest(int code, String reason, String message) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("code", code);
        body.put("reason", reason);
        body.put("message", message);
        return body;
    }

    // ------------------------------------------------------------------ the two named statuses

    @Test
    public void anEmptyBodied405BecomesUnsupportedMethodType() throws Exception {
        Response response = through(new Response(Status.METHOD_NOT_ALLOWED));

        assertThat(response.getStatus().getCode()).isEqualTo(405);
        assertThat(bodyOf(response)).containsExactly(entry("error", "unsupported_method_type"));
    }

    @Test
    public void aCrestBodied405BecomesUnsupportedMethodType() throws Exception {
        // The real CHF input. Restlet's filter only ever saw the empty case, so this row is the port's own.
        Response response = through(new Response(Status.METHOD_NOT_ALLOWED)
                .setEntity(new NotSupportedException("not allowed").toJsonValue().getObject()));

        assertThat(response.getStatus().getCode()).isEqualTo(405);
        assertThat(bodyOf(response)).containsExactly(entry("error", "unsupported_method_type"));
    }

    @Test
    public void anEmptyBodied412BecomesPreconditionFailed() throws Exception {
        // D6's conditional path returns a bare 412 precisely so this filter supplies the body.
        Response response = through(new Response(Status.valueOf(412)));

        assertThat(response.getStatus().getCode()).isEqualTo(412);
        assertThat(bodyOf(response)).containsExactly(entry("error", "precondition_failed"));
    }

    @Test
    public void neitherNamedStatusCarriesAnErrorDescription() throws Exception {
        assertThat(bodyOf(through(new Response(Status.METHOD_NOT_ALLOWED)))).doesNotContainKey("error_description");
        assertThat(bodyOf(through(new Response(Status.valueOf(412))))).doesNotContainKey("error_description");
    }

    // ------------------------------------------------------------------ Content-Type: bare, no charset

    @Test
    public void theRewrittenBodyIsBareApplicationJson() {
        // 5-E4 row 14, asserted exactly by the gate: application/json with NO charset on 405 and 412.
        // setEntity(Map) writes "; charset=UTF-8", so the header is re-stamped after the body.
        assertThat(through(new Response(Status.METHOD_NOT_ALLOWED)).getHeaders().getFirst("Content-Type"))
                .isEqualTo("application/json");
        assertThat(through(new Response(Status.valueOf(412))).getHeaders().getFirst("Content-Type"))
                .isEqualTo("application/json");
    }

    // ------------------------------------------------------------------ the catch-all: 500 server_error

    @Test
    public void anyOtherEmptyBodiedErrorBecomesAServerErrorAt500() throws Exception {
        Response response = through(new Response(Status.BAD_REQUEST));

        assertThat(response.getStatus().getCode()).isEqualTo(500);
        assertThat(bodyOf(response)).containsExactly(entry("error", "server_error"));
    }

    @Test
    public void theCatchAllCarriesTheCrestMessageAsErrorDescription() throws Exception {
        Response response = through(new Response(Status.BAD_REQUEST)
                .setEntity(crest(400, "Bad Request", "malformed")));

        assertThat(response.getStatus().getCode()).isEqualTo(500);
        assertThat(bodyOf(response)).containsExactly(
                entry("error", "server_error"), entry("error_description", "malformed"));
    }

    @Test
    public void aCrestBodyWithNoMessageYieldsNoErrorDescription() throws Exception {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("code", 503);
        body.put("reason", "Service Unavailable");
        Response response = through(new Response(Status.valueOf(503)).setEntity(body));

        assertThat(response.getStatus().getCode()).isEqualTo(500);
        assertThat(bodyOf(response)).containsExactly(entry("error", "server_error"));
    }

    // ------------------------------------------------------------------ the guard

    @Test
    public void aBodyAlreadyCarryingErrorIsUntouched() throws Exception {
        // The idempotency guard, and what keeps D2's OAuth2-shaped 401 out of the catch-all's 500.
        Map<String, Object> unauthorized = new LinkedHashMap<>();
        unauthorized.put("error", "invalid_token");
        unauthorized.put("error_description", "the token is expired");
        Response response = through(new Response(Status.UNAUTHORIZED).setEntity(unauthorized));

        assertThat(response.getStatus().getCode()).isEqualTo(401);
        assertThat(bodyOf(response)).containsExactly(
                entry("error", "invalid_token"), entry("error_description", "the token is expired"));
    }

    /**
     * The {@code error}-first half of the guard, which nothing else here reaches: every already-shaped body
     * above happens to lack {@code code}, so the CREST test alone would spare it. Only a body carrying
     * <em>both</em> keys tells the two clauses apart.
     * <p>
     * No producer in the chain emits one today -- {@code ChfAccessTokenProtectionFilter} answers in one shape
     * or the other, and the JSON base's {@code onError} never writes {@code code}. The clause is kept anyway,
     * for the same reason {@code OAuth2ErrorFilter} keeps it: this filter's output is fed to another
     * rewriting filter, so being idempotent by construction beats being idempotent by an accident of which
     * keys the current producers happen to use. Without this row the clause is dead weight no test defends.
     */
    @Test
    public void aBodyCarryingBothErrorAndCodeIsUntouched() throws Exception {
        Map<String, Object> both = new LinkedHashMap<>();
        both.put("code", 405);
        both.put("error", "unsupported_method_type");
        Response response = through(new Response(Status.METHOD_NOT_ALLOWED).setEntity(both));

        assertThat(bodyOf(response)).containsExactly(entry("code", 405), entry("error", "unsupported_method_type"));
    }

    @Test
    public void applyingTheFilterTwiceChangesNothing() throws Exception {
        Response response = through(through(new Response(Status.METHOD_NOT_ALLOWED)));

        assertThat(response.getStatus().getCode()).isEqualTo(405);
        assertThat(bodyOf(response)).containsExactly(entry("error", "unsupported_method_type"));
        assertThat(response.getHeaders().getFirst("Content-Type")).isEqualTo("application/json");
    }

    @Test
    public void aJsonBodyThatIsNeitherCrestNorOAuth2ShapedIsUntouched() throws Exception {
        // Not the Restlet filter's business: it acted only where the endpoint had produced no entity.
        Response response = through(new Response(Status.BAD_REQUEST)
                .setEntity(java.util.Collections.singletonMap("whatever", "value")));

        assertThat(response.getStatus().getCode()).isEqualTo(400);
        assertThat(bodyOf(response)).containsExactly(entry("whatever", "value"));
    }

    /**
     * 5-E4 row 3b: an {@code If-Match} that loses on a <strong>GET</strong> answers 412 <em>carrying the full
     * representation</em>, because Restlet's conditional layer has already run the read. That body is neither
     * CREST- nor OAuth2-shaped, so the guard spares it and the 412 branch above never fires — which is the
     * only reason [D6](../../../../../../../../../docs/migration/restlet/phase-5c.md)'s handler can produce
     * row 3b at all. Pinned here rather than left to 5c-2's IT: a guard loosened to "rewrite every 412" would
     * pass every other row in this class.
     */
    @Test
    public void a412CarryingTheRepresentationIsUntouched() throws Exception {
        Map<String, Object> representation = new LinkedHashMap<>();
        representation.put("_id", "rs-1");
        representation.put("name", "photo album");
        Response canned = new Response(Status.valueOf(412)).setEntity(representation);
        canned.getHeaders().put("ETag", "W/\"-1234567\"");

        Response response = through(canned);

        assertThat(response.getStatus().getCode()).isEqualTo(412);
        assertThat(bodyOf(response)).containsExactly(entry("_id", "rs-1"), entry("name", "photo album"));
        assertThat(response.getHeaders().getFirst("ETag")).isEqualTo("W/\"-1234567\"");
    }

    @Test
    public void aNonJsonBodyIsUntouched() throws Exception {
        Response canned = new Response(Status.BAD_REQUEST);
        canned.getHeaders().put("Content-Type", "text/html;charset=UTF-8");
        canned.setEntity("<html>error</html>");

        Response response = through(canned);

        assertThat(response.getStatus().getCode()).isEqualTo(400);
        assertThat(response.getEntity().getString()).isEqualTo("<html>error</html>");
    }

    @Test
    public void aSuccessIsUntouched() {
        Response response = through(new Response(Status.NO_CONTENT));

        assertThat(response.getStatus().getCode()).isEqualTo(204);
        assertThat(response.getEntity().isRawContentEmpty()).isTrue();
    }

    @Test
    public void a200CarryingACodeKeyIsUntouched() throws Exception {
        // The guard is status-first: a successful body that happens to have a `code` key is not an error.
        Response response = through(new Response(Status.OK).setEntity(crest(0, "ok", "fine")));

        assertThat(response.getStatus().getCode()).isEqualTo(200);
        assertThat(bodyOf(response)).containsKey("code");
    }

    // ------------------------------------------------------------------ composition with the root filter

    @Test
    public void theRootOAuth2ErrorFilterLeavesThisFiltersOutputAlone() throws Exception {
        // D3's ordering: ResourceSetErrorFilter runs first on the way out and always leaves an `error` key,
        // so OAuth2ErrorFilter's containsKey("error") guard returns it untouched. Without this, a 405 here
        // would be retargeted to D10's generic method_not_allowed.
        Handler inner = (ctx, req) -> Promises.newResultPromise(new Response(Status.METHOD_NOT_ALLOWED));
        Handler resourceSet = (ctx, req) -> filter.filter(ctx, req, inner);
        Response response = new OAuth2ErrorFilter()
                .filter(context, request, resourceSet).getOrThrowUninterruptibly();

        assertThat(response.getStatus().getCode()).isEqualTo(405);
        assertThat(bodyOf(response)).containsExactly(entry("error", "unsupported_method_type"));
        assertThat(response.getHeaders().getFirst("Content-Type")).isEqualTo("application/json");
    }
}
