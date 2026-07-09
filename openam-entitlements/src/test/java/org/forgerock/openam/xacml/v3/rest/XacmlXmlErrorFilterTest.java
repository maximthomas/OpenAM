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
 * Portions copyright 2026 3A Systems LLC.
 */

package org.forgerock.openam.xacml.v3.rest;

import static org.assertj.core.api.Assertions.assertThat;

import org.forgerock.http.Handler;
import org.forgerock.http.protocol.Request;
import org.forgerock.http.protocol.Response;
import org.forgerock.http.protocol.Status;
import org.forgerock.json.resource.BadRequestException;
import org.forgerock.json.resource.ForbiddenException;
import org.forgerock.json.resource.InternalServerErrorException;
import org.forgerock.json.resource.NotSupportedException;
import org.forgerock.services.context.Context;
import org.forgerock.services.context.RootContext;
import org.forgerock.util.promise.Promises;
import org.testng.annotations.Test;

public class XacmlXmlErrorFilterTest {

    private final XacmlXmlErrorFilter filter = new XacmlXmlErrorFilter();
    private final Context context = new RootContext();
    private final Request request = new Request();

    @Test
    public void shouldRewriteForbiddenExceptionToXml() throws Exception {
        Response response = respondWith(new Response(Status.FORBIDDEN)
                .setEntity(new ForbiddenException("no way").toJsonValue().getObject()));

        assertThat(response.getHeaders().getFirst("Content-Type")).isEqualTo("application/xml");
        String xml = response.getEntity().getString();
        assertThat(xml).contains("<code>403</code>");
        assertThat(xml).contains("<message>no way</message>");
    }

    @Test
    public void shouldRewriteBadRequestExceptionToXml() throws Exception {
        Response response = respondWith(new Response(Status.BAD_REQUEST)
                .setEntity(new BadRequestException("bad body").toJsonValue().getObject()));

        assertThat(response.getHeaders().getFirst("Content-Type")).isEqualTo("application/xml");
        assertThat(response.getEntity().getString()).contains("<code>400</code>", "<message>bad body</message>");
    }

    @Test
    public void shouldRewriteMethodNotAllowedFallbackToXml() throws Exception {
        // Endpoints.from's own 405 fallback sets the Response status to METHOD_NOT_ALLOWED but embeds
        // a bare NotSupportedException (code 501) as the entity; the filter only rewrites the body, so
        // the outer HTTP status (405) and the embedded XML <code> (501) legitimately differ.
        Response response = respondWith(new Response(Status.METHOD_NOT_ALLOWED)
                .setEntity(new NotSupportedException().toJsonValue().getObject()));

        assertThat(response.getStatus().getCode()).isEqualTo(405);
        assertThat(response.getHeaders().getFirst("Content-Type")).isEqualTo("application/xml");
        assertThat(response.getEntity().getString()).contains("<code>501</code>");
    }

    @Test
    public void shouldRewriteInternalServerErrorFallbackToXml() throws Exception {
        Response response = respondWith(new Response(Status.INTERNAL_SERVER_ERROR)
                .setEntity(new InternalServerErrorException(new RuntimeException("boom")).toJsonValue().getObject()));

        assertThat(response.getHeaders().getFirst("Content-Type")).isEqualTo("application/xml");
        assertThat(response.getEntity().getString()).contains("<code>500</code>");
    }

    @Test
    public void shouldLeaveSuccessResponseUntouched() throws Exception {
        Response response = respondWith(new Response(Status.OK).setEntity("hello".getBytes("UTF-8")));

        assertThat(response.getHeaders().getFirst("Content-Type")).isNotEqualTo("application/xml");
        assertThat(response.getEntity().getString()).isEqualTo("hello");
    }

    @Test
    public void shouldLeaveNonCrestErrorEntityUntouched() throws Exception {
        Response response = respondWith(new Response(Status.NOT_FOUND).setEntity("plain text".getBytes("UTF-8")));

        assertThat(response.getHeaders().getFirst("Content-Type")).isNotEqualTo("application/xml");
        assertThat(response.getEntity().getString()).isEqualTo("plain text");
    }

    private Response respondWith(final Response canned) throws Exception {
        Handler next = (ctx, req) -> Promises.newResultPromise(canned);
        return filter.filter(context, request, next).getOrThrowUninterruptibly();
    }
}
