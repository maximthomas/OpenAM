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

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Map;

import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerException;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.forgerock.http.Filter;
import org.forgerock.http.Handler;
import org.forgerock.http.protocol.Request;
import org.forgerock.http.protocol.Response;
import org.forgerock.openam.forgerockrest.utils.XMLResourceExceptionHandler;
import org.forgerock.services.context.Context;
import org.forgerock.util.Function;
import org.forgerock.util.promise.NeverThrowsException;
import org.forgerock.util.promise.Promise;
import org.w3c.dom.Document;

import com.sun.identity.shared.debug.Debug;
import com.sun.identity.shared.xml.XMLUtils;

/**
 * Rewrites CREST error-map JSON responses (business errors returned by {@link XacmlServiceHandler},
 * and the {@code Endpoints.from} 405/500 fallbacks) into the XML {@code <error>} form, reproducing
 * the legacy {@code XMLRestStatusService} behaviour for the {@code /xacml} endpoints.
 */
public class XacmlXmlErrorFilter implements Filter {

    private static final Debug DEBUG = Debug.getInstance("frRest");

    @Override
    public Promise<Response, NeverThrowsException> filter(Context context, Request request, Handler next) {
        return next.handle(context, request).then(new Function<Response, Response, NeverThrowsException>() {
            @Override
            public Response apply(Response response) {
                return rewriteIfError(response);
            }
        });
    }

    @SuppressWarnings("unchecked")
    private Response rewriteIfError(Response response) {
        if (response.getStatus().getCode() < 400) {
            return response;
        }
        Object entity;
        try {
            entity = response.getEntity().getJson();
        } catch (IOException e) {
            return response;
        }
        if (!(entity instanceof Map)) {
            return response;
        }
        Document xml = XMLResourceExceptionHandler.asXMLDOM((Map<String, Object>) entity);
        try {
            ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
            Transformer transformer = XMLUtils.getTransformerFactory().newTransformer();
            transformer.transform(new DOMSource(xml), new StreamResult(outputStream));
            response.getHeaders().put("Content-Type", "application/xml");
            response.setEntity(outputStream.toByteArray());
        } catch (TransformerException e) {
            DEBUG.error("XacmlXmlErrorFilter :: Could not render XML error body", e);
        }
        return response;
    }
}
