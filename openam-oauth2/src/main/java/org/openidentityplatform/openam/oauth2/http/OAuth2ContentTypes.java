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

import org.forgerock.http.header.ContentTypeHeader;
import org.forgerock.http.protocol.Request;

/**
 * The one content-type rule the two form-accepting OAuth2 endpoints share.
 *
 * <p>{@code /authorize} and {@code /access_token} were each wrapped by an {@link
 * org.forgerock.oauth2.restlet.OAuth2Filter} subclass whose {@code validateContentType} says the same thing in
 * two spellings -- {@code AuthorizeEndpointFilter:69} tests {@code getSize() > 0}, {@code TokenEndpointFilter:69}
 * tests {@code instanceof EmptyRepresentation}, and both then compare the media type to
 * {@code APPLICATION_WWW_FORM}. One predicate here rather than one per handler, because the two CHF ports had
 * drifted into a shared defect and fixing either alone would have left the other wrong.
 *
 * <p>The callers still differ in what they do with the answer, which is why this returns a boolean rather than
 * throwing: the token endpoint throws {@code InvalidRequestException} and lets its base mapper answer, while
 * {@code /authorize} must <em>build</em> its refusal (a thrown {@code InvalidRequestException} is redirectable,
 * and the browser base would send it to an unvalidated {@code redirect_uri}).
 */
public final class OAuth2ContentTypes {

    private static final String FORM_URLENCODED = "application/x-www-form-urlencoded";

    private OAuth2ContentTypes() {
    }

    /**
     * Whether the request body, if it has one, is the form the OAuth2 endpoints accept.
     *
     * <p>An <strong>empty</strong> body is never checked: both filters inspected the entity only when it was
     * non-empty, so the ordinary bodyless {@code GET /authorize} pays nothing here.
     *
     * <p>A non-empty body must carry {@code application/x-www-form-urlencoded}, compared against
     * {@link ContentTypeHeader#getType()}, which parses the {@code ;charset=} parameter off -- matching
     * Restlet, whose {@code ContentType} likewise split the charset out into the representation's character set
     * before {@code MediaType.equals} ever saw it. A bare string compare against the raw header would wrongly
     * reject a {@code ;charset=UTF-8} body.
     *
     * <p>⚠ <strong>A missing {@code Content-Type} is a rejection, not a pass.</strong> Restlet's test was
     * {@code !MediaType.APPLICATION_WWW_FORM.equals(entity.getMediaType())}, and {@code equals(null)} is false,
     * so the negation fires and a header-less body 400s. Reading that as "no type, no opinion" is the mistake
     * this method existed to make twice: on {@code /authorize} it is not even a wrong status but a wrong
     * <em>decision</em>, because {@code ChfOAuth2Request.getParameter} reads a POST body only when the type is
     * form, so the consent form's {@code decision=allow} arrives as {@code null} and the resource owner's
     * approval is recorded as a refusal.
     *
     * <p>⚠ One deliberate divergence, pinned by {@code RestletContentTypeParityTest}: the comparison here is
     * case-<em>insensitive</em>, where Restlet's {@code MediaType.equals} compared names case-sensitively and so
     * 400'd an {@code APPLICATION/X-WWW-FORM-URLENCODED} that RFC 7231 §3.1.1.1 says is legal. Kept, because it
     * can only turn a Restlet 400 into a success and never the reverse -- no working client can break on it.
     *
     * @param request the CHF request.
     * @return whether the endpoint accepts this body.
     */
    public static boolean isFormUrlEncoded(Request request) {
        if (request.getEntity().isRawContentEmpty()) {
            return true;
        }
        // equalsIgnoreCase(null) is false, which is the Restlet answer for an absent header -- see above.
        return FORM_URLENCODED.equalsIgnoreCase(ContentTypeHeader.valueOf(request).getType());
    }
}
