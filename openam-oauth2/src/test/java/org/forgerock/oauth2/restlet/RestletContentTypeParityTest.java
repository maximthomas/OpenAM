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
package org.forgerock.oauth2.restlet;

import static org.assertj.core.api.Assertions.assertThat;

import org.forgerock.oauth2.core.exceptions.InvalidRequestException;
import org.openidentityplatform.openam.oauth2.http.OAuth2ContentTypes;
import org.restlet.Request;
import org.restlet.data.MediaType;
import org.restlet.engine.header.ContentType;
import org.restlet.representation.EmptyRepresentation;
import org.restlet.representation.Representation;
import org.restlet.representation.StringRepresentation;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

/**
 * A/B's the CHF content-type predicate against the <strong>live Restlet filters</strong> it replaces, over one
 * table driven through both legs.
 *
 * <h2>Why a test and not a reading</h2>
 * Both {@code validateContentType} implementations turn on
 * {@code MediaType.APPLICATION_WWW_FORM.equals(entity.getMediaType())}, and the interesting rows are the ones
 * where that {@code equals} does something a reader would not predict: a {@code ;charset=UTF-8} body is
 * <em>accepted</em> (Restlet's {@code ContentType} splits the charset into the representation's character set
 * before {@code equals} ever sees it), while a body with <strong>no</strong> {@code Content-Type} at all is
 * <em>rejected</em> ({@code equals(null)} is false, so the negation fires). The CHF port had the second one
 * backwards, and only an executed comparison could show it.
 *
 * <h2>What this does and does not prove</h2>
 * It drives the real filters, so the acceptance rule itself is oracled rather than assumed. What it cannot
 * reach is the servlet adapter that produced the entity in production -- these requests are built here. That
 * gap does not matter for the row it was built for: the filter accepts <em>exactly one</em> media type, so
 * whatever an adapter defaults a header-less body to (null, {@code application/octet-stream}, {@code *}/{@code
 * *}), the answer is a 400 unless it defaults to {@code application/x-www-form-urlencoded} itself, which no
 * HTTP stack does.
 *
 * <p>Both filters are asserted, not just {@code /authorize}'s: they spell "empty body" differently
 * ({@code getSize() > 0} vs {@code instanceof EmptyRepresentation}) and the CHF side answers both from one
 * predicate, so a divergence between them would be a defect in that sharing.
 */
public class RestletContentTypeParityTest {

    private static final String FORM_BODY = "decision=allow&save_consent=on";

    /**
     * {@code rawContentType} is the header as a client would send it; {@code null} means the header is absent.
     * The last two columns are the Restlet answer and the CHF answer, kept <strong>separate</strong> so that a
     * deliberate divergence is a visible row rather than a missing test.
     */
    @DataProvider(name = "bodies")
    public Object[][] bodies() {
        return new Object[][]{
                //  name                              Content-Type                    body      restlet  chf
                {"form-urlencoded", "application/x-www-form-urlencoded", FORM_BODY, true, true},
                {"form-urlencoded with a charset", "application/x-www-form-urlencoded;charset=UTF-8", FORM_BODY,
                        true, true},
                // ⚠ Recorded divergence. Restlet's MediaType.equals compares the name case-SENSITIVELY, so it
                // 400s a header RFC 7231 3.1.1.1 says is legal. CHF accepts it: a widening that can only turn a
                // Restlet 400 into a success, never the reverse, so no working client can break on it.
                {"uppercase form-urlencoded", "APPLICATION/X-WWW-FORM-URLENCODED", FORM_BODY, false, true},
                {"json", "application/json", "{\"decision\":\"allow\"}", false, false},
                {"text", "text/plain", FORM_BODY, false, false},
                // The row this class was written for: a form body whose Content-Type header never arrived.
                {"no Content-Type at all", null, FORM_BODY, false, false},
                // An empty body is never inspected, so its type is irrelevant -- the ordinary bodyless GET.
                {"empty body, no Content-Type", null, "", true, true},
                {"empty body, json Content-Type", "application/json", "", true, true},
        };
    }

    @Test(dataProvider = "bodies")
    public void theAuthorizeFilterAgreesWithTheChfPredicate(String name, String rawContentType, String body,
            boolean restletAccepts, boolean chfAccepts) {
        AuthorizeEndpointFilter filter = new AuthorizeEndpointFilter(null, null);

        assertThat(restletAccepts(() -> filter.validateContentType(restletRequest(rawContentType, body))))
                .as("Restlet /authorize: " + name).isEqualTo(restletAccepts);
        assertThat(OAuth2ContentTypes.isFormUrlEncoded(chfRequest(rawContentType, body)))
                .as("CHF: " + name).isEqualTo(chfAccepts);
    }

    @Test(dataProvider = "bodies")
    public void theTokenFilterAgreesWithTheChfPredicate(String name, String rawContentType, String body,
            boolean restletAccepts, boolean chfAccepts) {
        TokenEndpointFilter filter = new TokenEndpointFilter(null, null);

        assertThat(restletAccepts(() -> filter.validateContentType(restletRequest(rawContentType, body))))
                .as("Restlet /access_token: " + name).isEqualTo(restletAccepts);
        assertThat(OAuth2ContentTypes.isFormUrlEncoded(chfRequest(rawContentType, body)))
                .as("CHF: " + name).isEqualTo(chfAccepts);
    }

    // --- fixtures ---------------------------------------------------------------------------------

    private interface Validation {
        void run() throws InvalidRequestException;
    }

    private static boolean restletAccepts(Validation validation) {
        try {
            validation.run();
            return true;
        } catch (InvalidRequestException e) {
            return false;
        }
    }

    /**
     * Builds the entity the way {@code ServerCall} does, in the two places where a naive fixture answers a
     * question production never asks:
     *
     * <ul>
     * <li>the raw header goes through Restlet's own {@code ContentType}, which is what separates the media type
     *     from the charset -- setting {@code MediaType.valueOf(raw)} directly would smuggle the charset into
     *     the media type and turn the charset row red for a reason the production path never has;
     * <li>an empty body is an {@link EmptyRepresentation}, as the adapter yields for a zero-length entity. A
     *     {@code StringRepresentation("")} is not one, and the two filters disagree about it --
     *     {@code AuthorizeEndpointFilter} asks {@code getSize() > 0} and skips, {@code TokenEndpointFilter}
     *     asks {@code instanceof EmptyRepresentation} and does not. That disagreement is an artefact of the
     *     fixture, not a divergence of the product, and modelling the adapter is what keeps it out.
     * </ul>
     */
    private static Request restletRequest(String rawContentType, String body) {
        Representation entity = body.isEmpty() ? new EmptyRepresentation() : new StringRepresentation(body);
        if (rawContentType == null) {
            entity.setMediaType(null);
        } else {
            ContentType contentType = new ContentType(rawContentType);
            entity.setMediaType(contentType.getMediaType());
            entity.setCharacterSet(contentType.getCharacterSet());
        }
        Request request = new Request();
        request.setEntity(entity);
        return request;
    }

    private static org.forgerock.http.protocol.Request chfRequest(String rawContentType, String body) {
        org.forgerock.http.protocol.Request request = new org.forgerock.http.protocol.Request();
        if (rawContentType != null) {
            request.getHeaders().put("Content-Type", rawContentType);
        }
        request.setEntity(body);
        return request;
    }

    /** Guards the fixture itself: a row's premise is that Restlet saw the media type we think it did. */
    @Test
    public void theFixtureSeparatesTheCharsetFromTheMediaType() {
        Representation entity =
                restletRequest("application/x-www-form-urlencoded;charset=UTF-8", FORM_BODY).getEntity();

        assertThat(entity.getMediaType()).isEqualTo(MediaType.APPLICATION_WWW_FORM);
        assertThat(entity.getCharacterSet().getName()).isEqualTo("UTF-8");
    }

    /**
     * Pins <em>where</em> the uppercase divergence comes from, so the recorded row cannot be misread as a
     * parsing artefact of this fixture: {@code MediaType.valueOf} preserves the spelling and
     * {@code MediaType.equals} compares names case-sensitively, which is Restlet's own behaviour and not
     * something the {@code ContentType} step introduced.
     */
    @Test
    public void restletMediaTypeEqualityIsCaseSensitive() {
        assertThat(MediaType.valueOf("APPLICATION/X-WWW-FORM-URLENCODED"))
                .isNotEqualTo(MediaType.APPLICATION_WWW_FORM);
        assertThat(MediaType.valueOf("application/x-www-form-urlencoded"))
                .isEqualTo(MediaType.APPLICATION_WWW_FORM);
    }
}
