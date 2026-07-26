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
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import jakarta.servlet.http.HttpServletRequest;

import org.forgerock.http.protocol.Request;
import org.forgerock.services.context.AttributesContext;
import org.forgerock.services.context.RootContext;
import org.openidentityplatform.openam.oauth2.core.ChfOAuth2Request;
import org.restlet.data.ClientInfo;
import org.restlet.data.Language;
import org.restlet.data.Preference;
import org.restlet.engine.header.PreferenceReader;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

/**
 * A/B's {@link ChfOAuth2Request#getAcceptedLanguages()} against the live Restlet parser, while both legs can
 * still be driven in one JVM (the {@code RestletErrorParityTest} pattern).
 *
 * <p>The consent page's {@code locale} key is the accepted-language tags joined with a space, interpolated
 * into the page's JavaScript for XUI to pick a translation. It is invisible in an English test and a
 * divergence would silently change which translation a user sees -- so the CHF implementation was written to
 * match what Restlet <em>produces</em>, not what its parser appears to say.
 *
 * <h2>Oracle fidelity</h2>
 * {@code PreferenceReader.addLanguages(header, clientInfo)} is the exact call
 * {@code org.restlet.engine.adapter.HttpRequest.getClientInfo()} makes -- verified in the bytecode of the jar
 * this reactor actually resolves, {@code org.openidentityplatform.openam.jakarta:org.restlet} (<em>not</em>
 * upstream {@code org.restlet.jee:2.4.4}). So this drives production's parser, not a reimplementation of it.
 *
 * <p>⚠ The adapter obtains the string as {@code getRequestHeaders().getValues(name)}, and {@code Series
 * .getValues} <strong>joins repeated header lines with a comma</strong>. Each row therefore feeds both legs a
 * {@code List} of header lines, not one string: a client may legally split its tags across several
 * {@code Accept-Language} lines, and {@code HttpServletRequest.getHeader} (singular) would silently return
 * only the first. A single-string data provider cannot reach that case at all.
 *
 * <p><strong>This test dies at Phase 5d-2</strong>, with the rest of the Restlet leg.
 */
public class RestletAcceptLanguageParityTest {

    /** An empty list means "the request carried no {@code Accept-Language} header at all". */
    @DataProvider(name = "headers")
    public Object[][] headers() {
        return new Object[][] {
                {"single tag", List.of("en")},
                {"q-ordered, out of header order", List.of("en-GB,en;q=0.8,fr;q=0.9")},
                {"wildcard", List.of("*")},
                {"zero quality", List.of("en;q=0")},
                {"equal quality, header order decides", List.of("de,fr")},
                {"spaces around elements", List.of("en-GB, fr ; q=0.5")},
                {"mixed case tag", List.of("EN-gb")},
                {"empty header", List.of("")},
                {"absent header", List.of()},
                {"trailing comma", List.of("en,")},
                {"tag with extension parameter", List.of("en;foo=bar;q=0.3,de")},
                // The rows a single-string provider cannot express: a client may split its tags over
                // several header lines, which the Restlet adapter folds together with a comma.
                {"two header lines", List.of("de", "fr")},
                {"three lines, q on the later ones", List.of("en-GB", "en;q=0.8", "fr;q=0.9")},
                {"second line empty", List.of("en", "")},
                // Malformed for Accept-Language (its grammar allows only q), but a naive split on ',' would
                // fabricate a tag out of the quoted comma -- and that tag reaches the consent page's script.
                {"comma inside a quoted parameter", List.of("en;x=\"a,b\",de")},
                // One escape level deeper than the row above: a backslash-escaped quote inside the quoted
                // string. A quote-toggling splitter that ignores "\\" closes the string early and splits on the
                // comma that follows. Whether Restlet's tokenising reader does the same is the question -- this
                // row records its answer rather than assuming either way.
                {"escaped quote inside a quoted parameter", List.of("en;x=\"a\\\",b\",de")},
        };
    }

    @Test(dataProvider = "headers")
    public void chfMatchesRestlet(String description, List<String> headerLines) throws Exception {
        assertThat(chf(headerLines)).as(description + " -- lines " + headerLines)
                .isEqualTo(restlet(headerLines));
    }

    /**
     * The one row where parity is neither achievable nor desirable: Restlet <em>throws</em> on an unparseable
     * {@code q}, which on the wire is a 500 for a header the client controls. CHF ignores the parameter --
     * it only ever fed an ordering Restlet does not apply. Recorded as a deliberate divergence.
     */
    @Test
    public void malformedQualityThrowsOnRestletButNotOnChf() throws Exception {
        assertThatThrownBy(() -> restlet(List.of("en;q=bogus"))).isInstanceOf(IllegalArgumentException.class);
        assertThat(chf(List.of("en;q=bogus"))).containsExactly("en");
    }

    /**
     * The live Restlet parser, driven the way the servlet adapter drives it: the adapter folds the header
     * lines with {@code Series.getValues}, then hands the joined string to {@code PreferenceReader}.
     */
    private static List<String> restlet(List<String> headerLines) {
        ClientInfo clientInfo = new ClientInfo();
        PreferenceReader.addLanguages(headerLines.isEmpty() ? null : String.join(",", headerLines), clientInfo);
        List<String> tags = new ArrayList<>();
        for (Preference<Language> language : clientInfo.getAcceptedLanguages()) {
            tags.add(language.getMetadata().getName());
        }
        return tags;
    }

    /**
     * Drives the production path: the header comes off the <em>servlet</em> request, because CHF's own
     * {@code Headers} canonicalises {@code Accept-Language} beyond recovery (see
     * {@code ChfOAuth2Request#getAcceptedLanguages}).
     */
    private static List<String> chf(List<String> headerLines) throws Exception {
        HttpServletRequest servletRequest = mock(HttpServletRequest.class);
        given(servletRequest.getHeaders("Accept-Language"))
                .willReturn(Collections.enumeration(headerLines));
        AttributesContext attributes = new AttributesContext(new RootContext());
        attributes.getAttributes().put(HttpServletRequest.class.getName(), servletRequest);
        return new ChfOAuth2Request(attributes, new Request().setMethod("GET").setUri("/oauth2/authorize"))
                .getAcceptedLanguages();
    }
}
