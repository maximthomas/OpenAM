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

import static java.nio.charset.StandardCharsets.ISO_8859_1;
import static java.nio.charset.StandardCharsets.UTF_8;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.openidentityplatform.openam.oauth2.http.RendererFixtures.NON_ASCII_USER_NAME;

import java.util.HashMap;
import java.util.Map;

import org.forgerock.http.header.ContentTypeHeader;
import org.forgerock.http.protocol.Response;
import org.forgerock.http.protocol.Status;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

import freemarker.cache.StringTemplateLoader;
import freemarker.core.TemplateClassResolver;
import freemarker.template.Configuration;
import freemarker.template.TemplateException;
import freemarker.template.TemplateExceptionHandler;
import freemarker.template.TemplateNotFoundException;

/**
 * Unit coverage for the renderer's own contract.
 * <p>
 * Byte-level fidelity to the legacy renderer is not asserted here -- that is
 * {@code RestletRendererParityTest}'s job, and it does it against the real Restlet renderer rather than
 * against anything hand-written. What this class covers is the surface that parity cannot speak to:
 * display resolution, the deliberate popup fix, the error contract, the UTF-8 response recipe, and the
 * {@code Configuration} settings that are no-ops today and would therefore vanish silently.
 */
public class FreemarkerTemplateRendererTest {

    /** {@code page/authorize.ftl} is the only display folder whose template reads {@code saveConsentEnabled}. */
    private static final String PAGE_ONLY_MARKER = "isSaveConsentEnabled: true";

    private FreemarkerTemplateRenderer renderer;

    @BeforeMethod
    public void setUp() {
        renderer = new FreemarkerTemplateRenderer();
    }

    @DataProvider(name = "displayFolders")
    public static Object[][] displayFolders() {
        return new Object[][] {
                // Each marker is unique to that folder's template, so a mis-resolved folder cannot pass.
                { "page", PAGE_ONLY_MARKER },
                { "touch", "isplayName:" },             // the folder's own long-standing typo
                { "wap", "<!DOCTYPE wml" },             // this one is WML, not HTML
                { "popup", "<title>Authorize popup</title>" },   // composed through popup.ftl
        };
    }

    @Test(dataProvider = "displayFolders")
    public void eachDisplayFolderResolvesItsOwnTemplate(String display, String marker) throws Exception {
        assertThat(renderer.renderForDisplay(display, "authorize.ftl", RendererFixtures.authorize()))
                .contains(marker);
    }

    @DataProvider(name = "emptyDisplays")
    public static Object[][] emptyDisplays() {
        return new Object[][] { { null }, { "" } };
    }

    /**
     * {@code ?display=} is a reachable URL and yields {@code ""}, not {@code null}. Both must mean
     * {@code page}. An implementation that only mirrors the legacy path builder's {@code display != null}
     * guard and then calls {@code Enum.valueOf("")} turns this request into a 400.
     */
    @Test(dataProvider = "emptyDisplays")
    public void nullAndEmptyDisplayBothMeanPage(String display) throws Exception {
        assertThat(renderer.renderForDisplay(display, "authorize.ftl", RendererFixtures.authorize()))
                .contains(PAGE_ONLY_MARKER);
    }

    @Test
    public void displayIsCaseInsensitive() throws Exception {
        assertThat(renderer.renderForDisplay("PaGe", "authorize.ftl", RendererFixtures.authorize()))
                .contains(PAGE_ONLY_MARKER);
    }

    /**
     * Reproduces the legacy behaviour by exception type, which {@code AuthorizeResource:120} relies on to
     * produce {@code invalid_request}. Defaulting to {@code page} would turn a rejected request into a
     * rendered consent page.
     */
    @Test
    public void unknownDisplayIsRejected() {
        assertThatThrownBy(() -> renderer.renderForDisplay("bogus", "authorize.ftl", RendererFixtures.authorize()))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    public void popupCompositionEmbedsTheRenderedPage() throws Exception {
        String html = renderer.renderForDisplay("popup", "authorize.ftl", RendererFixtures.authorize());

        assertThat(html)
                .as("the wrapper must be rendered, with the inner page embedded in it")
                .contains("<title>Authorize popup</title>")
                .contains("clientId: \"test_client_app\"");
    }

    /**
     * The D5 fix. {@code OAuth2Representation:80} hardcodes {@code "authorize.ftl"} and ignores its
     * {@code templateName}, so a popup always served the consent page; this renderer honours the name.
     * <p>
     * A {@code StringTemplateLoader} is needed rather than the shipping templates because {@code popup/}
     * contains only {@code authorize.ftl} and {@code popup.ftl} -- with no second real template in that
     * folder, there is nothing to prove pass-through against, and the legacy hardcoding would pass too.
     */
    @Test
    public void popupCompositionHonoursTheRequestedTemplateName() throws Exception {
        StringTemplateLoader templates = new StringTemplateLoader();
        templates.putTemplate("templates/popup/popup.ftl", "WRAPPER[${htmlCode}]");
        templates.putTemplate("templates/popup/authorize.ftl", "THE-CONSENT-PAGE");
        templates.putTemplate("templates/popup/something-else.ftl", "THE-REQUESTED-PAGE");

        String html = new FreemarkerTemplateRenderer(templates)
                .renderForDisplay("popup", "something-else.ftl", new HashMap<>());

        assertThat(html)
                .as("the legacy renderer would have produced WRAPPER[THE-CONSENT-PAGE] here")
                .isEqualTo("WRAPPER[THE-REQUESTED-PAGE]");
    }

    /**
     * The wrapper's {@code htmlCode} must not leak back into the caller's model. The legacy renderer added
     * it to the caller's own map; this one renders the wrapper from a copy, so the caller's map is untouched.
     */
    @Test
    public void popupCompositionDoesNotMutateTheCallersDataModel() throws Exception {
        Map<String, Object> model = RendererFixtures.authorize();

        renderer.renderForDisplay("popup", "authorize.ftl", model);

        assertThat(model).doesNotContainKey("htmlCode");
    }

    /**
     * The other half of the D5 fix: honouring the requested name means a popup whose inner template does not
     * exist now misses and throws, where {@code OAuth2Representation:80}'s hardcoded {@code authorize.ftl}
     * would have served the consent page. {@code OpenIDConnectCheckSessionEndpoint}'s {@code checkSession.ftl}
     * under {@code display=popup} is the live case; whether it should error or fall back is Phase 5b's call.
     */
    @Test
    public void popupCompositionThrowsWhenTheRequestedInnerTemplateIsMissing() {
        StringTemplateLoader templates = new StringTemplateLoader();
        templates.putTemplate("templates/popup/popup.ftl", "WRAPPER[${htmlCode}]");
        // Deliberately no templates/popup/checkSession.ftl.

        assertThatThrownBy(() -> new FreemarkerTemplateRenderer(templates)
                .renderForDisplay("popup", "checkSession.ftl", new HashMap<>()))
                .isInstanceOf(TemplateNotFoundException.class);
    }

    /** {@code FormPostResponse.ftl} sits at the template root, outside any display folder. */
    @Test
    public void formPostResponseIsRenderedFromTheTemplateRoot() throws Exception {
        assertThat(renderer.render("templates/FormPostResponse.ftl", RendererFixtures.formPost()))
                .contains("action=\"https://rp.example.com/callback\"")
                .contains("name=\"code\"");
    }

    /**
     * The legacy factory returned {@code null} on a miss, which forced every caller to re-detect it and
     * translate it into an exception of its own. The contract here is render or throw.
     */
    @Test
    public void aMissingTemplateThrowsRatherThanReturningNull() {
        assertThatThrownBy(() -> renderer.render("templates/page/no-such-template.ftl", new HashMap<>()))
                .isInstanceOf(TemplateNotFoundException.class);
    }

    /**
     * {@code page/error.ftl} dereferences {@code ${baseUrl?html}} outside every guard, and FreeMarker
     * treats a Java {@code null} as missing.
     * <p>
     * The property being pinned is that a failed render yields <em>no</em> HTML at all, so nothing can be
     * wrapped in a {@code Response}. The legacy renderer streamed templates directly into the response
     * entity, so FreeMarker's default {@code DEBUG_HANDLER} -- which writes the stack trace out and only
     * then rethrows -- had already put those bytes on the wire. Rendering eagerly to a String is what makes
     * that structurally impossible here.
     * <p>
     * Note this assertion passes under {@code DEBUG_HANDLER} too, precisely because the fix is the eager
     * render and not the handler. {@link #theConfigurationPinsSettingsThatAreNoOpsToday()} is what actually
     * guards the handler setting.
     */
    @Test
    public void aFailedRenderProducesNoHtmlToPutInAResponse() {
        Map<String, Object> incomplete = RendererFixtures.error();
        incomplete.remove("baseUrl");

        assertThatThrownBy(() -> renderer.render("templates/page/error.ftl", incomplete))
                .isInstanceOf(TemplateException.class);
    }

    @Test
    public void toHtmlResponseDeclaresHtmlAndUtf8() {
        Response response = FreemarkerTemplateRenderer.toHtmlResponse(Status.OK, "<html></html>");

        assertThat(response.getStatus()).isEqualTo(Status.OK);
        assertThat(response.getHeaders().getFirst(ContentTypeHeader.NAME)).isEqualTo("text/html; charset=UTF-8");
    }

    /**
     * The trap this recipe exists for. CHF encodes a {@code String} entity against the message's
     * {@code Content-Type} charset and falls back to ISO-8859-1 when it names none, so the natural
     * {@code setEntity(html)} silently mangles non-ASCII.
     * <p>
     * All ten templates are pure ASCII, so this can only be caught with a non-ASCII value in the
     * <em>data model</em> -- an ASCII fixture passes with the bug present. Hence the explicit assertion
     * that the bytes are <em>not</em> the ISO-8859-1 encoding.
     * <p>
     * <strong>Know what this does and does not catch.</strong> Verified by mutation: it fails if the
     * entity is set before the {@code Content-Type}, and the sibling test fails if the header is dropped.
     * It does <em>not</em> fail if {@code setEntity(html.getBytes(UTF_8))} is weakened to
     * {@code setEntity(html)} while the header still comes first -- and it cannot, because in that ordering
     * {@code Entity.setString} reads {@code charset=UTF-8} off the header and emits byte-for-byte the same
     * result. The {@code byte[]} form is defence in depth against a later reordering, so it is guarded by
     * the phase's grep gate ("no {@code setEntity(<String>)} on an HTML path") rather than by this test.
     * Do not retire that gate on the belief that this test covers it.
     */
    @Test
    public void toHtmlResponseEncodesTheBodyAsUtf8Bytes() throws Exception {
        String html = renderer.renderForDisplay("page", "authorize.ftl", RendererFixtures.authorize());
        assertThat(html).as("fixture must carry non-ASCII or this test proves nothing").contains(NON_ASCII_USER_NAME);

        Response response = FreemarkerTemplateRenderer.toHtmlResponse(Status.OK, html);
        byte[] body = response.getEntity().getBytes();

        assertThat(body).isEqualTo(html.getBytes(UTF_8));
        assertThat(body).isNotEqualTo(html.getBytes(ISO_8859_1));
        assertThat(new String(body, UTF_8)).contains(NON_ASCII_USER_NAME);
    }

    /**
     * Every setting asserted here is a no-op against today's templates, which is exactly why it is asserted
     * on the {@code Configuration} rather than through behaviour: delete any one of the corresponding lines
     * in the renderer and no behavioural test in this suite would notice. They are pinned because each
     * guards a future regression -- an incompatible-improvements bump silently swapping the ObjectWrapper,
     * a template gaining {@code ?new}, a stack trace reaching a browser after a streaming refactor, or
     * template decoding drifting with {@code file.encoding} across the JDK 11-26 CI matrix.
     */
    @Test
    public void theConfigurationPinsSettingsThatAreNoOpsToday() {
        Configuration configuration = renderer.configuration();

        assertThat(configuration.getIncompatibleImprovements()).isEqualTo(Configuration.VERSION_2_3_0);
        assertThat(configuration.getTemplateExceptionHandler()).isSameAs(TemplateExceptionHandler.RETHROW_HANDLER);
        assertThat(configuration.getNewBuiltinClassResolver()).isSameAs(TemplateClassResolver.SAFER_RESOLVER);
        assertThat(configuration.getDefaultEncoding()).isEqualTo("UTF-8");
        // One hour, matching the legacy setTemplateUpdateDelay(3600). The legacy setter took seconds; this
        // one takes milliseconds, so a verbatim 3600 here would re-stat every template every 3.6 seconds.
        assertThat(configuration.getTemplateUpdateDelayMilliseconds()).isEqualTo(3600_000L);
    }
}
