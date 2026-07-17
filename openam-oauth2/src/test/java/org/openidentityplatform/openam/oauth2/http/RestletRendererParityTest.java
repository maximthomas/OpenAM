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
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Map;

import org.forgerock.oauth2.core.OAuth2Request;
import org.forgerock.oauth2.restlet.OAuth2Representation;
import org.forgerock.oauth2.restlet.TemplateFactory;
import org.restlet.Component;
import org.restlet.Context;
import org.restlet.ext.freemarker.TemplateRepresentation;
import org.restlet.representation.Representation;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

/**
 * Asserts that the legacy Restlet renderer and the golden files agree, byte for byte, on every shipping
 * template.
 * <p>
 * This exists because phase 3c is build-ahead: the new renderer is wired to no route, so the usual
 * "the existing Restlet suite stays green" guardrail does not apply and a wrong contract would stay
 * invisible until the Phase 5d flip. No test anywhere else asserts rendered HTML, charset, or popup
 * composition. So this phase builds its own oracle — and it can only do so while Restlet is still on the
 * classpath to be one.
 * <p>
 * The design is a three-way assert, {@code Restlet == golden == CHF}, of which this class currently holds
 * the first half. Today it buys maximal confidence: the golden is <em>proven</em> to be the real output of
 * the code that serves {@code /oauth2} in production. After Phase 5d deletes the Restlet leg, removing
 * these assertions degrades it gracefully to {@code golden == CHF} — a durable regression guard that still
 * encodes Restlet's truth after Restlet itself is gone. That is the whole point, and it costs one extra
 * assert.
 * <p>
 * <strong>Never regenerate a golden after Phase 5d.</strong> Once the Restlet leg is deleted there is
 * nothing left to falsify a golden against, so a regenerated file would silently bless whatever the code
 * does at that moment. Post-5d, goldens may only be re-derived from git history.
 *
 * @see RendererFixtures for why the data models are derived from the producers rather than invented.
 */
public class RestletRendererParityTest {

    /** Run with {@code -Dgolden.regenerate=true} to (re)write the golden files. See the class javadoc. */
    private static final boolean REGENERATE = Boolean.getBoolean("golden.regenerate");

    /**
     * Resolved against the module basedir, which is Surefire's working directory. The goldens are read from
     * the source tree rather than the classpath so that regeneration and assertion cannot drift apart via a
     * stale {@code target/test-classes} copy.
     */
    private static final Path GOLDEN_DIR = Paths.get("src", "test", "resources", "golden");

    private Context restletContext;
    private TemplateFactory templateFactory;
    private FreemarkerTemplateRenderer renderer;

    @BeforeClass
    public void createRenderers() {
        renderer = new FreemarkerTemplateRenderer();
        // A bare `new Context()` cannot be used here, despite constructing fine and satisfying
        // TemplateFactory.newInstance: its clientDispatcher is null, and ContextTemplateLoader calls
        // handle() straight through it, so the first render dies with an NPE. Nothing catches that -- an
        // NPE is not an IOException, so neither MultiTemplateLoader's fall-through nor
        // TemplateRepresentation.getTemplate's `catch (IOException)` intercepts it.
        //
        // A Component context supplies a real client dispatcher with no CLAP client registered, which is
        // exactly the shape RestEndpointServlet gives production. ContextTemplateLoader then misses
        // gracefully and MultiTemplateLoader falls through to the ClassTemplateLoader, as it does live.
        restletContext = new Component().getContext().createChildContext();
        templateFactory = TemplateFactory.newInstance(restletContext);
    }

    @DataProvider(name = "templates")
    public static Object[][] templates() {
        return new Object[][] {
                { "templates/page/authorize.ftl", "page/authorize.html", RendererFixtures.authorize() },
                { "templates/popup/authorize.ftl", "popup/authorize.html", RendererFixtures.authorize() },
                { "templates/touch/authorize.ftl", "touch/authorize.html", RendererFixtures.authorize() },
                { "templates/wap/authorize.ftl", "wap/authorize.html", RendererFixtures.authorize() },
                { "templates/popup/popup.ftl", "popup/popup.html", RendererFixtures.popup() },
                { "templates/page/error.ftl", "page/error.html", RendererFixtures.error() },
                { "templates/page/checkSession.ftl", "page/checkSession.html", RendererFixtures.checkSession() },
                { "templates/FormPostResponse.ftl", "FormPostResponse.html", RendererFixtures.formPost() },
                { "templates/CodeVerificationForm.ftl", "CodeVerificationForm.html",
                        RendererFixtures.codeVerificationForm() },
                { "templates/CodeThanks.ftl", "CodeThanks.html", RendererFixtures.codeThanks() },
        };
    }

    /**
     * The three-way assert: the legacy renderer, the golden file and the new renderer must all agree.
     * <p>
     * At Phase 5d, delete the {@code renderWithRestlet} call and its assertion. What remains --
     * {@code golden == CHF} -- is still a real regression guard, because the golden was proven against the
     * legacy renderer back when the legacy renderer still existed.
     */
    @Test(dataProvider = "templates")
    public void restletRenderMatchesGoldenMatchesChf(String templatePath, String goldenName,
            Map<String, Object> dataModel) throws Exception {
        String restlet = renderWithRestlet(templatePath, dataModel);
        assertMatchesGolden(goldenName, restlet);

        assertThat(renderer.render(templatePath, dataModel))
                .as("the new renderer diverges from the legacy one on %s", templatePath)
                .isEqualTo(restlet);
    }

    /**
     * Popup composition lives in {@code OAuth2Representation.getRepresentation:79-92}, not in
     * {@code TemplateFactory}, so it needs its own scaffold: the data-provider cases above can only
     * characterize single-template renders. Hand-composing {@code htmlCode} in the test would assert
     * against a reimplementation rather than against the legacy code, which is exactly what this oracle
     * exists to avoid — so the real object is driven instead.
     * <p>
     * {@code new OAuth2Representation(null)} is safe: the request factory is dereferenced only by
     * {@code toRepresentation}, never by {@code getRepresentation}.
     * <p>
     * This case deliberately asks for {@code authorize.ftl}, the one template name for which the two
     * renderers are expected to agree. The new renderer honours the requested template name whereas
     * {@code OAuth2Representation:80} hardcodes {@code "authorize.ftl"} and discards it, so the two
     * diverge by design for every other name -- asking for {@code authorize.ftl} is what makes the legacy
     * hardcode a no-op and lets a genuine three-way assert hold here. That intended divergence is proven
     * separately, against a synthetic template pair, by
     * {@code FreemarkerTemplateRendererTest.popupCompositionHonoursTheRequestedTemplateName}; it is not
     * asserted here, because this test's job is to show that composition itself is byte-identical.
     * <p>
     * Fresh data models are passed to each leg on purpose: composing a popup writes {@code htmlCode} into
     * the model, in both the legacy renderer and this one.
     */
    @Test
    public void restletPopupCompositionMatchesGoldenMatchesChf() throws Exception {
        OAuth2Request request = mock(OAuth2Request.class);
        given(request.<String>getParameter("display")).willReturn("popup");

        Representation composed = new OAuth2Representation(null)
                .getRepresentation(restletContext, request, "authorize.ftl", RendererFixtures.authorize());
        String restlet = composed.getText();
        assertMatchesGolden("composed/popup-authorize.html", restlet);

        assertThat(renderer.renderForDisplay("popup", "authorize.ftl", RendererFixtures.authorize()))
                .as("the new renderer diverges from the legacy one on popup composition")
                .isEqualTo(restlet);
    }

    private String renderWithRestlet(String templatePath, Map<String, Object> dataModel) throws IOException {
        TemplateRepresentation representation = templateFactory.getTemplateRepresentation(templatePath);
        assertThat(representation)
                .as("legacy TemplateFactory found no template at %s (it returns null on a miss)", templatePath)
                .isNotNull();
        representation.setDataModel(dataModel);
        return representation.getText();
    }

    /**
     * Both directions pin UTF-8 explicitly. The renderer's own {@code setDefaultEncoding("UTF-8")} governs
     * how FreeMarker reads {@code .ftl} files and says nothing about how this test reads and writes
     * {@code golden/*.html}; defaulted file I/O would resolve against {@code file.encoding}, which is the
     * precise JDK 11-26 x 3-OS variable this phase exists to eliminate (JEP 400 flipped the platform default
     * at JDK 18). The fixtures deliberately put non-ASCII in the data model, so the golden bytes really are
     * non-ASCII and an unpinned charset would flap on CI while passing locally.
     */
    private void assertMatchesGolden(String goldenName, String actual) throws IOException {
        Path golden = GOLDEN_DIR.resolve(goldenName);
        if (REGENERATE) {
            Files.createDirectories(golden.getParent());
            Files.write(golden, actual.getBytes(UTF_8));
            return;
        }
        assertThat(golden)
                .as("missing golden %s -- regenerate with -Dgolden.regenerate=true, but only while the "
                        + "Restlet leg still exists to prove it", golden)
                .exists();
        assertThat(actual).isEqualTo(new String(Files.readAllBytes(golden), UTF_8));
    }
}
