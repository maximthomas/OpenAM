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
import static org.forgerock.oauth2.core.Utils.isEmpty;

import java.io.IOException;
import java.io.StringWriter;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;

import jakarta.inject.Inject;
import jakarta.inject.Singleton;

import org.forgerock.http.header.ContentTypeHeader;
import org.forgerock.http.protocol.Response;
import org.forgerock.http.protocol.Status;
import org.forgerock.openam.oauth2.OAuth2Constants.DisplayType;
import org.forgerock.util.annotations.VisibleForTesting;

import freemarker.cache.ClassTemplateLoader;
import freemarker.cache.TemplateLoader;
import freemarker.core.TemplateClassResolver;
import freemarker.template.Configuration;
import freemarker.template.Template;
import freemarker.template.TemplateException;
import freemarker.template.TemplateExceptionHandler;

/**
 * Renders the OAuth2 provider's FreeMarker pages (consent, error, check-session, device-code and
 * form-post) to HTML, and wraps rendered HTML in a CHF {@link Response}.
 * <p>
 * This is the transport-neutral replacement for {@code org.forgerock.oauth2.restlet.TemplateFactory} and
 * the rendering half of {@code OAuth2Representation}. Those two classes survive until Phase 5b ports their
 * last callers. Output is byte-identical to theirs on every shipping template, which is asserted by
 * {@code RestletRendererParityTest} while both renderers can still be driven in one JVM.
 *
 * <h2>The {@code Configuration} must be built once, not per request</h2>
 * The legacy code cached its {@code Configuration} on the Restlet {@code Context}
 * ({@code OAuth2Representation:127-136}), and there is one Restlet Context per application, so the cache
 * was effectively a singleton. CHF has no equivalent: {@code AttributesContext} is <em>per request</em>.
 * Hanging a {@code Configuration} there would rebuild the template loader and discard the parsed-template
 * cache on every single request. Hence {@code @Singleton} with the {@code Configuration} built in the
 * constructor. Guice JIT-binds this class (it is concrete with an {@code @Inject} constructor), so no
 * module binding is needed or wanted.
 *
 * <h2>Render eagerly; never stream</h2>
 * {@link #render} produces a complete {@code String} before any {@code Response} exists. That ordering is
 * load-bearing rather than stylistic. FreeMarker's default {@code TemplateExceptionHandler.DEBUG_HANDLER}
 * writes the stack trace into the output and only then rethrows, so the legacy renderer -- which streamed
 * templates straight into the Restlet response entity -- had already committed those bytes to the wire by
 * the time the throw happened, disclosing internals to the browser. Rendering to a String first means a
 * failed render is discarded before a single byte reaches a {@code Response}, whichever handler is set.
 * Do not "optimise" this into a streaming write.
 */
@Singleton
public class FreemarkerTemplateRenderer {

    private static final String TEMPLATE_ROOT = "templates/";

    /** The wrapper template that embeds another rendered page as {@link #HTML_CODE}. */
    private static final String POPUP_TEMPLATE = "popup.ftl";

    /** The data-model key {@code popup/popup.ftl} reads the embedded page from. */
    private static final String HTML_CODE = "htmlCode";

    /**
     * Explicit, because CHF's default is not. {@code Entity.setString} encodes against the message's
     * current {@code Content-Type} charset and falls back to ISO-8859-1 when there is none, so an HTML
     * page set as a String before its {@code Content-Type} is silently mangled. Restlet reached the same
     * wire result by inheritance -- {@code CharacterRepresentation}'s constructor sets {@code UTF_8} -- so
     * it never had to write this down. See {@link #toHtmlResponse}.
     */
    private static final String HTML_CONTENT_TYPE = "text/html; charset=UTF-8";

    private final Configuration configuration;

    @Inject
    public FreemarkerTemplateRenderer() {
        // The legacy factory paired this loader with a ContextTemplateLoader over "clap:///", but that leg
        // is dead: resolving it needs a CLAP client connector, and the servlet serving /oauth2 registers
        // none. Driving the real TemplateFactory both with and without a CLAP client produces byte-identical
        // output for all ten templates -- when registered, CLAP resolves to the very same classpath resource
        // this loader reads -- so dropping it is behaviour-preserving either way.
        this(new ClassTemplateLoader(FreemarkerTemplateRenderer.class, "/"));
    }

    @VisibleForTesting
    FreemarkerTemplateRenderer(TemplateLoader templateLoader) {
        // Pinned deliberately: `new Configuration()` (the legacy call) defaults to VERSION_2_3_0, and
        // getDefaultObjectWrapper branches at 2.3.21 -- below it the legacy ObjectWrapper.DEFAULT_WRAPPER,
        // at or above it a DefaultObjectWrapperBuilder. So raising this version silently changes how every
        // Map, String and bean in a data model is exposed to the templates. That may be worth doing one
        // day, but as its own golden-guarded change, never as a drive-by modernisation.
        configuration = new Configuration(Configuration.VERSION_2_3_0);
        configuration.setTemplateLoader(templateLoader);

        // A no-op today -- all ten templates are pure ASCII -- but it removes a file.encoding dependence
        // from template decoding, and file.encoding is not stable across the JDK 11-26 CI matrix (JEP 400
        // flipped the platform default at 18). The legacy config inherited the platform charset here.
        //
        // Note this is only consulted when Configuration's localeToCharsetMap is empty, which it is solely
        // because loadBuiltInEncodingMap() is never called. Calling it would map e.g. `en` to ISO-8859-1 and
        // take precedence over this line. Do not call it.
        configuration.setDefaultEncoding("UTF-8");

        // The legacy setTemplateUpdateDelay(3600) is deprecated and takes SECONDS; this setter takes
        // MILLISECONDS. Both mean one hour. Passing 3600 here would re-stat every template every 3.6s.
        configuration.setTemplateUpdateDelayMilliseconds(3600_000L);

        // Also a no-op today: no template uses ?new, ?api or ?eval. Free hardening against a future one.
        configuration.setNewBuiltinClassResolver(TemplateClassResolver.SAFER_RESOLVER);

        // Inert under the eager-render design above, since a failed render is discarded either way. Kept
        // because it is the correct production setting, it skips pointless stack-trace formatting on the
        // failure path, and it is what keeps the disclosure fixed if anyone ever makes this renderer stream.
        // Defence in depth, not the fix -- the fix is that render() returns a String.
        configuration.setTemplateExceptionHandler(TemplateExceptionHandler.RETHROW_HANDLER);

        try {
            // Verbatim from TemplateFactory:56, string form included, so the setting takes the identical
            // parse path rather than an equivalent-looking programmatic MruCacheStorage.
            configuration.setSetting(Configuration.CACHE_STORAGE_KEY, "strong:20, soft:250");
        } catch (TemplateException e) {
            throw new IllegalStateException("FreeMarker rejected a constant cache-storage setting", e);
        }
    }

    /**
     * Renders a template by its full classpath-relative path.
     *
     * @param templatePath the path under the classpath root, e.g. {@code templates/page/error.ftl}.
     * @param dataModel the data model.
     * @return the rendered page.
     * @throws IOException if the template cannot be found or read. Unlike the legacy
     *     {@code TemplateFactory}, which returned {@code null} on a miss and left every caller to
     *     re-detect it, the contract here is render or throw.
     * @throws TemplateException if the template fails to render, typically because a data-model value is
     *     absent or of the wrong type.
     */
    public String render(String templatePath, Map<String, Object> dataModel)
            throws IOException, TemplateException {
        Template template = configuration.getTemplate(templatePath);
        StringWriter rendered = new StringWriter();
        template.process(dataModel, rendered);
        return rendered.toString();
    }

    /**
     * Resolves {@code templates/{display}/{templateName}} and renders it, composing the popup wrapper when
     * the display type calls for it.
     * <p>
     * Takes the display as a {@code String} rather than an {@code OAuth2Request} so that this class stays
     * free of any transport coupling; callers pass {@code request.getParameter("display")}.
     * <p>
     * <strong>This differs from the legacy renderer in one deliberate way.</strong>
     * {@code OAuth2Representation:80} hardcodes {@code "authorize.ftl"} when composing a popup and ignores
     * its own {@code templateName} argument, so {@code display=popup} serves the consent page whatever was
     * asked for. The live authorize flow is unaffected -- the only shipping popup pair is
     * {@code authorize.ftl} plus {@code popup.ftl}, so the hardcoded name happens to be the right one --
     * and nobody can depend on being handed a consent page when they asked for a check-session iframe. So
     * {@code templateName} is honoured here. One caller is affected:
     * {@code OpenIDConnectCheckSessionEndpoint} asks for {@code checkSession.ftl}, which under
     * {@code display=popup} now resolves {@code templates/popup/checkSession.ftl} -- a template that does
     * not exist -- and therefore throws, where the legacy code returned 200 with the wrong page. Whether
     * that case should error or fall back to {@code page/} is Phase 5b's decision when it ports the
     * check-session endpoint.
     * <p>
     * Composing a popup needs {@code htmlCode} in the wrapper's model. Unlike the legacy renderer, which put
     * it into the caller's own {@code dataModel} ({@code OAuth2Representation:83}), this renders the wrapper
     * from a copy, so the caller's map is never mutated. The output is unchanged.
     *
     * @param display the requested display type, case-insensitive. {@code null} and {@code ""} both mean
     *     {@code page}.
     * @param templateName the bare template name, e.g. {@code authorize.ftl}.
     * @param dataModel the data model.
     * @return the rendered page.
     * @throws IllegalArgumentException if {@code display} is non-empty and not a known display type. This
     *     reproduces the legacy behaviour, which {@code AuthorizeResource:120} depends on by type to
     *     produce {@code invalid_request}; defaulting an unknown display to {@code page} would turn a
     *     rejected request into a rendered consent page. Phase 5b must map this to {@code invalid_request}.
     * @throws IOException if the template cannot be found or read.
     * @throws TemplateException if the template fails to render.
     */
    public String renderForDisplay(String display, String templateName, Map<String, Object> dataModel)
            throws IOException, TemplateException {
        // isEmpty covers null AND "", and both mean `page`. The empty case is not hypothetical: `?display=`
        // is a perfectly reachable URL and getParameter returns "" for it. Mirroring only the legacy path
        // builder -- which does `display != null ? display : "page"` -- and then calling Enum.valueOf on ""
        // would turn that request from a rendered page into a 400.
        DisplayType displayType = DisplayType.PAGE;
        if (!isEmpty(display)) {
            displayType = Enum.valueOf(DisplayType.class, display.toUpperCase(Locale.ROOT));
        }

        if (DisplayType.POPUP.equals(displayType)) {
            String embeddedPage = render(templatePath(displayType, templateName), dataModel);
            // The wrapper needs htmlCode, but the legacy renderer added it to the caller's own map
            // (OAuth2Representation:83) -- a side effect that throws on an immutable model and would strand
            // a stale htmlCode in a reused one. Render the wrapper from a copy: byte-identical, because
            // popup.ftl reads only htmlCode, but the caller's map is left untouched.
            Map<String, Object> wrapperModel = new HashMap<>(dataModel);
            wrapperModel.put(HTML_CODE, embeddedPage);
            return render(templatePath(displayType, POPUP_TEMPLATE), wrapperModel);
        }
        return render(templatePath(displayType, templateName), dataModel);
    }

    /**
     * Wraps rendered HTML in a CHF {@link Response}.
     * <p>
     * The {@code Content-Type} is set explicitly and the body is set as {@code byte[]}, which together make
     * the result independent of ordering and of CHF's charset fallback. Setting the body as a {@code String}
     * instead would route through {@code Entity.setString}, which encodes against whatever charset the
     * message's {@code Content-Type} currently names and falls back to <em>ISO-8859-1</em> when it names
     * none -- silently mangling every non-ASCII value in the data model, such as a client name or localized
     * scope text. All ten templates are pure ASCII, so that bug cannot be caught by a fixture that is
     * ASCII-only; the tests use a non-ASCII data-model value for exactly this reason.
     * <p>
     * Every page gets {@code text/html}, including {@code wap/authorize.ftl}, which is really WML. That is
     * the legacy behaviour: the media type was fixed at the representation and never varied by display.
     * Reproduced here rather than corrected, since no caller has asked otherwise; revisit in Phase 5b.
     *
     * @param status the response status.
     * @param html the rendered page.
     * @return a response carrying the page as UTF-8 bytes.
     */
    public static Response toHtmlResponse(Status status, String html) {
        // render() is render-or-throw and never returns null; fail loudly at the seam if a future caller
        // forgets that, rather than with a bare NPE from getBytes below.
        Objects.requireNonNull(html, "html");
        Response response = new Response(status);
        response.getHeaders().put(ContentTypeHeader.NAME, HTML_CONTENT_TYPE);
        response.setEntity(html.getBytes(UTF_8));
        return response;
    }

    /** Mirrors {@code OAuth2Representation:113}. {@code DisplayType.getFolder()} is the lowercased name. */
    private static String templatePath(DisplayType displayType, String templateName) {
        return TEMPLATE_ROOT + displayType.getFolder() + "/" + templateName;
    }

    /**
     * Exposed so the tests can assert the {@code Configuration} settings directly. Several of those
     * settings are no-ops against today's templates, so a behavioural test cannot tell whether they are
     * still applied -- only an assertion on the configuration itself fails if one is deleted.
     */
    @VisibleForTesting
    Configuration configuration() {
        return configuration;
    }
}
