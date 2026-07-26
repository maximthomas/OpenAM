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

package org.openidentityplatform.openam.http;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.forgerock.services.context.AttributesContext;
import org.forgerock.services.context.Context;

/**
 * Reads the servlet objects out of a CHF context chain.
 *
 * <p>{@code HttpFrameworkServlet} puts the servlet request and response into the {@link AttributesContext}
 * keyed by class name, so any handler mounted through
 * {@link org.forgerock.openam.http.annotations.Endpoints#from} can reach them. What such a chain does
 * <strong>not</strong> carry is a CREST {@code org.forgerock.json.resource.http.HttpContext} -- that one is
 * created by CREST's HTTP adapter and exists only under {@code /json}-style routes. Code shared between the
 * two worlds must therefore prefer the servlet request and treat {@code HttpContext} as the fallback;
 * asking for {@code HttpContext} unconditionally is what made {@code /uma/.well-known/uma-configuration}
 * a 500 after the phase-4 flip.
 *
 * <p>This lives in <strong>openam-http</strong> because that is the module defining the endpoint-hosting
 * contract it decodes, and because it is the lowest module every caller can reach: openam-oauth2, openam-uma
 * and openam-rest depend on it directly and openam-core-rest through openam-rest. Note the one place it
 * cannot serve — {@code BaseURLProvider} in <strong>openam-core</strong>, which openam-http depends on, so
 * the dependency cannot be inverted; see the follow-up note in
 * {@code docs/migration/restlet/phase-4-uma.md}.
 *
 * <p><strong>The attribute keys are an undocumented contract with commons, not an API.</strong> They are
 * written in exactly one place — {@code HttpFrameworkServlet} lines 247-248 of
 * {@code commons/http-framework/servlet} — under a comment reading "<em>FIXME ideally we don't want to
 * expose the HttpServlet Request and Response</em>". Commons publishes no constant and no accessor for
 * them, which is why this reader exists here rather than being reused from there. If commons ever drops
 * those two {@code put} calls, every caller silently gets {@code null}: that is the phase-4 500 again, so
 * this class is the single place to fix it.
 *
 * <p>Prefer <em>not</em> needing this at all. A CHF handler that wants the request URI, headers, scheme or
 * port should read them off the CHF {@code Request} and {@link org.forgerock.services.context.ClientContext},
 * which carry everything natively on both transports. Reach for the servlet objects only where an older API
 * demands them — {@code OAuth2Request#getHttpServletRequest()} being the case that keeps this class alive.
 */
public final class ChfContexts {

    private ChfContexts() {
    }

    /**
     * @param context The request context.
     * @return The servlet request the CHF servlet stashed, or {@code null} when the chain carries none.
     */
    public static HttpServletRequest servletRequest(Context context) {
        return (HttpServletRequest) attribute(context, HttpServletRequest.class.getName());
    }

    /**
     * @param context The request context.
     * @return The servlet response the CHF servlet stashed, or {@code null} when the chain carries none.
     */
    public static HttpServletResponse servletResponse(Context context) {
        return (HttpServletResponse) attribute(context, HttpServletResponse.class.getName());
    }

    private static Object attribute(Context context, String name) {
        if (context == null || !context.containsContext(AttributesContext.class)) {
            return null;
        }
        return context.asContext(AttributesContext.class).getAttributes().get(name);
    }
}
