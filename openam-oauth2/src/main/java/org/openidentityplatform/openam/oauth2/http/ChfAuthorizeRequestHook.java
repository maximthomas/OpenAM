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

import org.forgerock.oauth2.core.OAuth2Request;

/**
 * CHF-typed counterpart of {@code org.forgerock.oauth2.restlet.AuthorizeRequestHook}. Both halves run on both
 * verbs of {@code /authorize}. The neutral signature carries no transport type: an implementation reaches the
 * servlet request/response through {@link OAuth2Request#getHttpServletRequest()} /
 * {@link OAuth2Request#getHttpServletResponse()}, and a cookie written there survives the CHF write-back
 * (phase 5a-1 spike). The Restlet interface is deleted at 5d-2, leaving this one.
 *
 * <p>⚠ One Restlet capability has no equivalent here: {@code afterAuthorizeSuccess} could retract a
 * {@code Set-Cookie} that {@code beforeAuthorizeHandling} had added, because Restlet buffered them in a
 * {@code CookieSetting} series. A {@code HttpServletResponse} has no cookie-removal API, so an implementation
 * that needs the cookie gone must emit an explicit expiry instead -- see {@code LoginHintHook}.
 */
public interface ChfAuthorizeRequestHook {

    /**
     * @param o2request the current OAuth2 request, before any authorization work has run.
     */
    void beforeAuthorizeHandling(OAuth2Request o2request);

    /**
     * ⚠ <strong>Caller contract:</strong> pass the <em>same</em> {@link OAuth2Request} instance that was given
     * to {@link #beforeAuthorizeHandling}. An implementation that cannot retract what the before-hook emitted
     * (see the class note) has to know whether it emitted anything, and the only state it can rely on is the
     * request itself -- a re-created request, or one whose parameters the flow rewrote in between, can make
     * that answer differ from what actually happened. {@code AuthorizeHandler} creates one instance per
     * request and shares it with both hooks.
     *
     * @param o2request the current OAuth2 request, its authorization granted and its response composed.
     */
    void afterAuthorizeSuccess(OAuth2Request o2request);
}
