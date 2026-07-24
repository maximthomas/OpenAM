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
 * CHF-typed counterpart of {@code org.forgerock.oauth2.restlet.TokenRequestHook}, invoked once after a
 * successful token is issued. The neutral signature carries no transport type: an implementation reaches the
 * servlet request/response through {@link OAuth2Request#getHttpServletRequest()} /
 * {@link OAuth2Request#getHttpServletResponse()}, and a cookie written there survives the CHF write-back
 * (phase 5a-1 spike). The Restlet interface is deleted at 5d-2, leaving this one.
 */
public interface ChfTokenRequestHook {

    /**
     * @param o2request the current OAuth2 request, its token already issued.
     */
    void afterTokenHandling(OAuth2Request o2request);
}
