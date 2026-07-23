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
package org.openidentityplatform.openam.uma;

import static org.assertj.core.api.Assertions.assertThat;

import org.forgerock.openam.uma.UmaException;
import org.openidentityplatform.openam.oauth2.http.OAuth2Error;
import org.testng.annotations.Test;

/**
 * The thirty-first {@code OAuth2Exception}.
 * <p>
 * {@code OAuth2ErrorTest} in openam-oauth2 enumerates the other thirty and fails the build if one is added
 * without a verdict, but its classpath scan cannot reach this module -- the dependency runs the other way.
 * This is that guard's missing row, so the no-redirect policy is complete rather than complete-as-far-as-it-
 * can-see.
 */
public class UmaExceptionRedirectVerdictTest {

    @Test
    public void umaExceptionMayRedirect() {
        // UMA errors carry a caller-supplied status and error name and are served as JSON from endpoints
        // that have no redirect_uri at all, so nothing here needs the never-redirect guard. Phase 4 ports
        // those endpoints; if one ever grows a redirect, this is the line that has to be argued with.
        assertThat(OAuth2Error.mayRedirect(new UmaException(403, "not_authorised", "nope"))).isTrue();
    }
}
