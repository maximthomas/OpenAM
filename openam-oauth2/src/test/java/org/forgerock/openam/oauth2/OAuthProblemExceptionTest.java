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

package org.forgerock.openam.oauth2;

import static org.assertj.core.api.Assertions.assertThat;

import org.forgerock.openam.oauth2.OAuthProblemException.OAuthError;
import org.testng.annotations.Test;

/**
 * Pins the observable contract of {@link OAuthError#handle(String)}, which every error site in the
 * OAuth2 and UMA settings code raises through. The cases pass before and after the removal of the
 * exception's dead Restlet-request plumbing: they exist to hold the contract steady while the
 * constructor behind {@code handle} is rewritten to drop its never-taken request branch.
 */
public class OAuthProblemExceptionTest {

    private static final String DESCRIPTION = "Unable to construct ServiceConfigManager";

    @Test
    public void handleCarriesTheErrorCode() {
        OAuthProblemException exception = OAuthError.SERVER_ERROR.handle(DESCRIPTION);

        assertThat(exception.getStatus().getCode()).isEqualTo(400);
    }

    /**
     * Setting a description rebuilds the status through a Restlet constructor whose string argument
     * overrides the <em>reason phrase</em>, so {@code getError()} — the reason phrase — reports the
     * description too, while the status keeps the enum's canned description. Every serialized error
     * built through {@code handle} carries this shape, so it is pinned as-is.
     */
    @Test
    public void handleOverridesTheDescriptionAndTheErrorName() {
        OAuthProblemException exception = OAuthError.SERVER_ERROR.handle(DESCRIPTION);

        assertThat(exception.getDescription()).isEqualTo(DESCRIPTION);
        assertThat(exception.getError()).isEqualTo(DESCRIPTION);
        assertThat(exception.getStatus().getDescription())
                .startsWith("The authorization server encountered an unexpected condition");
    }

    /** The redirect fields only ever came from a request, and {@code handle(String)} has none. */
    @Test
    public void handleLeavesTheRedirectFieldsUnset() {
        OAuthProblemException exception = OAuthError.SERVER_ERROR.handle(DESCRIPTION);

        assertThat(exception.getRedirectUri()).isNull();
        assertThat(exception.getState()).isNull();
        assertThat(exception.getScope()).isNull();
    }

    @Test
    public void aCodeCarryingErrorKeepsItsCode() {
        OAuthProblemException exception = OAuthError.INVALID_CLIENT_401.handle(DESCRIPTION);

        assertThat(exception.getStatus().getCode()).isEqualTo(401);
    }
}
