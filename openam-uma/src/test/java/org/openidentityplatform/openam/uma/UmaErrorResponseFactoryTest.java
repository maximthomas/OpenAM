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
import static org.assertj.core.api.Assertions.entry;
import static org.forgerock.json.JsonValue.field;
import static org.forgerock.json.JsonValue.json;
import static org.forgerock.json.JsonValue.object;

import java.util.Map;

import org.forgerock.http.protocol.Response;
import org.forgerock.oauth2.core.exceptions.InvalidGrantException;
import org.forgerock.openam.uma.UmaException;
import org.testng.annotations.Test;

/**
 * Parity oracle: the Restlet {@code UmaExceptionHandler}. The three cases below mirror
 * {@code UmaExceptionHandlerTest} onto the CHF factory, with two deliberate divergences the port makes:
 * <ul>
 * <li>dispatch is on the thrown exception <em>directly</em> -- CHF hands the handler the real exception,
 *     never a wrapper -- so these pass a <em>bare</em> {@code UmaException}, not one behind
 *     {@code throwable.getCause()} (the R-4.3 guard);
 * <li>the uncaught branch emits a flat {@code 500}. The Restlet handler kept whatever status the response
 *     already carried (its test pre-seeded 444 and asserted it stayed); on CHF the {@code @ExceptionHandler}
 *     builds a fresh response, so there is no prior status to keep (D3).
 * </ul>
 * The fourth case pins the middle branch (a non-UMA {@code OAuth2Exception}) the oracle test never exercised.
 */
public class UmaErrorResponseFactoryTest {

    @Test
    public void genericThrowableYields500ServerError() throws Exception {
        Response response = UmaErrorResponseFactory.from(new Exception("MESSAGE"));

        assertThat(response.getStatus().getCode()).isEqualTo(500);
        assertThat(bodyOf(response)).containsOnly(
                entry("error", "server_error"), entry("error_description", "MESSAGE"));
    }

    @Test
    public void umaExceptionYieldsUmaBodyAndItsStatus() throws Exception {
        // Bare UmaException, dispatched directly -- no Restlet-style getCause() unwrap.
        Response response = UmaErrorResponseFactory.from(new UmaException(444, "ERROR", "DESCRIPTION"));

        assertThat(response.getStatus().getCode()).isEqualTo(444);
        assertThat(bodyOf(response)).containsOnly(
                entry("error", "ERROR"), entry("error_description", "DESCRIPTION"));
    }

    @Test
    public void umaExceptionDetailIsFlattenedIntoTheBody() throws Exception {
        Response response = UmaErrorResponseFactory.from(
                new UmaException(444, "ERROR", "DESCRIPTION").setDetail(json(object(field("DETAIL", "VALUE")))));

        assertThat(response.getStatus().getCode()).isEqualTo(444);
        assertThat(bodyOf(response)).containsOnly(entry("error", "ERROR"),
                entry("error_description", "DESCRIPTION"), entry("DETAIL", "VALUE"));
    }

    @Test
    public void oauth2ExceptionYieldsUmaBodyAndItsStatus() throws Exception {
        // A non-UMA OAuth2Exception takes the middle branch: its own status + error code, no detail.
        Response response = UmaErrorResponseFactory.from(new InvalidGrantException("boom"));

        assertThat(response.getStatus().getCode()).isEqualTo(400);
        assertThat(bodyOf(response)).containsOnly(
                entry("error", "invalid_grant"), entry("error_description", "boom"));
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> bodyOf(Response response) throws Exception {
        return (Map<String, Object>) response.getEntity().getJson();
    }
}
