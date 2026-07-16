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

package org.openidentityplatform.openam.oauth2.core;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

/**
 * The credentials carried by an {@code Authorization} request header, as consumed by the OAuth2
 * provider's client authentication.
 *
 * <p>Instances are transport neutral: they are produced from a Restlet {@code ChallengeResponse}
 * or from the raw CHF {@code Authorization} header.
 */
public final class BasicAuthHeader {

    private static final String BASIC = "basic";

    private final String clientId;
    private final char[] secret;

    /**
     * Constructs a new BasicAuthHeader.
     *
     * @param clientId The client identifier, may be {@code null} when the header does not carry one.
     * @param secret The client secret, may be {@code null}.
     */
    public BasicAuthHeader(String clientId, char[] secret) {
        this.clientId = clientId;
        this.secret = secret;
    }

    /**
     * Parses an {@code Authorization} header value.
     *
     * <p>Any non-{@code null} header yields a non-{@code null} result, even when its scheme is not
     * {@literal Basic} — in that case the client id and secret are {@code null}. This mirrors
     * Restlet, whose {@code Request#getChallengeResponse()} is non-{@code null} for every scheme,
     * and which the OAuth2 client authentication relies on to detect "multiple authentication
     * methods" on a request.
     *
     * <p>The Base64 payload is decoded as ISO-8859-1, matching Restlet's Basic scheme helper.
     *
     * @param authorizationHeader The raw {@code Authorization} header value, may be {@code null}.
     * @return The parsed credentials, or {@code null} when no header was present.
     */
    public static BasicAuthHeader parse(String authorizationHeader) {
        if (authorizationHeader == null) {
            return null;
        }
        int space = authorizationHeader.indexOf(' ');
        if (space < 0 || !BASIC.equalsIgnoreCase(authorizationHeader.substring(0, space))) {
            return new BasicAuthHeader(null, null);
        }
        byte[] decoded;
        try {
            decoded = Base64.getDecoder().decode(authorizationHeader.substring(space + 1).trim());
        } catch (IllegalArgumentException e) {
            return new BasicAuthHeader(null, null);
        }
        String credentials = new String(decoded, StandardCharsets.ISO_8859_1);
        int colon = credentials.indexOf(':');
        if (colon < 0) {
            return new BasicAuthHeader(credentials, null);
        }
        return new BasicAuthHeader(credentials.substring(0, colon), credentials.substring(colon + 1).toCharArray());
    }

    /**
     * Gets the client identifier.
     *
     * @return The client identifier, may be {@code null}.
     */
    public String getClientId() {
        return clientId;
    }

    /**
     * Gets the client secret.
     *
     * @return The client secret, may be {@code null}.
     */
    public char[] getSecret() {
        return secret;
    }
}
