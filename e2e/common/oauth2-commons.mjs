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
 * Copyright 2026 3A Systems, LLC.
 */

/**
 * Shared OAuth2 fixtures: the provider service and the two client registrations the suite
 * authorizes against, and the PKCE primitives every authorization request needs.
 *
 * These live here because two specs now need the same clients for opposite reasons —
 * oauth2/oauth2-test.spec.mjs drives the protocol with no browser, and xui/xui-authorize.spec.mjs
 * drives the consent screen the XUI renders for the same request. Neither should carry its own
 * idea of how a client is registered.
 *
 * Provisioning is idempotent rather than transactional, and nothing here tears down: the provider
 * service and the client registrations are realm configuration the two specs share, so a teardown
 * would make them order-dependent for no gain. e2e/local/openam-reset.sh is the way back to the
 * instance's baseline.
 */

import { OPENAM_BASE } from "./openam-commons.mjs";

/** The realm as the OAuth2 endpoints name it. The REST API calls the same realm "/". */
export const OAUTH2_REALM = "root";

export const AUTHORIZE_URL = `${OPENAM_BASE}/oauth2/realms/${OAUTH2_REALM}/authorize`;

/** A client for which consent is implied: an authorization request never reaches the consent screen. */
export const CLIENT_ID = "test_client_app";

/** A client for which it is not, so AM renders the consent screen and the decision is posted back. */
export const CONSENT_CLIENT_ID = "test_consent_app";

export const SCOPE = "profile";

/** RFC 6761 reserves .invalid, so this can never resolve — the client application is a fiction. */
export const REDIRECT_URI = "http://app.invalid/cb";

/**
 * PKCE is mandatory for these clients: they are public and authenticate with "none", so AM rejects an
 * authorization request without a code_challenge before it reaches consent handling.
 */
export function generateVerifier (length = 64) {
    const array = new Uint32Array(length);
    crypto.getRandomValues(array);
    const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~";
    return Array.from(array, (x) => chars[x % chars.length]).join("");
}

export async function generateChallenge (verifier) {
    const hash = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier));

    return btoa(String.fromCharCode(...new Uint8Array(hash)))
        .replace(/\+/g, "-")
        .replace(/\//g, "_")
        .replace(/=+$/, "");
}

/**
 * A failure message worth reading. The status alone is not enough here: AM answers a rejected SMS
 * write with an empty 500 body, and the cause is usually the instance rather than the request.
 */
async function describeFailure (what, response) {
    const body = (await response.text()).trim();
    let message = `${what}: HTTP ${response.status()}${body ? ` — ${body}` : ""}`;

    if (response.status() === 500) {
        message += "\nA 500 with no body from an SMS endpoint is usually the instance, not the request: "
            + "AM caches a ServiceSchemaManager per service holding the SSO token it was built with, and "
            + "once that token expires every create against that service fails schema validation. Run "
            + "e2e/local/openam-reset.sh.";
    }
    return new Error(message);
}

/**
 * The instance already had the object, but not the way the suite needs it. Nothing here updates in
 * place — these fixtures are realm configuration, and a spec that rewrote another spec's would make
 * the two order-dependent — so this is a stop, with the way out named.
 */
function mismatch (what, expectation) {
    return new Error(`${what} already exists on this instance but ${expectation}. The fixtures do not `
        + "modify configuration they did not create; run e2e/local/openam-reset.sh to get back to a "
        + "known baseline.");
}

/** Create the OAuth2 provider service in the realm if it is not there. A fresh instance has none. */
export async function ensureOAuth2ServiceExists (adminToken, request) {
    const url = `${OPENAM_BASE}/json/realms/${OAUTH2_REALM}/realm-config/services/oauth-oidc`;
    const response = await request.get(url, {
        headers: {
            "iPlanetDirectoryPro": adminToken,
            "Accept-API-Version": "protocol=1.0,resource=1.0",
        },
    });

    if (response.ok()) {
        // Whether consent can be skipped at all is a provider-wide setting, and half of what decides
        // which page an authorization request lands on -- every endpoint that can require consent
        // reads it together with the client's own isConsentImplied. A pre-existing provider with it
        // off sends every spec that expects consent to be implied down the consent branch instead,
        // where it fails looking like a UI regression.
        const service = await response.json();
        if (service.advancedOAuth2Config?.clientsCanSkipConsent !== true) {
            throw mismatch("The OAuth2 provider service", "does not set clientsCanSkipConsent");
        }
        return;
    }
    if (response.status() !== 404) {
        throw await describeFailure("Failed to check the OAuth2 provider service", response);
    }

    const created = await request.post(`${url}?_action=create`, {
        headers: {
            "iPlanetDirectoryPro": adminToken,
            "Content-Type": "application/json",
            "Accept-API-Version": "protocol=1.0,resource=1.0",
        },
        data: {
            advancedOAuth2Config: {
                clientsCanSkipConsent: true,
                supportedScopes: [SCOPE],
                defaultScopes: [SCOPE],
            },
        },
    });

    if (!created.ok()) {
        throw await describeFailure("Failed to create the OAuth2 provider service", created);
    }
}

/**
 * Create an OAuth2 client registration if it is not there.
 *
 * isConsentImplied is the whole point of the second client: with it false, AM stops at the consent
 * screen instead of redirecting straight back with a code.
 */
export async function ensureOAuth2ClientExists (adminToken, request, clientId = CLIENT_ID,
    isConsentImplied = true) {
    const url = `${OPENAM_BASE}/json/realms/${OAUTH2_REALM}/realm-config/agents/OAuth2Client/${clientId}`;
    const headers = {
        "iPlanetDirectoryPro": adminToken,
        "Accept-API-Version": "protocol=2.0,resource=1.0",
    };
    const response = await request.get(url, { headers });

    if (response.ok()) {
        // The other half of that decision, and the reason both clients exist. A client left behind by
        // an earlier run with the opposite setting would silently swap which page the browser lands
        // on: the consent screen where a code was expected, or a code where the consent screen was.
        const client = await response.json();
        if (client.isConsentImplied !== isConsentImplied) {
            throw mismatch(`The OAuth2 client "${clientId}"`,
                `has isConsentImplied=${client.isConsentImplied}, not ${isConsentImplied}`);
        }
        return;
    }
    if (response.status() !== 404) {
        throw await describeFailure(`Failed to check the OAuth2 client "${clientId}"`, response);
    }

    // The "[0]=value" syntax is how the SMS represents an ordered multi-valued attribute.
    const created = await request.put(url, {
        headers: { ...headers, "Content-Type": "application/json" },
        data: {
            "com.forgerock.openam.oauth2provider.clientType": "Public",
            "com.forgerock.openam.oauth2provider.redirectionURIs": [`[0]=${REDIRECT_URI}`],
            "com.forgerock.openam.oauth2provider.scopes": [`[0]=${SCOPE}`],
            "com.forgerock.openam.oauth2provider.defaultScopes": [`[0]=${SCOPE}`],
            "com.forgerock.openam.oauth2provider.grantTypes": ["[0]=authorization_code"],
            "com.forgerock.openam.oauth2provider.responseTypes": ["[0]=code"],
            "com.forgerock.openam.oauth2provider.tokenEndPointAuthMethod": "none",
            "isConsentImplied": isConsentImplied,
            "sunIdentityServerDeviceStatus": "Active",
        },
    });

    if (!created.ok()) {
        throw await describeFailure(`Failed to create the OAuth2 client "${clientId}"`, created);
    }
}
