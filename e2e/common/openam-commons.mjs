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

export const OPENAM_BASE = process.env.OPENAM_BASE_URL ?? "http://openam.example.org:8080/openam";
export const ADMIN_USER = process.env.OPENAM_ADMIN_USER ?? "amadmin";
export const ADMIN_PASS = process.env.OPENAM_ADMIN_PASS ?? "ampassword";

export const USERNAME = process.env.OPENAM_USERNAME ?? "demo";
export const PASSWORD = process.env.OPENAM_PASSWORD ?? "changeit";

export async function getAdminToken(request) {
    return getAuthToken(request, ADMIN_USER, ADMIN_PASS)
}

/**
 * A failure message worth reading, for a REST call that was expected to succeed.
 *
 * The status alone is not enough against AM's SMS endpoints: they answer a rejected write with an
 * empty 500 body, and the cause is usually the instance rather than the request. Shared because both
 * fixture modules provision through those endpoints and would otherwise each carry their own copy of
 * the same explanation.
 */
export async function describeFailure(what, response) {
  const body = (await response.text()).trim();
  let message = `${what}: HTTP ${response.status()}${body ? ` — ${body}` : ""}`;

  if (response.status() === 500) {
    message += "\nA 500 with no body from an SMS endpoint is usually the instance, not the request: "
      + "AM caches a ServiceSchemaManager per service holding the SSO token it was built with, and "
      + "once that token expires every write against that service fails schema validation. Run "
      + "e2e/local/openam-reset.sh.";
  }
  return new Error(message);
}

export async function getAuthToken(request, username, password) {
  const resp = await request.post(`${OPENAM_BASE}/json/authenticate`, {
    headers: { 
      "Content-Type": "application/json",
      "X-OpenAM-Username": username,
      "X-OpenAM-Password": password,
      "Content-Type": "application/json",
      "Accept-API-Version": "resource=2.0, protocol=1.0",
    }
  });
  const json = await resp.json();
  return json.tokenId;
}