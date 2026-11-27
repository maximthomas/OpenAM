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

import { expect, test } from "@playwright/test";
import { isDeepStrictEqual } from "node:util";
import { OPENAM_BASE } from "../common/openam-commons.mjs";
import {
  REDIRECT_URI, SCOPE, isInactiveIntrospection, pkce, unreportedRequest,
  withIntrospectionClient, withRealmProvider,
} from "../common/oauth2-fixtures.mjs";

test.use({ trace: "off", screenshot: "off" });

test("creates a realm provider without clients, resource owners or owner sessions", async ({ ignoreHTTPSErrors }) => {
  await withRealmProvider({ ignoreHTTPSErrors }, async (realm) => {
    const prefixes = {
      nested: OPENAM_BASE + "/oauth2/realms/root/realms/" + realm.name,
      legacy: OPENAM_BASE + "/oauth2/" + realm.name,
      flat: OPENAM_BASE + "/oauth2/realms/" + realm.name,
      query: OPENAM_BASE + "/oauth2",
    };
    expect(realm.oauthUrl === prefixes.nested, "Canonical realm URL is independently derived").toBe(true);
    for (const spelling of Object.keys(prefixes)) {
      for (const path of ["/authorize", "/access_token", "/introspect", "/userinfo", "/token/revoke"]) {
        const params = new URLSearchParams([["tag", "first"], ["tag", "second"]]);
        const expected = new URL(prefixes[spelling] + path + "?existing=value");
        for (const [key, value] of params) expected.searchParams.append(key, value);
        if (spelling === "query") expected.searchParams.append("realm", realm.name);
        const actual = realm.endpoint(spelling, path + "?existing=value", params);
        expect(actual === expected.href, "Spelling preserves its own path and repeated query values").toBe(true);
      }
    }
    const request = unreportedRequest.newContext({
      ignoreHTTPSErrors, maxRedirects: 0,
    });
    try {
      const response = await request.get(realm.endpoint("nested", "/.well-known/openid-configuration"));
      expect(response.status(), "Realm-only discovery returns the direct response").toBe(200);
      const body = await response.json().catch(() => undefined);
      expect(body?.issuer === prefixes.nested, "Discovery uses the canonical realm issuer").toBe(true);
    } finally {
      await request.dispose();
    }
  });
});
