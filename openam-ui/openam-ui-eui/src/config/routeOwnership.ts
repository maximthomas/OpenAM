/**
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

import type { MountMap, RouteOwnership } from '@openidentityplatform/commons-ui-next/routing'

// RUNTIME mirror of docs/migration/route-ownership.yml (the doc source of truth). routeOwnership.test.ts
// asserts the two stay in sync, so flip an entry to "eui" in BOTH places as each slice migrates.
//
// These absolute mounts are the legitimate cross-app coexistence-handoff targets, NOT a violation of
// "never hardcode the mount" (ADR-0004) — that rule is about the router basename / asset paths, which
// stay runtime-resolved in config/runtime.ts. CrossLink only uses mounts for the OTHER app's prefix;
// same-app links resolve through react-router against the runtime basename.
export const mounts: MountMap = {
  eui: '/EUI',
  xui: '/XUI',
}

// Everything is owned by the legacy XUI today; nothing has migrated yet. The current app is "eui".
export const routeOwnership: RouteOwnership[] = [
  // ---- Phase 1: login / auth ----
  { path: 'login', owner: 'eui' },
  { path: 'passwordReset', owner: 'xui' },
  { path: 'register', owner: 'xui' },
  { path: 'forgotUsername', owner: 'xui' },
  // ---- Phase 2: user self-service ----
  { path: 'dashboard', owner: 'xui' },
  { path: 'uma', owner: 'xui' },
  { path: 'profile', owner: 'xui' },
  { path: 'oauth2/tokens', owner: 'xui' },
  // ---- Phase 3: admin ----
  { path: 'realms', owner: 'xui' },
  { path: 'realms/*/authentication', owner: 'xui' },
  { path: 'realms/*/applications', owner: 'xui' },
  { path: 'realms/*/sessions', owner: 'xui' },
  { path: 'realms/*/scripts', owner: 'xui' },
  { path: 'configuration', owner: 'xui' },
  { path: 'deployment', owner: 'xui' },
]
