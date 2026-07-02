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

// Transport seam shared by ./auth and ./session.
// Real implementation lives in ./http/index.ts (P1-2).

import { createAmTransport } from './http/index.ts'

export type Transport = (path: string, init?: RequestInit) => Promise<Response>

export function createFetchTransport(opts: { baseUrl: string; realm?: string | false }): Transport {
  return createAmTransport({ baseUrl: opts.baseUrl, realm: opts.realm ?? '/' })
}
