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

import { createMiddleware } from '@mswjs/http-middleware'
import { handlers } from '@openidentityplatform/commons-ui-next/mock'

// Single shared Express middleware over the shared MSW handler set (ADR-0010).
// Both server.ts and xui-harness.ts mount this same instance — one mock, no duplication.
export const mockMiddleware = createMiddleware(...handlers)
