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

// Browser counterpart of src/test/setup.ts (which uses msw/node `setupServer`). Same shared
// AM-REST handlers from commons-ui-next (ADR-0010, P0-7), driven through a service worker so the
// EUI app runs at /EUI in a real browser with no OpenAM/Tomcat. Started conditionally from
// main.tsx under the VITE_MOCK flag (npm run dev:mock).
import { setupWorker } from 'msw/browser'
import { handlers } from '@openidentityplatform/commons-ui-next/mock'

export const worker = setupWorker(...handlers)
