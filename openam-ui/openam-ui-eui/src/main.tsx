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

import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import { BrowserRouter } from 'react-router'
import { CrossLinkProvider, createCrossLinkResolver } from '@openidentityplatform/commons-ui-next/routing'
import App from './App.tsx'
import { getBasename } from './config/runtime.ts'
import { mounts, routeOwnership } from './config/routeOwnership.ts'
import './index.css'

const rootElement = document.getElementById('root')
if (!rootElement) {
  throw new Error('EUI bootstrap failed: #root element not found')
}

// Resolves cross-app links against the route-ownership map: routes still owned by the legacy /XUI
// app become full-page handoffs, migrated routes stay in-app (ADR-0004/0008).
const crossLinkResolver = createCrossLinkResolver({
  routes: routeOwnership,
  mounts,
  currentOwner: 'eui',
})

// basename is resolved at runtime so the same build is relocatable across /EUI and /XUI.
createRoot(rootElement).render(
  <StrictMode>
    <BrowserRouter basename={getBasename()}>
      <CrossLinkProvider resolver={crossLinkResolver}>
        <App />
      </CrossLinkProvider>
    </BrowserRouter>
  </StrictMode>,
)
