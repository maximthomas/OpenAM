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

/**
 * Standalone mock AM server — exposes the shared MSW handlers over real HTTP (ADR-0010).
 * Usable by curl, Playwright, or any cross-origin client.
 *
 *   npm run mock             → listens on MOCK_PORT (default 4000)
 */

import express from 'express'
import { mockMiddleware } from './middleware.ts'

const port = Number(process.env.MOCK_PORT ?? 4000)

const app = express()

// Permissive CORS so curl / Playwright / a separately-served EUI can reach this server.
app.use((_req, res, next) => {
  res.setHeader('Access-Control-Allow-Origin', '*')
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, PATCH, DELETE, HEAD, OPTIONS')
  res.setHeader('Access-Control-Allow-Headers', '*')
  if (_req.method === 'OPTIONS') {
    res.sendStatus(204)
    return
  }
  next()
})

app.use(mockMiddleware)

app.listen(port, () => {
  console.log(`Mock AM server running at http://localhost:${port}`)
  console.log('  POST /json/authenticate  → challenge / auth')
  console.log('  GET  /json/serverinfo/*  → server info')
  console.log('  *    /json/sessions      → session / logout')
})
