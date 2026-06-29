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
 * Legacy XUI no-AM harness (ADR-0010).
 * Serves compiled openam-ui-ria static assets at /XUI and answers their /json/* AM REST calls
 * from the shared MSW handlers — runs the OLD UI in a browser with no OPENAM_HOME / Tomcat.
 *
 *   npm run dev:xui          → http://localhost:XUI_PORT/XUI/ (default port 8081)
 *
 * Prerequisite: build openam-ui-ria first:
 *   mvn -pl openam-ui/openam-ui-ria install   (or: npm run build:production from openam-ui-ria)
 */

import { existsSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import path from 'node:path'
import express from 'express'
import { mockMiddleware } from './middleware.ts'

const __dirname = path.dirname(fileURLToPath(import.meta.url))
// scripts/mock-server/ → openam-ui-eui/ → openam-ui/ → openam-ui-ria/target/compiled
const compiledDir = path.resolve(__dirname, '../../../openam-ui-ria/target/compiled')

if (!existsSync(compiledDir)) {
  console.error(`\nError: compiled XUI not found at:\n  ${compiledDir}\n`)
  console.error('Build openam-ui-ria first:')
  console.error('  mvn -pl openam-ui/openam-ui-ria install')
  console.error('  (or: cd openam-ui/openam-ui-ria && npm run build:production)\n')
  process.exit(1)
}

const port = Number(process.env.XUI_PORT ?? 8081)

const app = express()

// Convenience redirect: / → /XUI/
app.get('/', (_req, res) => { res.redirect('/XUI/') })

// Route /json/* calls through the mock first (before static, so they don't fall through to 404).
// The full path (e.g. /XUI/json/authenticate) is preserved, which matches the */json/* patterns.
app.use((req, res, next) => {
  if (req.path.includes('/json/')) {
    mockMiddleware(req, res, next)
  } else {
    next()
  }
})

// Serve compiled XUI static assets under /XUI/
app.use('/XUI', express.static(compiledDir))

// Fallback: any unmatched /XUI/* deep-link → index.html (RequireJS hash routing)
app.use('/XUI', (_req, res) => {
  res.sendFile(path.join(compiledDir, 'index.html'))
})

app.listen(port, () => {
  console.log(`Legacy XUI harness running at http://localhost:${port}/XUI/`)
  console.log(`  Serving static assets from: ${compiledDir}`)
  console.log('  AM REST calls (/json/*) answered by the shared mock handlers')
})
