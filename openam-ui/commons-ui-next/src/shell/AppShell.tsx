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

import { Outlet } from 'react-router'
import { Header } from './Header'
import { Footer } from './Footer'
import type { AppShellProps } from './types'
import styles from './shell.module.scss'

// The layout that wraps routed content with shared chrome. Used as a react-router layout-route
// element (renders the matched child via <Outlet>). `variant="auth"` renders no navbar at all —
// the legacy LoginBaseTemplate has none either, just a centered logo above the form — and instead
// centers `brand` above a plain Bootstrap `.container` (each auth page narrows further itself, e.g.
// LoginPage's col-md-6/offset-md-3, mirroring RESTLoginTemplate.html); the default `app` variant
// shows full chrome.
export function AppShell({ variant = 'app', brand, nav, end, footerVersion }: AppShellProps) {
  const minimal = variant === 'auth'
  return (
    <div className={styles.shell}>
      {!minimal && <Header brand={brand} nav={nav} end={end} />}
      <main className={minimal ? styles.authMain : styles.main}>
        {minimal ? (
          <>
            {brand != null && <div className={styles.authBrand}>{brand}</div>}
            <div className="container">
              <Outlet />
            </div>
          </>
        ) : (
          <Outlet />
        )}
      </main>
      <Footer version={footerVersion} />
    </div>
  )
}
