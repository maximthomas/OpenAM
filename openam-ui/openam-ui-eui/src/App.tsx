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

import { Routes, Route } from 'react-router'
import { AppShell } from '@openidentityplatform/commons-ui-next/shell'
import Home from './routes/Home.tsx'
import LoginPage from './features/auth/LoginPage.tsx'
import ConfirmLogin from './features/auth/ConfirmLogin.tsx'
import LoginFailure from './features/auth/LoginFailure.tsx'
import SessionExpired from './features/auth/SessionExpired.tsx'
import SessionGuard from './features/auth/SessionGuard.tsx'
import Logout from './features/auth/Logout.tsx'
import Brand from './shell/Brand.tsx'

export default function App() {
  return (
    <Routes>
      {/* Full-chrome layout. Nav items are added as slices migrate. */}
      <Route element={<AppShell brand={<Brand />} />}>
        {/* Session-timeout monitor + re-auth dialog (P1-5k) for the authenticated shell. */}
        <Route element={<SessionGuard />}>
          <Route path="/" element={<Home />} />
        </Route>
      </Route>
      {/* Minimal pre-auth shell (no nav/end) for the login route (P1-5). */}
      <Route element={<AppShell variant="auth" brand={<Brand />} />}>
        <Route path="/login" element={<LoginPage />} />
        <Route path="/confirmLogin" element={<ConfirmLogin />} />
        <Route path="/failedLogin" element={<LoginFailure />} />
        <Route path="/sessionExpired" element={<SessionExpired />} />
        <Route path="/logout" element={<Logout />} />
      </Route>
    </Routes>
  )
}
