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

import { useState } from 'react'
import { Outlet, useNavigate } from 'react-router'
import { isSelfServiceUser } from './isSelfServiceUser.ts'
import SessionTimeoutDialog from './SessionTimeoutDialog.tsx'
import { useSessionMonitor } from './useSessionMonitor.ts'

type SessionGuardProps = {
  // Override for tests; production callers rely on useSessionMonitor's default.
  pollIntervalMs?: number
}

// Layout route (P1-5k) — mounted around the authenticated shell (App.tsx). Watches the session
// and, on expiry, either navigates a self-service user to /sessionExpired or pops the
// non-closable SessionTimeoutDialog for everyone else (isSelfServiceUser defaults false ->
// modal until real role wiring lands in P2-4 — see isSelfServiceUser.ts).
export default function SessionGuard({ pollIntervalMs }: SessionGuardProps = {}) {
  const navigate = useNavigate()
  const [showDialog, setShowDialog] = useState(false)

  useSessionMonitor(() => {
    if (isSelfServiceUser()) {
      void navigate('/sessionExpired')
    } else {
      setShowDialog(true)
    }
  }, pollIntervalMs)

  return (
    <>
      <Outlet />
      {showDialog && <SessionTimeoutDialog onResume={() => setShowDialog(false)} />}
    </>
  )
}
