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

import { useEffect, useRef } from 'react'
import { getToken, isSessionValid } from '@openidentityplatform/commons-ui-next/session'
import { amTransport } from '../../config/transport.ts'

const DEFAULT_INTERVAL_MS = 30000

/**
 * Background poll for the authenticated shell (P1-5k). Fires onExpiry once per detected
 * expiry (edge-triggered on the valid→expired transition, so it doesn't refire on every tick
 * while a re-auth dialog is already open) and resets once the session is valid again — e.g.
 * after SessionTimeoutDialog sets a fresh token. Pauses (no network calls) while there is no
 * token, and clears its timer on unmount.
 */
export function useSessionMonitor(onExpiry: () => void, intervalMs: number = DEFAULT_INTERVAL_MS): void {
  const onExpiryRef = useRef(onExpiry)
  onExpiryRef.current = onExpiry

  useEffect(() => {
    let cancelled = false
    let wasValid = true

    const check = async () => {
      const token = getToken()
      if (token === null) return

      const valid = await isSessionValid(amTransport, token)
      if (cancelled) return

      if (!valid && wasValid) {
        onExpiryRef.current()
      }
      wasValid = valid
    }

    const id = setInterval(check, intervalMs)
    return () => {
      cancelled = true
      clearInterval(id)
    }
  }, [intervalMs])
}
