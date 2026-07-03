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

import { describe, it, expect, vi, afterEach } from 'vitest'
import { renderHook, waitFor } from '@testing-library/react'
import { clearToken, setToken } from '@openidentityplatform/commons-ui-next/session'
import { DEMO_TOKEN_ID, EXPIRING_TOKEN_ID } from '@openidentityplatform/commons-ui-next/mock'
import { useSessionMonitor } from './useSessionMonitor.ts'

const POLL_MS = 20

describe('useSessionMonitor', () => {
  afterEach(() => {
    clearToken()
  })

  it('fires onExpiry once when the session is already expired, and does not refire while it stays expired', async () => {
    setToken(EXPIRING_TOKEN_ID)
    const onExpiry = vi.fn()
    renderHook(() => useSessionMonitor(onExpiry, POLL_MS))

    await waitFor(() => expect(onExpiry).toHaveBeenCalledTimes(1))

    await new Promise((resolve) => setTimeout(resolve, POLL_MS * 4))
    expect(onExpiry).toHaveBeenCalledTimes(1)
  })

  it('does not fire while the session is valid', async () => {
    setToken(DEMO_TOKEN_ID)
    const onExpiry = vi.fn()
    renderHook(() => useSessionMonitor(onExpiry, POLL_MS))

    await new Promise((resolve) => setTimeout(resolve, POLL_MS * 4))
    expect(onExpiry).not.toHaveBeenCalled()
  })

  it('pauses (no fetch calls) while there is no token', async () => {
    clearToken()
    const onExpiry = vi.fn()
    const fetchSpy = vi.spyOn(globalThis, 'fetch')
    renderHook(() => useSessionMonitor(onExpiry, POLL_MS))

    await new Promise((resolve) => setTimeout(resolve, POLL_MS * 4))
    expect(onExpiry).not.toHaveBeenCalled()
    expect(fetchSpy).not.toHaveBeenCalled()
    fetchSpy.mockRestore()
  })

  it('clears its timer on unmount', async () => {
    setToken(EXPIRING_TOKEN_ID)
    const onExpiry = vi.fn()
    const { unmount } = renderHook(() => useSessionMonitor(onExpiry, POLL_MS))

    await waitFor(() => expect(onExpiry).toHaveBeenCalledTimes(1))
    unmount()
    const callsAtUnmount = onExpiry.mock.calls.length

    await new Promise((resolve) => setTimeout(resolve, POLL_MS * 4))
    expect(onExpiry).toHaveBeenCalledTimes(callsAtUnmount)
  })
})
