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

import { useCallback, useEffect, useRef, useState } from 'react'
import { useMutation } from '@tanstack/react-query'
import {
  getTrackingCookie,
  getWaitTime,
  isPollingWaitCallback,
  isRedirectCallback,
  startAuthentication,
  submitCallbacks,
  type AmAuthChallenge,
  type AuthStep,
} from '@openidentityplatform/commons-ui-next/auth'
import { amTransport } from '../../config/transport.ts'

export type AuthFlowHook = {
  /** Current authentication step; null while the initial startAuthentication is in flight. */
  step: AuthStep | null
  /** True while startAuthentication is running (initial or restart). */
  isStarting: boolean
  /** True while a submitCallbacks mutation is in flight or a poll is scheduled. */
  isSubmitting: boolean
  /** Submit a filled challenge to advance the flow. */
  submit: (filledChallenge: AmAuthChallenge) => void
  /** Restart the flow from scratch (fresh startAuthentication). */
  restart: () => void
}

/**
 * Multi-stage AM authentication flow hook (P1-5b/P1-5c/P1-5d).
 * Starts authentication on mount; loops until success or failure via submit().
 * Handles PollingWaitCallback auto-submit, RedirectCallback tracking-cookie detection,
 * and 408 timeout restart.
 *
 * queryString (P1-5d): optional query string to append to /authenticate
 * (e.g. "?authIndexType=module&authIndexValue=DataStore").
 */
export function useAuthenticationFlow(queryString?: string): AuthFlowHook {
  const [step, setStep] = useState<AuthStep | null>(null)
  const [isStarting, setIsStarting] = useState(false)
  // Set to true when a redirect challenge with a trackingCookie is seen — suppresses 408 restart.
  const hasTrackingCookieRef = useRef(false)
  const pollingTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null)

  const startAuth = useCallback(() => {
    setStep(null)
    setIsStarting(true)
    startAuthentication(amTransport, queryString)
      .then(setStep)
      .finally(() => setIsStarting(false))
  }, [queryString])

  useEffect(() => {
    startAuth()
  }, [startAuth])

  const submitMutation = useMutation({
    mutationFn: (challenge: AmAuthChallenge) => submitCallbacks(amTransport, challenge),
    onSuccess: setStep,
    retry: false,
  })

  // Watch each step for special handling.
  useEffect(() => {
    if (!step) return

    // Detect a redirect with a tracking cookie — suppress 408 restart after federation.
    if (step.kind === 'requirements') {
      const redirectCb = step.challenge.callbacks.find(isRedirectCallback)
      if (redirectCb && getTrackingCookie(redirectCb)) {
        hasTrackingCookieRef.current = true
      }
    }

    // 408 timeout: restart the flow unless a redirect tracking cookie is in play.
    if (step.kind === 'failure' && step.error.code === 408) {
      if (!hasTrackingCookieRef.current) {
        startAuth()
      }
      return
    }

    // PollingWaitCallback: schedule an auto-submit after waitTime ms.
    if (pollingTimerRef.current !== null) {
      clearTimeout(pollingTimerRef.current)
      pollingTimerRef.current = null
    }
    if (step.kind === 'requirements') {
      const pollingCb = step.challenge.callbacks.find(isPollingWaitCallback)
      if (pollingCb) {
        const challenge = step.challenge
        pollingTimerRef.current = setTimeout(() => {
          submitMutation.mutate(challenge)
        }, getWaitTime(pollingCb))
      }
    }

    return () => {
      if (pollingTimerRef.current !== null) {
        clearTimeout(pollingTimerRef.current)
        pollingTimerRef.current = null
      }
    }
  }, [step, startAuth, submitMutation])

  return {
    step,
    isStarting,
    isSubmitting: submitMutation.isPending,
    submit: submitMutation.mutate,
    restart: startAuth,
  }
}
