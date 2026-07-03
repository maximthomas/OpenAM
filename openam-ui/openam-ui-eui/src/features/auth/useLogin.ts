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
  clearTrackingToken,
  getTrackingCookie,
  getTrackingToken,
  getWaitTime,
  isPollingWaitCallback,
  isRedirectCallback,
  resumeAuthentication,
  setTrackingToken,
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
  /** True when the initial /authenticate call returned success without any submit — live session. */
  isExistingSession: boolean
  /**
   * True when the current 'failure' step is a 408 whose restart was suppressed because a tracked
   * authId (return-leg resume, P1-5i) is in play — mirrors AuthNService's "Suppress retry when
   * using Redirect Callback" branch. The caller should show the timeout message and stop.
   */
  isTimedOut: boolean
  /**
   * True when startAuthentication/resumeAuthentication itself threw (network/unexpected error),
   * as opposed to a 'failure' step *value*. The caller should navigate to /failedLogin (P1-5f).
   */
  startFailed: boolean
  /** Submit a filled challenge to advance the flow. */
  submit: (filledChallenge: AmAuthChallenge) => void
  /** Restart the flow from scratch (fresh startAuthentication). */
  restart: () => void
}

/**
 * Multi-stage AM authentication flow hook (P1-5b/P1-5c/P1-5d/P1-5i).
 * Starts authentication on mount; loops until success or failure via submit().
 * Handles PollingWaitCallback auto-submit, RedirectCallback tracking-cookie detection,
 * 408 timeout restart, and return-leg resume after a federated redirect (P1-5i).
 *
 * queryString (P1-5d): optional query string to append to /authenticate
 * (e.g. "?authIndexType=module&authIndexValue=DataStore").
 */
export function useAuthenticationFlow(queryString?: string): AuthFlowHook {
  const [step, setStep] = useState<AuthStep | null>(null)
  const [isStarting, setIsStarting] = useState(false)
  const [isTimedOut, setIsTimedOut] = useState(false)
  const [startFailed, setStartFailed] = useState(false)
  const pollingTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null)
  // Count of submitted callbacks — zero at the time of a success means an existing session.
  const submitCountRef = useRef(0)

  const startAuth = useCallback(() => {
    setStep(null)
    setIsStarting(true)
    setIsTimedOut(false)
    setStartFailed(false)
    submitCountRef.current = 0

    // Return-leg resume (P1-5i): a tracked authId cookie means a federated redirect is
    // returning — resume instead of restarting (mirrors AuthNService.getRequirements).
    const trackedAuthId = getTrackingToken()
    const authPromise = trackedAuthId
      ? resumeAuthentication(amTransport, trackedAuthId, queryString).then((result) => {
          // Legacy clears the cookie only once the resume call resolves (jQuery .done() — a
          // next stage or success), not on a 401/408 failure.
          if (result.kind !== 'failure') {
            clearTrackingToken()
          }
          return result
        })
      : startAuthentication(amTransport, queryString)

    authPromise
      .then(setStep)
      .catch(() => setStartFailed(true))
      .finally(() => setIsStarting(false))
  }, [queryString])

  useEffect(() => {
    startAuth()
  }, [startAuth])

  const submitMutation = useMutation({
    mutationFn: (challenge: AmAuthChallenge) => submitCallbacks(amTransport, challenge),
    onSuccess: (result: AuthStep) => {
      submitCountRef.current += 1
      setStep(result)
    },
    retry: false,
  })

  // Watch each step for special handling.
  useEffect(() => {
    if (!step) return

    // Detect a redirect with a tracking cookie — store the authId (P1-5i) so a return visit can
    // resume, and mirror AuthNService.handleRequirements: only set it if none is already stored.
    if (step.kind === 'requirements') {
      const redirectCb = step.challenge.callbacks.find(isRedirectCallback)
      if (redirectCb && getTrackingCookie(redirectCb) && !getTrackingToken()) {
        setTrackingToken(step.challenge.authId)
      }
    }

    // 408 timeout: restart the flow unless a tracked authId is in play — matches legacy, which
    // shows the timeout message and stops rather than looping when a redirect token is tracked.
    if (step.kind === 'failure' && step.error.code === 408) {
      if (getTrackingToken()) {
        setIsTimedOut(true)
      } else {
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
    isExistingSession: step?.kind === 'success' && submitCountRef.current === 0,
    isTimedOut,
    startFailed,
    submit: submitMutation.mutate,
    restart: startAuth,
  }
}
