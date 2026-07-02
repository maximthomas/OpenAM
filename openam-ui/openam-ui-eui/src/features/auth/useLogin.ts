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

import { useCallback, useEffect, useState } from 'react'
import { useMutation } from '@tanstack/react-query'
import {
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
  /** True while a submitCallbacks mutation is in flight. */
  isSubmitting: boolean
  /** Submit a filled challenge to advance the flow. */
  submit: (filledChallenge: AmAuthChallenge) => void
  /** Restart the flow from scratch (fresh startAuthentication). */
  restart: () => void
}

/**
 * Multi-stage AM authentication flow hook (P1-5b).
 * Starts authentication on mount; loops until success or failure via submit().
 */
export function useAuthenticationFlow(): AuthFlowHook {
  const [step, setStep] = useState<AuthStep | null>(null)
  const [isStarting, setIsStarting] = useState(false)

  const startAuth = useCallback(() => {
    setStep(null)
    setIsStarting(true)
    startAuthentication(amTransport)
      .then(setStep)
      .finally(() => setIsStarting(false))
  }, [])

  useEffect(() => {
    startAuth()
  }, [startAuth])

  const submitMutation = useMutation({
    mutationFn: (challenge: AmAuthChallenge) => submitCallbacks(amTransport, challenge),
    onSuccess: setStep,
    retry: false,
  })

  return {
    step,
    isStarting,
    isSubmitting: submitMutation.isPending,
    submit: submitMutation.mutate,
    restart: startAuth,
  }
}
