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

import { useMemo, useEffect, useRef, useState } from 'react'
import { Alert, Spinner } from 'react-bootstrap'
import { useNavigate, useSearchParams } from 'react-router'
import { useTranslation } from '@openidentityplatform/commons-ui-next/i18n'
import {
  CallbackForm,
  getRedirectData,
  getRedirectMethod,
  getRedirectUrl,
  isRedirectCallback,
  validateGoto,
} from '@openidentityplatform/commons-ui-next/auth'
import { setToken } from '@openidentityplatform/commons-ui-next/session'
import { amTransport } from '../../config/transport.ts'
import { buildAuthQuery, parseLoginParams } from './loginParams.ts'
import { useAuthenticationFlow } from './useLogin.ts'

export default function LoginPage() {
  const { t } = useTranslation()
  const navigate = useNavigate()
  const [searchParams] = useSearchParams()
  const loginParams = useMemo(() => parseLoginParams(searchParams), [searchParams])
  const authQuery = useMemo(() => buildAuthQuery(loginParams), [loginParams])

  const { step, isStarting, isSubmitting, submit, restart } = useAuthenticationFlow(authQuery)
  const [errorMessage, setErrorMessage] = useState<string | null>(null)
  const isRedirectingRef = useRef(false)

  // Handle success, failure, and redirect side-effects.
  useEffect(() => {
    if (step?.kind === 'success') {
      setToken(step.success.tokenId)

      if (loginParams.goto) {
        validateGoto(amTransport, loginParams.goto).then((sanitizedUrl) => {
          if (sanitizedUrl) {
            window.location.href = sanitizedUrl
          } else {
            // goto was rejected by AM's open-redirect guard — fall back to app home.
            void navigate('/')
          }
        })
      } else {
        void navigate('/')
      }
      return
    }
    if (step?.kind === 'failure' && step.error.code !== 408) {
      // 408 is handled inside useAuthenticationFlow (auto-restart); show error for other failures.
      setErrorMessage(t('config.messages.CommonMessages.authenticationFailed'))
      restart()
      return
    }
    if (step?.kind === 'requirements') {
      const redirectCb = step.challenge.callbacks.find(isRedirectCallback)
      if (redirectCb && !isRedirectingRef.current) {
        isRedirectingRef.current = true
        const url = getRedirectUrl(redirectCb)
        if (getRedirectMethod(redirectCb) === 'POST') {
          const data = getRedirectData(redirectCb)
          const form = document.createElement('form')
          form.action = url
          form.method = 'POST'
          for (const [name, value] of Object.entries(data)) {
            const input = document.createElement('input')
            input.type = 'hidden'
            input.name = name
            input.value = value
            form.appendChild(input)
          }
          document.body.appendChild(form)
          form.submit()
        } else {
          window.location.replace(url)
        }
      }
    }
  }, [step, navigate, restart, t, loginParams.goto])

  if (isStarting || step === null) {
    return (
      <>
        {errorMessage && <Alert variant="danger">{errorMessage}</Alert>}
        <Spinner animation="border" role="status" />
      </>
    )
  }

  if (step.kind === 'requirements') {
    // Show a spinner while a redirect is in progress (page is navigating away).
    if (step.challenge.callbacks.some(isRedirectCallback)) {
      return <Spinner animation="border" role="status" />
    }

    return (
      <>
        {errorMessage && <Alert variant="danger">{errorMessage}</Alert>}
        <CallbackForm
          key={step.challenge.authId}
          challenge={step.challenge}
          onSubmit={(ch) => {
            setErrorMessage(null)
            submit(ch)
          }}
          submitting={isSubmitting}
        />
      </>
    )
  }

  // success / failure handled by the useEffect above; render nothing while navigating.
  return null
}
