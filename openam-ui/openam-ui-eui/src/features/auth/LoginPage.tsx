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
import { useQuery } from '@tanstack/react-query'
import { useTranslation } from '@openidentityplatform/commons-ui-next/i18n'
import {
  CallbackForm,
  fillCallbacks,
  getRedirectData,
  getRedirectMethod,
  getRedirectUrl,
  isRedirectCallback,
  validateGoto,
} from '@openidentityplatform/commons-ui-next/auth'
import { clearToken, setToken } from '@openidentityplatform/commons-ui-next/session'
import { fetchServerInfo, isZeroPageLoginAllowed } from '@openidentityplatform/commons-ui-next/serverinfo'
import { amTransport, serverInfoTransport } from '../../config/transport.ts'
import { buildAuthQuery, extractIDTokens, parseLoginParams } from './loginParams.ts'
import { useAuthenticationFlow } from './useLogin.ts'

function normalizeRealm(realm: string): string {
  return realm.replace(/\/+$/, '').toLowerCase() || '/'
}

export default function LoginPage() {
  const { t } = useTranslation()
  const navigate = useNavigate()
  const [searchParams] = useSearchParams()
  const loginParams = useMemo(() => parseLoginParams(searchParams), [searchParams])
  const authQuery = useMemo(() => buildAuthQuery(loginParams), [loginParams])

  const { step, isStarting, isSubmitting, isExistingSession, submit, restart } = useAuthenticationFlow(authQuery)
  const [errorMessage, setErrorMessage] = useState<string | null>(null)
  const isRedirectingRef = useRef(false)

  // Step 3: clear any stored EUI token on mount when arg=newsession is requested.
  // AM handles the server-side session invalidation via the forwarded arg param.
  useEffect(() => {
    if (loginParams.arg === 'newsession') {
      clearToken()
    }
  }, [loginParams.arg])

  // Step 7: fetch server info once to check the zeroPageLogin gate.
  const { data: serverInfo } = useQuery({
    queryKey: ['serverinfo'],
    queryFn: () => fetchServerInfo(serverInfoTransport),
    staleTime: Infinity,
  })

  // Step 7: extract IDToken params from URL for zero-page auto-login.
  const idTokens = useMemo(() => extractIDTokens(searchParams), [searchParams])

  // Referrer whitelist gate (Stage 4, P1-5h) — mirrors legacy RESTLoginView.isZeroPageLoginAllowed.
  const zeroPageAllowed = useMemo(
    () => (serverInfo ? isZeroPageLoginAllowed(serverInfo.zeroPageLogin, document.referrer) : false),
    [serverInfo],
  )

  // Guard: only attempt zero-page auto-submit once per page load.
  const zeroPageAttemptedRef = useRef(false)

  // Handle success, failure, redirect, existing-session, and zero-page side-effects.
  useEffect(() => {
    // Step 4: existing-session branch — initial /authenticate returned success immediately.
    if (step?.kind === 'success' && isExistingSession) {
      const sessionRealm = step.success.realm ?? '/'
      const urlRealm = loginParams.realm ?? '/'
      if (normalizeRealm(sessionRealm) !== normalizeRealm(urlRealm)) {
        void navigate(`/confirmLogin?previousRealm=${encodeURIComponent(sessionRealm)}`)
      } else {
        setToken(step.success.tokenId)
        if (loginParams.goto) {
          validateGoto(amTransport, loginParams.goto).then((sanitizedUrl) => {
            if (sanitizedUrl) {
              window.location.href = sanitizedUrl
            } else {
              void navigate('/')
            }
          })
        } else {
          void navigate('/')
        }
      }
      return
    }

    if (step?.kind === 'success') {
      setToken(step.success.tokenId)

      if (loginParams.goto) {
        validateGoto(amTransport, loginParams.goto).then((sanitizedUrl) => {
          if (sanitizedUrl) {
            window.location.href = sanitizedUrl
          } else {
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
        return
      }

      // Step 7: zero-page auto-login — pre-fill callbacks from URL IDToken params and submit.
      if (!zeroPageAttemptedRef.current && idTokens.length > 0 && zeroPageAllowed) {
        zeroPageAttemptedRef.current = true
        const filled = fillCallbacks(step.challenge, idTokens)
        submit(filled)
        return
      }
    }
  }, [step, isExistingSession, navigate, restart, t, loginParams, submit, idTokens, zeroPageAllowed])

  // While server info is loading and IDTokens are present, show a spinner to avoid briefly
  // flashing the form before the zero-page check completes.
  if (isStarting || step === null || (idTokens.length > 0 && serverInfo === undefined)) {
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

    // Show a spinner while zero-page auto-submit is about to fire (effect hasn't run yet)
    // or is already in flight. Prevents a brief form flash before auto-submit.
    if (idTokens.length > 0 && zeroPageAllowed && !zeroPageAttemptedRef.current) {
      return <Spinner animation="border" role="status" />
    }
    if (zeroPageAttemptedRef.current && isSubmitting) {
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
