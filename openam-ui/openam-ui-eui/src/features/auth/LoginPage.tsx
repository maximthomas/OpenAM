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

import { useEffect, useState } from 'react'
import { Alert, Spinner } from 'react-bootstrap'
import { useNavigate } from 'react-router'
import { useTranslation } from '@openidentityplatform/commons-ui-next/i18n'
import { CallbackForm } from '@openidentityplatform/commons-ui-next/auth'
import { setToken } from '@openidentityplatform/commons-ui-next/session'
import { useAuthenticationFlow } from './useLogin.ts'

export default function LoginPage() {
  const { t } = useTranslation()
  const navigate = useNavigate()
  const { step, isStarting, isSubmitting, submit, restart } = useAuthenticationFlow()
  const [errorMessage, setErrorMessage] = useState<string | null>(null)

  useEffect(() => {
    if (step?.kind === 'success') {
      setToken(step.success.tokenId)
      void navigate('/')
    }
    if (step?.kind === 'failure') {
      setErrorMessage(t('config.messages.CommonMessages.authenticationFailed'))
      restart()
    }
  }, [step, navigate, restart, t])

  if (isStarting || step === null) {
    return (
      <>
        {errorMessage && <Alert variant="danger">{errorMessage}</Alert>}
        <Spinner animation="border" role="status" />
      </>
    )
  }

  if (step.kind === 'requirements') {
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
