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
import { Alert, Modal, Spinner } from 'react-bootstrap'
import { useTranslation } from '@openidentityplatform/commons-ui-next/i18n'
import { CallbackForm } from '@openidentityplatform/commons-ui-next/auth'
import { clearToken, setToken } from '@openidentityplatform/commons-ui-next/session'
import { useAuthenticationFlow } from './useLogin.ts'

type SessionTimeoutDialogProps = {
  // Called once re-authentication succeeds — the caller closes the dialog. No navigation: the
  // user stays on the page they were on (legacy RESTLoginDialog re-auths in place).
  onResume: () => void
}

// Non-closable re-auth modal (P1-5k) — legacy RESTLoginDialog.js/AMConfig's
// EVENT_SHOW_LOGIN_DIALOG admin/unknown branch. Reuses the same login engine as the full-page
// flow, just hosted in a modal instead of navigating to /login.
export default function SessionTimeoutDialog({ onResume }: SessionTimeoutDialogProps) {
  const { t } = useTranslation()
  const { step, isStarting, isSubmitting, isTimedOut, startFailed, submit, restart } = useAuthenticationFlow()
  const [errorMessage, setErrorMessage] = useState<string | null>(null)

  // Legacy SessionToken.remove(): clear the stale client-side token before re-authenticating so
  // the still-live session cookie isn't sent as an (unwanted) session-upgrade attempt.
  useEffect(() => {
    clearToken()
  }, [])

  useEffect(() => {
    if (step?.kind === 'success') {
      setToken(step.success.tokenId)
      onResume()
      return
    }
    if (step?.kind === 'failure' && step.error.code === 408) {
      if (isTimedOut) {
        setErrorMessage(t('config.messages.CommonMessages.loginTimeout'))
      }
      return
    }
    if (step?.kind === 'failure') {
      setErrorMessage(t('config.messages.CommonMessages.authenticationFailed'))
      restart()
    }
  }, [step, isTimedOut, onResume, restart, t])

  return (
    <Modal show backdrop="static" keyboard={false} centered>
      <Modal.Header>
        <Modal.Title>{t('common.form.sessionExpired')}</Modal.Title>
      </Modal.Header>
      <Modal.Body>
        {errorMessage && <Alert variant="danger">{errorMessage}</Alert>}
        {(isStarting || step === null) && !startFailed && <Spinner animation="border" role="status" />}
        {startFailed && <Alert variant="danger">{t('openam.authentication.unavailable')}</Alert>}
        {step?.kind === 'requirements' && (
          <CallbackForm
            key={step.challenge.authId}
            challenge={step.challenge}
            onSubmit={(ch) => {
              setErrorMessage(null)
              submit(ch)
            }}
            submitting={isSubmitting}
          />
        )}
      </Modal.Body>
    </Modal>
  )
}
