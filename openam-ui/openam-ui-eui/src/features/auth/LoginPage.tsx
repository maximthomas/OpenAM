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

import { useState, type FormEvent } from 'react'
import { Form, Button, Alert } from 'react-bootstrap'
import { useNavigate } from 'react-router'
import { useTranslation } from '@openidentityplatform/commons-ui-next/i18n'
import { setToken } from '@openidentityplatform/commons-ui-next/session'
import { isAuthSuccess, isAuthFailure } from '@openidentityplatform/commons-ui-next/auth'
import { useLogin } from './useLogin.ts'

// Single-stage username/password login (P1-5 minimal slice). Multi-stage callback chains,
// remember-me, goto handling, etc. are deferred to P1-5b.
export default function LoginPage() {
  const { t } = useTranslation()
  const navigate = useNavigate()
  const login = useLogin()
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [error, setError] = useState<string | null>(null)

  async function handleSubmit(event: FormEvent) {
    event.preventDefault()
    setError(null)

    const step = await login.mutateAsync({ username, password })
    if (isAuthSuccess(step)) {
      setToken(step.success.tokenId)
      navigate('/')
    } else if (isAuthFailure(step)) {
      setError(t('config.messages.CommonMessages.authenticationFailed'))
    } else {
      setError(t('config.messages.CommonMessages.unknown'))
    }
  }

  return (
    <Form onSubmit={handleSubmit}>
      {error && <Alert variant="danger">{error}</Alert>}
      <Form.Group className="mb-3" controlId="login-username">
        <Form.Label>{t('common.user.username')}</Form.Label>
        <Form.Control value={username} onChange={(event) => setUsername(event.target.value)} required />
      </Form.Group>
      <Form.Group className="mb-3" controlId="login-password">
        <Form.Label>{t('common.user.password')}</Form.Label>
        <Form.Control
          type="password"
          value={password}
          onChange={(event) => setPassword(event.target.value)}
          required
        />
      </Form.Group>
      <Button type="submit" disabled={login.isPending}>
        {t('common.user.login')}
      </Button>
    </Form>
  )
}
