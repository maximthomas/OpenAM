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
import { Alert, Button, Form, Spinner } from 'react-bootstrap'
import { useTranslation } from 'react-i18next'
import { setCallbackValue } from './authenticate.ts'
import {
  getChoices,
  getConfirmationOptions,
  getMessageType,
  getOutput,
  getPollingMessage,
  getPrompt,
  isChoiceCallback,
  isConfirmationCallback,
  isHiddenValueCallback,
  isPasswordCallback,
  isPollingWaitCallback,
  isTextInputCallback,
  isTextOutputCallback,
} from './callbacks.ts'
import type { AmAuthChallenge } from './types.ts'

export type CallbackFormProps = {
  challenge: AmAuthChallenge
  onSubmit: (filledChallenge: AmAuthChallenge) => void
  submitting: boolean
}

/**
 * Generic AM callback renderer. Seeds controlled state from the challenge, renders one control
 * per callback, injects a synthetic Submit button when no ConfirmationCallback is present.
 * TextOutputCallback messageType 4 (ScriptTextOutput) is intentionally skipped — deferred to P1-5g.
 */
export function CallbackForm({ challenge, onSubmit, submitting }: CallbackFormProps) {
  const { t } = useTranslation()

  const [values, setValues] = useState<string[]>(() =>
    challenge.callbacks.map((cb) => String(cb.input[0]?.value ?? '')),
  )

  const hasConfirmation = challenge.callbacks.some(isConfirmationCallback)
  const pollingCb = challenge.callbacks.find(isPollingWaitCallback)

  function buildFilled(confirmationIndex?: number): AmAuthChallenge {
    return challenge.callbacks.reduce((ch, cb, i) => {
      if (isConfirmationCallback(cb)) {
        return confirmationIndex !== undefined ? setCallbackValue(ch, i, String(confirmationIndex)) : ch
      }
      return setCallbackValue(ch, i, values[i] ?? '')
    }, challenge)
  }

  function handleFormSubmit(e: FormEvent) {
    e.preventDefault()
    onSubmit(buildFilled())
  }

  function updateValue(index: number, value: string) {
    setValues((prev) => prev.map((v, i) => (i === index ? value : v)))
  }

  // PollingWaitCallback: render a waiting state — no user input, auto-submit is driven by the
  // parent hook (useAuthenticationFlow). Show a message from the polling callback if present.
  if (pollingCb) {
    const message = getPollingMessage(pollingCb)
    return (
      <div className="d-flex flex-column align-items-center gap-3 py-3">
        <Spinner animation="border" role="status" />
        {message && <p className="mb-0">{message}</p>}
      </div>
    )
  }

  return (
    <Form onSubmit={handleFormSubmit}>
      {challenge.header && <h4>{challenge.header}</h4>}

      {challenge.callbacks.map((cb, i) => {
        // TextOutputCallback: render as Bootstrap alert (messageType 4 = script, skipped)
        if (isTextOutputCallback(cb)) {
          const msgType = getMessageType(cb)
          if (msgType === 4) return null
          const message = String(getOutput(cb, 'message')?.value ?? '')
          const variant = msgType === 2 ? 'danger' : msgType === 1 ? 'warning' : 'info'
          return (
            <Alert key={i} variant={variant}>
              {message}
            </Alert>
          )
        }

        // HiddenValueCallback: hidden input, value seeded from challenge
        if (isHiddenValueCallback(cb)) {
          return <input key={i} type="hidden" readOnly value={values[i] ?? ''} />
        }

        // ConfirmationCallback: one button per option; clicking immediately submits
        if (isConfirmationCallback(cb)) {
          return (
            <div key={i} className="d-flex gap-2">
              {getConfirmationOptions(cb).map((label, btnIdx) => (
                <Button
                  key={btnIdx}
                  type="button"
                  variant={btnIdx === 0 ? 'primary' : 'secondary'}
                  disabled={submitting}
                  onClick={() => onSubmit(buildFilled(btnIdx))}
                >
                  {label}
                </Button>
              ))}
            </div>
          )
        }

        // ChoiceCallback: labeled <select>
        if (isChoiceCallback(cb)) {
          return (
            <Form.Group key={i} className="mb-3" controlId={`cb-${i}`}>
              <Form.Label>{getPrompt(cb)}</Form.Label>
              <Form.Select value={values[i] ?? '0'} onChange={(e) => updateValue(i, e.target.value)}>
                {getChoices(cb).map((choice, ci) => (
                  <option key={ci} value={String(ci)}>
                    {choice}
                  </option>
                ))}
              </Form.Select>
            </Form.Group>
          )
        }

        // TextInputCallback: textarea
        if (isTextInputCallback(cb)) {
          return (
            <Form.Group key={i} className="mb-3" controlId={`cb-${i}`}>
              <Form.Label>{getPrompt(cb)}</Form.Label>
              <Form.Control as="textarea" value={values[i] ?? ''} onChange={(e) => updateValue(i, e.target.value)} />
            </Form.Group>
          )
        }

        // PasswordCallback: password input; NameCallback / unknown: text input (default)
        return (
          <Form.Group key={i} className="mb-3" controlId={`cb-${i}`}>
            <Form.Label>{getPrompt(cb)}</Form.Label>
            <Form.Control
              type={isPasswordCallback(cb) ? 'password' : 'text'}
              value={values[i] ?? ''}
              onChange={(e) => updateValue(i, e.target.value)}
            />
          </Form.Group>
        )
      })}

      {!hasConfirmation && (
        <Button type="submit" disabled={submitting}>
          {t('common.form.submit')}
        </Button>
      )}
    </Form>
  )
}
