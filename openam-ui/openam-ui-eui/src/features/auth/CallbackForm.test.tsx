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

import { describe, it, expect, vi } from 'vitest'
import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { I18nextProvider, createI18nInstance } from '@openidentityplatform/commons-ui-next/i18n'
import {
  CallbackForm,
  type AmAuthChallenge,
} from '@openidentityplatform/commons-ui-next/auth'
import {
  AUTH_CHALLENGE,
  AUTH_CHALLENGE_CHOICE,
  AUTH_CHALLENGE_CONFIRMATION,
  AUTH_CHALLENGE_TEXT_OUTPUT,
} from '@openidentityplatform/commons-ui-next/mock'

function renderForm(challenge: AmAuthChallenge, onSubmit = vi.fn(), submitting = false) {
  return render(
    <I18nextProvider i18n={createI18nInstance()}>
      <CallbackForm challenge={challenge} onSubmit={onSubmit} submitting={submitting} />
    </I18nextProvider>,
  )
}

describe('CallbackForm', () => {
  describe('NameCallback + PasswordCallback (default single-stage challenge)', () => {
    it('renders prompt-derived labels (colon trimmed)', () => {
      renderForm(AUTH_CHALLENGE)
      expect(screen.getByLabelText('User Name')).toBeInTheDocument()
      expect(screen.getByLabelText('Password')).toBeInTheDocument()
    })

    it('renders a synthetic Submit button when no ConfirmationCallback is present', () => {
      renderForm(AUTH_CHALLENGE)
      expect(screen.getByRole('button', { name: 'Submit' })).toBeInTheDocument()
    })

    it('password field has type=password', () => {
      renderForm(AUTH_CHALLENGE)
      expect(screen.getByLabelText('Password')).toHaveAttribute('type', 'password')
    })

    it('calls onSubmit with filled challenge when form is submitted', async () => {
      const user = userEvent.setup()
      const onSubmit = vi.fn()
      renderForm(AUTH_CHALLENGE, onSubmit)

      await user.type(screen.getByLabelText('User Name'), 'alice')
      await user.type(screen.getByLabelText('Password'), 'secret')
      await user.click(screen.getByRole('button', { name: 'Submit' }))

      expect(onSubmit).toHaveBeenCalledOnce()
      const [filledChallenge] = onSubmit.mock.calls[0] as [AmAuthChallenge]
      expect(filledChallenge.callbacks[0].input[0].value).toBe('alice')
      expect(filledChallenge.callbacks[1].input[0].value).toBe('secret')
    })

    it('disables submit button while submitting', () => {
      renderForm(AUTH_CHALLENGE, vi.fn(), true)
      expect(screen.getByRole('button', { name: 'Submit' })).toBeDisabled()
    })
  })

  describe('ChoiceCallback', () => {
    it('renders a labeled <select> with all choices', () => {
      renderForm(AUTH_CHALLENGE_CHOICE)
      const select = screen.getByLabelText('Select security question')
      expect(select.tagName).toBe('SELECT')
      expect(screen.getByRole('option', { name: 'What is your pet name?' })).toBeInTheDocument()
      expect(screen.getByRole('option', { name: 'What city were you born in?' })).toBeInTheDocument()
    })

    it('submits with the selected choice index', async () => {
      const user = userEvent.setup()
      const onSubmit = vi.fn()
      renderForm(AUTH_CHALLENGE_CHOICE, onSubmit)

      await user.selectOptions(screen.getByLabelText('Select security question'), '1')
      await user.click(screen.getByRole('button', { name: 'Submit' }))

      expect(onSubmit).toHaveBeenCalledOnce()
      const [filledChallenge] = onSubmit.mock.calls[0] as [AmAuthChallenge]
      expect(filledChallenge.callbacks[0].input[0].value).toBe('1')
    })
  })

  describe('ConfirmationCallback', () => {
    it('renders one button per option', () => {
      renderForm(AUTH_CHALLENGE_CONFIRMATION)
      expect(screen.getByRole('button', { name: 'Submit' })).toBeInTheDocument()
      expect(screen.getByRole('button', { name: 'Cancel' })).toBeInTheDocument()
    })

    it('does NOT render a synthetic Submit button', () => {
      renderForm(AUTH_CHALLENGE_CONFIRMATION)
      // Both buttons are from the callback; there is no additional synthetic button.
      const buttons = screen.getAllByRole('button')
      expect(buttons).toHaveLength(2)
    })

    it('calls onSubmit with confirmationIndex 0 when first button clicked', async () => {
      const user = userEvent.setup()
      const onSubmit = vi.fn()
      renderForm(AUTH_CHALLENGE_CONFIRMATION, onSubmit)

      await user.click(screen.getByRole('button', { name: 'Submit' }))

      expect(onSubmit).toHaveBeenCalledOnce()
      const [filledChallenge] = onSubmit.mock.calls[0] as [AmAuthChallenge]
      expect(filledChallenge.callbacks[0].input[0].value).toBe('0')
    })

    it('calls onSubmit with confirmationIndex 1 when Cancel clicked', async () => {
      const user = userEvent.setup()
      const onSubmit = vi.fn()
      renderForm(AUTH_CHALLENGE_CONFIRMATION, onSubmit)

      await user.click(screen.getByRole('button', { name: 'Cancel' }))

      expect(onSubmit).toHaveBeenCalledOnce()
      const [filledChallenge] = onSubmit.mock.calls[0] as [AmAuthChallenge]
      expect(filledChallenge.callbacks[0].input[0].value).toBe('1')
    })
  })

  describe('TextOutputCallback + HiddenValueCallback', () => {
    it('renders an info alert for messageType 0', () => {
      renderForm(AUTH_CHALLENGE_TEXT_OUTPUT)
      expect(screen.getByRole('alert')).toHaveTextContent(
        'Please review your profile before continuing.',
      )
    })

    it('does NOT render a visible control for HiddenValueCallback', () => {
      renderForm(AUTH_CHALLENGE_TEXT_OUTPUT)
      // There should be no labeled form field for the hidden callback.
      expect(screen.queryByRole('textbox')).toBeNull()
    })

    it('renders a synthetic Submit button (no ConfirmationCallback in this challenge)', () => {
      renderForm(AUTH_CHALLENGE_TEXT_OUTPUT)
      expect(screen.getByRole('button', { name: 'Submit' })).toBeInTheDocument()
    })
  })
})
