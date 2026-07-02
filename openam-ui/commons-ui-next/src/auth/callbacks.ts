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

// Pure helpers for inspecting AM callback objects.

import type { AmCallback, AmCallbackOutput } from './types.ts'

export function getOutput(cb: AmCallback, name: string): AmCallbackOutput | undefined {
  return cb.output.find((o) => o.name === name)
}

/** Returns the 'prompt' output value with a trailing colon stripped. */
export function getPrompt(cb: AmCallback): string {
  const raw = String(getOutput(cb, 'prompt')?.value ?? '')
  return raw.endsWith(':') ? raw.slice(0, -1) : raw
}

/** Returns the choices array for a ChoiceCallback. */
export function getChoices(cb: AmCallback): string[] {
  const val = getOutput(cb, 'choices')?.value
  return Array.isArray(val) ? (val as string[]) : []
}

/** Returns the messageType number for TextOutputCallback / ConfirmationCallback. */
export function getMessageType(cb: AmCallback): number {
  const val = getOutput(cb, 'messageType')?.value
  return typeof val === 'number' ? val : 0
}

/** Returns the options array (button labels) for a ConfirmationCallback. */
export function getConfirmationOptions(cb: AmCallback): string[] {
  const val = getOutput(cb, 'options')?.value
  return Array.isArray(val) ? (val as string[]) : []
}

// Type guards — narrow the open `type: string` to a specific known type.
export const isNameCallback = (cb: AmCallback): boolean => cb.type === 'NameCallback'
export const isPasswordCallback = (cb: AmCallback): boolean => cb.type === 'PasswordCallback'
export const isTextInputCallback = (cb: AmCallback): boolean => cb.type === 'TextInputCallback'
export const isHiddenValueCallback = (cb: AmCallback): boolean => cb.type === 'HiddenValueCallback'
export const isChoiceCallback = (cb: AmCallback): boolean => cb.type === 'ChoiceCallback'
export const isConfirmationCallback = (cb: AmCallback): boolean => cb.type === 'ConfirmationCallback'
export const isTextOutputCallback = (cb: AmCallback): boolean => cb.type === 'TextOutputCallback'
export const isRedirectCallback = (cb: AmCallback): boolean => cb.type === 'RedirectCallback'
export const isPollingWaitCallback = (cb: AmCallback): boolean => cb.type === 'PollingWaitCallback'

// RedirectCallback accessors.
export function getRedirectUrl(cb: AmCallback): string {
  return String(getOutput(cb, 'redirectUrl')?.value ?? '')
}

export function getRedirectMethod(cb: AmCallback): string {
  return String(getOutput(cb, 'redirectMethod')?.value ?? 'GET').toUpperCase()
}

/** Returns the POST hidden-field map for a RedirectCallback with redirectMethod=POST. */
export function getRedirectData(cb: AmCallback): Record<string, string> {
  const val = getOutput(cb, 'redirectData')?.value
  if (val && typeof val === 'object' && !Array.isArray(val)) {
    return val as Record<string, string>
  }
  return {}
}

/** Returns the tracking-cookie value, used to suppress 408 retry after a federated redirect. */
export function getTrackingCookie(cb: AmCallback): string {
  return String(getOutput(cb, 'trackingCookie')?.value ?? '')
}

// PollingWaitCallback accessors.
/** Returns the polling wait time in milliseconds. */
export function getWaitTime(cb: AmCallback): number {
  const val = getOutput(cb, 'waitTime')?.value
  return typeof val === 'number' ? val : parseInt(String(val ?? '0'), 10) || 0
}

/** Returns the optional status message from a PollingWaitCallback. */
export function getPollingMessage(cb: AmCallback): string {
  return String(getOutput(cb, 'message')?.value ?? '')
}
