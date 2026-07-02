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

import type { Transport } from '../transport.ts'
import type { AmAuthChallenge, AmAuthError, AmAuthSuccess, AuthStep } from './types.ts'

const AUTH_VERSION = 'protocol=1.0,resource=2.1'

function resolveStep(json: AmAuthChallenge | AmAuthSuccess | AmAuthError, status: number): AuthStep {
  if (status === 401 || status === 408) {
    return { kind: 'failure', error: json as AmAuthError }
  }
  if ('tokenId' in json) {
    return { kind: 'success', success: json as AmAuthSuccess }
  }
  return { kind: 'requirements', challenge: json as AmAuthChallenge }
}

// Step 1: POST with empty body → challenge (authId + callbacks).
// queryString (e.g. "?authIndexType=module&authIndexValue=DataStore") is appended to the path when
// auth URL params are present (P1-5d).
export async function startAuthentication(transport: Transport, queryString?: string): Promise<AuthStep> {
  const path = queryString ? `/authenticate${queryString}` : '/authenticate'
  const res = await transport(path, {
    method: 'POST',
    headers: { 'Accept-API-Version': AUTH_VERSION },
  })
  const json = (await res.json()) as AmAuthChallenge | AmAuthSuccess | AmAuthError
  return resolveStep(json, res.status)
}

// Step 2+: POST the challenge (with input values filled) → next challenge, success, or failure.
export async function submitCallbacks(transport: Transport, challenge: AmAuthChallenge): Promise<AuthStep> {
  const res = await transport('/authenticate', {
    method: 'POST',
    headers: {
      'Accept-API-Version': AUTH_VERSION,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify(challenge),
  })
  const json = (await res.json()) as AmAuthChallenge | AmAuthSuccess | AmAuthError
  return resolveStep(json, res.status)
}

// Immutable update of a single callback's first input value.
export function setCallbackValue(challenge: AmAuthChallenge, index: number, value: string): AmAuthChallenge {
  const callbacks = challenge.callbacks.map((cb, i) => {
    if (i !== index) return cb
    return { ...cb, input: cb.input.map((inp, j) => (j === 0 ? { ...inp, value } : inp)) }
  })
  return { ...challenge, callbacks }
}

// Fill all callbacks in order (first input slot of each callback).
export function fillCallbacks(challenge: AmAuthChallenge, values: string[]): AmAuthChallenge {
  return values.reduce<AmAuthChallenge>((ch, val, i) => setCallbackValue(ch, i, val), challenge)
}

export const isAuthSuccess = (step: AuthStep): step is { kind: 'success'; success: AmAuthSuccess } =>
  step.kind === 'success'

export const isAuthFailure = (step: AuthStep): step is { kind: 'failure'; error: AmAuthError } =>
  step.kind === 'failure'
