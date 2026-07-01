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

import { useMutation } from '@tanstack/react-query'
import { startAuthentication, submitCallbacks, setCallbackValue, type AuthStep } from '@openidentityplatform/commons-ui-next/auth'
import { amTransport } from '../../config/transport.ts'

type Credentials = { username: string; password: string }

// Single-stage username/password login only (P1-5 minimal slice). Multi-stage callback chains,
// redirects, and polling are deferred to P1-5b — see docs/migration/reference/legacy-login.md.
async function login({ username, password }: Credentials): Promise<AuthStep> {
  const start = await startAuthentication(amTransport)
  if (start.kind !== 'requirements') {
    return start
  }

  const nameIndex = start.challenge.callbacks.findIndex((cb) => cb.type === 'NameCallback')
  const passwordIndex = start.challenge.callbacks.findIndex((cb) => cb.type === 'PasswordCallback')

  let challenge = start.challenge
  if (nameIndex !== -1) {
    challenge = setCallbackValue(challenge, nameIndex, username)
  }
  if (passwordIndex !== -1) {
    challenge = setCallbackValue(challenge, passwordIndex, password)
  }

  return submitCallbacks(amTransport, challenge)
}

export function useLogin() {
  return useMutation({ mutationFn: login })
}
