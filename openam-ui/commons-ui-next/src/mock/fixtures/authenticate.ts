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

import type { AmAuthChallenge, AmAuthError, AmAuthSuccess } from '../types.ts'

// Recorded from a real AM DataStore1 authentication tree.
export const AUTH_ID =
  'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJvdGsiOiJsa21mODI5dHEzbmhraDNyNmVsbGZtYWpybCIsInJlYWxtIjoiZGM9b3BlbmFtLGRjPW9wZW5pZGVudGl0eXBsYXRmb3JtLGRjPW9yZyIsInNlc3Npb25JZCI6IkFRSUM1d00yTFk0U2ZjekloNTRQLTZ1czRod0tSa09ibWFKa251U0p3SUxNYi1VLipBQUpUU1FBQ01ERUFBbE5MQUJNMk56VTVOVEF5T1RrNU5UUXpOemM0T1RZNEFBSlRNUUFBKiJ9.0lYgF063co7bcg_-xbabvrZponm7NMq3s-IeYPaf9Js'

// The single valid session token — shared with sessions fixture.
export const DEMO_TOKEN_ID =
  'AQIC5wM2LY4SfcwIaAQY6dwlk4xEQjX9v59vw3gRzpGwfTI.*AAJTSQACMDEAAlNLABM2NDI1MzUyMDYwODgwODYyNzkyAAJTMQAA*'

// Step-1 response: challenge with empty inputs for the UI to fill.
export const AUTH_CHALLENGE: AmAuthChallenge = {
  authId: AUTH_ID,
  template: '',
  stage: 'DataStore1',
  header: 'Sign in to OpenAM',
  callbacks: [
    {
      type: 'NameCallback',
      output: [{ name: 'prompt', value: 'User Name:' }],
      input: [{ name: 'IDToken1', value: '' }],
    },
    {
      type: 'PasswordCallback',
      output: [{ name: 'prompt', value: 'Password:' }],
      input: [{ name: 'IDToken2', value: '' }],
    },
  ],
}

// Step-2 success response for credentials demo / changeit.
export const AUTH_SUCCESS: AmAuthSuccess = {
  tokenId: DEMO_TOKEN_ID,
  successUrl: '/openam/console',
  realm: '/',
}

export const AUTH_ERROR: AmAuthError = {
  code: 401,
  reason: 'Unauthorized',
  message: 'Authentication Failed!!',
}
