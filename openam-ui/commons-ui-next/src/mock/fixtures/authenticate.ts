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

// ── Multi-stage fixtures (2-stage: username → password) ─────────────────────

export const MULTI_AUTH_ID_1 = 'multi-stage-auth-id-stage-1-xxxxxxxxxxxxxxxxxx'
export const MULTI_AUTH_ID_2 = 'multi-stage-auth-id-stage-2-xxxxxxxxxxxxxxxxxx'

/** Stage 1: username only. */
export const AUTH_CHALLENGE_USERNAME_STAGE: AmAuthChallenge = {
  authId: MULTI_AUTH_ID_1,
  template: '',
  stage: 'MultiStage1',
  header: 'Sign in to OpenAM',
  callbacks: [
    {
      type: 'NameCallback',
      output: [{ name: 'prompt', value: 'User Name:' }],
      input: [{ name: 'IDToken1', value: '' }],
    },
  ],
}

/** Stage 2: password only. */
export const AUTH_CHALLENGE_PASSWORD_STAGE: AmAuthChallenge = {
  authId: MULTI_AUTH_ID_2,
  template: '',
  stage: 'MultiStage2',
  header: 'Sign in to OpenAM',
  callbacks: [
    {
      type: 'PasswordCallback',
      output: [{ name: 'prompt', value: 'Password:' }],
      input: [{ name: 'IDToken2', value: '' }],
    },
  ],
}

// ── Callback-type fixtures (used in CallbackForm component tests) ─────────────

export const CHOICE_AUTH_ID = 'choice-callback-auth-id-xxxxxxxxxxxxxxxxxx'

/** Stage with a ChoiceCallback. */
export const AUTH_CHALLENGE_CHOICE: AmAuthChallenge = {
  authId: CHOICE_AUTH_ID,
  template: '',
  stage: 'ChoiceStage',
  header: 'Choose an option',
  callbacks: [
    {
      type: 'ChoiceCallback',
      output: [
        { name: 'prompt', value: 'Select security question:' },
        { name: 'choices', value: ['What is your pet name?', 'What city were you born in?'] },
        { name: 'defaultChoice', value: 0 },
      ],
      input: [{ name: 'IDToken1', value: 0 }],
    },
  ],
}

export const CONFIRMATION_AUTH_ID = 'confirmation-callback-auth-id-xxxxxxxxxxxxxxx'

/** Stage with a ConfirmationCallback. */
export const AUTH_CHALLENGE_CONFIRMATION: AmAuthChallenge = {
  authId: CONFIRMATION_AUTH_ID,
  template: '',
  stage: 'ConfirmStage',
  header: 'Confirm',
  callbacks: [
    {
      type: 'ConfirmationCallback',
      output: [
        { name: 'prompt', value: '' },
        { name: 'messageType', value: 0 },
        { name: 'options', value: ['Submit', 'Cancel'] },
        { name: 'optionType', value: -1 },
        { name: 'defaultOption', value: 0 },
      ],
      input: [{ name: 'IDToken1', value: 0 }],
    },
  ],
}

export const TEXT_OUTPUT_AUTH_ID = 'text-output-callback-auth-id-xxxxxxxxxxxxxxxxx'

/** Stage with a TextOutputCallback (info) and a HiddenValueCallback. */
export const AUTH_CHALLENGE_TEXT_OUTPUT: AmAuthChallenge = {
  authId: TEXT_OUTPUT_AUTH_ID,
  template: '',
  stage: 'TextOutputStage',
  header: 'Notice',
  callbacks: [
    {
      type: 'TextOutputCallback',
      output: [
        { name: 'message', value: 'Please review your profile before continuing.' },
        { name: 'messageType', value: 0 },
      ],
      input: [],
    },
    {
      type: 'HiddenValueCallback',
      output: [
        { name: 'value', value: 'hidden-token-value' },
        { name: 'id', value: 'hv1' },
      ],
      input: [{ name: 'IDToken1', value: 'hidden-token-value' }],
    },
  ],
}

// ── RedirectCallback fixtures ─────────────────────────────────────────────────

export const REDIRECT_GET_AUTH_ID = 'redirect-get-auth-id-xxxxxxxxxxxxxxxxxxxxxxxx'
export const REDIRECT_POST_AUTH_ID = 'redirect-post-auth-id-xxxxxxxxxxxxxxxxxxxxxx'

/** Stage with a GET RedirectCallback (e.g. OAuth2 / OIDC federation). */
export const AUTH_CHALLENGE_REDIRECT_GET: AmAuthChallenge = {
  authId: REDIRECT_GET_AUTH_ID,
  template: '',
  stage: 'OAuthRedirect',
  header: '',
  callbacks: [
    {
      type: 'RedirectCallback',
      output: [
        { name: 'redirectUrl', value: 'https://mock-idp.example.com/oauth2/authorize' },
        { name: 'redirectMethod', value: 'GET' },
        { name: 'redirectData', value: {} },
        { name: 'trackingCookie', value: '' },
      ],
      input: [],
    },
  ],
}

/** Stage with a POST RedirectCallback (e.g. SAML2 federation) including a trackingCookie. */
export const AUTH_CHALLENGE_REDIRECT_POST: AmAuthChallenge = {
  authId: REDIRECT_POST_AUTH_ID,
  template: '',
  stage: 'SAMLRedirect',
  header: '',
  callbacks: [
    {
      type: 'RedirectCallback',
      output: [
        { name: 'redirectUrl', value: 'https://mock-idp.example.com/saml2/sso' },
        { name: 'redirectMethod', value: 'POST' },
        { name: 'redirectData', value: { SAMLRequest: 'mock-saml-request', RelayState: 'mock-relay-state' } },
        { name: 'trackingCookie', value: 'mock-tracking-cookie' },
      ],
      input: [],
    },
  ],
}

// ── PollingWaitCallback fixtures ──────────────────────────────────────────────
// Short waitTime (50 ms) so tests complete quickly without fake timers.

export const POLLING_AUTH_ID_1 = 'polling-auth-id-stage-1-xxxxxxxxxxxxxxxxxxxx'
export const POLLING_AUTH_ID_2 = 'polling-auth-id-stage-2-xxxxxxxxxxxxxxxxxxxx'

/** First poll stage — returns another poll stage. */
export const AUTH_CHALLENGE_POLLING_1: AmAuthChallenge = {
  authId: POLLING_AUTH_ID_1,
  template: '',
  stage: 'PushAuth',
  header: '',
  callbacks: [
    {
      type: 'PollingWaitCallback',
      output: [
        { name: 'waitTime', value: 50 },
        { name: 'message', value: 'Waiting for push notification...' },
      ],
      input: [{ name: 'IDToken1', value: '' }],
    },
  ],
}

/** Second (final) poll stage — resolves to success on next submit. */
export const AUTH_CHALLENGE_POLLING_2: AmAuthChallenge = {
  authId: POLLING_AUTH_ID_2,
  template: '',
  stage: 'PushAuth',
  header: '',
  callbacks: [
    {
      type: 'PollingWaitCallback',
      output: [
        { name: 'waitTime', value: 50 },
        { name: 'message', value: 'Almost there...' },
      ],
      input: [{ name: 'IDToken1', value: '' }],
    },
  ],
}

// ── 408 timeout fixture ───────────────────────────────────────────────────────

export const AUTH_TIMEOUT_ERROR: AmAuthError = {
  code: 408,
  reason: 'Request Timeout',
  message: 'Authentication session timed out',
}
