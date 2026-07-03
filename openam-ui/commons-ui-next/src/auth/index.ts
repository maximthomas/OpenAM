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

export type {
  AmCallback,
  AmCallbackInput,
  AmCallbackOutput,
  AmAuthChallenge,
  AmAuthSuccess,
  AmAuthError,
  AuthStep,
  KnownCallbackType,
} from './types.ts'

export { KNOWN_CALLBACK_TYPES } from './types.ts'

export {
  startAuthentication,
  resumeAuthentication,
  submitCallbacks,
  fillCallbacks,
  setCallbackValue,
  isAuthSuccess,
  isAuthFailure,
} from './authenticate.ts'

export { validateGoto } from './validateGoto.ts'

export { getTrackingToken, setTrackingToken, clearTrackingToken } from './trackingToken.ts'
export type { TrackingCookieOptions } from './trackingToken.ts'

export {
  getOutput,
  getPrompt,
  getChoices,
  getMessageType,
  getConfirmationOptions,
  getRedirectUrl,
  getRedirectMethod,
  getRedirectData,
  getTrackingCookie,
  getWaitTime,
  getPollingMessage,
  getScript,
  isNameCallback,
  isPasswordCallback,
  isTextInputCallback,
  isHiddenValueCallback,
  isChoiceCallback,
  isConfirmationCallback,
  isTextOutputCallback,
  isScriptTextOutputCallback,
  isRedirectCallback,
  isPollingWaitCallback,
} from './callbacks.ts'

export { CallbackForm } from './CallbackForm.tsx'
export type { CallbackFormProps } from './CallbackForm.tsx'

export { createFetchTransport } from '../transport.ts'
export type { Transport } from '../transport.ts'
