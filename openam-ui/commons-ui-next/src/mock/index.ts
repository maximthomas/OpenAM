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

export { handlers } from './handlers/index.ts'

export type {
  AmAuthChallenge,
  AmAuthError,
  AmAuthSuccess,
  AmCallback,
  AmCallbackInput,
  AmCallbackOutput,
  AmLogoutResult,
  AmServerInfo,
  AmSessionInfo,
} from './types.ts'

export {
  AUTH_CHALLENGE,
  AUTH_ERROR,
  AUTH_ID,
  AUTH_SUCCESS,
  DEMO_TOKEN_ID,
  MULTI_AUTH_ID_1,
  MULTI_AUTH_ID_2,
  AUTH_CHALLENGE_USERNAME_STAGE,
  AUTH_CHALLENGE_PASSWORD_STAGE,
  AUTH_CHALLENGE_CHOICE,
  AUTH_CHALLENGE_CONFIRMATION,
  AUTH_CHALLENGE_TEXT_OUTPUT,
  CHOICE_AUTH_ID,
  CONFIRMATION_AUTH_ID,
  TEXT_OUTPUT_AUTH_ID,
  REDIRECT_GET_AUTH_ID,
  REDIRECT_POST_AUTH_ID,
  AUTH_CHALLENGE_REDIRECT_GET,
  AUTH_CHALLENGE_REDIRECT_POST,
  POLLING_AUTH_ID_1,
  POLLING_AUTH_ID_2,
  AUTH_CHALLENGE_POLLING_1,
  AUTH_CHALLENGE_POLLING_2,
  AUTH_TIMEOUT_ERROR,
} from './fixtures/authenticate.ts'

export {
  multiStageAuthenticateHandler,
  redirectAuthenticateHandler,
  pollingAuthenticateHandler,
  make408ThenRecoverHandler,
} from './handlers/authenticate.ts'

export { SERVER_INFO } from './fixtures/serverinfo.ts'

export { DEMO_SESSION, LOGOUT_RESULT } from './fixtures/sessions.ts'

export { MOCK_GOTO_ALLOWED, MOCK_GOTO_REJECTED } from './handlers/users.ts'
