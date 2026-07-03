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

import type { AmSessionInfo } from '@openidentityplatform/commons-ui-next/session'

// Legacy AMConfig.js's EVENT_SHOW_LOGIN_DIALOG branches on loggedUser.hasRole("ui-self-service-user").
// AmSessionInfo carries no role field yet (role data comes from a separate user-profile fetch,
// not /json/sessions), so this always takes the legacy "else" branch (admin/unknown -> modal)
// until real role wiring lands with the profile slice (P2-4). The sessionInfo param is accepted
// now so callers don't need to change when that wiring arrives.
export function isSelfServiceUser(sessionInfo?: AmSessionInfo): boolean {
  void sessionInfo
  return false
}
