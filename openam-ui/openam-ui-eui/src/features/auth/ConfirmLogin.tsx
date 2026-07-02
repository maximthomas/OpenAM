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

import { Alert } from 'react-bootstrap'
import { Link, useSearchParams } from 'react-router'
import { useTranslation } from '@openidentityplatform/commons-ui-next/i18n'

export default function ConfirmLogin() {
  const [searchParams] = useSearchParams()
  const previousRealm = searchParams.get('previousRealm') ?? '/'
  const { t } = useTranslation()

  return (
    <Alert variant="info">
      <Alert.Heading>{t('common.user.loggedOutOfPreviousSite')}</Alert.Heading>
      <p>{t('login.confirmLogin.body', { realm: previousRealm })}</p>
      <Link to="/login">{t('common.user.logInToNewSite')}</Link>
    </Alert>
  )
}
