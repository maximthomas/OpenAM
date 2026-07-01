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

import { Container } from 'react-bootstrap'
import { Trans, useTranslation } from 'react-i18next'
import type { FooterProps } from './types'
import styles from './shell.module.scss'

// Page footer: community copyright line plus an optional "Build <version>" (rendered only when the
// app supplies a version — the legacy footer shows it to admins; fetching is deferred, so the
// version arrives as a prop here).
export function Footer({ version }: FooterProps) {
  const { t } = useTranslation()
  return (
    <footer className={styles.footer}>
      <Container fluid className="text-muted d-flex flex-wrap justify-content-between gap-2">
        <span>
          <Trans
            i18nKey="common.form.copyright"
            components={{
              community: (
                <a href="https://github.com/OpenIdentityPlatform/OpenAM/blob/master/README.md" />
              ),
            }}
          />
        </span>
        {version != null && version !== '' && (
          <span>
            {t('common.form.build')} {version}
          </span>
        )}
      </Container>
    </footer>
  )
}
