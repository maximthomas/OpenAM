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

import { Nav as BsNav } from 'react-bootstrap'
import { CrossLink } from '../routing'
import type { NavProps } from './types'

// Generic, data-driven primary navigation. Each item links through <CrossLink>, so entries pointing
// at not-yet-migrated routes become full-page /XUI handoffs and migrated ones stay in-app — the app
// just supplies the items. Flat for now; nested/dropdown menus arrive with the admin slices (P3).
export function Nav({ items, ariaLabel, className }: NavProps) {
  return (
    <BsNav as="nav" aria-label={ariaLabel} className={className}>
      {items.map((item) => (
        <CrossLink key={item.id} to={item.to} className="nav-link">
          {item.label}
        </CrossLink>
      ))}
    </BsNav>
  )
}
