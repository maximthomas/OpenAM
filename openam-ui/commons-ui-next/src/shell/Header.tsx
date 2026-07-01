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

import { Container, Navbar } from 'react-bootstrap'
import type { HeaderProps } from './types'

// Top chrome: brand on the left, optional collapsible nav, and a right-aligned `end` region
// (reserved for the user menu / realm switcher). The nav/end slots are supplied by the app; the
// login (`auth`) variant passes none, giving the minimal pre-auth header.
export function Header({ brand, nav, end }: HeaderProps) {
  const hasCollapse = Boolean(nav || end)
  return (
    <Navbar as="header" bg="dark" variant="dark" expand="lg">
      <Container fluid>
        {brand != null && <Navbar.Brand>{brand}</Navbar.Brand>}
        {hasCollapse && (
          <>
            <Navbar.Toggle aria-controls="eui-shell-nav" />
            <Navbar.Collapse id="eui-shell-nav">
              {nav}
              {end != null && <div className="ms-auto d-flex align-items-center">{end}</div>}
            </Navbar.Collapse>
          </>
        )}
      </Container>
    </Navbar>
  )
}
