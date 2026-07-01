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

// App-shell primitive types. App-agnostic (ADR-0002): the consuming app supplies branding, nav
// items, and version — no OpenAM-specific content lives here.

import type { ReactNode } from 'react'

/**
 * `app` = full chrome (nav + header end region); `auth` = minimal chrome for the pre-auth login
 * flow (brand + footer only), mirroring the legacy LoginBaseTemplate vs DefaultBaseTemplate split.
 */
export type ShellVariant = 'app' | 'auth'

/** One navigation entry. `to` is an app-relative route resolved through CrossLink. */
export interface NavItem {
  id: string
  label: string
  to: string
}

export interface NavProps {
  items: NavItem[]
  /** Accessible name for the nav landmark. */
  ariaLabel?: string
  className?: string
}

export interface HeaderProps {
  /** Product branding (logo/name); supplied by the app. */
  brand?: ReactNode
  /** Primary navigation, typically a <Nav>. Omitted in the `auth` variant. */
  nav?: ReactNode
  /** Right-aligned region (reserved for the user menu / realm switcher). Omitted in `auth`. */
  end?: ReactNode
}

export interface FooterProps {
  /** Optional version string; the "Build …" line renders only when this is set. */
  version?: string
}

export interface AppShellProps {
  variant?: ShellVariant
  brand?: ReactNode
  nav?: ReactNode
  end?: ReactNode
  footerVersion?: string
}
