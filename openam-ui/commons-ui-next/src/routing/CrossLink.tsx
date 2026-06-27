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

import { createContext, useContext } from 'react'
import type { AnchorHTMLAttributes, ReactNode } from 'react'
import { Link } from 'react-router'
import type { CrossLinkResolver } from './types'

// <CrossLink> renders a link that is either an in-app react-router <Link> (when the target route is
// owned by the current app) or a plain full-page <a> handoff to another mount (when it is not). The
// decision comes from the resolver supplied via <CrossLinkProvider>. Callers just say
// <CrossLink to="realms"> and never hardcode which app owns the route — flipping the ownership map
// retargets every link automatically as slices migrate.

const CrossLinkContext = createContext<CrossLinkResolver | null>(null)

export function CrossLinkProvider({
  resolver,
  children,
}: {
  resolver: CrossLinkResolver
  children: ReactNode
}) {
  return <CrossLinkContext.Provider value={resolver}>{children}</CrossLinkContext.Provider>
}

export function useCrossLink(): CrossLinkResolver {
  const resolver = useContext(CrossLinkContext)
  if (!resolver) {
    throw new Error('useCrossLink must be used within a <CrossLinkProvider>')
  }
  return resolver
}

// `href` is omitted so it cannot override the resolver-computed destination — the whole point of
// CrossLink is that callers express intent via `to` and never hardcode an href (mirrors react-router
// LinkProps, which also omits href).
export interface CrossLinkProps extends Omit<AnchorHTMLAttributes<HTMLAnchorElement>, 'href'> {
  /** App-relative target route, e.g. "login" or "realms/alpha/authentication". */
  to: string
  children: ReactNode
}

export function CrossLink({ to, children, ...rest }: CrossLinkProps) {
  const resolve = useCrossLink()
  const { sameApp, href } = resolve(to)

  if (sameApp) {
    return (
      <Link to={href} {...rest}>
        {children}
      </Link>
    )
  }
  // Cross-boundary: a real anchor so the browser does a full-page load (session cookie survives).
  return (
    <a href={href} {...rest}>
      {children}
    </a>
  )
}
