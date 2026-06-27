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

import type {
  CrossLinkConfig,
  CrossLinkResolution,
  CrossLinkResolver,
  RouteOwnership,
} from './types'

// Resolves a target route to either an in-app (router) href or a full-page cross-mount href, by
// looking the route's owner up in the ownership map. During the strangler coexistence, links whose
// owner differs from the current app are full-page navigations across the /EUI <-> /XUI boundary
// (the AM session cookie survives the reload), so the new app never bundles the other mount's prefix
// anywhere but the injected MountMap (ADR-0004/0008).

function stripLeadingSlash(path: string): string {
  return path.startsWith('/') ? path.slice(1) : path
}

/** Split a target into its path and any trailing "?query"/"#fragment" so the suffix can be matched
 *  out of the way and re-attached to the resolved href (auth links carry goto/realm params). */
function splitTarget(to: string): { path: string; suffix: string } {
  const i = to.search(/[?#]/)
  return i === -1 ? { path: to, suffix: '' } : { path: to.slice(0, i), suffix: to.slice(i) }
}

/**
 * Find the owning route for `path`. A route owns its whole subtree, so matching is by SEGMENT PREFIX:
 * a pattern matches when every one of its segments equals the corresponding target segment (or is a
 * "*" wildcard matching exactly one segment) and the pattern is no longer than the target. The most
 * specific match wins — longest prefix first, then fewest wildcards (an exact row beats a wildcard of
 * the same depth). This keeps a parent route (e.g. "realms") owning "realms/alpha" and deeper legacy
 * deep-links, while a more specific migrated row (one with a deeper "*" wildcard path) still wins.
 */
function matchRoute(path: string, routes: RouteOwnership[]): RouteOwnership | undefined {
  const targetSegments = stripLeadingSlash(path).split('/')
  let best: RouteOwnership | undefined
  let bestDepth = -1
  let bestWildcards = Number.POSITIVE_INFINITY

  for (const route of routes) {
    const patternSegments = route.path.split('/')
    if (patternSegments.length > targetSegments.length) {
      continue
    }
    let wildcards = 0
    const matches = patternSegments.every((segment, i) => {
      if (segment === '*') {
        wildcards += 1
        return true
      }
      return segment === targetSegments[i]
    })
    if (!matches) {
      continue
    }
    const depth = patternSegments.length
    if (depth > bestDepth || (depth === bestDepth && wildcards < bestWildcards)) {
      best = route
      bestDepth = depth
      bestWildcards = wildcards
    }
  }
  return best
}

/** Join an absolute mount path with an app-relative path, collapsing the boundary slash. */
function joinMount(mount: string, path: string): string {
  const left = mount.endsWith('/') ? mount.slice(0, -1) : mount
  return `${left}/${stripLeadingSlash(path)}`
}

export function createCrossLinkResolver(config: CrossLinkConfig): CrossLinkResolver {
  const { routes, mounts, currentOwner } = config
  return (to: string): CrossLinkResolution => {
    const { path, suffix } = splitTarget(to)
    const matched = matchRoute(path, routes)

    // Unmatched routes (and routes the current app owns) navigate in-app. Root-relative (single
    // leading slash) so react-router resolves against the basename, not the current route.
    if (!matched || matched.owner === currentOwner) {
      return { sameApp: true, href: `/${stripLeadingSlash(path)}${suffix}` }
    }

    const mount = mounts[matched.owner]
    if (mount === undefined) {
      throw new Error(`CrossLink: no mount configured for owner "${matched.owner}" (route "${to}")`)
    }
    return { sameApp: false, href: `${joinMount(mount, matched.legacyHref ?? path)}${suffix}` }
  }
}
