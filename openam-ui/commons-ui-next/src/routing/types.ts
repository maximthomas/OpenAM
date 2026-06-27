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

// Cross-link routing types. App-agnostic (ADR-0002): owner ids and mount paths are supplied by the
// consuming app, so no OpenAM route names or "/EUI"/"/XUI" literals appear here.

/** One row of the route-ownership map: which app owns an app-relative route path. */
export interface RouteOwnership {
  // App-relative path, no leading slash, e.g. "login" or a "*" wildcard segment as in
  // "realms/*/authentication" (where "*" matches exactly one path segment).
  path: string
  /** Owner app id (e.g. "eui" | "xui"); compared against CrossLinkConfig.currentOwner. */
  owner: string
  /** Optional explicit href used when linking to this route in another app (ADR-0008 seam). */
  legacyHref?: string
}

/** Owner app id -> absolute mount path, e.g. { eui: "/EUI", xui: "/XUI" }. */
export type MountMap = Record<string, string>

export interface CrossLinkConfig {
  routes: RouteOwnership[]
  mounts: MountMap
  /** The app id this resolver runs inside; routes it owns resolve to in-app navigation. */
  currentOwner: string
}

export interface CrossLinkResolution {
  /** true -> in-app (react-router) navigation; false -> full-page handoff to another mount. */
  sameApp: boolean
  href: string
}

export type CrossLinkResolver = (to: string) => CrossLinkResolution
