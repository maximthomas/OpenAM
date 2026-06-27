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

/**
 * Routing primitives — path-relocatable helpers on top of react-router 7: the CrossLink helper for
 * linking between the new (/EUI) and legacy (/XUI) mounts without hardcoded prefixes (ADR-0004/0008).
 * App-agnostic: the consuming app supplies the route-ownership map and mount paths (ADR-0002).
 */
export type {
  RouteOwnership,
  MountMap,
  CrossLinkConfig,
  CrossLinkResolution,
  CrossLinkResolver,
} from './types'
export { createCrossLinkResolver } from './resolver'
export { CrossLink, CrossLinkProvider, useCrossLink } from './CrossLink'
export type { CrossLinkProps } from './CrossLink'
