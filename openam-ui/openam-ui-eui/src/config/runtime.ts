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

// Runtime (NOT build-time) configuration for the path-relocatable EUI app.
// The same build artifact is served first from /EUI and later from /XUI (ADR-0004),
// so the router basename must be resolved at runtime and never hardcoded. No absolute
// "/EUI" literal appears in the bundle.

export interface EuiRuntimeConfig {
  /** Path the app is mounted at, e.g. "/EUI" or "/XUI"; used as the router basename. */
  basename: string
}

declare global {
  interface Window {
    __EUI_RUNTIME__?: Partial<EuiRuntimeConfig>
  }
}

const DEFAULT_BASENAME = '/'

/**
 * Resolve the router basename at runtime from the canonical mount signal. Resolution order:
 *   1. the document's `<base href>` — host-rewritten at deploy time; it also anchors the
 *      relative asset URLs, so deriving the basename from it keeps routing and assets in sync.
 *   2. `window.__EUI_RUNTIME__.basename` — programmatic escape hatch for environments that have
 *      no `<base href>` (Vitest, mock mode).
 *   3. "/" fallback (dev server).
 */
export function getBasename(): string {
  const baseHref = document.querySelector('base')?.getAttribute('href')
  if (baseHref && baseHref.trim() !== '') {
    return normalize(hrefToPath(baseHref))
  }

  const injected = window.__EUI_RUNTIME__?.basename
  if (injected && injected.trim() !== '') {
    return normalize(injected)
  }

  return DEFAULT_BASENAME
}

function hrefToPath(href: string): string {
  try {
    return new URL(href, window.location.origin).pathname
  } catch {
    return href
  }
}

function normalize(path: string): string {
  // react-router basename convention: leading slash, no trailing slash (except root "/").
  let p = path.startsWith('/') ? path : `/${path}`
  if (p.length > 1 && p.endsWith('/')) {
    p = p.slice(0, -1)
  }
  return p
}
