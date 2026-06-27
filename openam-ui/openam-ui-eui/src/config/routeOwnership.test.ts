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

// Drift guard: the runtime route-ownership map MUST mirror the doc source of truth
// (docs/migration/route-ownership.yml). If a slice updates one and not the other, this fails.

import { existsSync, readFileSync } from 'node:fs'
import { resolve } from 'node:path'
import { describe, it, expect } from 'vitest'
import { load } from 'js-yaml'
import { mounts, routeOwnership } from './routeOwnership'

interface YamlDoc {
  mounts: Record<string, string>
  routes: { path: string; owner: string; status: string; slice: string }[]
}

// The yaml lives in the sibling legacy module (until docs are relocated at cutover, P4-3). Resolve it
// from cwd, tolerating both run contexts: cwd = openam-ui-eui (npm run ... -w eui) and cwd = the
// workspace root openam-ui (a root-level vitest run in CI).
const YAML_REL = 'docs/migration/route-ownership.yml'
function findRouteOwnershipYaml(): string {
  const candidates = [
    resolve(process.cwd(), '..', 'openam-ui-ria', YAML_REL),
    resolve(process.cwd(), 'openam-ui-ria', YAML_REL),
  ]
  const found = candidates.find((candidate) => existsSync(candidate))
  if (!found) {
    throw new Error(`route-ownership.yml not found; looked in:\n${candidates.join('\n')}`)
  }
  return found
}

const doc = load(readFileSync(findRouteOwnershipYaml(), 'utf8')) as YamlDoc

describe('routeOwnership mirrors route-ownership.yml', () => {
  it('keeps the full mount map in sync with the yaml (excluding the doc-only "final" pointer)', () => {
    // "final" is the canonical end-state path (ADR-0004) — documentation only, not a runtime mount.
    const runtimeMounts = Object.fromEntries(
      Object.entries(doc.mounts).filter(([key]) => key !== 'final'),
    )
    expect(mounts).toEqual(runtimeMounts)
  })

  it('defines a mount for every owner referenced by the route map', () => {
    // Otherwise a CrossLink to such a route throws "no mount configured" at runtime (resolver.ts).
    for (const owner of new Set(routeOwnership.map((route) => route.owner))) {
      expect(mounts).toHaveProperty(owner)
    }
  })

  it('keeps every route path + owner in sync with the yaml, in order', () => {
    const fromYaml = doc.routes.map((route) => ({ path: route.path, owner: route.owner }))
    const fromTs = routeOwnership.map((route) => ({ path: route.path, owner: route.owner }))
    expect(fromTs).toEqual(fromYaml)
  })
})
