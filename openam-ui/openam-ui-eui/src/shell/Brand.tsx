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

import loginLogo from '../assets/images/login-logo.png'

type BrandProps = {
  // 'sm' fits the dark navbar (app shell); 'lg' matches the legacy loginLogo size (225x57,
  // ThemeConfiguration.js) for the centered pre-auth logo. Height-only so the PNG's own aspect
  // ratio holds (width: auto).
  size?: 'sm' | 'lg'
}

// App-owned product branding fed into the shell Header. Kept in the app (not commons) so the
// reusable shell stays product-agnostic. Imported (not a `public/` reference) so Vite fingerprints
// it and rewrites its URL relative to `base: './'`, keeping it path-relocatable (ADR-0004) — a
// hardcoded `/images/...` path would stay root-absolute and break under `/EUI` or `/XUI`.
// Same asset as the legacy XUI's `images/login-logo.png` (ThemeConfiguration's `logo`/`loginLogo`
// both default to it).
export default function Brand({ size = 'sm' }: BrandProps) {
  return (
    <img src={loginLogo} alt="OpenAM" title="OpenAM" style={{ height: size === 'lg' ? 57 : 32, width: 'auto' }} />
  )
}
