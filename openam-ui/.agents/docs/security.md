# Security Notes

## Known CVEs

| CVE | Component | Impact | Mitigation |
|---|---|---|---|
| CVE-2024-38999 | RequireJS ≤ 2.3.6 | Prototype pollution | Project uses 2.3.7+; do not downgrade |
| CVE-2025-26791 | DOMPurify, swagger-ui | XSS in openam-ui-api | Keep up-to-date; merge Dependabot PRs promptly |
| CVE-2025-8662 | SAML IdP cache | Request parameter tampering corrupts internal cache | Validate all user-supplied input before passing to OpenAM REST endpoints |

## Security Checklist for New Code

- **No hardcoded secrets** — never commit API keys, passwords, or tokens
- **Validate input** — sanitize user-supplied data before using in queries, shell commands, file paths, or HTML output
- **XSS prevention** — use `v-html` with DOMPurify sanitization; never render raw user input
- **Auth at the right boundary** — authentication checks belong in route guards and service layer, not just UI
- **Encode URLs** — use `encodeURIComponent()` on user-supplied IDs in URL paths
- **No CDN at runtime** — all third-party assets must go through the Maven dependency pipeline
