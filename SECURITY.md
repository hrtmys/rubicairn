# Security Policy

## Architecture & Threat Model

Rubicairn is designed for single-user self-hosting behind an authenticating reverse proxy (such as Cloudflare Access):

- **Public endpoints** (`/users/*`, `/privacy`, `/.well-known/webfinger`, `/users/:name/inbox`) enforce strict `Content-Security-Policy: default-src 'none'; style-src 'unsafe-inline';`, chunked request body size limits, UTF-8 validation, and HTTP Signatures (`draft-cavage` `rsa-sha256`).
- **Outbound HTTP** (`Rubicairn::SafeHTTP`) blocks private, loopback, link-local, and multicast IPv4/IPv6 ranges (including IPv4-mapped IPv6), limits redirects, and caps response body sizes.
- **Admin endpoints** (`/admin*`) require both the authenticating proxy header (`Cf-Access-Authenticated-User-Email`) and a WebAuthn Passkey session that unlocks the `AES-256-GCM` encrypted ActivityPub signing key (`config/private.pem.enc`) in memory. High-risk actions (following, accepting followers, managing Passkeys) require a fresh single-use step-up Passkey assertion.

## Reporting a Vulnerability

Please report security issues privately via GitHub Security Advisories (or directly to the repository maintainer) rather than opening a public issue with exploit details.
