# Admin web UI — design notes and deviations (Phase 9, spec 1.5.5)

`src/web/` runs as `usbscan-web` under gunicorn on loopback. A TLS reverse proxy sits in
front (spec §9.1).

## Owner decisions (13 Oct 2026)

- **Read-only UI.**
  - The plan's "trigger config reload" and "trigger signature update (freshclam via a systemd
    transient unit)" are not implemented. Both would need a privilege path from the web
    process (a polkit rule letting `usbscan-web` start units).
  - Signatures update through freshclam's own timer. Configuration changes follow the
    on-device procedure.
  - The only POST routes are sign-in and sign-out.
- **Vendored front-end libraries, no CDN.**
  - htmx 2.0.11 and Chart.js 4.5.1 are byte-identical copies from the npm registry tarballs,
    verified against the registry's SHA-512 integrity (`static/vendor/VENDOR.md`; a unit test
    re-checks the file hashes).
  - CSP is `script-src 'self'` / `style-src 'self'`, with no `unsafe-inline` and no
    `unsafe-eval`. A test forbids inline scripts, styles, event handlers, `hx-on` and `|safe`
    in templates.
  - htmx runs with `allowEval: false`, `allowScriptTags: false`,
    `includeIndicatorStyles: false` and `historyCacheSize: 0` (no page snapshots in
    localStorage).

## Authentication (spec §10.2)

- **OIDC.**
  - Authorization-code flow with PKCE S256, `state` and `nonce`, implemented with httpx +
    joserfc. authlib's Flask client is built on `requests`, which the project rules exclude,
    and authlib 1.8's httpx integration expects an `httpx2` package.
  - Discovery: the `issuer` in the metadata must match the configured issuer exactly, and all
    endpoints must be https.
  - The ID token is checked for:
    - an asymmetric algorithm from an allow-list (HS*/none are rejected; tested);
    - a signature from the provider's JWKS, which is re-fetched once on an unknown `kid` (key
      rotation; tested);
    - `iss`, `aud`, `azp` when there are several audiences, `exp`, `iat`, `sub` and `nonce`.
- **MFA proof.** The ID token's `amr` must contain one of `mfa_amr_values` (RFC 8176, default
  `["mfa"]`), or `acr` must be one of `mfa_acr_values`; otherwise the login is refused with
  403. Which claim an IdP emits is IdP-specific: configure it per deployment and verify it
  with the real IdP.
- **Roles** come from a claim (default `groups`), mapped to viewer/operator/admin in config.
  The highest matching role wins; no match means no login.
- **Pending logins.**
  - Single-use and expire after 10 minutes.
  - Bound to the browser by a random cookie. Only that browser can consume the pending
    login, so a leaked `state` can neither log in an attacker nor cancel the real login
    (tested).
  - The login start is a POST with the login-form CSRF token, which prevents login CSRF.
- **Local accounts** (spec 1.5.10: a regular method, alone or next to OIDC; `local_enabled`).
  - Individual named accounts from `file:` `auth.web.local.accounts_ref`
    (`username:role:bcrypt[:totp_seed[:disabled]]`, cost ≥ 12 enforced at load), written only by
    the root CLI `src.web.accounts_admin`. Every change is audited first (fail closed).
  - The file is re-read when it changes; an unparseable or world-readable file disables local
    sign-in (fail closed).
  - TOTP second factor (RFC 6238, SHA-1/6 digits/30 s, ±1 step), verified against the RFC 6238
    and RFC 4226 test vectors. The last accepted step per account is stored, so a code cannot be
    replayed. `require_totp: false` is a documented deviation (start-up warning; sessions marked
    `local` instead of `local+totp`).
  - Local sessions are bound to the exact account entry they were issued from (SHA-256 of the
    entry: passphrase hash, TOTP seed, role, status) and re-checked on every request. Any change
    with the CLI ends the session, including one created by a login that was in flight while the
    credentials changed (external review finding, fixed 1.5.10). The CLI also deletes sessions
    directly.
- **Cross-process atomicity.** gunicorn runs two workers, each with its own SQLite connection.
  TOTP step consumption, OIDC pending-login consumption and the failure counter are
  read-modify-write operations in `BEGIN IMMEDIATE` transactions. A 4-process test reproduced
  double acceptance and lost lockout increments before the fix.
  - Passphrases over 72 bytes are refused before bcrypt (bcrypt 5.0).
  - Unknown usernames cost one bcrypt check too, against a dummy hash.
  - Persistent lockout per account and per client address.
  - No shared accounts or PINs.
- **No account enumeration.** Every refusal shows the same "Sign-in failed." The specific
  reason goes only to the `web_auth` audit event.

## Sessions

- **Storage.** Server-side SQLite (`admin_web.state_dir/web.db`, 0600). The cookie holds a
  256-bit random token; the database stores its SHA-256. A new token is issued at each login.
  Flask-Session is not used.
- **Expiry and IP binding.** Idle timeout (15 min), absolute timeout (8 h), logout, and IP
  binding: a request from a different client address revokes the session (401) and records
  `session_rejected`. Behind the proxy, `admin_web.trusted_proxies` sets how many
  X-Forwarded-For hops are trusted (ProxyFix).
- **Cookies.** `__Host-` prefix: Secure, Path=/, no Domain.
  - **Deviation from the plan (SameSite=Strict):** session and OIDC-binding cookies are
    `SameSite=Lax`. The OIDC callback is a cross-site top-level navigation from the IdP, which
    never carries Strict cookies, so the browser binding could not be checked and every OIDC
    login would fail.
  - CSRF protection does not depend on SameSite: every POST needs a synchroniser token (or the
    double-submit token on the login form). A missing or wrong token gives 400.
  - The login-form cookie stays `Strict`.

## Authorization and auditing

| Role | Access |
|---|---|
| viewer | dashboard (HTMX poll every 5 s), statistics, configuration (read-only) |
| operator | + scan history, scan details, CSV/JSON export |
| admin | + audit log, file paths, policy-violation paths, device serial numbers |

- **Sensitive data.** File paths and serials are personal or sensitive data (spec §3.7) and
  are shown to admins only.
- **Configuration view.** Secret fields contain references only; resolved secrets never reach
  a template (tested).
- **Access auditing.** Every data view writes a `web_access` event (user, role, method, path,
  query, status, client address), including denied (403) attempts. Logins, failures, logouts
  and session rejections write `web_auth`. The 5-second status poll is not audited (it would
  add ~17 000 events per day per open browser).
  - Deviation: the plan asks to log "every authenticated request".
- **Fail closed.** If an audit event cannot be written, the response is 503 and no data leaves
  without an audit record. A login is not completed without its audit record.
- **Restricted append role.** The web uid has its own role on `events.sock`
  (`events.web_audit_users`): it can query and append only `web_auth`/`web_access`, and no
  other uid may append those types (tested both ways).
- **Socket group.** The events socket group is now a dedicated `usbscan-audit`. Joining group
  `usbscan` would have given the web process connect access to `broker.sock` and `yara.sock`.
- **Export.**
  - Streamed and capped at 100 000 rows.
  - Filename `scans_<station>_<from>_<to>.<fmt>`.
  - CSV cells starting with `= + - @ TAB CR` are prefixed with `'` (formula injection; tested
    with a malicious signature name).
  - Serials are hidden for non-admins.

## Hardening

- Response headers: CSP as above, `X-Frame-Options: DENY`, `nosniff`,
  `Referrer-Policy: no-referrer`, COOP/CORP, HSTS, and `Cache-Control: no-store` on all
  non-static responses.
- Request bodies are limited to 64 KiB. Templates autoescape; `|safe` is banned.
- Flask debug mode makes `create_app` raise outside tests.
- `wsgi.py` refuses to start when `admin_web.enabled` is false.
- Unit draft `systemd/usb-scan-admin.service (spec §5.4 name)`:
  - `PrivateDevices`, no capabilities, the syscall filter;
  - USB mounts, quarantine, and the orchestrator and events state made inaccessible;
  - outbound traffic is only needed for the IdP.

## Fixed along the way

- **Commit `5d9fe14`:** a verdict with ~20 000 detections exceeded the events-service message
  limit and permanently wedged the orchestrator's spool (station stuck NOT_READY). The
  committed record is now byte-budgeted (`truncated`, `*_count`), and oversized records are
  rejected instead of spooled.
- **`--verify` output:** it reported the checkpoint count as the event count; it now prints
  both.
- **HEALTH events** now carry `details` (ClamAV engine, DB version and time, YARA ruleset
  version, temperatures) for the dashboard. They are republished when versions change and at
  least hourly.

## Still to validate

- A real OIDC provider: amr/acr behaviour, role claim, client authentication method.
- The reverse proxy (`trusted_proxies`, X-Forwarded-*).
- The unit draft on the Pi, including `MemoryDenyWriteExecute`.
