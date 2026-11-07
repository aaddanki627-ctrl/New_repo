# TrustVault threat model

## Assets and boundaries

Assets are document contents and metadata, account credentials, sessions, permissions, and the evidence trail. The trust boundary is the Node.js server: the browser is untrusted. Documents and the SQLite database live on private server-side storage; the upload directory is not statically served. The assumed deployment uses HTTPS and a host whose filesystem and process are access-controlled.

## Threats and mitigations

| Threat | Mitigation |
|---|---|
| IDOR, guessed document IDs, or direct download URL | Every document detail, download, edit, delete, and permission route authenticates and checks the document's current owner/grant server-side. Inaccessible IDs return `404`; files are not public static content. |
| Cross-user leakage from document listings | The database query returns only owned documents and documents with a matching current permission for the authenticated user. Search filters only that permitted result set. |
| Viewer privilege escalation | Role checks are enforced at upload, user-list, permission, deletion, and admin-audit endpoints. Only owners/admins may upload; admins own their uploaded documents and do not bypass other document permissions. Request body role fields are ignored. |
| Revoked or stale access | The API reads current permissions from SQLite on every request. Revocation deletes the grant; no signed/public file link survives it. |
| Unauthorized edit or destructive action | Metadata/file replacement requires owner or `edit`; document deletion and permission changes require the owner. Every handler checks independently of UI controls. |
| Malicious/oversized upload | Server-side count/size limits, extension allowlist, signature checks for supported binary formats, generated private storage names, sanitized display names, and category allowlist. |
| Session theft or cross-site request forgery | Random opaque session token stored as a hash; HTTP-only, same-site cookie; expiry; CSRF token for mutations; production Secure cookie; security headers. HTTPS is required in deployment. |
| Brute-force login | Login rate limit and constant-work password verification for unknown accounts. Passwords are salted scrypt hashes. |
| Audit event modification/reordering | Every event contains a keyed HMAC over its canonical fields and previous event hash. SQLite triggers reject event updates/deletions; startup verifies the chain. Denied access is recorded before returning denial. |
| Log injection and sensitive-data exposure | Audit detail is bounded and input control characters are stripped where applicable. Passwords, session tokens, and file contents are not logged. |
| Cross-site scripting in document names/audit fields | Browser UI builds rows with DOM `textContent`, not HTML interpolation; restrictive Content Security Policy. |

## Accepted risks and operational controls

- This is a local SQLite/single-process implementation, not a distributed authorization service. Deploy one instance with a persistent, private volume. Do not share that volume with untrusted processes.
- HMAC chaining plus SQLite triggers is tamper-evident against ordinary application/API access, not mathematically immutable. An attacker with both database and `AUDIT_HMAC_KEY` control can rewrite history. Store the key separately and export events to independently administered WORM/append-only storage for high-assurance evidence.
- SQLite/filesystem loss, host compromise, insecure reverse-proxy configuration, TLS termination failure, backups containing secrets, or weak operator passwords can expose data. Use HTTPS, least-privilege hosting, monitored backups, protected environment variables, and incident-response procedures.
- A successful download is an authorized transfer; TrustVault cannot prevent an authorized recipient from copying or photographing its contents.
- Malware scanning, document-content sanitization, antivirus, data-loss prevention, MFA, SSO, password reset, account lockout, and external key management are not implemented. Do not treat this prototype as a certified regulated-data vault.
- Audit events represent server-observed requests and outcomes; they are not proof that a human read a document or that all bytes reached a client.

## Security tests

`npm test` directly calls protected API routes as separate owner, viewer, and admin sessions. It checks unauthorized read/download/edit/replacement/delete/permission access, role restrictions, upload validation, grant/edit/revoke behavior, immediate denial after revocation, search filters, unauthenticated and denied audit events, and rejection of audit-row updates.
