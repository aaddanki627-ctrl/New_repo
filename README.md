# TrustVault

TrustVault is a Node.js/Express document-sharing application. Its browser interface is served by the application; document bytes, sessions, permissions, and audit events are handled by the server, not browser storage.

## Requirements

- Node.js 20 or newer and npm.
- A persistent writable data directory. Back up `data/` securely; it contains the SQLite database, signing key, and private uploads.
- A persistent, private `AUDIT_HMAC_KEY` of at least 32 random bytes for production. Do not lose or disclose it: chain verification depends on this key.
- HTTPS in production; the session cookie is marked `Secure` automatically when `NODE_ENV=production`.

## Run locally

```powershell
npm install
Copy-Item .env.example .env
```

Set unique passwords of at least 12 characters in `.env` for `ADMIN_PASSWORD`, `OWNER_PASSWORD`, and `VIEWER_PASSWORD`. Set `AUDIT_HMAC_KEY` to a persistent 64-character hexadecimal secret. Keep `.env` private.

```powershell
npm run seed
npm start
```

Open `http://localhost:3000`. The seed script creates an admin, an owner, and a viewer; it creates no sample documents and never resets an existing audit log. For a local-only first run without `.env` passwords, `npm run seed` uses `ChangeMe123!`; change these credentials before sharing the app and always configure passwords explicitly for deployment.

The database and uploaded files are stored under `TRUSTVAULT_DATA_DIR` (default: `./data`). Configure a persistent disk at this location when deploying. The application exits if the audit chain is invalid or if the production audit key is missing.

## Tests

```powershell
npm test
```

The automated API tests sign in separate users and try direct document, download, edit, replacement, delete, permission, and administrative routes. They also test admin-owned uploads, grants, immediate revocation, role restrictions, invalid and oversized uploads, searchable metadata, invalid dates, malformed/unknown API requests, audit tamper detection, and the denied-attempt audit trail.

## Security behavior and limitations

- Every document endpoint independently authenticates the session and checks the current document permission. A file identifier or stale browser page does not grant access.
- Owners and admins can upload (and own) documents. A document's owner can edit or replace its file, delete it, and grant/revoke read or edit access to named users; an admin only has these rights on documents the admin owns. Edit permission allows metadata edits and validated file replacement, not permission management or deletion. Viewers cannot upload or grant.
- Revocation takes effect on the next request. There are no public file URLs.
- Only the admin can view the administrative audit endpoint. Admin does not automatically bypass document ownership or sharing.
- Every sign-in, API document-list query, denied unauthenticated request, denied document lookup, and audited document/permission operation adds a chained HMAC event. SQLite triggers prevent application-level update/deletion of events.
- The HMAC chain is tamper-evident, not a standalone immutable/WORM backup. An attacker controlling both the database and signing key can forge a chain. Export/back up the key separately and send audit events to independently administered WORM storage for stronger evidence.
- The app supports one Node process and local SQLite/private-disk storage. Use a single application instance with a persistent volume; this is not a horizontally scaled or certified compliance archive.

See [THREATS.md](./THREATS.md), [API.md](./API.md), and [PROMPTS.md](./PROMPTS.md).

## Deployment

1. Deploy this repository to a Node.js 20+ host with HTTPS and a persistent writable volume.
2. Set `NODE_ENV=production`, `PORT` (if required), `TRUSTVAULT_DATA_DIR` to the mounted persistent volume, a private random `AUDIT_HMAC_KEY`, and three separate passwords of at least 12 characters.
3. Run `npm ci`, then `npm run seed` once. The seed command requires the production passwords to be configured and does not add example documents.
4. Start with `npm start`; expose only the HTTPS proxy. Ensure the proxy forwards the client IP safely and configure Express `trust proxy` only for the actual proxy topology.
5. Test sign-in, owner upload, viewer denial, grant, viewer access, revoke, immediate denied access, and admin audit in the deployed environment. Back up the database, private uploads, and audit key under separate access controls.

No live deployment or public repository is configured by this project checkout.
