# API reference

All API routes use the same-origin application. Except `GET /api/health` and `POST /api/login`, routes require an active session cookie. Every state-changing route requires the session's `x-csrf-token`. Document identifiers are not credentials. The server returns `404` for inaccessible documents to avoid disclosing whether they exist.

Roles: **admin**, **owner**, **viewer**. The admin role provides audit access, not an implicit document-access bypass. The document owner has read, edit, permission-management, and delete access. A user granted **read** can read/download; **edit** additionally allows metadata edits and validated file replacement. Only the owner can manage permissions and delete.

| Method and path | Permission | Purpose |
|---|---|---|
| `GET /api/health` | Public | Health probe. |
| `POST /api/login` | Public; rate-limited | JSON `{ "email", "password" }`; sets an HTTP-only session cookie and returns the user and CSRF token. |
| `GET /api/session` | Signed-in | Return current user and session CSRF token. |
| `POST /api/logout` | Signed-in + CSRF | End current session. |
| `GET /api/documents` | Signed-in | List only owned/shared documents; optional `name`, `owner`, `category`, `from`, and `to` (`YYYY-MM-DD`) filters. |
| `POST /api/documents` | Owner or admin + CSRF | Multipart `file` and optional category (`Work`, `Legal`, `Finance`, `Other`). 10 MB maximum; PDF, DOCX, TXT, PNG, JPEG only. The uploader becomes the document owner. |
| `GET /api/documents/:id` | Owner or read/edit grantee | Read document metadata. |
| `GET /api/documents/:id/download` | Owner or read/edit grantee | Download private file bytes. |
| `PUT /api/documents/:id/file` | Owner or edit grantee + CSRF | Multipart `file` replaces the private document after the upload size/type/signature checks. |
| `PATCH /api/documents/:id` | Owner or edit grantee + CSRF | JSON metadata update: `name` and/or `category`. |
| `DELETE /api/documents/:id` | Owner + CSRF | Delete document and uploaded bytes. |
| `GET /api/documents/:id/permissions` | Document owner | List named grantees and current levels. |
| `GET /api/users` | Owner or admin | List share targets, excluding the current user. An admin can manage permissions only on documents the admin owns. |
| `PUT /api/documents/:id/permissions/:userId` | Document owner + CSRF | JSON `{ "level": "read" | "edit" }`; grants or updates access. |
| `DELETE /api/documents/:id/permissions/:userId` | Document owner + CSRF | Revoke access immediately. |
| `GET /api/admin/audit` | Admin | Read audit events; optional `limit` (1-500) and `before` sequence. Includes event and previous HMAC hashes. |

Failed authentication, CSRF checks, role checks, invalid uploads, and denied document operations are recorded in the audit trail where the server can identify and persist the attempt. Authentication errors return `401`, forbidden role/CSRF checks return `403`, inaccessible document IDs return `404`, and invalid input returns `400`.

## Example

After signing in, use the returned CSRF token for a protected mutation:

```http
PUT /api/documents/DOCUMENT_ID/permissions/USER_ID
Content-Type: application/json
x-csrf-token: SESSION_CSRF_TOKEN

{"level":"read"}
```
