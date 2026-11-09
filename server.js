require('dotenv').config();

const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const express = require('express');
const helmet = require('helmet');
const multer = require('multer');
const { rateLimit } = require('express-rate-limit');
const { db, dataDir } = require('./src/db');
const { audit, verifyAuditChain } = require('./src/audit');
const { authenticate, requireCsrf, login, hash, passwordHash, clearSessionCookie } = require('./src/auth');
const { getDocument, canRead, canEdit, visibleDocuments } = require('./src/permissions');

const app = express();
const uploadDir = path.join(dataDir, 'uploads');
fs.mkdirSync(uploadDir, { recursive: true, mode: 0o700 });
const MAX_FILE_BYTES = 10 * 1024 * 1024;
const allowedTypes = {
  '.pdf': { mime: 'application/pdf', signature: bytes => bytes.subarray(0, 5).toString() === '%PDF-' },
  '.txt': { mime: 'text/plain', signature: () => true },
  '.png': { mime: 'image/png', signature: bytes => bytes.subarray(0, 8).equals(Buffer.from([137, 80, 78, 71, 13, 10, 26, 10])) },
  '.jpg': { mime: 'image/jpeg', signature: bytes => bytes.subarray(0, 3).equals(Buffer.from([255, 216, 255])) },
  '.jpeg': { mime: 'image/jpeg', signature: bytes => bytes.subarray(0, 3).equals(Buffer.from([255, 216, 255])) },
  '.docx': { mime: 'application/vnd.openxmlformats-officedocument.wordprocessingml.document', signature: bytes => bytes.subarray(0, 2).toString() === 'PK' }
};

app.disable('x-powered-by');
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"], styleSrc: ["'self'"], scriptSrc: ["'self'"], imgSrc: ["'self'", 'data:'],
      connectSrc: ["'self'"], objectSrc: ["'none'"], baseUri: ["'self'"], frameAncestors: ["'none'"], formAction: ["'self'"]
    }
  },
  crossOriginResourcePolicy: { policy: 'same-origin' }
}));
app.use(express.json({ limit: '32kb', strict: true }));
app.use('/api', (_req, res, next) => {
  res.set('Cache-Control', 'no-store');
  next();
});

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 10,
  standardHeaders: 'draft-8',
  legacyHeaders: false,
  handler: (req, res) => {
    audit(req, { action: 'LOGIN', detail: 'Rate limit exceeded', outcome: 'denied' });
    res.status(429).json({ error: 'Too many sign-in attempts. Try again later.' });
  }
});

function cleanText(value, maxLength) {
  return typeof value === 'string' ? value.trim().replace(/[\u0000-\u001f\u007f]/g, '').slice(0, maxLength) : '';
}

function validDate(value) {
  return /^\d{4}-\d{2}-\d{2}$/.test(value) &&
    !Number.isNaN(Date.parse(`${value}T00:00:00.000Z`)) &&
    new Date(`${value}T00:00:00.000Z`).toISOString().slice(0, 10) === value;
}

function jsonError(res, status, message) {
  return res.status(status).json({ error: message });
}

function requireRole(...roles) {
  return (req, res, next) => {
    if (!roles.includes(req.user.role)) {
      audit(req, { action: `${req.method} ${req.path}`, detail: `Required role: ${roles.join(' or ')}`, outcome: 'denied' });
      return jsonError(res, 403, 'This action is not permitted for your role.');
    }
    next();
  };
}

function loadAuthorizedDocument(access = 'read') {
  return (req, res, next) => {
    const document = getDocument(req.params.id);
    const permitted = document && (access === 'owner'
      ? document.owner_id === req.user.id
      : access === 'edit' ? canEdit(req.user.id, document) : canRead(req.user.id, document));
    if (!permitted) {
      audit(req, { action: `${req.method} DOCUMENT_${access.toUpperCase()}`, documentId: req.params.id, outcome: 'denied' });
      return jsonError(res, 404, 'Document not found.');
    }
    req.document = document;
    next();
  };
}

const upload = multer({
  storage: multer.diskStorage({
    destination: (_req, _file, callback) => callback(null, uploadDir),
    filename: (_req, _file, callback) => callback(null, crypto.randomUUID())
  }),
  limits: { fileSize: MAX_FILE_BYTES, files: 1, fields: 4, fieldSize: 200 }
});

function parseUpload(req, res, next) {
  upload.single('file')(req, res, error => {
    if (error) {
      audit(req, { action: 'UPLOAD', detail: error.code === 'LIMIT_FILE_SIZE' ? 'File exceeds 10 MB limit' : 'Invalid upload request', outcome: 'denied' });
      return jsonError(res, error.code === 'LIMIT_FILE_SIZE' ? 413 : 400, error.code === 'LIMIT_FILE_SIZE' ? 'File exceeds the 10 MB limit.' : 'Invalid upload request.');
    }
    next();
  });
}

app.get('/api/health', (_req, res) => res.json({ status: 'ok' }));

app.post('/api/login', loginLimiter, (req, res, next) => {
  try {
    if (!req.is('application/json')) {
      audit(req, { action: 'LOGIN', detail: 'Credentials were not sent as JSON', outcome: 'denied' });
      return jsonError(res, 415, 'Send credentials as JSON.');
    }
    return login(req, res);
  } catch (error) {
    next(error);
  }
});

app.use('/api', authenticate);

app.get('/api/session', (req, res) => {
  let csrfToken = req.session.csrfToken;
  if (!csrfToken) {
    csrfToken = crypto.randomBytes(32).toString('base64url');
    db.prepare('UPDATE sessions SET csrf_hash = ?, csrf_token = ? WHERE token_hash = ?')
      .run(hash(csrfToken), csrfToken, req.session.tokenHash);
  }
  res.json({ user: req.user, csrfToken });
});

app.post('/api/logout', requireCsrf, (req, res, next) => {
  try {
    db.transaction(() => {
      audit(req, { action: 'LOGOUT', detail: 'Session ended' });
      db.prepare('DELETE FROM sessions WHERE token_hash = ?').run(req.session.tokenHash);
    })();
    clearSessionCookie(res);
    res.status(204).end();
  } catch (error) {
    next(error);
  }
});

app.get('/api/documents', (req, res, next) => {
  try {
    const name = cleanText(req.query.name, 120).toLowerCase();
    const owner = cleanText(req.query.owner, 120).toLowerCase();
    const category = cleanText(req.query.category, 40).toLowerCase();
    const from = cleanText(req.query.from, 10);
    const to = cleanText(req.query.to, 10);
    if ((from && !validDate(from)) || (to && !validDate(to))) {
      audit(req, { action: 'LIST_DOCUMENTS', detail: 'Invalid date filter', outcome: 'denied' });
      return jsonError(res, 400, 'Dates must use YYYY-MM-DD.');
    }
    const rows = visibleDocuments(req.user).filter(doc =>
      doc.name.toLowerCase().includes(name) &&
      doc.owner_email.toLowerCase().includes(owner) &&
      doc.category.toLowerCase().includes(category) &&
      (!from || doc.created_at.slice(0, 10) >= from) &&
      (!to || doc.created_at.slice(0, 10) <= to)
    );
    audit(req, { action: 'LIST_DOCUMENTS', detail: `Returned ${rows.length} accessible document(s)` });
    res.json({ documents: rows });
  } catch (error) {
    next(error);
  }
});

app.post('/api/documents', requireCsrf, (req, res, next) => {
  if (!['owner', 'admin'].includes(req.user.role)) {
    audit(req, { action: 'UPLOAD', detail: 'Only owners and admins can upload', outcome: 'denied' });
    return jsonError(res, 403, 'Only owners and admins can upload documents.');
  }
  next();
}, parseUpload, (req, res, next) => {
  try {
    if (!req.file) {
      audit(req, { action: 'UPLOAD', detail: 'No file provided', outcome: 'denied' });
      return jsonError(res, 400, 'Choose a file to upload.');
    }
    const ext = path.extname(req.file.originalname).toLowerCase();
    const type = allowedTypes[ext];
    const fileName = path.basename(req.file.originalname).replace(/[\u0000-\u001f\u007f]/g, '').trim().slice(0, 150);
    const category = cleanText(req.body.category || 'Other', 40);
    const prefix = fs.readFileSync(req.file.path).subarray(0, 8);
    if (!type || !fileName || fileName.startsWith('.') || !type.signature(prefix) ||
        !['Work', 'Legal', 'Finance', 'Other'].includes(category)) {
      fs.unlinkSync(req.file.path);
      audit(req, { action: 'UPLOAD', detail: 'Unsupported type, invalid file signature, filename, or category', outcome: 'denied' });
      return jsonError(res, 400, 'Use a valid PDF, DOCX, TXT, PNG, or JPEG file and a supported category.');
    }
    const id = crypto.randomUUID();
    const now = new Date().toISOString();
    db.transaction(() => {
      db.prepare(`
        INSERT INTO documents (id, owner_id, name, category, mime_type, size, storage_name, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
      `).run(id, req.user.id, fileName, category, type.mime, req.file.size, req.file.filename, now, now);
      audit(req, { action: 'UPLOAD', documentId: id, detail: fileName });
    })();
    res.status(201).json({ document: { id, name: fileName, category, mimeType: type.mime, size: req.file.size, createdAt: now } });
  } catch (error) {
    if (req.file && fs.existsSync(req.file.path)) fs.unlinkSync(req.file.path);
    next(error);
  }
});

app.get('/api/documents/:id', loadAuthorizedDocument(), (req, res, next) => {
  try {
    const doc = req.document;
    audit(req, { action: 'READ_DOCUMENT', documentId: doc.id, detail: doc.name });
    res.json({ document: {
      id: doc.id, name: doc.name, category: doc.category, mimeType: doc.mime_type,
      size: doc.size, ownerId: doc.owner_id, createdAt: doc.created_at, updatedAt: doc.updated_at
    } });
  } catch (error) {
    next(error);
  }
});

app.get('/api/documents/:id/download', loadAuthorizedDocument(), (req, res, next) => {
  try {
    const filePath = path.join(uploadDir, req.document.storage_name);
    if (!fs.existsSync(filePath)) {
      audit(req, { action: 'DOWNLOAD', documentId: req.document.id, detail: 'Stored file missing', outcome: 'failure' });
      return jsonError(res, 410, 'The stored file is unavailable.');
    }
    audit(req, { action: 'DOWNLOAD', documentId: req.document.id, detail: req.document.name });
    res.download(filePath, req.document.name, error => {
      if (error) {
        try {
          audit(req, { action: 'DOWNLOAD', documentId: req.document.id, detail: 'File transfer failed', outcome: 'failure' });
        } catch (auditError) {
          return next(auditError);
        }
      }
      if (error && !res.headersSent) next(error);
    });
  } catch (error) {
    next(error);
  }
});

app.put('/api/documents/:id/file', requireCsrf, loadAuthorizedDocument('edit'), parseUpload, (req, res, next) => {
  let replacementCommitted = false;
  try {
    if (!req.file) {
      audit(req, { action: 'EDIT_FILE', documentId: req.document.id, detail: 'No replacement file provided', outcome: 'denied' });
      return jsonError(res, 400, 'Choose a replacement file.');
    }
    const ext = path.extname(req.file.originalname).toLowerCase();
    const type = allowedTypes[ext];
    const fileName = path.basename(req.file.originalname).replace(/[\u0000-\u001f\u007f]/g, '').trim().slice(0, 150);
    const prefix = fs.readFileSync(req.file.path).subarray(0, 8);
    if (!type || !fileName || fileName.startsWith('.') || !type.signature(prefix)) {
      fs.unlinkSync(req.file.path);
      audit(req, { action: 'EDIT_FILE', documentId: req.document.id, detail: 'Unsupported type, invalid file signature, or filename', outcome: 'denied' });
      return jsonError(res, 400, 'Use a valid PDF, DOCX, TXT, PNG, or JPEG file.');
    }

    const previousPath = path.join(uploadDir, req.document.storage_name);
    const now = new Date().toISOString();
    db.transaction(() => {
      db.prepare(`
        UPDATE documents SET name = ?, mime_type = ?, size = ?, storage_name = ?, updated_at = ?
        WHERE id = ?
      `).run(fileName, type.mime, req.file.size, req.file.filename, now, req.document.id);
      audit(req, { action: 'EDIT_FILE', documentId: req.document.id, detail: `Replaced file with ${fileName}` });
    })();
    replacementCommitted = true;

    try {
      if (fs.existsSync(previousPath)) fs.unlinkSync(previousPath);
    } catch (error) {
      audit(req, { action: 'EDIT_FILE_CLEANUP', documentId: req.document.id, detail: 'Previous private file could not be removed', outcome: 'failure' });
      console.error(error);
      return jsonError(res, 500, 'The replacement is active, but the previous private copy could not be removed.');
    }
    res.json({ document: { id: req.document.id, name: fileName, mimeType: type.mime, size: req.file.size, updatedAt: now } });
  } catch (error) {
    if (!replacementCommitted && req.file && fs.existsSync(req.file.path)) fs.unlinkSync(req.file.path);
    next(error);
  }
});

app.patch('/api/documents/:id', requireCsrf, loadAuthorizedDocument('edit'), (req, res, next) => {
  try {
    const name = req.body.name === undefined ? req.document.name : cleanText(req.body.name, 150);
    const category = req.body.category === undefined ? req.document.category : cleanText(req.body.category, 40);
    if (!name || name.startsWith('.') || !['Work', 'Legal', 'Finance', 'Other'].includes(category)) {
      audit(req, { action: 'EDIT', documentId: req.document.id, detail: 'Invalid metadata', outcome: 'denied' });
      return jsonError(res, 400, 'Provide a valid filename and supported category.');
    }
    const now = new Date().toISOString();
    db.transaction(() => {
      db.prepare('UPDATE documents SET name = ?, category = ?, updated_at = ? WHERE id = ?')
        .run(name, category, now, req.document.id);
      audit(req, { action: 'EDIT', documentId: req.document.id, detail: `Updated metadata for ${name}` });
    })();
    res.json({ document: { id: req.document.id, name, category, updatedAt: now } });
  } catch (error) {
    next(error);
  }
});

app.delete('/api/documents/:id', requireCsrf, loadAuthorizedDocument('owner'), (req, res, next) => {
  try {
    const now = new Date().toISOString();
    db.transaction(() => {
      db.prepare('UPDATE documents SET deleted_at = ?, updated_at = ? WHERE id = ?')
        .run(now, now, req.document.id);
      audit(req, { action: 'DELETE', documentId: req.document.id, detail: req.document.name });
    })();
    const storedPath = path.join(uploadDir, req.document.storage_name);
    if (fs.existsSync(storedPath)) fs.unlinkSync(storedPath);
    res.status(204).end();
  } catch (error) {
    next(error);
  }
});

app.get('/api/documents/:id/permissions', loadAuthorizedDocument('owner'), (req, res, next) => {
  try {
    audit(req, { action: 'VIEW_PERMISSIONS', documentId: req.document.id });
    const permissions = db.prepare(`
      SELECT p.user_id AS userId, u.email, u.name, p.level, p.granted_at AS grantedAt
      FROM permissions p JOIN users u ON u.id = p.user_id
      WHERE p.document_id = ? ORDER BY u.email
    `).all(req.document.id);
    res.json({ permissions });
  } catch (error) {
    next(error);
  }
});

app.get('/api/users', requireRole('owner', 'admin'), (req, res, next) => {
  try {
    audit(req, { action: 'LIST_SHARE_TARGETS' });
    res.json({ users: db.prepare('SELECT id, email, name, role FROM users WHERE id != ? ORDER BY email').all(req.user.id) });
  } catch (error) {
    next(error);
  }
});

app.put('/api/documents/:id/permissions/:userId', requireCsrf, loadAuthorizedDocument('owner'), (req, res, next) => {
  try {
    const target = db.prepare('SELECT id FROM users WHERE id = ?').get(req.params.userId);
    const level = req.body.level;
    if (!target || target.id === req.user.id || !['read', 'edit'].includes(level)) {
      audit(req, { action: 'GRANT_PERMISSION', documentId: req.document.id, detail: 'Invalid user or permission level', outcome: 'denied' });
      return jsonError(res, 400, 'Choose another named user and the read or edit permission.');
    }
    const now = new Date().toISOString();
    db.transaction(() => {
      db.prepare(`
        INSERT INTO permissions (document_id, user_id, level, granted_by, granted_at)
        VALUES (?, ?, ?, ?, ?)
        ON CONFLICT(document_id, user_id) DO UPDATE SET level = excluded.level, granted_by = excluded.granted_by, granted_at = excluded.granted_at
      `).run(req.document.id, target.id, level, req.user.id, now);
      audit(req, { action: 'GRANT_PERMISSION', documentId: req.document.id, detail: `Granted ${level} permission to ${target.id}` });
    })();
    res.status(204).end();
  } catch (error) {
    next(error);
  }
});

app.delete('/api/documents/:id/permissions/:userId', requireCsrf, loadAuthorizedDocument('owner'), (req, res, next) => {
  try {
    db.transaction(() => {
      db.prepare('DELETE FROM permissions WHERE document_id = ? AND user_id = ?').run(req.document.id, req.params.userId);
      audit(req, { action: 'REVOKE_PERMISSION', documentId: req.document.id, detail: `Revoked permission for ${req.params.userId}` });
    })();
    res.status(204).end();
  } catch (error) {
    next(error);
  }
});

app.get('/api/admin/audit', requireRole('admin'), (req, res, next) => {
  try {
    const limit = Math.min(Math.max(Number.parseInt(req.query.limit, 10) || 100, 1), 500);
    const before = Number.parseInt(req.query.before, 10);
    audit(req, { action: 'VIEW_AUDIT', detail: `Requested up to ${limit} events` });
    const rows = Number.isSafeInteger(before) && before > 0
      ? db.prepare('SELECT sequence, id, occurred_at AS occurredAt, actor_email AS actorEmail, action, document_id AS documentId, detail, outcome, ip_address AS ipAddress, previous_hash AS previousHash, event_hash AS eventHash FROM audit_events WHERE sequence < ? ORDER BY sequence DESC LIMIT ?').all(before, limit)
      : db.prepare('SELECT sequence, id, occurred_at AS occurredAt, actor_email AS actorEmail, action, document_id AS documentId, detail, outcome, ip_address AS ipAddress, previous_hash AS previousHash, event_hash AS eventHash FROM audit_events ORDER BY sequence DESC LIMIT ?').all(limit);
    res.json({ events: rows });
  } catch (error) {
    next(error);
  }
});

app.use('/api', (req, res) => {
  audit(req, {
    action: 'API_NOT_FOUND',
    documentId: req.path.match(/^\/documents\/([^/]+)/)?.[1] || null,
    detail: req.path,
    outcome: 'denied'
  });
  jsonError(res, 404, 'Not found.');
});

app.use(express.static(path.join(__dirname, 'public'), {
  dotfiles: 'deny',
  index: 'index.html',
  fallthrough: true,
  maxAge: process.env.NODE_ENV === 'production' ? '1h' : 0
}));

app.use((req, res) => jsonError(res, 404, 'Not found.'));

app.use((error, req, res, _next) => {
  if (req.file && fs.existsSync(req.file.path)) fs.unlinkSync(req.file.path);
  if ([400, 413].includes(error.status)) {
    console.warn(`Rejected request: ${req.method} ${req.path} (${error.status}).`);
  } else {
    console.error(error);
  }
  if (req.path.startsWith('/api/') && [400, 413].includes(error.status)) {
    try {
      audit(req, {
        action: 'REQUEST_REJECTED',
        documentId: req.path.match(/^\/api\/documents\/([^/]+)/)?.[1] || null,
        detail: error.status === 413 ? 'Request body exceeded the allowed size' : 'Malformed request body',
        outcome: 'denied'
      });
    } catch (auditError) {
      console.error(auditError);
      if (!res.headersSent) return res.status(500).json({ error: 'Request could not be securely recorded.' });
    }
  }
  if (res.headersSent) return _next(error);
  const status = error.status === 400 ? 400 : 500;
  res.status(status).json({ error: status === 400 ? 'Invalid request.' : 'An unexpected server error occurred.' });
});

function seedUsers(accounts) {
  const insert = db.prepare(`
    INSERT INTO users (id, email, name, role, password_hash, created_at)
    VALUES (@id, @email, @name, @role, @passwordHash, @createdAt)
    ON CONFLICT(email) DO UPDATE SET name = excluded.name, role = excluded.role, password_hash = excluded.password_hash
  `);
  const seed = db.transaction((rows) => rows.forEach(account => insert.run({
    ...account,
    email: account.email.toLowerCase(),
    passwordHash: passwordHash(account.password),
    createdAt: new Date().toISOString()
  })));
  seed(accounts);
}

verifyAuditChain();

if (require.main === module) {
  const port = Number(process.env.PORT || 3000);
  app.listen(port, () => console.log(`TrustVault listening on http://localhost:${port}`));
}

module.exports = Object.assign(app, {
  app,
  db,
  seedUsers,
  verifyAuditChain,
  hash,
  dataDir
});
