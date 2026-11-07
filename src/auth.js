const crypto = require('node:crypto');
const { db } = require('./db');
const { audit } = require('./audit');

const SESSION_COOKIE = 'trustvault_session';
const sessionTtlHours = Number(process.env.SESSION_TTL_HOURS || 8);
if (!Number.isFinite(sessionTtlHours) || sessionTtlHours < 1 || sessionTtlHours > 168) {
  throw new Error('SESSION_TTL_HOURS must be between 1 and 168.');
}

function hash(value) {
  return crypto.createHash('sha256').update(value).digest('hex');
}

function passwordHash(password, salt = crypto.randomBytes(16).toString('hex')) {
  return `${salt}:${crypto.scryptSync(password, salt, 64).toString('hex')}`;
}

function verifyPassword(password, storedHash) {
  const [salt, expectedHex] = storedHash.split(':');
  const expected = Buffer.from(expectedHex || '', 'hex');
  const actual = crypto.scryptSync(password, salt || '', 64);
  return expected.length === actual.length && crypto.timingSafeEqual(expected, actual);
}

function setSessionCookie(res, token) {
  const secure = process.env.NODE_ENV === 'production' ? '; Secure' : '';
  res.setHeader('Set-Cookie', `${SESSION_COOKIE}=${token}; HttpOnly; Path=/; SameSite=Strict; Max-Age=${sessionTtlHours * 3600}${secure}`);
}

function clearSessionCookie(res) {
  const secure = process.env.NODE_ENV === 'production' ? '; Secure' : '';
  res.setHeader('Set-Cookie', `${SESSION_COOKIE}=; HttpOnly; Path=/; SameSite=Strict; Max-Age=0${secure}`);
}

function authenticate(req, res, next) {
  const recordUnauthenticatedAttempt = () => {
    try {
      const documentId = req.path.match(/^\/documents\/([^/]+)/)?.[1] || null;
      audit(req, {
        action: `${req.method} UNAUTHENTICATED_ACCESS`,
        documentId,
        detail: req.path,
        outcome: 'denied'
      });
    } catch (error) {
      next(error);
      return false;
    }
    return true;
  };
  const token = (req.headers.cookie || '').split(';').map(part => part.trim()).find(part => part.startsWith(`${SESSION_COOKIE}=`))?.slice(SESSION_COOKIE.length + 1);
  if (!token) {
    if (!recordUnauthenticatedAttempt()) return;
    return res.status(401).json({ error: 'Authentication required.' });
  }
  const row = db.prepare(`
    SELECT s.token_hash, s.csrf_hash, s.csrf_token, s.expires_at, u.id, u.email, u.name, u.role
    FROM sessions s JOIN users u ON u.id = s.user_id
    WHERE s.token_hash = ?
  `).get(hash(token));
  if (!row || row.expires_at <= new Date().toISOString()) {
    if (row) db.prepare('DELETE FROM sessions WHERE token_hash = ?').run(row.token_hash);
    clearSessionCookie(res);
    if (!recordUnauthenticatedAttempt()) return;
    return res.status(401).json({ error: 'Session expired. Please sign in again.' });
  }
  req.user = { id: row.id, email: row.email, name: row.name, role: row.role };
  req.session = { tokenHash: row.token_hash, csrfHash: row.csrf_hash, csrfToken: row.csrf_token };
  next();
}

function requireCsrf(req, res, next) {
  const token = req.get('x-csrf-token') || '';
  const actual = Buffer.from(hash(token));
  const expected = Buffer.from(req.session.csrfHash);
  if (actual.length !== expected.length || !crypto.timingSafeEqual(actual, expected)) {
    audit(req, {
      action: `${req.method} CSRF_REJECTED`,
      documentId: req.path.match(/^\/documents\/([^/]+)/)?.[1] || null,
      detail: req.path,
      outcome: 'denied'
    });
    return res.status(403).json({ error: 'Invalid CSRF token.' });
  }
  next();
}

function login(req, res) {
  const email = typeof req.body.email === 'string' ? req.body.email.trim().toLowerCase() : '';
  const password = typeof req.body.password === 'string' ? req.body.password : '';
  const user = db.prepare('SELECT id, email, name, role, password_hash FROM users WHERE email = ? COLLATE NOCASE').get(email);
  const valid = user ? verifyPassword(password, user.password_hash) : verifyPassword(password, passwordHash('invalid-account'));
  if (!user || !valid) {
    audit(req, { actor: user, action: 'LOGIN', detail: email || 'missing email', outcome: 'denied' });
    return res.status(401).json({ error: 'Invalid email or password.' });
  }
  const token = crypto.randomBytes(32).toString('base64url');
  const csrfToken = crypto.randomBytes(32).toString('base64url');
  const now = new Date();
  const expiresAt = new Date(now.getTime() + sessionTtlHours * 3600_000).toISOString();
  db.prepare('INSERT INTO sessions (token_hash, user_id, csrf_hash, csrf_token, expires_at, created_at) VALUES (?, ?, ?, ?, ?, ?)')
    .run(hash(token), user.id, hash(csrfToken), csrfToken, expiresAt, now.toISOString());
  setSessionCookie(res, token);
  audit(req, { actor: user, action: 'LOGIN', detail: 'Session created', outcome: 'success' });
  return res.json({ user: { id: user.id, email: user.email, name: user.name, role: user.role }, csrfToken });
}

module.exports = { authenticate, requireCsrf, login, hash, passwordHash, verifyPassword, setSessionCookie, clearSessionCookie };
