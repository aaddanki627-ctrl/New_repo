const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const { dataDir, db } = require('./db');

function loadAuditKey() {
  const configured = process.env.AUDIT_HMAC_KEY;
  if (configured) {
    if (!/^(?:[a-f0-9]{2}){32,}$/i.test(configured)) {
      throw new Error('AUDIT_HMAC_KEY must contain at least 64 hexadecimal characters.');
    }
    const key = Buffer.from(configured, 'hex');
    if (key.length < 32) throw new Error('AUDIT_HMAC_KEY must be at least 64 hexadecimal characters.');
    return key;
  }
  if (process.env.NODE_ENV === 'production') {
    throw new Error('AUDIT_HMAC_KEY is required in production.');
  }
  const keyPath = path.join(dataDir, 'audit.key');
  if (!fs.existsSync(keyPath)) {
    fs.writeFileSync(keyPath, crypto.randomBytes(32), { mode: 0o600, flag: 'wx' });
  }
  return fs.readFileSync(keyPath);
}

const auditKey = loadAuditKey();

function hashEvent(event, previousHash) {
  const payload = JSON.stringify({
    id: event.id,
    occurredAt: event.occurredAt,
    actorId: event.actorId,
    actorEmail: event.actorEmail,
    action: event.action,
    documentId: event.documentId,
    detail: event.detail,
    outcome: event.outcome,
    ipAddress: event.ipAddress,
    previousHash
  });
  return crypto.createHmac('sha256', auditKey).update(payload).digest('hex');
}

const insertEvent = db.prepare(`
  INSERT INTO audit_events
    (id, occurred_at, actor_id, actor_email, action, document_id, detail, outcome, ip_address, previous_hash, event_hash)
  VALUES
    (@id, @occurredAt, @actorId, @actorEmail, @action, @documentId, @detail, @outcome, @ipAddress, @previousHash, @eventHash)
`);
const lastEvent = db.prepare('SELECT event_hash FROM audit_events ORDER BY sequence DESC LIMIT 1');
const appendTransaction = db.transaction((event) => {
  const previousHash = lastEvent.get()?.event_hash || 'GENESIS';
  const eventHash = hashEvent(event, previousHash);
  insertEvent.run({ ...event, previousHash, eventHash });
});

function audit(req, { actor = req.user, action, documentId = null, detail = '', outcome = 'success' }) {
  const event = {
    id: crypto.randomUUID(),
    occurredAt: new Date().toISOString(),
    actorId: actor?.id || null,
    actorEmail: actor?.email || 'anonymous',
    action,
    documentId,
    detail: String(detail).slice(0, 500),
    outcome,
    ipAddress: req.ip || req.socket.remoteAddress || 'unknown'
  };
  appendTransaction(event);
  return event;
}

function verifyAuditChain() {
  let previousHash = 'GENESIS';
  const rows = db.prepare('SELECT id, occurred_at, actor_id, actor_email, action, document_id, detail, outcome, ip_address, previous_hash, event_hash FROM audit_events ORDER BY sequence').all();
  for (const row of rows) {
    const event = {
      id: row.id,
      occurredAt: row.occurred_at,
      actorId: row.actor_id,
      actorEmail: row.actor_email,
      action: row.action,
      documentId: row.document_id,
      detail: row.detail,
      outcome: row.outcome,
      ipAddress: row.ip_address
    };
    const expected = hashEvent(event, previousHash);
    const actualHash = Buffer.from(row.event_hash, 'hex');
    const expectedHash = Buffer.from(expected, 'hex');
    if (row.previous_hash !== previousHash || actualHash.length !== expectedHash.length ||
        !crypto.timingSafeEqual(actualHash, expectedHash)) {
      throw new Error(`Audit chain integrity check failed at event ${row.id}.`);
    }
    previousHash = row.event_hash;
  }
  return true;
}

module.exports = { audit, verifyAuditChain };
