const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { after, before, test } = require('node:test');
const supertest = require('supertest');

const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'trustvault-test-'));
process.env.TRUSTVAULT_DATA_DIR = tempDir;
process.env.NODE_ENV = 'test';

const { app, db, seedUsers, verifyAuditChain } = require('../server');
const api = {
  owner: supertest.agent(app),
  viewer: supertest.agent(app),
  admin: supertest.agent(app)
};
const unauthenticated = supertest(app);
const users = {
  owner: { email: 'owner@example.test', password: 'owner-test-password' },
  viewer: { email: 'viewer@example.test', password: 'viewer-test-password' },
  admin: { email: 'admin@example.test', password: 'admin-test-password' }
};
const csrf = {};
let documentId;
let adminDocumentId;

before(() => {
  seedUsers([
    { id: 'test-owner', ...users.owner, name: 'Owner', role: 'owner' },
    { id: 'test-viewer', ...users.viewer, name: 'Viewer', role: 'viewer' },
    { id: 'test-admin', ...users.admin, name: 'Admin', role: 'admin' }
  ]);
});

after(() => {
  db.close();
  fs.rmSync(tempDir, { recursive: true, force: true });
});

async function signIn(role) {
  const response = await api[role].post('/api/login').send(users[role]).expect(200);
  assert.equal(response.headers['cache-control'], 'no-store');
  csrf[role] = response.body.csrfToken;
}

function grantPath(userId) {
  return `/api/documents/${documentId}/permissions/${userId}`;
}

test('authorization, document workflow, immediate revocation, and verifiable audit', async () => {
  await unauthenticated.get('/api/documents/not-a-real-document').expect(401);
  await signIn('owner');
  await signIn('viewer');
  await signIn('admin');
  await api.owner.get('/api/session').expect(200).expect('Cache-Control', 'no-store');

  const adminUpload = await api.admin.post('/api/documents').set('x-csrf-token', csrf.admin)
    .field('category', 'Work')
    .attach('file', Buffer.from('%PDF-1.7\nAdmin-owned test fixture'), 'admin-private.pdf', { contentType: 'application/pdf' })
    .expect(201);
  adminDocumentId = adminUpload.body.document.id;
  await api.owner.get(`/api/documents/${adminDocumentId}`).expect(404);
  await api.admin.put(`/api/documents/${adminDocumentId}/permissions/test-viewer`).set('x-csrf-token', csrf.admin)
    .send({ level: 'read' }).expect(204);
  await api.viewer.get(`/api/documents/${adminDocumentId}`).expect(200);
  await api.admin.delete(`/api/documents/${adminDocumentId}/permissions/test-viewer`).set('x-csrf-token', csrf.admin)
    .expect(204);
  await api.viewer.get(`/api/documents/${adminDocumentId}`).expect(404);

  await api.viewer.post('/api/documents').set('x-csrf-token', csrf.viewer)
    .attach('file', Buffer.from('%PDF-1.7\nnot allowed'), 'viewer.pdf').expect(403);
  await api.owner.post('/api/documents').set('x-csrf-token', csrf.owner)
    .attach('file', Buffer.from('not a PDF'), 'invalid.pdf').expect(400);
  await api.owner.post('/api/documents').set('x-csrf-token', csrf.owner)
    .attach('file', Buffer.alloc(10 * 1024 * 1024 + 1, 65), 'oversized.txt').expect(413);

  const created = await api.owner.post('/api/documents').set('x-csrf-token', csrf.owner)
    .field('category', 'Legal')
    .attach('file', Buffer.from('%PDF-1.7\nTrustVault test fixture'), 'contract.pdf', { contentType: 'application/pdf' })
    .expect(201);
  documentId = created.body.document.id;
  assert.ok(documentId);

  await api.viewer.get(`/api/documents/${documentId}`).expect(404);
  await api.viewer.get(`/api/documents/${documentId}/download`).expect(404);
  await api.viewer.patch(`/api/documents/${documentId}`).set('x-csrf-token', csrf.viewer)
    .send({ name: 'stolen.pdf' }).expect(404);
  await api.viewer.delete(`/api/documents/${documentId}`).set('x-csrf-token', csrf.viewer).expect(404);
  await api.viewer.get(`/api/documents/${documentId}/permissions`).expect(404);
  await api.viewer.put(grantPath('test-admin')).set('x-csrf-token', csrf.viewer)
    .send({ level: 'read' }).expect(404);
  await api.viewer.get('/api/documents').expect(200).expect(response => {
    assert.equal(response.body.documents.some(doc => doc.id === documentId), false);
  });
  await api.admin.get(`/api/documents/${documentId}`).expect(404);
  await api.admin.get('/api/admin/audit').expect(200);

  await api.owner.put(grantPath('test-viewer')).set('x-csrf-token', csrf.owner)
    .send({ level: 'read' }).expect(204);
  await api.viewer.get(`/api/documents/${documentId}`).expect(200);
  await api.viewer.get(`/api/documents/${documentId}/download`).expect(200);
  await api.viewer.put(`/api/documents/${documentId}/file`).set('x-csrf-token', csrf.viewer)
    .attach('file', Buffer.from('%PDF-1.7\nread-only replacement'), 'read-only.pdf').expect(404);
  await api.viewer.patch(`/api/documents/${documentId}`).set('x-csrf-token', csrf.viewer)
    .send({ name: 'forbidden.pdf' }).expect(404);
  await api.viewer.delete(`/api/documents/${documentId}`).set('x-csrf-token', csrf.viewer).expect(404);

  await api.owner.delete(grantPath('test-viewer')).set('x-csrf-token', csrf.owner).expect(204);
  await api.viewer.get(`/api/documents/${documentId}`).expect(404);
  await api.viewer.get(`/api/documents/${documentId}/download`).expect(404);

  await api.owner.put(grantPath('test-viewer')).set('x-csrf-token', csrf.owner)
    .send({ level: 'edit' }).expect(204);
  await api.viewer.patch(`/api/documents/${documentId}`).set('x-csrf-token', csrf.viewer)
    .send({ name: 'renamed.pdf', category: 'Work' }).expect(200);
  const replacementBytes = Buffer.from('%PDF-1.7\nreplacement content');
  await api.viewer.put(`/api/documents/${documentId}/file`).set('x-csrf-token', csrf.viewer)
    .attach('file', replacementBytes, 'renamed.pdf').expect(200);
  const download = await api.viewer.get(`/api/documents/${documentId}/download`)
    .buffer(true)
    .parse((response, callback) => {
      const chunks = [];
      response.on('data', chunk => chunks.push(chunk));
      response.on('end', () => callback(null, Buffer.concat(chunks)));
    })
    .expect(200);
  assert.equal(download.body.toString(), replacementBytes.toString());
  await api.viewer.delete(`/api/documents/${documentId}`).set('x-csrf-token', csrf.viewer).expect(404);

  const filtered = await api.owner.get('/api/documents?name=renamed&owner=owner%40example.test&category=work').expect(200);
  assert.equal(filtered.body.documents.length, 1);
  await api.owner.get('/api/documents?from=invalid').expect(400);
  await api.owner.get('/api/documents?from=2026-99-99').expect(400);
  await api.owner.get('/api/documents').set('x-csrf-token', 'wrong').expect(200);
  await api.owner.get('/api/admin/audit').expect(403);
  await api.viewer.get('/api/unknown-route').expect(404);

  const audit = await api.admin.get('/api/admin/audit?limit=500').expect(200);
  const actions = audit.body.events.map(event => event.action);
  for (const action of ['UPLOAD', 'DOWNLOAD', 'READ_DOCUMENT', 'GRANT_PERMISSION', 'REVOKE_PERMISSION', 'EDIT', 'EDIT_FILE', 'LOGIN']) {
    assert.ok(actions.includes(action), `audit should contain ${action}`);
  }
  assert.ok(audit.body.events.some(event => event.outcome === 'denied'));
  assert.ok(audit.body.events.every(event => /^[a-f0-9]{64}$/.test(event.eventHash)));
  assert.equal(verifyAuditChain(), true);
  assert.throws(() => db.prepare('UPDATE audit_events SET detail = ? WHERE sequence = 1').run('tampered'));

  await api.owner.delete(`/api/documents/${documentId}`).set('x-csrf-token', csrf.owner).expect(204);
  await api.owner.get(`/api/documents/${documentId}`).expect(404);
  await api.admin.delete(`/api/documents/${adminDocumentId}`).set('x-csrf-token', csrf.admin).expect(204);
  assert.equal(verifyAuditChain(), true);
});

test('mutating API requests reject missing CSRF tokens and audit the denial', async () => {
  await api.viewer.post('/api/logout').expect(403);
  const event = db.prepare("SELECT action, outcome FROM audit_events WHERE action = 'POST CSRF_REJECTED' ORDER BY sequence DESC LIMIT 1").get();
  assert.deepEqual(event, { action: 'POST CSRF_REJECTED', outcome: 'denied' });

  await unauthenticated.post('/api/login')
    .set('content-type', 'application/json')
    .send('{')
    .expect(400);
  const malformedEvent = db.prepare("SELECT action, outcome FROM audit_events WHERE action = 'REQUEST_REJECTED' ORDER BY sequence DESC LIMIT 1").get();
  assert.deepEqual(malformedEvent, { action: 'REQUEST_REJECTED', outcome: 'denied' });

  const unknownEvent = db.prepare("SELECT action, outcome FROM audit_events WHERE action = 'API_NOT_FOUND' ORDER BY sequence DESC LIMIT 1").get();
  assert.deepEqual(unknownEvent, { action: 'API_NOT_FOUND', outcome: 'denied' });
});
