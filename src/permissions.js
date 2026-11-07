const { db } = require('./db');

function getDocument(documentId) {
  return db.prepare('SELECT * FROM documents WHERE id = ? AND deleted_at IS NULL').get(documentId);
}

function permissionLevel(userId, document) {
  if (!document) return null;
  if (document.owner_id === userId) return 'owner';
  return db.prepare('SELECT level FROM permissions WHERE document_id = ? AND user_id = ?')
    .get(document.id, userId)?.level || null;
}

function canRead(userId, document) {
  return permissionLevel(userId, document) !== null;
}

function canEdit(userId, document) {
  const level = permissionLevel(userId, document);
  return level === 'owner' || level === 'edit';
}

function visibleDocuments(user) {
  return db.prepare(`
    SELECT DISTINCT d.id, d.owner_id, owner.email AS owner_email, d.name, d.category, d.mime_type,
      d.size, d.created_at, d.updated_at,
      CASE WHEN d.owner_id = ? THEN 'owner' ELSE p.level END AS access_level
    FROM documents d
    JOIN users owner ON owner.id = d.owner_id
    LEFT JOIN permissions p ON p.document_id = d.id AND p.user_id = ?
    WHERE d.deleted_at IS NULL AND (d.owner_id = ? OR p.user_id = ?)
  `).all(user.id, user.id, user.id, user.id);
}

module.exports = { getDocument, permissionLevel, canRead, canEdit, visibleDocuments };
