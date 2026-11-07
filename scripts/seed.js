require('dotenv').config();
const { seedUsers } = require('../server');

const developmentPassword = process.env.NODE_ENV === 'production' ? '' : 'ChangeMe123!';
const accounts = [
  { id: 'admin', email: process.env.ADMIN_EMAIL || 'admin@trustvault.com', name: 'TrustVault Admin', role: 'admin', password: process.env.ADMIN_PASSWORD || developmentPassword },
  { id: 'owner', email: process.env.OWNER_EMAIL || 'owner@trustvault.com', name: 'Document Owner', role: 'owner', password: process.env.OWNER_PASSWORD || developmentPassword },
  { id: 'viewer', email: process.env.VIEWER_EMAIL || 'viewer@trustvault.com', name: 'Document Viewer', role: 'viewer', password: process.env.VIEWER_PASSWORD || developmentPassword }
];
if (accounts.some(account => account.password.length < 12)) {
  throw new Error('Set a unique password of at least 12 characters for every seeded account.');
}
seedUsers(accounts);
console.log(`Seeded ${accounts.length} TrustVault accounts. Change development passwords before any public deployment.`);
