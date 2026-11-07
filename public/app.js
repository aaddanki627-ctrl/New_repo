const state = { user: null, csrfToken: '', documents: [], activeDocument: null };
const byId = id => document.getElementById(id);

async function request(url, options = {}) {
  const headers = new Headers(options.headers || {});
  if (state.csrfToken && options.method && !['GET', 'HEAD'].includes(options.method)) {
    headers.set('x-csrf-token', state.csrfToken);
  }
  const response = await fetch(url, { ...options, headers, credentials: 'same-origin' });
  if (response.status === 204) return null;
  const body = await response.json().catch(() => ({}));
  if (!response.ok) {
    const error = new Error(body.error || `Request failed (${response.status}).`);
    error.status = response.status;
    throw error;
  }
  return body;
}

function showNotice(message, isError = false) {
  const notice = byId('notice');
  notice.textContent = message;
  notice.classList.toggle('error', isError);
}

function setSignedIn(user) {
  state.user = user;
  byId('loginView').classList.add('hidden');
  byId('appView').classList.remove('hidden');
  byId('userBadge').textContent = `${user.name} · ${user.role}`;
  const canUpload = user.role === 'owner' || user.role === 'admin';
  byId('uploadForm').classList.toggle('hidden', !canUpload);
  byId('activityNav').classList.toggle('hidden', user.role !== 'admin');
  loadDocuments();
}

function makeButton(label, className, handler) {
  const button = document.createElement('button');
  button.type = 'button';
  button.textContent = label;
  button.className = className;
  button.addEventListener('click', handler);
  return button;
}

function renderDocuments(documents) {
  const grid = byId('fileGrid');
  grid.replaceChildren();
  byId('emptyState').classList.toggle('hidden', documents.length > 0);
  for (const doc of documents) {
    const card = document.createElement('article');
    card.className = 'card';
    const tag = document.createElement('span');
    tag.className = 'owner-tag';
    tag.textContent = doc.access_level === 'owner' ? 'Owner' : `${doc.access_level} access`;
    const title = document.createElement('h2');
    title.textContent = doc.name;
    const meta = document.createElement('div');
    meta.className = 'card-meta';
    const details = [
      `Owner: ${doc.owner_email}`,
      `Category: ${doc.category}`,
      `Size: ${(doc.size / 1024 / 1024).toFixed(2)} MB`,
      `Created: ${new Date(doc.created_at).toLocaleString()}`
    ];
    for (const detail of details) {
      const line = document.createElement('span');
      line.textContent = detail;
      meta.append(line);
    }
    const actions = document.createElement('div');
    actions.className = 'card-actions';
    actions.append(makeButton('Download', '', () => downloadDocument(doc)));
    if (doc.access_level === 'owner' || doc.access_level === 'edit') {
      actions.append(makeButton('Edit details', 'secondary', () => openEditDialog(doc)));
      actions.append(makeButton('Replace file', 'secondary', () => chooseReplacementFile(doc)));
    }
    if (doc.access_level === 'owner') {
      actions.append(makeButton('Manage access', 'secondary', () => openPermissionDialog(doc)));
      actions.append(makeButton('Delete', 'secondary', () => deleteDocument(doc)));
    }
    card.append(tag, title, meta, actions);
    grid.append(card);
  }
}

async function loadDocuments(params = new URLSearchParams()) {
  try {
    const result = await request(`/api/documents?${params}`);
    state.documents = result.documents;
    renderDocuments(result.documents);
  } catch (error) {
    showNotice(error.message, true);
  }
}

async function downloadDocument(doc) {
  try {
    const response = await fetch(`/api/documents/${encodeURIComponent(doc.id)}/download`, { credentials: 'same-origin' });
    if (!response.ok) {
      const body = await response.json().catch(() => ({}));
      throw new Error(body.error || `Download failed (${response.status}).`);
    }
    const blob = await response.blob();
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement('a');
    anchor.href = url;
    anchor.download = doc.name;
    document.body.append(anchor);
    anchor.click();
    anchor.remove();
    window.setTimeout(() => URL.revokeObjectURL(url), 1000);
    showNotice(`Downloaded ${doc.name}.`);
  } catch (error) {
    showNotice(error.message, true);
  }
}

async function deleteDocument(doc) {
  if (!window.confirm(`Permanently remove "${doc.name}"?`)) return;
  try {
    await request(`/api/documents/${encodeURIComponent(doc.id)}`, { method: 'DELETE' });
    showNotice('Document deleted.');
    await loadDocuments();
  } catch (error) {
    showNotice(error.message, true);
  }
}

function chooseReplacementFile(doc) {
  const input = document.createElement('input');
  input.type = 'file';
  input.accept = '.pdf,.docx,.txt,.png,.jpg,.jpeg';
  input.hidden = true;
  input.addEventListener('change', async () => {
    const file = input.files[0];
    input.remove();
    if (!file || !window.confirm(`Replace "${doc.name}" with "${file.name}"?`)) return;
    const formData = new FormData();
    formData.append('file', file);
    try {
      await request(`/api/documents/${encodeURIComponent(doc.id)}/file`, { method: 'PUT', body: formData });
      showNotice('Document file replaced.');
      await loadDocuments();
    } catch (error) {
      showNotice(error.message, true);
    }
  }, { once: true });
  document.body.append(input);
  input.click();
}

function openEditDialog(doc) {
  state.activeDocument = doc;
  byId('editName').value = doc.name;
  byId('editCategory').value = doc.category;
  byId('editDialog').showModal();
}

async function openPermissionDialog(doc) {
  state.activeDocument = doc;
  byId('permissionDocument').textContent = doc.name;
  try {
    const [usersResult, permissionResult] = await Promise.all([
      request('/api/users'),
      request(`/api/documents/${encodeURIComponent(doc.id)}/permissions`)
    ]);
    const select = byId('shareUser');
    select.replaceChildren();
    for (const user of usersResult.users) {
      const option = document.createElement('option');
      option.value = user.id;
      option.textContent = `${user.name} (${user.email}) — ${user.role}`;
      select.append(option);
    }
    renderPermissions(permissionResult.permissions);
    byId('permissionDialog').showModal();
  } catch (error) {
    showNotice(error.message, true);
  }
}

function renderPermissions(permissions) {
  const list = byId('permissionList');
  list.replaceChildren();
  if (permissions.length === 0) {
    const empty = document.createElement('p');
    empty.className = 'muted';
    empty.textContent = 'No other users currently have access.';
    list.append(empty);
    return;
  }
  for (const permission of permissions) {
    const row = document.createElement('div');
    row.className = 'permission-row';
    const label = document.createElement('span');
    label.textContent = `${permission.name} (${permission.email}) · ${permission.level}`;
    row.append(label, makeButton('Revoke', 'secondary', () => revokeAccess(permission.userId)));
    list.append(row);
  }
}

async function revokeAccess(userId) {
  try {
    await request(`/api/documents/${encodeURIComponent(state.activeDocument.id)}/permissions/${encodeURIComponent(userId)}`, { method: 'DELETE' });
    const result = await request(`/api/documents/${encodeURIComponent(state.activeDocument.id)}/permissions`);
    renderPermissions(result.permissions);
    showNotice('Access revoked immediately.');
  } catch (error) {
    showNotice(error.message, true);
  }
}

async function loadAudit() {
  try {
    const { events } = await request('/api/admin/audit?limit=200');
    const body = byId('auditBody');
    body.replaceChildren();
    for (const event of events) {
      const row = document.createElement('tr');
      const values = [
        new Date(event.occurredAt).toLocaleString(), event.actorEmail, event.action,
        event.documentId || '—', event.outcome, event.detail || '—', event.eventHash
      ];
      values.forEach((value, index) => {
        const cell = document.createElement('td');
        cell.textContent = value;
        if (index === values.length - 1) cell.className = 'hash';
        row.append(cell);
      });
      body.append(row);
    }
  } catch (error) {
    showNotice(error.message, true);
  }
}

byId('loginForm').addEventListener('submit', async event => {
  event.preventDefault();
  byId('loginError').textContent = '';
  try {
    const result = await request('/api/login', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ email: byId('email').value, password: byId('password').value })
    });
    state.csrfToken = result.csrfToken;
    setSignedIn(result.user);
  } catch (error) {
    byId('loginError').textContent = error.message;
  }
});

byId('logoutButton').addEventListener('click', async () => {
  try {
    await request('/api/logout', { method: 'POST' });
    window.location.reload();
  } catch (error) {
    showNotice(error.message, true);
  }
});

byId('uploadForm').addEventListener('submit', async event => {
  event.preventDefault();
  const form = event.currentTarget;
  const formData = new FormData(form);
  try {
    await request('/api/documents', { method: 'POST', body: formData });
    form.reset();
    showNotice('Document uploaded.');
    await loadDocuments();
  } catch (error) {
    showNotice(error.message, true);
  }
});

byId('searchForm').addEventListener('submit', event => {
  event.preventDefault();
  const params = new URLSearchParams(new FormData(event.currentTarget));
  for (const [key, value] of params) if (!value) params.delete(key);
  loadDocuments(params);
});

byId('clearSearch').addEventListener('click', () => {
  byId('searchForm').reset();
  loadDocuments();
});

byId('grantForm').addEventListener('submit', async event => {
  event.preventDefault();
  const userId = byId('shareUser').value;
  if (!userId) return showNotice('Select a user first.', true);
  try {
    await request(`/api/documents/${encodeURIComponent(state.activeDocument.id)}/permissions/${encodeURIComponent(userId)}`, {
      method: 'PUT',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ level: byId('shareLevel').value })
    });
    const result = await request(`/api/documents/${encodeURIComponent(state.activeDocument.id)}/permissions`);
    renderPermissions(result.permissions);
    showNotice('Access granted.');
  } catch (error) {
    showNotice(error.message, true);
  }
});

byId('editForm').addEventListener('submit', async event => {
  event.preventDefault();
  try {
    await request(`/api/documents/${encodeURIComponent(state.activeDocument.id)}`, {
      method: 'PATCH',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ name: byId('editName').value, category: byId('editCategory').value })
    });
    byId('editDialog').close();
    showNotice('Document updated.');
    await loadDocuments();
  } catch (error) {
    showNotice(error.message, true);
  }
});

byId('cancelEdit').addEventListener('click', () => byId('editDialog').close());
byId('refreshAudit').addEventListener('click', loadAudit);
document.querySelectorAll('.nav-button').forEach(button => button.addEventListener('click', () => {
  document.querySelectorAll('.nav-button').forEach(item => item.classList.toggle('active', item === button));
  byId('documentsTab').classList.toggle('hidden', button.dataset.tab !== 'documents');
  byId('activityTab').classList.toggle('hidden', button.dataset.tab !== 'activity');
  if (button.dataset.tab === 'activity') loadAudit();
}));

(async function restoreSession() {
  try {
    const result = await request('/api/session');
    state.csrfToken = result.csrfToken;
    setSignedIn(result.user);
  } catch (error) {
    byId('loginView').classList.remove('hidden');
    if (error.status !== 401) byId('loginError').textContent = error.message;
  }
})();
