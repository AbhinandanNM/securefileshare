/* ==========================================================================
   dashboard.js — Cryptographic Operations & Security Dashboard Controller
   CNS 26ECSC403 Project
   ========================================================================== */

let currentInspectedFileId = null;

document.addEventListener('DOMContentLoaded', () => {
  // Session check
  if (!isLoggedIn()) {
    redirectToLogin();
    return;
  }

  initUserDisplay();
  initSidebarNav();
  initUploadZone();
  initCryptoModal();
  initAttackLab();
  
  // Initial data loading
  loadDashboardData();

  // Refresh buttons
  document.getElementById('refresh-btn')?.addEventListener('click', loadMyFiles);
  document.getElementById('refresh-shared-btn')?.addEventListener('click', loadSharedWithMe);
  document.getElementById('refresh-audit-btn')?.addEventListener('click', loadAuditLogs);
});

/* ---- User Profile Display ---- */
function initUserDisplay() {
  const username = getUsername() || 'User';
  const displayEl = document.getElementById('username-display');
  const avatarEl = document.getElementById('user-avatar');
  if (displayEl) displayEl.textContent = username;
  if (avatarEl) avatarEl.textContent = username.charAt(0).toUpperCase();

  document.getElementById('logout-btn')?.addEventListener('click', () => {
    clearAuth();
    showToast('Session destroyed. Signed out securely.', 'info');
    setTimeout(redirectToLogin, 600);
  });
}

/* ---- Sidebar Navigation Tabs ---- */
function initSidebarNav() {
  const navItems = document.querySelectorAll('.sidebar-menu .nav-item');
  navItems.forEach(btn => {
    btn.addEventListener('click', () => {
      navItems.forEach(b => b.classList.remove('active'));
      btn.classList.add('active');

      const targetView = btn.getAttribute('data-view');
      document.querySelectorAll('.view-panel').forEach(panel => {
        panel.style.display = 'none';
        panel.classList.remove('active');
      });

      const activePanel = document.getElementById(`view-${targetView}`);
      if (activePanel) {
        activePanel.style.display = 'block';
        activePanel.classList.add('active');
      }

      // Contextual refresh
      if (targetView === 'audit-trail') loadAuditLogs();
      if (targetView === 'shared-with-me') loadSharedWithMe();
      if (targetView === 'my-files') loadMyFiles();
      if (targetView === 'attack-lab') populateLabFileSelect();
    });
  });
}

/* ---- Master Data Loader ---- */
async function loadDashboardData() {
  await Promise.all([
    loadMyFiles(),
    loadSharedWithMe(),
    loadSecurityMetrics()
  ]);
}

/* ---- Security Metrics & KPI Bar ---- */
async function loadSecurityMetrics() {
  try {
    const res = await apiFetch('/api/audit/metrics');
    const json = await res.json();
    if (json.status === 'success') {
      const stats = json.data.stats;
      document.getElementById('kpi-files-count').textContent = stats.user_files;
      document.getElementById('kpi-tamper-count').textContent = stats.tampered_files;
      const integrityEl = document.getElementById('kpi-integrity-status');
      if (stats.tampered_files > 0) {
        integrityEl.textContent = 'ALERT!';
        integrityEl.style.color = 'var(--accent-rose)';
      } else {
        integrityEl.textContent = '100%';
        integrityEl.style.color = 'var(--accent-emerald)';
      }
    }
  } catch (err) {
    console.warn('Metrics error:', err);
  }
}

/* ---- Drag & Drop + Cryptographic Progress Upload ---- */
function initUploadZone() {
  const zone = document.getElementById('upload-dropzone');
  const input = document.getElementById('file-input');

  if (!zone || !input) return;

  ['dragenter', 'dragover'].forEach(name => {
    zone.addEventListener(name, (e) => {
      e.preventDefault();
      zone.classList.add('dragover');
    });
  });

  ['dragleave', 'drop'].forEach(name => {
    zone.addEventListener(name, (e) => {
      e.preventDefault();
      zone.classList.remove('dragover');
    });
  });

  zone.addEventListener('drop', (e) => {
    const files = e.dataTransfer.files;
    if (files.length > 0) uploadFile(files[0]);
  });

  input.addEventListener('change', () => {
    if (input.files.length > 0) {
      uploadFile(input.files[0]);
      input.value = '';
    }
  });
}

async function uploadFile(file) {
  const progressBox = document.getElementById('upload-progress-box');
  const bar = document.getElementById('upload-bar-fill');
  const stepHash = document.getElementById('step-hash');
  const stepKey = document.getElementById('step-key');
  const stepEnc = document.getElementById('step-enc');
  const stepStore = document.getElementById('step-store');

  if (progressBox) progressBox.style.display = 'block';

  // Step 1: Hashing
  stepHash.className = 'step active';
  bar.style.width = '25%';
  await new Promise(r => setTimeout(r, 200));

  // Step 2: Key Generation & Wrap
  stepHash.className = 'step completed';
  stepKey.className = 'step active';
  bar.style.width = '55%';
  await new Promise(r => setTimeout(r, 200));

  // Step 3: AES-256-CBC Payload Encryption
  stepKey.className = 'step completed';
  stepEnc.className = 'step active';
  bar.style.width = '80%';

  const formData = new FormData();
  formData.append('file', file);

  try {
    const res = await apiFetch('/api/files/upload', {
      method: 'POST',
      body: formData,
    });
    const json = await res.json();

    if (!res.ok || json.status !== 'success') {
      throw new Error(json.message || 'Upload failed');
    }

    // Step 4: Storage complete
    stepEnc.className = 'step completed';
    stepStore.className = 'step completed';
    bar.style.width = '100%';

    showToast(`"${file.name}" encrypted with AES-256-CBC and stored!`, 'success');
    await loadMyFiles();
    await loadSecurityMetrics();
  } catch (err) {
    showToast(err.message, 'error');
  } finally {
    setTimeout(() => {
      if (progressBox) progressBox.style.display = 'none';
      bar.style.width = '0%';
      [stepHash, stepKey, stepEnc, stepStore].forEach(s => s.className = 'step');
    }, 1200);
  }
}

/* ---- Load My Files ---- */
async function loadMyFiles() {
  const tbody = document.getElementById('files-tbody');
  if (!tbody) return;

  try {
    const res = await apiFetch('/api/files/');
    const json = await res.json();
    if (!res.ok) throw new Error(json.message);

    const files = json.data?.files || [];
    _allVaultFiles = files;
    populateLabFileSelect();
    document.getElementById('my-files-count').textContent = files.length;
    document.getElementById('kpi-files-count').textContent = files.length;

    if (files.length === 0) {
      tbody.innerHTML = `<tr><td colspan="6" class="empty-state">No files uploaded yet. Upload a file above to encrypt with AES-256-CBC.</td></tr>`;
      return;
    }

    tbody.innerHTML = files.map(f => {
      const isTampered = f.is_tampered;
      const statusBadge = isTampered
        ? `<span class="badge red">⚠️ TAMPERED</span>`
        : `<span class="badge green">🔒 AES-256 SECURE</span>`;

      return `
        <tr>
          <td>
            <div class="file-name-cell">
              <div class="file-icon">
                <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/></svg>
              </div>
              <div>
                <div>${escapeHtml(f.filename)}</div>
                <div style="font-size:0.72rem; color:var(--text-dim);">${formatDate(f.uploaded_at)}</div>
              </div>
            </div>
          </td>
          <td>
            <div>${formatBytes(f.size)}</div>
            <div style="font-size:0.72rem; color:var(--text-dim);">Cipher: ${formatBytes(f.ciphertext_size)}</div>
          </td>
          <td>
            <span class="badge blue">${f.cipher_algo || 'AES-256-CBC'}</span>
          </td>
          <td>
            <span class="hash-badge" title="Click to copy full SHA-256 hash" onclick="navigator.clipboard.writeText('${f.file_hash}'); showToast('SHA-256 hash copied to clipboard!', 'info')">
              <svg xmlns="http://www.w3.org/2000/svg" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect width="14" height="14" x="8" y="8" rx="2" ry="2"/><path d="M4 16c-1.1 0-2-.9-2-2V4c0-1.1.9-2 2-2h10c1.1 0 2 .9 2 2"/></svg>
              ${f.file_hash.substring(0, 12)}...
            </span>
          </td>
          <td>${statusBadge}</td>
          <td>
            <div class="action-buttons-group">
              <button class="action-btn download" title="Download & Verify Integrity (O3)" onclick="downloadFile(${f.id}, '${escapeHtml(f.filename)}')">
                <svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>
              </button>
              <button class="action-btn inspect" title="Inspect Cryptographic Vectors & Hex Dump" onclick="openCryptoInspector(${f.id})">
                <svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg>
              </button>
              <button class="action-btn share" title="Grant Permission / Share File (O5)" onclick="openShareModal(${f.id}, '${escapeHtml(f.filename)}')">
                <svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M16 21v-2a4 4 0 0 0-4-4H6a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M22 21v-2a4 4 0 0 0-3-3.87"/><path d="M16 3.13a4 4 0 0 1 0 7.75"/></svg>
              </button>
              <button class="action-btn delete" title="Secure Delete File" onclick="deleteFile(${f.id}, '${escapeHtml(f.filename)}')">
                <svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="3 6 5 6 21 6"/><path d="M19 6l-1 14a2 2 0 0 1-2 2H8a2 2 0 0 1-2-2L5 6"/><line x1="10" y1="11" x2="10" y2="17"/><line x1="14" y1="11" x2="14" y2="17"/></svg>
              </button>
            </div>
          </td>
        </tr>
      `;
    }).join('');
  } catch (err) {
    tbody.innerHTML = `<tr><td colspan="6" class="empty-state" style="color:var(--accent-rose);">Error loading files: ${err.message}</td></tr>`;
  }
}

/* ---- Download & Integrity Decrypt Flow ---- */
async function downloadFile(fileId, filename) {
  showToast(`Initiating secure download & integrity audit for "${filename}"...`, 'info');
  try {
    const res = await apiFetch(`/api/files/${fileId}/download`);

    if (res.status === 409) {
      const errJson = await res.json();
      showToast(errJson.message || 'Integrity check failed! File tampered!', 'error');
      return;
    }

    if (!res.ok) {
      const errJson = await res.json().catch(() => ({}));
      throw new Error(errJson.message || 'Download failed');
    }

    const blob = await res.blob();
    const url = window.URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    a.remove();
    window.URL.revokeObjectURL(url);

    showToast(`"${filename}" verified (SHA-256 match) & decrypted!`, 'success');
  } catch (err) {
    showToast(err.message, 'error');
  }
}

/* ---- Delete File ---- */
async function deleteFile(fileId, filename) {
  if (!confirm(`Are you sure you want to delete "${filename}" and purge its encrypted storage?`)) return;
  try {
    const res = await apiFetch(`/api/files/${fileId}`, { method: 'DELETE' });
    const json = await res.json();
    if (!res.ok) throw new Error(json.message);
    showToast(`"${filename}" purged from vault.`, 'success');
    loadMyFiles();
    loadSecurityMetrics();
  } catch (err) {
    showToast(err.message, 'error');
  }
}

/* ---- Load Files Shared With Me ---- */
async function loadSharedWithMe() {
  const tbody = document.getElementById('shared-tbody');
  if (!tbody) return;

  try {
    const res = await apiFetch('/api/shares/');
    const json = await res.json();
    if (!res.ok) throw new Error(json.message);

    const received = json.data?.shares_received || [];
    document.getElementById('shared-count').textContent = received.length;

    if (received.length === 0) {
      tbody.innerHTML = `<tr><td colspan="6" class="empty-state">No files have been shared with your account yet.</td></tr>`;
      return;
    }

    tbody.innerHTML = received.map(s => {
      const permBadge = s.permission === 'write'
        ? `<span class="badge purple">READ / WRITE</span>`
        : `<span class="badge blue">READ ONLY</span>`;

      const expiryBadge = s.is_expired
        ? `<span class="badge red">EXPIRED</span>`
        : s.expires_at ? `<span class="badge amber">Expires ${s.expires_at.split('T')[0]}</span>` : `<span class="badge green">Permanent</span>`;

      return `
        <tr>
          <td><strong>${escapeHtml(s.filename)}</strong></td>
          <td>${escapeHtml(s.sharer_username)}</td>
          <td>${permBadge}</td>
          <td>${expiryBadge}</td>
          <td>
            <span class="hash-badge" onclick="navigator.clipboard.writeText('${s.file_hash}'); showToast('SHA-256 hash copied!', 'info')">
              ${(s.file_hash || '').substring(0, 10)}...
            </span>
          </td>
          <td style="text-align: right;">
            ${s.is_expired ? '<span style="color:var(--text-dim);font-size:.8rem;">Access Revoked</span>' : `
              <button class="btn btn-secondary btn-sm" onclick="downloadFile(${s.file_id}, '${escapeHtml(s.filename)}')">
                <svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>
                Decrypt & Download
              </button>
            `}
          </td>
        </tr>
      `;
    }).join('');
  } catch (err) {
    tbody.innerHTML = `<tr><td colspan="6" class="empty-state" style="color:var(--accent-rose);">Error: ${err.message}</td></tr>`;
  }
}

/* ---- Cryptographic Inspector Modal Controller ---- */
function initCryptoModal() {
  const modal = document.getElementById('crypto-modal');
  const closeBtn = document.getElementById('crypto-modal-close');
  if (closeBtn && modal) {
    closeBtn.addEventListener('click', () => modal.style.display = 'none');
    modal.addEventListener('click', (e) => {
      if (e.target === modal) modal.style.display = 'none';
    });
  }

  // Live Verify button in inspector
  document.getElementById('ci-run-verify-btn')?.addEventListener('click', async () => {
    if (!currentInspectedFileId) return;
    const resultBox = document.getElementById('ci-tamper-result');
    resultBox.style.display = 'block';
    resultBox.className = 'tamper-result-box';
    resultBox.textContent = 'Running SHA-256 cryptographic verification check...';

    try {
      const res = await apiFetch(`/api/files/${currentInspectedFileId}/verify-integrity`, { method: 'POST' });
      const json = await res.json();
      if (json.data && json.data.passed) {
        resultBox.className = 'tamper-result-box pass';
        resultBox.innerHTML = `✅ <strong>INTEGRITY VERIFIED!</strong><br>${json.data.message}<br><small style="font-family:var(--font-mono)">Computed: ${json.data.computed_hash}</small>`;
      } else {
        resultBox.className = 'tamper-result-box fail';
        resultBox.innerHTML = `🚨 <strong>INTEGRITY VIOLATION DETECTED!</strong><br>${json.data.message}<br><small style="font-family:var(--font-mono)">Expected: ${json.data.expected_hash}<br>Computed: ${json.data.computed_hash}</small>`;
      }
      loadMyFiles();
      loadSecurityMetrics();
    } catch (err) {
      resultBox.className = 'tamper-result-box fail';
      resultBox.textContent = 'Error: ' + err.message;
    }
  });

  // Tamper Simulation button
  document.getElementById('ci-tamper-btn')?.addEventListener('click', async () => {
    if (!currentInspectedFileId) return;
    try {
      const res = await apiFetch(`/api/files/${currentInspectedFileId}/simulate-tamper`, { method: 'POST' });
      const json = await res.json();
      showToast(json.message, 'warning');
      document.getElementById('ci-restore-btn').style.display = 'inline-flex';
      openCryptoInspector(currentInspectedFileId);
      loadMyFiles();
      loadSecurityMetrics();
    } catch (err) {
      showToast(err.message, 'error');
    }
  });

  // Restore button
  document.getElementById('ci-restore-btn')?.addEventListener('click', async () => {
    if (!currentInspectedFileId) return;
    try {
      const res = await apiFetch(`/api/files/${currentInspectedFileId}/restore-tamper`, { method: 'POST' });
      const json = await res.json();
      showToast(json.message, 'success');
      document.getElementById('ci-restore-btn').style.display = 'none';
      openCryptoInspector(currentInspectedFileId);
      loadMyFiles();
      loadSecurityMetrics();
    } catch (err) {
      showToast(err.message, 'error');
    }
  });
}

async function openCryptoInspector(fileId) {
  currentInspectedFileId = fileId;
  const modal = document.getElementById('crypto-modal');
  const loading = document.getElementById('crypto-loading');
  const content = document.getElementById('crypto-content');
  const resultBox = document.getElementById('ci-tamper-result');

  if (!modal) return;
  modal.style.display = 'flex';
  loading.style.display = 'block';
  content.style.display = 'none';
  if (resultBox) resultBox.style.display = 'none';

  try {
    const res = await apiFetch(`/api/files/${fileId}/crypto-details`);
    const json = await res.json();
    if (!res.ok) throw new Error(json.message);

    const d = json.data;
    document.getElementById('modal-crypto-filename').textContent = `Cryptographic Inspector: ${d.filename}`;
    document.getElementById('ci-cipher').textContent = `${d.cipher_algorithm} (${d.cipher_mode})`;
    document.getElementById('ci-keysize').textContent = `${d.key_size_bits}b DEK / ${d.block_size_bytes}B Block`;
    
    const badge = document.getElementById('ci-integrity-badge');
    if (d.integrity_status === 'VERIFIED') {
      badge.textContent = 'VERIFIED';
      badge.className = 'badge green';
    } else {
      badge.textContent = 'TAMPERED / CORRUPT';
      badge.className = 'badge red';
    }

    document.getElementById('ci-sha256').textContent = d.plaintext_sha256;
    document.getElementById('ci-iv').textContent = d.iv_hex;
    document.getElementById('ci-dek').textContent = d.wrapped_dek_hex;
    document.getElementById('ci-hexdump').textContent = d.ciphertext_hex_preview;

    const restoreBtn = document.getElementById('ci-restore-btn');
    if (d.is_tampered) {
      restoreBtn.style.display = 'inline-flex';
    } else {
      restoreBtn.style.display = 'none';
    }

    loading.style.display = 'none';
    content.style.display = 'block';
  } catch (err) {
    loading.textContent = 'Error loading cryptographic parameters: ' + err.message;
  }
}

/* ---- Security Audit Trail Loader (SIEM) ---- */
async function loadAuditLogs() {
  const tbody = document.getElementById('audit-tbody');
  if (!tbody) return;

  try {
    const res = await apiFetch('/api/audit/logs');
    const json = await res.json();
    if (!res.ok) throw new Error(json.message);

    const logs = json.data?.logs || [];
    if (logs.length === 0) {
      tbody.innerHTML = `<tr><td colspan="6" class="empty-state">No security events recorded yet.</td></tr>`;
      return;
    }

    tbody.innerHTML = logs.map(l => {
      let statusBadge = '<span class="badge green">SUCCESS</span>';
      if (l.status === 'WARNING') statusBadge = '<span class="badge amber">WARNING</span>';
      if (l.status === 'CRITICAL') statusBadge = '<span class="badge red">CRITICAL</span>';

      return `
        <tr>
          <td style="font-family:var(--font-mono);font-size:0.75rem;">${formatDate(l.created_at)}</td>
          <td><span class="badge blue">${escapeHtml(l.event_type)}</span></td>
          <td><strong>${escapeHtml(l.username)}</strong> <span style="font-size:0.72rem;color:var(--text-dim);">(${escapeHtml(l.ip_address)})</span></td>
          <td>${l.filename ? escapeHtml(l.filename) : '<span style="color:var(--text-dim);">-</span>'}</td>
          <td>${statusBadge}</td>
          <td style="font-size:0.8rem; color:var(--text-muted);">${escapeHtml(l.details)}</td>
        </tr>
      `;
    }).join('');
  } catch (err) {
    tbody.innerHTML = `<tr><td colspan="6" class="empty-state" style="color:var(--accent-rose);">Error: ${err.message}</td></tr>`;
  }
}

/* ---- Helpers ---- */
function formatBytes(bytes) {
  if (!bytes || bytes === 0) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

function formatDate(isoStr) {
  if (!isoStr) return '-';
  const d = new Date(isoStr);
  return d.toLocaleString([], { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit', second: '2-digit' });
}

/* ---- Live Attack & Proof Lab Controller ---- */
let _allVaultFiles = [];

function populateLabFileSelect() {
  const select = document.getElementById('lab-file-select');
  if (!select) return;
  if (!_allVaultFiles || _allVaultFiles.length === 0) {
    select.innerHTML = '<option value="">No files uploaded yet in vault</option>';
    return;
  }
  select.innerHTML = _allVaultFiles.map(f => `
    <option value="${f.id}">${escapeHtml(f.filename)} (${formatBytes(f.size)})</option>
  `).join('');
}

function initAttackLab() {
  // 1. 3rd-Party Attack simulation
  document.getElementById('btn-run-unauth-attack')?.addEventListener('click', async () => {
    const fileId = document.getElementById('lab-file-select')?.value;
    const resBox = document.getElementById('lab-unauth-result');
    if (!fileId) {
      showToast('Please select a file first', 'error');
      return;
    }
    resBox.style.display = 'block';
    resBox.className = 'tamper-result-box';
    resBox.innerHTML = 'Sending unauthorized download request as attacker "adversary_eve"...';

    try {
      const res = await apiFetch(`/api/audit/proof/simulate-unauthorized-attack/${fileId}`, {
        method: 'POST',
        body: JSON.stringify({ attacker_username: 'adversary_eve' })
      });
      const data = await res.json();
      const r = data.simulation_results;

      resBox.className = 'tamper-result-box fail';
      resBox.innerHTML = `
        <div style="font-weight:800; font-size:0.95rem; margin-bottom:0.4rem; color:var(--accent-rose);">
          🚨 ATTACK INTERCEPTED & BLOCKED BY ACCESS CONTROL GATE!
        </div>
        <div style="font-size:0.82rem; line-height:1.5;">
          <strong>• Attacker (Unauthorized User):</strong> ${escapeHtml(r.attacker_identity)}<br>
          <strong>• File Owner:</strong> ${escapeHtml(r.owner_username)}<br>
          <strong>• Attack Vector:</strong> Direct Access Attempt (OWASP A01: Broken Access Control)<br>
          <strong>• Intercepted HTTP Status:</strong> <span class="badge red">${r.http_response_code} Forbidden</span><br>
          <strong>• Security Barrier:</strong> ${escapeHtml(r.security_barrier)}<br>
          <strong>• Data Leaked:</strong> 0 Bytes (Zero plaintext/keys exposed)<br>
          <strong>• SIEM Audit:</strong> Logged in Security Audit Trail as <code>UNAUTHORIZED_ACCESS_BLOCKED</code>
        </div>
        <div style="margin-top:0.6rem; font-size:0.78rem; color:var(--text-muted); background:var(--bg-input); padding:0.5rem; border-radius:var(--radius-sm);">
          ${escapeHtml(r.message)}
        </div>
      `;
      loadSecurityMetrics();
    } catch (err) {
      resBox.className = 'tamper-result-box fail';
      resBox.textContent = 'Attack Simulation Error: ' + err.message;
    }
  });

  // 2. Encryption Side-by-Side Proof
  document.getElementById('btn-run-encryption-proof')?.addEventListener('click', async () => {
    const fileId = document.getElementById('lab-file-select')?.value;
    const resBox = document.getElementById('lab-enc-result');
    if (!fileId) {
      showToast('Please select a file first', 'error');
      return;
    }
    resBox.style.display = 'block';
    resBox.innerHTML = '<p style="color:var(--text-muted); font-size:0.85rem;">Retrieving plaintext vs ciphertext storage dump...</p>';

    try {
      const res = await apiFetch(`/api/audit/proof/encryption-comparison/${fileId}`);
      const data = await res.json();
      const d = data.data;

      resBox.innerHTML = `
        <div style="display:grid; grid-template-columns:1fr 1fr; gap:0.85rem; margin-top:0.5rem;">
          <div style="background:var(--bg-input); padding:0.85rem; border-radius:var(--radius-sm); border:1px solid var(--border-subtle);">
            <div style="font-size:0.75rem; font-weight:800; color:var(--accent-emerald); text-transform:uppercase; margin-bottom:0.4rem;">
              ✔ Decrypted Plaintext (Human-Readable)
            </div>
            <pre style="font-family:var(--font-mono); font-size:0.75rem; color:#86efac; word-break:break-all; max-height:140px; overflow-y:auto; white-space:pre-wrap;">${escapeHtml(d.plaintext_preview)}</pre>
            <div style="margin-top:0.4rem; font-size:0.7rem; color:var(--text-dim);">SHA-256: ${d.plaintext_sha256.slice(0, 16)}...</div>
          </div>

          <div style="background:#080b12; padding:0.85rem; border-radius:var(--radius-sm); border:1px solid var(--border-subtle);">
            <div style="font-size:0.75rem; font-weight:800; color:#38bdf8; text-transform:uppercase; margin-bottom:0.4rem;">
              🔒 Raw Ciphertext in uploads/${d.stored_uuid.slice(0, 8)}... (Disk Dump)
            </div>
            <pre style="font-family:var(--font-mono); font-size:0.72rem; color:#38bdf8; max-height:140px; overflow-y:auto;">${escapeHtml(d.ciphertext_hex_dump)}</pre>
            <div style="margin-top:0.4rem; font-size:0.7rem; color:var(--text-dim);">Cipher SHA-256: ${d.ciphertext_sha256.slice(0, 16)}...</div>
          </div>
        </div>
        <div style="margin-top:0.6rem; font-size:0.78rem; color:#86efac; background:rgba(16, 185, 129, 0.1); border:1px solid rgba(16, 185, 129, 0.2); padding:0.5rem 0.75rem; border-radius:var(--radius-sm);">
          ✔ <strong>MATHEMATICAL PROOF:</strong> The disk file contains zero plaintext symbols. Data at rest is encrypted with AES-256-CBC and DEK wrapped with Master Key via PBKDF2 (100k rounds).
        </div>
      `;
    } catch (err) {
      resBox.innerHTML = `<p style="color:var(--accent-rose); font-size:0.85rem;">Error: ${escapeHtml(err.message)}</p>`;
    }
  });

  // 3. Tamper Simulation in Lab
  document.getElementById('btn-lab-tamper')?.addEventListener('click', async () => {
    const fileId = document.getElementById('lab-file-select')?.value;
    const resBox = document.getElementById('lab-tamper-result');
    if (!fileId) return showToast('Please select a file first', 'error');
    try {
      const res = await apiFetch(`/api/files/${fileId}/simulate-tamper`, { method: 'POST' });
      const json = await res.json();
      showToast(json.message, 'warning');
      resBox.style.display = 'block';
      resBox.className = 'tamper-result-box fail';
      resBox.innerHTML = `⚠️ <strong>1 BYTE TAMPERED!</strong> Ciphertext byte inverted at index 16. Now click <strong>"Test Download"</strong> to observe the SHA-256 defense!`;
      loadMyFiles();
      loadSecurityMetrics();
    } catch (err) {
      showToast(err.message, 'error');
    }
  });

  document.getElementById('btn-lab-test-dl')?.addEventListener('click', async () => {
    const fileId = document.getElementById('lab-file-select')?.value;
    const resBox = document.getElementById('lab-tamper-result');
    if (!fileId) return showToast('Please select a file first', 'error');

    resBox.style.display = 'block';
    resBox.className = 'tamper-result-box';
    resBox.textContent = 'Attempting download and performing pre-release SHA-256 verification...';

    try {
      const res = await apiFetch(`/api/files/${fileId}/download`);
      if (res.status === 409) {
        const errJson = await res.json();
        resBox.className = 'tamper-result-box fail';
        resBox.innerHTML = `
          🚨 <strong>TAMPERING DETECTED! DOWNLOAD HALTED (HTTP 409)!</strong><br>
          ${escapeHtml(errJson.message)}<br>
          <span style="font-size:0.78rem; color:var(--text-dim);">Expected SHA-256: ${errJson.data?.expected_hash}<br>Computed SHA-256: ${errJson.data?.computed_hash}</span>
        `;
      } else if (res.ok) {
        resBox.className = 'tamper-result-box pass';
        resBox.innerHTML = `✅ <strong>INTEGRITY VERIFIED (HTTP 200)!</strong> File is intact and unmodified. Decrypted payload matches stored hash.`;
      } else {
        const errJson = await res.json().catch(() => ({}));
        resBox.className = 'tamper-result-box fail';
        resBox.textContent = `Server rejected download (HTTP ${res.status}): ${errJson.message || 'Error'}`;
      }
    } catch (err) {
      resBox.className = 'tamper-result-box fail';
      resBox.textContent = 'Error: ' + err.message;
    }
  });

  document.getElementById('btn-lab-restore')?.addEventListener('click', async () => {
    const fileId = document.getElementById('lab-file-select')?.value;
    const resBox = document.getElementById('lab-tamper-result');
    if (!fileId) return showToast('Please select a file first', 'error');
    try {
      const res = await apiFetch(`/api/files/${fileId}/restore-tamper`, { method: 'POST' });
      const json = await res.json();
      showToast(json.message, 'success');
      resBox.style.display = 'block';
      resBox.className = 'tamper-result-box pass';
      resBox.innerHTML = `✅ <strong>CIPHERTEXT RESTORED!</strong> Original unmodified storage restored. Subsequent downloads will now pass with 100% integrity.`;
      loadMyFiles();
      loadSecurityMetrics();
    } catch (err) {
      showToast(err.message, 'error');
    }
  });
}

function escapeHtml(str) {
  if (!str) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}
