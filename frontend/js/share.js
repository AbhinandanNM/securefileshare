/* ==========================================================================
   share.js — Cryptographic Access Control & Revocation Controller
   CNS 26ECSC403 Project (Objective O5)
   ========================================================================== */

let _currentShareFileId = null;

document.addEventListener('DOMContentLoaded', () => {
  const modal = document.getElementById('share-modal');
  const closeBtn = document.getElementById('share-modal-close');
  const cancelBtn = document.getElementById('modal-cancel-btn');

  if (closeBtn && modal) {
    closeBtn.addEventListener('click', closeShareModal);
  }
  if (cancelBtn && modal) {
    cancelBtn.addEventListener('click', closeShareModal);
  }

  // Close on backdrop click
  if (modal) {
    modal.addEventListener('click', (e) => {
      if (e.target === modal) closeShareModal();
    });
  }

  // Submit buttons
  document.getElementById('share-submit-btn')?.addEventListener('click', submitShare);
  document.getElementById('share-form')?.addEventListener('submit', (e) => {
    e.preventDefault();
    submitShare();
  });
});

function openShareModal(fileId, fileName) {
  _currentShareFileId = fileId;
  const modal = document.getElementById('share-modal');
  const titleSub = document.getElementById('modal-share-filename');
  const errorEl = document.getElementById('share-error');
  const usernameInput = document.getElementById('share-username');
  const expiryInput = document.getElementById('share-expiry');

  if (titleSub) titleSub.textContent = `File: ${fileName}`;
  if (usernameInput) usernameInput.value = '';
  if (expiryInput) expiryInput.value = '';
  if (errorEl) {
    errorEl.textContent = '';
    errorEl.style.display = 'none';
  }

  const defaultRadio = document.querySelector('input[name="share-perm"][value="read"]');
  if (defaultRadio) defaultRadio.checked = true;

  if (modal) modal.style.display = 'flex';
  loadSharesForFile(fileId);
}

function closeShareModal() {
  const modal = document.getElementById('share-modal');
  if (modal) modal.style.display = 'none';
  _currentShareFileId = null;
}

async function loadSharesForFile(fileId) {
  const container = document.getElementById('shares-items');
  if (!container) return;
  container.innerHTML = '<p style="color:var(--text-muted);font-size:.85rem;">Loading active permissions...</p>';

  try {
    const res = await apiFetch('/api/shares/');
    if (!res.ok) throw new Error('Failed to load delegations');
    const data = await res.json();

    const myShares = (data.data?.shares_created || []).filter(s => s.file_id === fileId && !s.revoked);

    if (myShares.length === 0) {
      container.innerHTML = '<p style="color:var(--text-muted);font-size:.85rem;">No active delegations on this file yet.</p>';
      return;
    }

    container.innerHTML = myShares.map(s => `
      <div class="share-item-row" id="share-row-${s.id}">
        <div>
          <strong>${escapeHtml(s.recipient_username || 'User #' + s.shared_with)}</strong>
          <span class="badge ${s.permission === 'write' ? 'purple' : 'blue'}" style="margin-left: 0.5rem; font-size: 0.7rem;">
            ${s.permission.toUpperCase()}
          </span>
          <span style="font-size:0.75rem; color:var(--text-dim); margin-left: 0.4rem;">
            ${s.expires_at ? '· Expires ' + s.expires_at.split('T')[0] : '· Permanent'}
          </span>
        </div>
        <button class="btn btn-danger btn-sm" title="Revoke Permission (O5)" onclick="revokeShare(${s.id})">
          Revoke
        </button>
      </div>
    `).join('');
  } catch (err) {
    container.innerHTML = `<p style="color:var(--accent-rose);font-size:.85rem;">${escapeHtml(err.message)}</p>`;
  }
}

async function submitShare() {
  const errorEl = document.getElementById('share-error');
  const sharedWith = document.getElementById('share-username').value.trim();
  const permission = document.querySelector('input[name="share-perm"]:checked')?.value || 'read';
  const expiryRaw = document.getElementById('share-expiry').value;
  const expires_at = expiryRaw ? new Date(expiryRaw).toISOString() : null;

  if (errorEl) {
    errorEl.textContent = '';
    errorEl.style.display = 'none';
  }

  if (!sharedWith) {
    if (errorEl) {
      errorEl.textContent = 'Please enter a target username to grant access.';
      errorEl.style.display = 'block';
    }
    return;
  }

  if (!_currentShareFileId) return;

  const btnText = document.getElementById('share-btn-text');
  const spinner = document.getElementById('share-spinner');
  if (btnText) btnText.style.display = 'none';
  if (spinner) spinner.style.display = 'inline-block';

  try {
    const res = await apiFetch('/api/shares/', {
      method: 'POST',
      body: JSON.stringify({
        file_id: _currentShareFileId,
        shared_with_username: sharedWith,
        permission,
        expires_at: expiryRaw || null,
      }),
    });

    const data = await res.json();
    if (res.ok && data.status === 'success') {
      showToast(`Access granted to "${sharedWith}" with ${permission.toUpperCase()} permission!`, 'success');
      document.getElementById('share-username').value = '';
      document.getElementById('share-expiry').value = '';
      await loadSharesForFile(_currentShareFileId);
      if (typeof loadSharedWithMe === 'function') loadSharedWithMe();
      if (typeof loadSecurityMetrics === 'function') loadSecurityMetrics();
    } else {
      if (errorEl) {
        errorEl.textContent = data.message || 'Failed to grant access.';
        errorEl.style.display = 'block';
      }
    }
  } catch (err) {
    if (errorEl) {
      errorEl.textContent = err.message;
      errorEl.style.display = 'block';
    }
  } finally {
    if (btnText) btnText.style.display = 'inline';
    if (spinner) spinner.style.display = 'none';
  }
}

async function revokeShare(shareId) {
  if (!confirm('Are you sure you want to revoke this user\'s access to the encrypted file?')) return;
  try {
    const res = await apiFetch(`/api/shares/${shareId}`, { method: 'DELETE' });
    const data = await res.json();
    if (res.ok && data.status === 'success') {
      showToast('Permission revoked immediately! Recipient cannot decrypt or download this file.', 'success');
      const row = document.getElementById(`share-row-${shareId}`);
      if (row) row.remove();
      if (typeof loadSharedWithMe === 'function') loadSharedWithMe();
      if (typeof loadSecurityMetrics === 'function') loadSecurityMetrics();
    } else {
      showToast(data.message || 'Failed to revoke access.', 'error');
    }
  } catch (err) {
    showToast(err.message, 'error');
  }
}
