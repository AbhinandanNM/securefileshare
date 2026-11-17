/* =====================================================
   auth.js – Login / Register logic
   SecureCloud CNS Project
   ===================================================== */

const API_BASE = window.location.origin.startsWith('http') ? window.location.origin : 'https://localhost:5000';
const TOKEN_KEY = 'cns_token';
const USERNAME_KEY = 'cns_username';

/* ---- Helpers ---- */

function getToken() {
  return localStorage.getItem(TOKEN_KEY);
}

function setToken(token) {
  localStorage.setItem(TOKEN_KEY, token);
}

function getUsername() {
  return localStorage.getItem(USERNAME_KEY);
}

function setUsername(username) {
  localStorage.setItem(USERNAME_KEY, username);
}

function clearAuth() {
  localStorage.removeItem(TOKEN_KEY);
  localStorage.removeItem(USERNAME_KEY);
}

function isLoggedIn() {
  return !!getToken();
}

function redirectToDashboard() {
  window.location.href = 'dashboard.html';
}

function redirectToLogin() {
  window.location.href = 'index.html';
}

/* ---- Toast ---- */

function showToast(message, type = 'info') {
  const container = document.getElementById('toast-container');
  if (!container) return;

  const icons = {
    success: `<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#22c55e" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"/></svg>`,
    error:   `<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#ef4444" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><line x1="15" y1="9" x2="9" y2="15"/><line x1="9" y1="9" x2="15" y2="15"/></svg>`,
    info:    `<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#3b82f6" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>`,
  };

  const toast = document.createElement('div');
  toast.className = `toast toast-${type}`;
  toast.innerHTML = `<span class="toast-icon">${icons[type] || icons.info}</span><span>${message}</span>`;
  container.appendChild(toast);

  setTimeout(() => {
    toast.classList.add('hide');
    setTimeout(() => toast.remove(), 300);
  }, 3500);
}

/* ---- API call helper ---- */

async function apiFetch(path, options = {}) {
  const url = `${API_BASE}${path}`;
  const defaults = {
    mode: 'cors',
    credentials: 'include',
    headers: { 'Content-Type': 'application/json', ...(options.headers || {}) },
  };

  const token = getToken();
  if (token) {
    defaults.headers['Authorization'] = `Bearer ${token}`;
  }

  // Merge – but don't override Content-Type if body is FormData
  if (options.body instanceof FormData) {
    delete defaults.headers['Content-Type'];
  }

  try {
    const res = await fetch(url, { ...defaults, ...options, headers: { ...defaults.headers, ...(options.headers || {}) } });

    // If token expired or invalid, force re-login
    if (res.status === 401 || res.status === 422) {
      const ct = res.headers.get('Content-Type') || '';
      if (ct.includes('application/json')) {
        const body = await res.clone().json().catch(() => ({}));
        const msg = (body.message || '').toLowerCase();
        if (msg.includes('token') || msg.includes('expired') || msg.includes('invalid') || res.status === 422) {
          clearAuth();
          if (document.getElementById('logout-btn')) {
            // We're on the dashboard — redirect
            showToast && showToast('Session expired. Please sign in again.', 'error');
            setTimeout(redirectToLogin, 1500);
          }
        }
      }
    }

    return res;
  } catch (err) {
    console.error('Fetch error:', err);
    throw new Error('Cannot reach server. Make sure the backend is running at ' + API_BASE);
  }
}

/* ---- Auth page logic (index.html only) ---- */

if (document.getElementById('login-form')) {
  // If already logged in, go to dashboard
  if (isLoggedIn()) redirectToDashboard();

  // --- Tab switching ---
  document.querySelectorAll('.tab-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
      document.querySelectorAll('.tab-panel').forEach(p => p.classList.remove('active'));
      btn.classList.add('active');
      document.getElementById(`tab-${btn.dataset.tab}`).classList.add('active');
    });
  });

  /* -- Login -- */
  const loginForm = document.getElementById('login-form');
  loginForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    const errorEl = document.getElementById('login-error');
    errorEl.classList.remove('show');

    const username = document.getElementById('login-username').value.trim();
    const password = document.getElementById('login-password').value;

    if (!username || !password) {
      errorEl.textContent = 'Please fill in all fields.';
      errorEl.classList.add('show');
      return;
    }

    const btnText = document.getElementById('login-btn-text');
    const spinner = document.getElementById('login-spinner');
    btnText.style.display = 'none';
    spinner.style.display = 'inline-block';

    try {
      const res = await apiFetch('/api/auth/login', {
        method: 'POST',
        body: JSON.stringify({ username, password }),
      });

      const data = await res.json();

      if (res.ok && data.status === 'success') {
        setToken(data.data.access_token);
        setUsername(data.data.username || username);
        showToast('Login successful!', 'success');
        setTimeout(redirectToDashboard, 500);
      } else {
        errorEl.textContent = data.message || 'Login failed. Check your credentials.';
        errorEl.classList.add('show');
      }
    } catch (err) {
      errorEl.textContent = err.message;
      errorEl.classList.add('show');
    } finally {
      btnText.style.display = 'inline';
      spinner.style.display = 'none';
    }
  });

  /* -- Register -- */
  const registerForm = document.getElementById('register-form');
  registerForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    const errorEl = document.getElementById('register-error');
    errorEl.classList.remove('show');

    const username = document.getElementById('reg-username').value.trim();
    const email    = document.getElementById('reg-email').value.trim();
    const password = document.getElementById('reg-password').value;
    const confirm  = document.getElementById('reg-confirm').value;

    if (!username || !email || !password || !confirm) {
      errorEl.textContent = 'Please fill in all fields.';
      errorEl.classList.add('show');
      return;
    }

    if (password !== confirm) {
      errorEl.textContent = 'Passwords do not match.';
      errorEl.classList.add('show');
      return;
    }

    if (password.length < 6) {
      errorEl.textContent = 'Password must be at least 6 characters.';
      errorEl.classList.add('show');
      return;
    }

    const btnText = document.getElementById('register-btn-text');
    const spinner = document.getElementById('register-spinner');
    btnText.style.display = 'none';
    spinner.style.display = 'inline-block';

    try {
      const res = await apiFetch('/api/auth/register', {
        method: 'POST',
        body: JSON.stringify({ username, email, password }),
      });

      const data = await res.json();

      if (res.ok && data.status === 'success') {
        showToast('Account created! Signing you in...', 'success');

        // Auto-login
        const loginRes = await apiFetch('/api/auth/login', {
          method: 'POST',
          body: JSON.stringify({ username, password }),
        });
        const loginData = await loginRes.json();

        if (loginRes.ok && loginData.status === 'success') {
          setToken(loginData.data.access_token);
          setUsername(loginData.data.username || username);
          setTimeout(redirectToDashboard, 600);
        } else {
          // Registered but login failed – go to login tab
          document.querySelector('[data-tab="login"]').click();
        }
      } else {
        errorEl.textContent = data.message || 'Registration failed.';
        errorEl.classList.add('show');
      }
    } catch (err) {
      errorEl.textContent = err.message;
      errorEl.classList.add('show');
    } finally {
      btnText.style.display = 'inline';
      spinner.style.display = 'none';
    }
  });
}

/* ---- Dashboard auth guard ---- */

if (document.getElementById('logout-btn')) {
  if (!isLoggedIn()) redirectToLogin();

  document.getElementById('logout-btn').addEventListener('click', () => {
    clearAuth();
    redirectToLogin();
  });
}
