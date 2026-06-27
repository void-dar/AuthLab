/**
 * AuthLab — Core JavaScript Utilities
 * Shared across all pages: API client, auth state, toasts, JWT utils
 */

// ── API CLIENT ─────────────────────────────────────────────

const API = {
  async request(method, path, body = null) {
    const opts = {
      method,
      headers: { 'Content-Type': 'application/json' },
      credentials: 'include',   // Send cookies automatically
    };
    if (body) opts.body = JSON.stringify(body);

    const res = await fetch(path, opts);
    const data = await res.json().catch(() => ({ error: 'Invalid JSON response' }));

    if (!res.ok) {
      const msg = data.detail || data.error || data.message || `HTTP ${res.status}`;
      throw new APIError(msg, res.status, data);
    }
    return data;
  },

  get:    (path)          => API.request('GET', path),
  post:   (path, body)    => API.request('POST', path, body),
  put:    (path, body)    => API.request('PUT', path, body),
  delete: (path)          => API.request('DELETE', path),
  patch:  (path, body)    => API.request('PATCH', path, body),
};

class APIError extends Error {
  constructor(message, status, data) {
    super(message);
    this.status = status;
    this.data = data;
    this.name = 'APIError';
  }
}


// ── AUTH STATE ─────────────────────────────────────────────

const Auth = {
  _user: null,

  async getUser() {
    if (this._user) return this._user;
    try {
      this._user = await API.get('/api/auth/me');
      return this._user;
    } catch {
      return null;
    }
  },

  async isLoggedIn() {
    const user = await this.getUser();
    return !!user;
  },

  async logout() {
    try {
      await API.post('/api/auth/logout');
    } catch {}
    this._user = null;
    window.location.href = '/login';
  },

  async refreshToken() {
    try {
      await API.post('/api/auth/refresh');
      this._user = null;  // Force re-fetch
      return true;
    } catch {
      return false;
    }
  },

  /** Call on every protected page to render user info in nav */
  async initNav() {
    const user = await this.getUser();
    const navUser = document.getElementById('nav-user');
    const navLogin = document.getElementById('nav-login');
    const navLogout = document.getElementById('nav-logout');
    const navAdmin = document.getElementById('nav-admin');

    if (user) {
      if (navUser) {
        navUser.textContent = `${user.username} (${user.role})`;
        navUser.style.display = 'block';
      }
      if (navLogout) navLogout.style.display = 'inline-flex';
      if (navLogin) navLogin.style.display = 'none';
      if (navAdmin && user.role === 'admin') navAdmin.style.display = 'inline-flex';
    } else {
      if (navUser) navUser.style.display = 'none';
      if (navLogout) navLogout.style.display = 'none';
      if (navLogin) navLogin.style.display = 'inline-flex';
    }
    return user;
  }
};

// Wire up logout button
document.addEventListener('DOMContentLoaded', () => {
  const logoutBtn = document.getElementById('nav-logout');
  if (logoutBtn) logoutBtn.addEventListener('click', () => Auth.logout());

  // Auto-refresh token if 401
  // (handled per-page as needed)
});


// ── TOAST NOTIFICATIONS ─────────────────────────────────────

const Toast = {
  show(message, type = 'info', duration = 4000) {
    let container = document.querySelector('.toast-container');
    if (!container) {
      container = document.createElement('div');
      container.className = 'toast-container';
      document.body.appendChild(container);
    }

    const toast = document.createElement('div');
    toast.className = `toast ${type}`;
    toast.textContent = message;
    container.appendChild(toast);

    setTimeout(() => {
      toast.style.opacity = '0';
      toast.style.transform = 'translateX(100%)';
      toast.style.transition = '0.3s ease';
      setTimeout(() => toast.remove(), 300);
    }, duration);
  },

  success: (msg) => Toast.show(msg, 'success'),
  error:   (msg) => Toast.show(msg, 'error', 6000),
  info:    (msg) => Toast.show(msg, 'info'),
  warning: (msg) => Toast.show(msg, 'warning', 5000),
};


// ── CLIPBOARD ──────────────────────────────────────────────

function copyToClipboard(text, label = 'Copied') {
  navigator.clipboard.writeText(text).then(() => {
    Toast.success(`${label} to clipboard!`);
  }).catch(() => {
    // Fallback
    const ta = document.createElement('textarea');
    ta.value = text;
    ta.style.position = 'fixed';
    ta.style.opacity = '0';
    document.body.appendChild(ta);
    ta.select();
    document.execCommand('copy');
    document.body.removeChild(ta);
    Toast.success(`${label} to clipboard!`);
  });
}

document.addEventListener('click', (e) => {
  if (e.target.classList.contains('hash-value')) {
    copyToClipboard(e.target.textContent, 'Hash copied');
  }
  if (e.target.classList.contains('copy-btn')) {
    const target = e.target.dataset.copy || e.target.closest('[data-copy]')?.dataset.copy;
    if (target) copyToClipboard(target, 'Copied');
  }
});


// ── JWT UTILITIES ────────────────────────────────────────────

const JWT = {
  decode(token) {
    const parts = token.split('.');
    if (parts.length !== 3) return null;
    try {
      const decode = (s) => {
        s = s.replace(/-/g, '+').replace(/_/g, '/');
        while (s.length % 4) s += '=';
        return JSON.parse(atob(s));
      };
      return {
        header: decode(parts[0]),
        payload: decode(parts[1]),
        signature: parts[2],
      };
    } catch {
      return null;
    }
  },

  renderParts(token, containerId) {
    const container = document.getElementById(containerId);
    if (!container) return;
    const parts = token.split('.');
    if (parts.length !== 3) {
      container.innerHTML = '<span class="text-red">Invalid JWT format</span>';
      return;
    }
    container.innerHTML = `
      <div style="font-family: var(--font-code); font-size: 0.75rem; word-break: break-all; line-height: 1.8;">
        <span class="jwt-header" style="padding: 2px 4px; border-radius: 3px;">${parts[0]}</span><span class="jwt-dot">.</span><span class="jwt-payload" style="padding: 2px 4px; border-radius: 3px;">${parts[1]}</span><span class="jwt-dot">.</span><span class="jwt-signature" style="padding: 2px 4px; border-radius: 3px;">${parts[2]}</span>
      </div>
      <div style="display:flex; gap: 0.75rem; margin-top: 0.5rem; font-size: 0.7rem;">
        <span style="color: #c4b5fd;">■ Header</span>
        <span style="color: #fcd34d;">■ Payload</span>
        <span style="color: #6ee7b7;">■ Signature</span>
      </div>
    `;
  },
};


// ── TABS ─────────────────────────────────────────────────────

function initTabs(containerId) {
  const container = document.getElementById(containerId) || document;
  const btns = container.querySelectorAll('.tab-btn');
  const panels = container.querySelectorAll('.tab-panel');

  btns.forEach(btn => {
    btn.addEventListener('click', () => {
      btns.forEach(b => b.classList.remove('active'));
      panels.forEach(p => p.classList.remove('active'));
      btn.classList.add('active');
      const target = document.getElementById(btn.dataset.tab);
      if (target) target.classList.add('active');
    });
  });

  // Activate first tab
  if (btns.length > 0) btns[0].click();
}


// ── LOADING STATE ────────────────────────────────────────────

function setLoading(btn, loading, originalText = null) {
  if (loading) {
    btn.dataset.originalText = btn.innerHTML;
    btn.innerHTML = '<span class="spinner"></span> Working...';
    btn.disabled = true;
  } else {
    btn.innerHTML = originalText || btn.dataset.originalText || btn.innerHTML;
    btn.disabled = false;
  }
}


// ── JSON DISPLAY ─────────────────────────────────────────────

function renderJSON(data, containerId, collapsible = false) {
  const container = document.getElementById(containerId);
  if (!container) return;
  const json = typeof data === 'string' ? data : JSON.stringify(data, null, 2);
  container.innerHTML = `<pre>${syntaxHighlight(json)}</pre>`;
}

function syntaxHighlight(json) {
  return json
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
    .replace(/("(\\u[\da-fA-F]{4}|\\[^u]|[^\\"])*"(\s*:)?|\b(true|false|null)\b|-?\d+(?:\.\d*)?(?:[eE][+\-]?\d+)?)/g, (match) => {
      let cls = 'text-code';
      if (/^"/.test(match)) {
        cls = /:$/.test(match) ? 'text-secondary' : 'text-green';
      } else if (/true/.test(match)) {
        cls = 'text-green';
      } else if (/false|null/.test(match)) {
        cls = 'text-amber';
      } else {
        cls = 'text-cyan';
      }
      return `<span class="${cls}">${match}</span>`;
    });
}


// ── FORM HELPERS ─────────────────────────────────────────────

function getFormData(formId) {
  const form = document.getElementById(formId);
  if (!form) return {};
  const data = {};
  new FormData(form).forEach((val, key) => { data[key] = val; });
  return data;
}

function showError(containerId, message) {
  const el = document.getElementById(containerId);
  if (el) {
    el.innerHTML = `<div class="alert alert-danger"><span class="alert-icon">⚠️</span><span>${message}</span></div>`;
    el.classList.remove('hidden');
  }
}

function showSuccess(containerId, message) {
  const el = document.getElementById(containerId);
  if (el) {
    el.innerHTML = `<div class="alert alert-success"><span class="alert-icon">✅</span><span>${message}</span></div>`;
    el.classList.remove('hidden');
  }
}

function clearMessage(containerId) {
  const el = document.getElementById(containerId);
  if (el) { el.innerHTML = ''; el.classList.add('hidden'); }
}
