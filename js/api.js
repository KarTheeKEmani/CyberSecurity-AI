/**
 * AIAC Cyber — Centralized API Client v3.0
 * New endpoints: chatbot, alert generator, email notifications, detection rules
 */

const API_BASE_URL = (window.API_BASE_URL || 'http://localhost:8000') + '/api';

class ApiClient {
  static getToken() {
    return localStorage.getItem('aiac_access_token');
  }

  static getRefreshToken() {
    return localStorage.getItem('aiac_refresh_token');
  }

  static setTokens(accessToken, refreshToken) {
    if (accessToken) localStorage.setItem('aiac_access_token', accessToken);
    if (refreshToken) localStorage.setItem('aiac_refresh_token', refreshToken);
  }

  static clearAuth() {
    localStorage.removeItem('aiac_access_token');
    localStorage.removeItem('aiac_refresh_token');
    localStorage.removeItem('cybersentinel_user');
  }

  static getStoredUser() {
    try {
      const u = localStorage.getItem('cybersentinel_user');
      return u ? JSON.parse(u) : null;
    } catch (e) {
      return null;
    }
  }

  static async request(endpoint, options = {}) {
    const url = `${API_BASE_URL}${endpoint}`;
    const headers = {
      'Content-Type': 'application/json',
      ...(options.headers || {}),
    };

    const token = this.getToken();
    if (token && !headers['Authorization']) {
      headers['Authorization'] = `Bearer ${token}`;
    }

    const config = { ...options, headers };

    try {
      const response = await fetch(url, config);

      if (response.status === 401 && !endpoint.includes('/auth/login') && !endpoint.includes('/auth/me')) {
        const refreshed = await this.tryRefreshToken();
        if (refreshed) {
          headers['Authorization'] = `Bearer ${this.getToken()}`;
          return await (await fetch(url, { ...options, headers })).json();
        } else {
          this.clearAuth();
          if (!window.location.pathname.endsWith('index.html') && !window.location.pathname.endsWith('/')) {
            window.location.href = 'index.html';
          }
          throw new Error('Session expired. Please log in again.');
        }
      }

      if (!response.ok) {
        const errorData = await response.json().catch(() => ({ detail: response.statusText }));
        throw new Error(errorData.detail || `HTTP Error ${response.status}`);
      }

      // Handle 204 No Content
      if (response.status === 204) return {};

      return await response.json();
    } catch (err) {
      if (err.name === 'TypeError' && (err.message === 'Failed to fetch' || err.message.includes('fetch'))) {
        throw new Error(`Backend server is not reachable at ${API_BASE_URL}. Ensure the backend is running on port 8000.`);
      }
      console.warn(`[API] Error on ${options.method || 'GET'} ${endpoint}:`, err.message);
      throw err;
    }
  }

  static async tryRefreshToken() {
    const refreshToken = this.getRefreshToken();
    if (!refreshToken) return false;

    try {
      const res = await fetch(`${API_BASE_URL}/auth/refresh`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ refresh_token: refreshToken }),
      });
      if (res.ok) {
        const data = await res.json();
        this.setTokens(data.access_token);
        return true;
      }
      return false;
    } catch (e) {
      return false;
    }
  }
}

// ---- Domain Endpoints ----

const authApi = {
  login: async (email, password, role) => {
    const data = await ApiClient.request('/auth/login', {
      method: 'POST',
      body: JSON.stringify({ email, password, role }),
    });
    ApiClient.setTokens(data.access_token, data.refresh_token);
    localStorage.setItem('cybersentinel_user', JSON.stringify({
      id: data.user.id,
      email: data.user.email,
      name: data.user.full_name,
      role: data.user.role.toLowerCase(),
      mfa: data.user.mfa_enabled,
      lastLogin: data.user.last_login,
    }));
    return data;
  },
  getMe: () => ApiClient.request('/auth/me'),
  logout: async () => {
    try {
      await ApiClient.request('/auth/logout', { method: 'POST' });
    } catch (e) {}
    ApiClient.clearAuth();
  },
};

const incidentsApi = {
  list: (params = {}) => {
    const q = new URLSearchParams();
    if (params.page) q.append('page', params.page);
    if (params.page_size) q.append('page_size', params.page_size);
    if (params.severity) q.append('severity', params.severity);
    if (params.status) q.append('status', params.status);
    if (params.category) q.append('category', params.category);
    if (params.assignee) q.append('assignee', params.assignee);
    if (params.search) q.append('search', params.search);
    return ApiClient.request(`/incidents?${q.toString()}`);
  },
  get: (id) => ApiClient.request(`/incidents/${id}`),
  create: (data) => ApiClient.request('/incidents', {
    method: 'POST',
    body: JSON.stringify(data),
  }),
  update: (id, data) => ApiClient.request(`/incidents/${id}`, {
    method: 'PATCH',
    body: JSON.stringify(data),
  }),
  updateStatus: (id, status) => ApiClient.request(`/incidents/${id}/status`, {
    method: 'PATCH',
    body: JSON.stringify({ status }),
  }),
  delete: (id) => ApiClient.request(`/incidents/${id}`, { method: 'DELETE' }),
};

const aiApi = {
  triage: (id, data = {}) => ApiClient.request(`/incidents/${id}/triage`, {
    method: 'POST',
    body: JSON.stringify(data),
  }),
  getConfig: () => ApiClient.request('/ai/config'),
};

// NEW: Chatbot API
const chatbotApi = {
  send: (message, conversationId = null, incidentId = null) =>
    ApiClient.request('/chatbot/chat', {
      method: 'POST',
      body: JSON.stringify({ message, conversation_id: conversationId, incident_id: incidentId }),
    }),
  listConversations: () => ApiClient.request('/chatbot/conversations'),
  getMessages: (convId) => ApiClient.request(`/chatbot/conversations/${convId}/messages`),
  deleteConversation: (convId) => ApiClient.request(`/chatbot/conversations/${convId}`, { method: 'DELETE' }),
  getSuggestions: (incidentId = null) =>
    ApiClient.request(`/chatbot/suggestions${incidentId ? `?incident_id=${incidentId}` : ''}`),
};

// NEW: Mock Alert Generator API
const alertGenApi = {
  generateSingle: (category = null, severity = null) =>
    ApiClient.request('/alerts/generate/single', {
      method: 'POST',
      body: JSON.stringify({ category, severity }),
    }),
  generateBatch: (count = 5, category = null, severity = null) =>
    ApiClient.request('/alerts/generate/batch', {
      method: 'POST',
      body: JSON.stringify({ count, category, severity }),
    }),
  getCategories: () => ApiClient.request('/alerts/generate/categories'),
  getStatus:     () => ApiClient.request('/alerts/generate/status'),

  // --- Phase 4: Scheduler Controls ---
  getSchedulerStatus: () => ApiClient.request('/alerts/generate/scheduler/status'),
  startScheduler:     () => ApiClient.request('/alerts/generate/scheduler/start',  { method: 'POST' }),
  stopScheduler:      () => ApiClient.request('/alerts/generate/scheduler/stop',   { method: 'POST' }),
  pauseScheduler:     () => ApiClient.request('/alerts/generate/scheduler/pause',  { method: 'POST' }),
  resumeScheduler:    () => ApiClient.request('/alerts/generate/scheduler/resume', { method: 'POST' }),
  configureScheduler: (interval_seconds) =>
    ApiClient.request('/alerts/generate/scheduler/config', {
      method: 'PATCH',
      body: JSON.stringify({ interval_seconds }),
    }),
};


// NEW: Email Notifications API
const emailApi = {
  getConfig: () => ApiClient.request('/email/config'),
  getRules: () => ApiClient.request('/email/rules'),
  createRule: (data) => ApiClient.request('/email/rules', { method: 'POST', body: JSON.stringify(data) }),
  updateRule: (id, data) => ApiClient.request(`/email/rules/${id}`, { method: 'PATCH', body: JSON.stringify(data) }),
  deleteRule: (id) => ApiClient.request(`/email/rules/${id}`, { method: 'DELETE' }),
  getLogs: (page = 1) => ApiClient.request(`/email/logs?page=${page}`),
  sendTest: (recipient) => ApiClient.request('/email/test', { method: 'POST', body: JSON.stringify({ recipient }) }),
  getRecipients: () => ApiClient.request('/email/recipients'),
  updateRecipients: (recipients) => ApiClient.request('/email/recipients', { method: 'POST', body: JSON.stringify({ recipients }) }),
  retryLog: (id) => ApiClient.request(`/email/logs/${id}/retry`, { method: 'POST' }),
};

const playbooksApi = {
  list: () => ApiClient.request('/playbooks'),
  get: (id) => ApiClient.request(`/playbooks/${id}`),
  execute: (incidentId, data = {}) => ApiClient.request(`/incidents/${incidentId}/playbook/execute`, {
    method: 'POST',
    body: JSON.stringify({ execution_mode: 'SIMULATION', ...data }),
  }),
};

const analyticsApi = {
  getSummary: () => ApiClient.request('/analytics/summary'),
  getOverview: () => ApiClient.request('/analytics/overview'),
};

const auditApi = {
  list: (params = {}) => {
    const q = new URLSearchParams();
    if (params.page) q.append('page', params.page);
    if (params.page_size) q.append('page_size', params.page_size);
    if (params.action) q.append('action', params.action);
    if (params.resource) q.append('resource', params.resource);
    if (params.search) q.append('search', params.search);
    return ApiClient.request(`/audit?${q.toString()}`);
  },
};

const usersApi = {
  list: () => ApiClient.request('/users'),
  create: (data) => ApiClient.request('/users', {
    method: 'POST',
    body: JSON.stringify(data),
  }),
  update: (id, data) => ApiClient.request(`/users/${id}`, {
    method: 'PATCH',
    body: JSON.stringify(data),
  }),
};

const apiKeysApi = {
  list: () => ApiClient.request('/api-keys'),
  create: (data) => ApiClient.request('/api-keys', {
    method: 'POST',
    body: JSON.stringify(data),
  }),
  revoke: (id) => ApiClient.request(`/api-keys/${id}`, { method: 'DELETE' }),
};

const integrationsApi = {
  list: () => ApiClient.request('/integrations'),
  update: (id, data) => ApiClient.request(`/integrations/${id}`, {
    method: 'PATCH',
    body: JSON.stringify(data),
  }),
  test: (id) => ApiClient.request(`/integrations/${id}/test`, { method: 'POST' }),
};

const notificationsApi = {
  list: () => ApiClient.request('/notifications'),
  markAllRead: () => ApiClient.request('/notifications/mark-all-read', { method: 'POST' }),
  markRead: (id) => ApiClient.request(`/notifications/${id}/read`, { method: 'PATCH' }),
};
