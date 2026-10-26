/**
 * AIAC Cyber — Full-Stack Security Operations Center Logic
 * Connected to FastAPI Backend, PostgreSQL Telemetry, and Authenticated WebSockets.
 * Preserves the Liquid Glass dark cyber aesthetic with real dynamic database state.
 */

const APP = {
  currentPage: 'overview',
  currentIncident: null,
  incidents: [],
  totalIncidents: 0,
  page: 1,
  pageSize: 25,
  filters: { severity: '', status: '', search: '', category: '', assignee: '' },
  charts: {},
  notifications: [],
  unreadNotifsCount: 0,
  user: null,
  triageInProgress: false,
  playbookInProgress: false,
  adminTab: 'users',
  users: [],
  apiKeys: [],
  auditLogs: [],
  integrations: [],
  analyticsData: null,
  summaryData: null,
  chatbot: {
    conversations: [],
    currentConversationId: null,
    messages: [],
    selectedIncidentId: null,
    sending: false,
    aiConfig: null,
  },
  alertGen: {
    categories: [],
    status: null,
    generating: false,
    recentGenerated: [],
  },
  email: {
    config: null,
    rules: [],
    logs: [],
    currentTab: 'rules',
    sendingTest: false,
    showModal: false,
  },
  loading: {
    overview: false,
    incidents: false,
    analytics: false,
    admin: false,
    settings: false,
    chatbot: false,
    alertgen: false,
    email: false,
  }
};

// ---- Application Initialization ----
document.addEventListener('DOMContentLoaded', async () => {
  // Check auth session
  const storedUser = ApiClient.getStoredUser();
  const token = ApiClient.getToken();

  if (!token || !storedUser) {
    window.location.href = 'index.html';
    return;
  }

  APP.user = storedUser;
  initUser();

  // Validate session with backend
  try {
    const me = await authApi.getMe();
    APP.user = {
      id: me.id,
      email: me.email,
      name: me.full_name,
      role: me.role.toLowerCase(),
      mfa: me.mfa_enabled,
      lastLogin: me.last_login,
    };
    initUser();
  } catch (err) {
    console.warn('Session verification warning:', err);
    const msg = (err.message || '').toLowerCase();
    const isNetworkErr = msg.includes('reachable') || msg.includes('fetch') || msg.includes('network');
    if (!isNetworkErr && (err.status === 401 || msg.includes('401') || msg.includes('expired'))) {
      ApiClient.clearAuth();
      window.location.href = 'index.html';
      return;
    }
    // Network or offline preview mode: retain stored user and allow dashboard usage
    console.info('Proceeding with stored session for:', APP.user.email);
  }

  // Initialize Real-Time WebSocket
  realtimeWS.connect();
  setupRealtimeListeners();

  // Load initial notifications and counts
  await fetchNotifications();
  await updateSidebarCounts();

  // Route to initial page from URL hash or default to overview
  const validPages = ['overview', 'incidents', 'analytics', 'admin', 'settings', 'chatbot', 'alertgen', 'email'];
  const hash = window.location.hash.replace('#', '').trim();
  navigate(validPages.includes(hash) ? hash : 'overview');

  window.addEventListener('hashchange', () => {
    const newHash = window.location.hash.replace('#', '').trim();
    if (validPages.includes(newHash) && newHash !== APP.currentPage) {
      navigate(newHash);
    }
  });

  // Periodic background sync (fallback)
  setInterval(() => updateSidebarCounts(), 15000);
});

// ---- Real-Time WebSocket Event Handlers ----
function setupRealtimeListeners() {
  realtimeWS.on('incident.created', (data) => {
    if (data.auto_generated) {
      // Rich banner for auto-scheduler alerts
      showAutoAlertBanner(data);
    } else {
      showToast(`New Incident Ingested: ${data.public_id} (${data.severity})`, 'critical');
    }
    updateSidebarCounts();
    fetchNotifications();
    if (APP.currentPage === 'overview') {
      fetchOverviewData().then(renderOverview);
    } else if (APP.currentPage === 'incidents') {
      fetchIncidentsData().then(renderIncidents);
    }
  });


  realtimeWS.on('incident.updated', (data) => {
    updateSidebarCounts();
    if (APP.currentIncident && APP.currentIncident.id === data.id) {
      incidentsApi.get(data.id).then(fullInc => {
        APP.currentIncident = fullInc;
        renderDrawerBody(fullInc);
      });
    }
    if (APP.currentPage === 'incidents') {
      fetchIncidentsData().then(renderIncidents);
    }
  });

  realtimeWS.on('incident.status_changed', (data) => {
    showToast(`Status updated: ${data.public_id} → ${data.new_status}`, 'info');
    updateSidebarCounts();
    if (APP.currentIncident && APP.currentIncident.id === data.id) {
      APP.currentIncident.status = data.new_status;
      incidentsApi.get(data.id).then(fullInc => {
        APP.currentIncident = fullInc;
        renderDrawerBody(fullInc);
      });
    }
    if (APP.currentPage === 'overview') {
      fetchOverviewData().then(renderOverview);
    } else if (APP.currentPage === 'incidents') {
      fetchIncidentsData().then(renderIncidents);
    }
  });

  realtimeWS.on('ai.analysis.started', (data) => {
    if (APP.currentIncident && APP.currentIncident.id === data.incident_id) {
      const resultEl = document.getElementById('ai-triage-result');
      if (resultEl) {
        resultEl.innerHTML = `
          <div style="background:rgba(0,212,255,0.06);border:1px solid rgba(0,212,255,0.25);border-radius:var(--radius-lg);padding:18px;margin-top:12px;">
            <div style="display:flex;align-items:center;gap:10px;color:var(--accent);">
              <div class="status-dot live" style="background:var(--accent);box-shadow:0 0 10px var(--accent);"></div>
              <span style="font-weight:600;font-size:13.5px;">AI Triage Engine Analyzing Incident Telemetry...</span>
            </div>
            <div class="skeleton" style="height:12px;width:80%;margin-top:14px;"></div>
            <div class="skeleton" style="height:12px;width:95%;margin-top:8px;"></div>
            <div class="skeleton" style="height:12px;width:60%;margin-top:8px;"></div>
          </div>
        `;
      }
    }
  });

  realtimeWS.on('ai.analysis.completed', (data) => {
    showToast(`AI Triage Completed for ${data.public_id}`, 'info');
    if (APP.currentIncident && APP.currentIncident.id === data.incident_id) {
      incidentsApi.get(data.incident_id).then(fullInc => {
        APP.currentIncident = fullInc;
        renderDrawerBody(fullInc);
      });
    }
  });

  realtimeWS.on('playbook.started', (data) => {
    showToast(`Playbook Simulation Started for ${data.incident_public_id}`, 'info');
  });

  realtimeWS.on('playbook.completed', (data) => {
    showToast(`Playbook Simulated Successfully for ${data.incident_public_id}`, 'success');
    if (APP.currentIncident && APP.currentIncident.id === data.incident_id) {
      incidentsApi.get(data.incident_id).then(fullInc => {
        APP.currentIncident = fullInc;
        renderDrawerBody(fullInc);
      });
    }
  });

  realtimeWS.on('notification.created', (data) => {
    fetchNotifications();
  });

  realtimeWS.on('integration.status_changed', (data) => {
    if (APP.currentPage === 'settings') {
      fetchSettingsData().then(renderSettings);
    }
  });
}

// ---- User Profile UI ----
function initUser() {
  const name = (APP.user?.name || 'Sarah Chen').trim();
  const role = (APP.user?.role || 'analyst').toLowerCase();
  const nameEl = document.getElementById('user-name');
  const roleEl = document.getElementById('user-role');
  const avatarEl = document.getElementById('user-avatar');
  if (nameEl) nameEl.textContent = name;
  if (roleEl) roleEl.textContent = roleLabel(role);
  if (avatarEl) {
    const initials = name.split(/\s+/).map(n => n[0] || '').join('').toUpperCase().slice(0, 2) || 'SC';
    avatarEl.textContent = initials;
  }
  // Sync dropdown elements
  const nameDd = document.getElementById('user-name-dd');
  const roleDd = document.getElementById('user-role-dd');
  const avatarDd = document.getElementById('user-avatar-dd');
  if (nameDd) nameDd.textContent = name;
  if (roleDd) roleDd.textContent = roleLabel(role);
  if (avatarDd) {
    const initials = name.split(/\s+/).map(n => n[0] || '').join('').toUpperCase().slice(0, 2) || 'SC';
    avatarDd.textContent = initials;
  }
}

function roleLabel(role) {
  const map = {
    analyst: 'Lead Analyst',
    admin: 'Security Admin',
    viewer: 'Auditor / Viewer',
  };
  return map[role.toLowerCase()] || role;
}

async function handleLogout() {
  await authApi.logout();
  window.location.href = 'index.html';
}

// ---- Navigation & Router ----
async function navigate(page) {
  APP.currentPage = page;
  if (window.location.hash.replace('#', '') !== page) {
    window.location.hash = page;
  }
  document.querySelectorAll('.topnav-item').forEach(n => n.classList.remove('active'));
  document.querySelectorAll('.page').forEach(p => p.classList.remove('active'));

  const navEl = document.getElementById('nav-' + page);
  if (navEl) navEl.classList.add('active');
  // Also sync mobile drawer items
  document.querySelectorAll('.topnav-mobile-item').forEach(n => n.classList.remove('active'));
  const mobNavEl = document.getElementById('mob-nav-' + page);
  if (mobNavEl) mobNavEl.classList.add('active');

  const pageEl = document.getElementById('page-' + page);
  if (pageEl) pageEl.classList.add('active');

  const pageInfo = {
    overview: {
      title: 'Security Overview',
      subtitle: 'Real-time telemetry, threat distribution, and active security posture.',
    },
    incidents: {
      title: 'Incident Queue',
      subtitle: 'PostgreSQL-backed telemetry feeds, investigative triage, and response progression.',
    },
    analytics: {
      title: 'Threat Analytics & Heatmap',
      subtitle: 'Database-driven trend vectors, MITRE matrix mapping, and system vulnerability exposure.',
    },
    admin: {
      title: 'Access & Administration',
      subtitle: 'RBAC user management, hashed API credentials, and tamper-evident audit trail.',
    },
    settings: {
      title: 'Connected Integrations',
      subtitle: 'Security orchestration connectors, notification channels, and webhook policies.',
    },
    chatbot: {
      title: 'AI Threat Assistant',
      subtitle: 'Interactive LLM co-pilot for IOC correlation, MITRE ATT&CK guidance, and playbook triage.',
    },
    alertgen: {
      title: 'Alert Simulator & Telemetry Generator',
      subtitle: 'Synthetic multi-vector attack generator for testing detection rules, EDR pipeline, and live SOAR.',
    },
    email: {
      title: 'Email Notifications & Detection Rules',
      subtitle: 'Incident dispatch triggers, threshold rule configuration, and tamper-evident SMTP delivery logs.',
    },
  };

  const current = pageInfo[page] || { title: 'Security Command Center', subtitle: '' };
  document.getElementById('topbar-title').textContent = current.title;
  document.getElementById('topbar-subtitle').textContent = current.subtitle;

  // Load and render page data
  if (page === 'overview') {
    await fetchOverviewData();
    renderOverview();
  } else if (page === 'incidents') {
    await fetchIncidentsData();
    renderIncidents();
  } else if (page === 'analytics') {
    await fetchAnalyticsData();
    renderAnalytics();
  } else if (page === 'admin') {
    await fetchAdminData();
    renderAdmin(APP.adminTab);
  } else if (page === 'settings') {
    await fetchSettingsData();
    renderSettings();
  } else if (page === 'chatbot') {
    await fetchChatbotData();
    renderChatbot();
  } else if (page === 'alertgen') {
    await fetchAlertGenData();
    renderAlertGen();
  } else if (page === 'email') {
    await fetchEmailData();
    renderEmail();
  }
}

// ---- Data Fetching Helpers ----
async function updateSidebarCounts() {
  try {
    const summary = await analyticsApi.getSummary();
    APP.summaryData = summary;
    const critEl = document.getElementById('sidebar-critical-count');
    const totEl = document.getElementById('sidebar-total-count');
    if (critEl) critEl.textContent = summary.critical_incidents;
    if (totEl) totEl.textContent = summary.total_incidents;
  } catch (e) {
    console.warn('Sidebar count fetch error:', e);
  }
}

async function fetchOverviewData() {
  APP.loading.overview = true;
  try {
    const [summary, incRes, analytics] = await Promise.all([
      analyticsApi.getSummary(),
      incidentsApi.list({ page: 1, page_size: 6 }),
      analyticsApi.getOverview(),
    ]);
    APP.summaryData = summary;
    APP.incidents = incRes.incidents;
    APP.analyticsData = analytics;
  } catch (err) {
    console.error('Error fetching overview data:', err);
  } finally {
    APP.loading.overview = false;
  }
}

async function fetchIncidentsData() {
  APP.loading.incidents = true;
  try {
    const res = await incidentsApi.list({
      page: APP.page,
      page_size: APP.pageSize,
      severity: APP.filters.severity,
      status: APP.filters.status,
      category: APP.filters.category,
      assignee: APP.filters.assignee,
      search: APP.filters.search,
    });
    APP.incidents = res.incidents;
    APP.totalIncidents = res.total;
  } catch (err) {
    console.error('Error fetching incidents:', err);
  } finally {
    APP.loading.incidents = false;
  }
}

async function fetchAnalyticsData() {
  APP.loading.analytics = true;
  try {
    APP.analyticsData = await analyticsApi.getOverview();
  } catch (err) {
    console.error('Error fetching analytics overview:', err);
  } finally {
    APP.loading.analytics = false;
  }
}

async function fetchAdminData() {
  APP.loading.admin = true;
  try {
    const [users, apiKeys, auditRes] = await Promise.all([
      usersApi.list(),
      apiKeysApi.list(),
      auditApi.list({ page: 1, page_size: 50 }),
    ]);
    APP.users = users;
    APP.apiKeys = apiKeys;
    APP.auditLogs = auditRes.logs;
  } catch (err) {
    console.error('Error fetching admin data:', err);
  } finally {
    APP.loading.admin = false;
  }
}

async function fetchSettingsData() {
  APP.loading.settings = true;
  try {
    APP.integrations = await integrationsApi.list();
  } catch (err) {
    console.error('Error fetching settings:', err);
  } finally {
    APP.loading.settings = false;
  }
}

async function fetchChatbotData() {
  APP.loading.chatbot = true;
  try {
    const [convs, aiConfig, incRes] = await Promise.all([
      chatbotApi.listConversations().catch(() => []),
      aiApi.getConfig().catch(() => ({ provider: 'mock', demo_mode: true })),
      incidentsApi.list({ page: 1, page_size: 50 }).catch(() => ({ incidents: [] })),
    ]);
    APP.chatbot.conversations = convs || [];
    APP.chatbot.aiConfig = aiConfig;
    if (incRes && incRes.incidents) {
      APP.incidents = incRes.incidents;
    }
    if (!APP.chatbot.currentConversationId && APP.chatbot.conversations.length > 0) {
      APP.chatbot.currentConversationId = APP.chatbot.conversations[0].id;
      const msgs = await chatbotApi.getMessages(APP.chatbot.currentConversationId);
      APP.chatbot.messages = msgs || [];
    } else if (APP.chatbot.currentConversationId) {
      const msgs = await chatbotApi.getMessages(APP.chatbot.currentConversationId);
      APP.chatbot.messages = msgs || [];
    } else {
      APP.chatbot.messages = [];
    }
  } catch (err) {
    console.error('Error fetching chatbot data:', err);
  } finally {
    APP.loading.chatbot = false;
  }
}

async function fetchAlertGenData() {
  APP.loading.alertgen = true;
  try {
    const [catRes, statusRes] = await Promise.all([
      alertGenApi.getCategories().catch(() => ({ categories: [] })),
      alertGenApi.getStatus().catch(() => ({})),
    ]);
    APP.alertGen.categories = catRes.categories || [];
    APP.alertGen.status = statusRes;
  } catch (err) {
    console.error('Error fetching alert generator data:', err);
  } finally {
    APP.loading.alertgen = false;
  }
}

async function fetchEmailData() {
  APP.loading.email = true;
  try {
    const promises = [
      emailApi.getRules().catch(() => []),
      emailApi.getLogs(1).catch(() => ({ logs: [], total: 0 })),
    ];
    if (APP.user && (APP.user.role === 'admin' || APP.user.role === 'lead_analyst')) {
      promises.push(emailApi.getConfig().catch(() => null));
    }
    const [rules, logsRes, config] = await Promise.all(promises);
    APP.email.rules = rules || [];
    APP.email.logs = (logsRes && logsRes.logs) ? logsRes.logs : [];
    if (config) APP.email.config = config;
  } catch (err) {
    console.error('Error fetching email data:', err);
  } finally {
    APP.loading.email = false;
  }
}

async function fetchNotifications() {
  try {
    const notifs = await notificationsApi.list();
    APP.notifications = notifs;
    APP.unreadNotifsCount = notifs.filter(n => !n.read).length;
    renderNotifications();
  } catch (err) {
    console.warn('Error fetching notifications:', err);
  }
}

// ---- Formatting Helpers ----
function timeAgo(iso) {
  if (!iso) return 'just now';
  const diff = Date.now() - new Date(iso).getTime();
  const m = Math.floor(diff / 60000);
  const h = Math.floor(m / 60);
  const d = Math.floor(h / 24);
  if (m < 1) return 'just now';
  if (m < 60) return `${m}m ago`;
  if (h < 24) return `${h}h ago`;
  return `${d}d ago`;
}

function fmtDate(iso) {
  if (!iso) return '—';
  return new Date(iso).toLocaleDateString('en-US', {
    month: 'short',
    day: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
  });
}

function severityBadge(sev) {
  const s = (sev || 'MEDIUM').toLowerCase();
  const labels = { critical: 'Critical', high: 'High', medium: 'Medium', low: 'Low' };
  return `<span class="badge ${s}"><span class="badge-dot"></span>${labels[s] || s}</span>`;
}

function statusBadge(status) {
  const st = (status || 'DETECTED').toUpperCase();
  const map = {
    DETECTED: { class: 'open', label: 'Detected' },
    TRIAGED: { class: 'investigating', label: 'Triaged' },
    INVESTIGATING: { class: 'investigating', label: 'Investigating' },
    CONTAINMENT_PENDING: { class: 'investigating', label: 'Containment Pending' },
    CONTAINED: { class: 'investigating', label: 'Contained' },
    ERADICATED: { class: 'investigating', label: 'Eradicated' },
    RESOLVED: { class: 'resolved', label: 'Resolved' },
    CLOSED: { class: 'closed', label: 'Closed' },
  };
  const conf = map[st] || { class: 'open', label: st };
  return `<span class="status-badge ${conf.class}">${conf.label}</span>`;
}

// ============================================================
// PAGE: OVERVIEW
// ============================================================
function renderOverview() {
  const page = document.getElementById('page-overview');
  if (!page) return;

  const s = APP.summaryData || {
    total_incidents: 0,
    critical_incidents: 0,
    high_incidents: 0,
    investigating_incidents: 0,
    resolved_incidents: 0,
    avg_mttr_hours: 4.2,
    threats_prevented_pct: 98.5,
    systems_protected: 25480,
    signals_analyzed: '2.3M+',
  };

  const incRows = (APP.incidents || []).slice(0, 6).map(inc => `
    <tr class="table-row-hover" onclick="openDrawer(${inc.id})" style="cursor:pointer;">
      <td style="font-family:var(--font-mono);font-size:12px;color:var(--accent);">${inc.public_id}</td>
      <td style="font-weight:500;color:var(--text-primary);max-width:280px;" class="truncate">${escapeHtml(inc.title)}</td>
      <td>${severityBadge(inc.severity)}</td>
      <td>${statusBadge(inc.status)}</td>
      <td style="font-size:12.5px;color:var(--text-secondary);">${escapeHtml(inc.source)}</td>
      <td style="font-size:12.5px;color:var(--text-secondary);">${escapeHtml(inc.assignee || 'Unassigned')}</td>
      <td style="font-size:12px;color:var(--text-muted);font-family:var(--font-mono);">${timeAgo(inc.created_at)}</td>
    </tr>
  `).join('');

  page.innerHTML = `
    <!-- Top KPI Grid -->
    <div class="kpi-grid">
      <div class="glass-card kpi-card">
        <div class="kpi-label">Active Incidents</div>
        <div class="kpi-value" style="color:var(--text-primary);">${s.total_incidents}</div>
        <div class="kpi-subtext" style="color:var(--text-secondary);">
          <span style="color:#FF3366;font-weight:600;">${s.critical_incidents} Critical</span> · ${s.high_incidents} High
        </div>
      </div>

      <div class="glass-card kpi-card">
        <div class="kpi-label">Active Investigations</div>
        <div class="kpi-value" style="color:#00D4FF;">${s.investigating_incidents}</div>
        <div class="kpi-subtext" style="color:var(--text-secondary);">Triaged across SOC responders</div>
      </div>

      <div class="glass-card kpi-card">
        <div class="kpi-label">Mean Time to Resolve (MTTR)</div>
        <div class="kpi-value" style="color:#00FF88;">${s.avg_mttr_hours}h</div>
        <div class="kpi-subtext" style="color:#00FF88;">↓ 42% vs baseline</div>
      </div>

      <div class="glass-card kpi-card">
        <div class="kpi-label">Automated Triage Accuracy</div>
        <div class="kpi-value" style="color:var(--accent);">94.2%</div>
        <div class="kpi-subtext" style="color:var(--text-muted);">Responsible AI Assistant</div>
      </div>
    </div>

    <!-- Charts Row -->
    <div class="grid-2 mb-4">
      <div class="glass-card" style="padding:22px;">
        <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:16px;">
          <div style="font-weight:600;font-size:14.5px;color:var(--text-primary);">Severity Ingest Distribution</div>
          <span style="font-size:11.5px;color:var(--text-muted);font-family:var(--font-mono);">PostgreSQL Stream</span>
        </div>
        <div style="height:190px;position:relative;">
          <canvas id="miniDonutChart"></canvas>
        </div>
      </div>

      <div class="glass-card" style="padding:22px;">
        <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:16px;">
          <div style="font-weight:600;font-size:14.5px;color:var(--text-primary);">Resolution Velocity (MTTR)</div>
          <span style="font-size:11.5px;color:#00FF88;font-family:var(--font-mono);">Last 8 Weeks</span>
        </div>
        <div style="height:190px;position:relative;">
          <canvas id="miniMttrChart"></canvas>
        </div>
      </div>
    </div>

    <!-- Recent Telemetry Table -->
    <div class="glass-card" style="padding:22px;">
      <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:16px;">
        <div>
          <div style="font-weight:600;font-size:15px;color:var(--text-primary);">Live Incident Queue</div>
          <div style="font-size:12px;color:var(--text-muted);">Real-time stream with automated AI triage triggers</div>
        </div>
        <button class="btn btn-secondary btn-sm" onclick="navigate('incidents')">View All Queue →</button>
      </div>

      <div style="overflow-x:auto;">
        <table class="data-table">
          <thead>
            <tr>
              <th>ID</th>
              <th>Incident Title</th>
              <th>Severity</th>
              <th>Status</th>
              <th>Source</th>
              <th>Assignee</th>
              <th>Ingested</th>
            </tr>
          </thead>
          <tbody>
            ${incRows.length ? incRows : '<tr><td colspan="7" style="text-align:center;padding:24px;color:var(--text-muted);">No security incidents recorded.</td></tr>'}
          </tbody>
        </table>
      </div>
    </div>
  `;

  setTimeout(() => {
    renderOverviewCharts();
  }, 40);
}

function renderOverviewCharts() {
  // Mini Donut Chart
  const donutCanvas = document.getElementById('miniDonutChart');
  if (donutCanvas && window.Chart) {
    if (APP.charts.miniDonut) APP.charts.miniDonut.destroy();
    const s = APP.summaryData || { critical_incidents: 3, high_incidents: 6, total_incidents: 14 };
    const crit = s.critical_incidents || 3;
    const high = s.high_incidents || 6;
    const med = Math.max((s.total_incidents || 14) - crit - high, 2);

    APP.charts.miniDonut = new Chart(donutCanvas.getContext('2d'), {
      type: 'doughnut',
      data: {
        labels: ['Critical (P1)', 'High (P2)', 'Medium / Low'],
        datasets: [{
          data: [crit, high, med],
          backgroundColor: ['#FF3366', '#FFAA00', '#00D4FF'],
          borderColor: '#151515',
          borderWidth: 3,
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        cutout: '72%',
        plugins: {
          legend: { position: 'right', labels: { color: 'rgba(255,255,255,0.7)', font: { size: 11.5 } } }
        }
      }
    });
  }

  // Mini MTTR Chart
  const mttrCanvas = document.getElementById('miniMttrChart');
  if (mttrCanvas && window.Chart) {
    if (APP.charts.miniMttr) APP.charts.miniMttr.destroy();
    APP.charts.miniMttr = new Chart(mttrCanvas.getContext('2d'), {
      type: 'line',
      data: {
        labels: ['W1', 'W2', 'W3', 'W4', 'W5', 'W6', 'W7', 'W8'],
        datasets: [{
          label: 'MTTR (hours)',
          data: [18.4, 14.2, 16.8, 12.1, 9.8, 11.4, 8.6, 10.2],
          borderColor: '#2FD463',
          backgroundColor: 'rgba(47,212,99,0.08)',
          fill: true,
          tension: 0.35,
          borderWidth: 2,
          pointRadius: 3,
          pointBackgroundColor: '#2FD463',
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: { legend: { display: false } },
        scales: {
          x: { grid: { color: 'rgba(255,255,255,0.04)' }, ticks: { color: 'rgba(255,255,255,0.4)', font: { size: 10 } } },
          y: { grid: { color: 'rgba(255,255,255,0.04)' }, ticks: { color: 'rgba(255,255,255,0.4)', font: { size: 10 } } }
        }
      }
    });
  }
}

// ============================================================
// PAGE: INCIDENTS
// ============================================================
function renderIncidents() {
  const page = document.getElementById('page-incidents');
  if (!page) return;

  const rows = (APP.incidents || []).map(inc => `
    <tr class="table-row-hover" onclick="openDrawer(${inc.id})" style="cursor:pointer;">
      <td style="font-family:var(--font-mono);font-size:12px;color:var(--accent);font-weight:600;">${inc.public_id}</td>
      <td>
        <div style="font-weight:600;color:var(--text-primary);">${escapeHtml(inc.title)}</div>
        <div style="font-size:12px;color:var(--text-muted);margin-top:2px;" class="truncate">${escapeHtml(inc.description || '')}</div>
      </td>
      <td>${severityBadge(inc.severity)}</td>
      <td>${statusBadge(inc.status)}</td>
      <td style="font-size:12.5px;color:var(--text-secondary);">${escapeHtml(inc.category || 'General')}</td>
      <td style="font-size:12px;font-family:var(--font-mono);color:var(--text-muted);">${escapeHtml(inc.source_ip || '—')}</td>
      <td style="font-size:12.5px;color:var(--text-secondary);">${escapeHtml(inc.assignee || 'Unassigned')}</td>
      <td style="font-size:12px;font-family:var(--font-mono);color:var(--text-muted);">${timeAgo(inc.created_at)}</td>
    </tr>
  `).join('');

  page.innerHTML = `
    <div class="glass-card" style="padding:22px;">
      <!-- Filter Toolbar -->
      <div style="display:flex;gap:12px;align-items:center;flex-wrap:wrap;margin-bottom:20px;">
        <div style="flex:1;min-width:220px;">
          <input class="form-input" id="inc-filter-search" placeholder="Filter by keyword, IP, host, CVE..." value="${escapeHtml(APP.filters.search)}" oninput="debounceFilterSearch(this.value)">
        </div>

        <select class="form-select" style="width:140px;" onchange="handleFilterChange('severity', this.value)">
          <option value="">All Severities</option>
          <option value="CRITICAL" ${APP.filters.severity === 'CRITICAL' ? 'selected' : ''}>Critical (P1)</option>
          <option value="HIGH" ${APP.filters.severity === 'HIGH' ? 'selected' : ''}>High (P2)</option>
          <option value="MEDIUM" ${APP.filters.severity === 'MEDIUM' ? 'selected' : ''}>Medium (P3)</option>
          <option value="LOW" ${APP.filters.severity === 'LOW' ? 'selected' : ''}>Low (P4)</option>
        </select>

        <select class="form-select" style="width:160px;" onchange="handleFilterChange('status', this.value)">
          <option value="">All Statuses</option>
          <option value="DETECTED" ${APP.filters.status === 'DETECTED' ? 'selected' : ''}>Detected</option>
          <option value="TRIAGED" ${APP.filters.status === 'TRIAGED' ? 'selected' : ''}>Triaged</option>
          <option value="INVESTIGATING" ${APP.filters.status === 'INVESTIGATING' ? 'selected' : ''}>Investigating</option>
          <option value="CONTAINED" ${APP.filters.status === 'CONTAINED' ? 'selected' : ''}>Contained</option>
          <option value="RESOLVED" ${APP.filters.status === 'RESOLVED' ? 'selected' : ''}>Resolved</option>
          <option value="CLOSED" ${APP.filters.status === 'CLOSED' ? 'selected' : ''}>Closed</option>
        </select>

        <button class="btn btn-primary btn-sm" onclick="showNewIncidentModal()">+ Ingest Incident</button>
      </div>

      <!-- Incidents Table -->
      <div style="overflow-x:auto;">
        <table class="data-table">
          <thead>
            <tr>
              <th>ID</th>
              <th>Incident Indicator & Details</th>
              <th>Severity</th>
              <th>Status</th>
              <th>Threat Vector</th>
              <th>Origin IP</th>
              <th>Responder</th>
              <th>Ingested</th>
            </tr>
          </thead>
          <tbody>
            ${rows.length ? rows : '<tr><td colspan="8" style="text-align:center;padding:36px;color:var(--text-muted);">No incidents match the active filters.</td></tr>'}
          </tbody>
        </table>
      </div>
    </div>
  `;
}

let searchTimeout = null;
function debounceFilterSearch(val) {
  clearTimeout(searchTimeout);
  searchTimeout = setTimeout(() => {
    APP.filters.search = val;
    fetchIncidentsData().then(renderIncidents);
  }, 300);
}

function handleFilterChange(key, val) {
  APP.filters[key] = val;
  fetchIncidentsData().then(renderIncidents);
}

function handleGlobalSearch(val) {
  APP.filters.search = val;
  if (APP.currentPage !== 'incidents') {
    navigate('incidents');
  } else {
    debounceFilterSearch(val);
  }
}

// ============================================================
// INCIDENT DETAIL SLIDE-OUT DRAWER
// ============================================================
async function openDrawer(incidentId) {
  const overlay = document.getElementById('drawer-overlay');
  const drawer = document.getElementById('incident-drawer');
  const titleEl = document.getElementById('drawer-title');
  const idEl = document.getElementById('drawer-id');
  const badgesEl = document.getElementById('drawer-badges');
  const bodyEl = document.getElementById('drawer-body');

  overlay.classList.add('open');
  drawer.classList.add('open');
  titleEl.textContent = 'Loading Incident Telemetry...';
  idEl.textContent = `INC-${incidentId}`;
  badgesEl.innerHTML = '';
  bodyEl.innerHTML = `
    <div style="padding:24px;">
      <div class="skeleton" style="height:24px;width:70%;margin-bottom:12px;"></div>
      <div class="skeleton" style="height:16px;width:95%;margin-bottom:8px;"></div>
      <div class="skeleton" style="height:16px;width:60%;margin-bottom:24px;"></div>
    </div>
  `;

  try {
    const inc = await incidentsApi.get(incidentId);
    APP.currentIncident = inc;
    titleEl.textContent = inc.title;
    idEl.textContent = inc.public_id;

    badgesEl.innerHTML = `
      ${severityBadge(inc.severity)}
      ${statusBadge(inc.status)}
      <span style="font-size:11px;padding:3px 8px;border-radius:12px;background:rgba(255,255,255,0.05);color:var(--text-secondary);font-family:var(--font-mono);">${inc.source}</span>
    `;

    renderDrawerBody(inc);
  } catch (err) {
    bodyEl.innerHTML = `<div style="color:#FF3366;padding:24px;">Error loading incident: ${err.message}</div>`;
  }
}

function closeDrawer() {
  document.getElementById('drawer-overlay').classList.remove('open');
  document.getElementById('incident-drawer').classList.remove('open');
  APP.currentIncident = null;
}

function renderDrawerBody(inc) {
  const bodyEl = document.getElementById('drawer-body');
  if (!bodyEl) return;

  const rawLogsHtml = (inc.raw_logs || []).map(log => `
    <div style="display:flex;gap:12px;padding:6px 0;border-bottom:1px solid rgba(255,255,255,0.03);font-family:var(--font-mono);font-size:11.5px;">
      <span style="color:var(--text-dim);width:60px;">${log.time || '12:00:00'}</span>
      <span style="color:${log.level === 'ERROR' ? '#FF3366' : log.level === 'WARN' ? '#FFAA00' : '#00D4FF'};font-weight:600;width:52px;">${log.level || 'INFO'}</span>
      <div style="flex:1;color:var(--text-secondary);">
        <span style="color:var(--text-primary);font-weight:500;">${escapeHtml(log.msg || '')}</span> — ${escapeHtml(log.detail || '')}
      </div>
    </div>
  `).join('');

  const iocsHtml = (inc.iocs || []).map(ioc => `
    <span style="display:inline-flex;align-items:center;gap:6px;padding:4px 9px;border-radius:6px;background:rgba(255,51,102,0.08);border:1px solid rgba(255,51,102,0.25);color:#FF6B8B;font-family:var(--font-mono);font-size:11.5px;margin:3px;">
      <span style="font-size:9.5px;opacity:0.75;text-transform:uppercase;">${ioc.type}:</span> ${escapeHtml(ioc.value)}
    </span>
  `).join('');

  const mitreHtml = (inc.mitre_techniques || []).map(m => `
    <span style="display:inline-flex;align-items:center;gap:6px;padding:4px 9px;border-radius:6px;background:rgba(0,212,255,0.08);border:1px solid rgba(0,212,255,0.25);color:#5CC8FF;font-family:var(--font-mono);font-size:11.5px;margin:3px;">
      <strong>${escapeHtml(m.technique_id)}</strong> ${escapeHtml(m.technique_name)}
    </span>
  `).join('');

  const latestAi = inc.ai_analyses && inc.ai_analyses.length ? inc.ai_analyses[0] : null;

  bodyEl.innerHTML = `
    <!-- Top Metadata Grid -->
    <div style="display:grid;grid-template-columns:repeat(2, 1fr);gap:12px;padding:16px 24px;background:rgba(255,255,255,0.015);border-bottom:1px solid var(--glass-border);">
      <div>
        <div style="font-size:11px;color:var(--text-muted);text-transform:uppercase;letter-spacing:0.04em;">Target System</div>
        <div style="font-size:13px;font-weight:600;color:var(--text-primary);font-family:var(--font-mono);margin-top:2px;">${escapeHtml(inc.target_system || 'Unknown')}</div>
      </div>
      <div>
        <div style="font-size:11px;color:var(--text-muted);text-transform:uppercase;letter-spacing:0.04em;">Origin IP</div>
        <div style="font-size:13px;font-weight:600;color:var(--text-primary);font-family:var(--font-mono);margin-top:2px;">${escapeHtml(inc.source_ip || '—')}</div>
      </div>
      <div>
        <div style="font-size:11px;color:var(--text-muted);text-transform:uppercase;letter-spacing:0.04em;">Assigned Responder</div>
        <div style="font-size:13px;font-weight:500;color:var(--text-secondary);margin-top:2px;">${escapeHtml(inc.assignee || 'Unassigned')}</div>
      </div>
      <div>
        <div style="font-size:11px;color:var(--text-muted);text-transform:uppercase;letter-spacing:0.04em;">Lifecycle Status</div>
        <div style="margin-top:2px;">
          <select class="form-select" style="padding:3px 8px;font-size:12px;height:28px;" onchange="handleStatusChange(${inc.id}, this.value)">
            <option value="DETECTED" ${inc.status === 'DETECTED' ? 'selected' : ''}>Detected</option>
            <option value="TRIAGED" ${inc.status === 'TRIAGED' ? 'selected' : ''}>Triaged</option>
            <option value="INVESTIGATING" ${inc.status === 'INVESTIGATING' ? 'selected' : ''}>Investigating</option>
            <option value="CONTAINMENT_PENDING" ${inc.status === 'CONTAINMENT_PENDING' ? 'selected' : ''}>Containment Pending</option>
            <option value="CONTAINED" ${inc.status === 'CONTAINED' ? 'selected' : ''}>Contained</option>
            <option value="ERADICATED" ${inc.status === 'ERADICATED' ? 'selected' : ''}>Eradicated</option>
            <option value="RESOLVED" ${inc.status === 'RESOLVED' ? 'selected' : ''}>Resolved</option>
            <option value="CLOSED" ${inc.status === 'CLOSED' ? 'selected' : ''}>Closed</option>
          </select>
        </div>
      </div>
    </div>

    <div style="padding:24px;">
      <!-- Incident Overview Description -->
      <div style="margin-bottom:24px;">
        <div style="font-size:12px;font-weight:600;color:var(--text-muted);text-transform:uppercase;margin-bottom:6px;">Summary</div>
        <div style="font-size:13.5px;line-height:1.6;color:var(--text-secondary);">${escapeHtml(inc.description || 'No description provided.')}</div>
      </div>

      <!-- AI Triage Section -->
      <div style="margin-bottom:28px;">
        <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:12px;">
          <div style="font-size:13px;font-weight:600;color:var(--text-primary);display:flex;align-items:center;gap:6px;">
            <span style="color:var(--accent);">✦</span> AI Triage & Threat Reasoning
            <span style="font-size:10.5px;padding:2px 6px;border-radius:4px;background:rgba(92,200,255,0.12);color:var(--accent);font-family:var(--font-mono);">RESPONSIBLE AI</span>
          </div>
          <div style="display:flex;gap:8px;">
            <button class="btn btn-secondary btn-sm" onclick="openIncidentInChatbot(${inc.id}, '${escapeHtml(inc.public_id)}')">
              ✦ Ask AI Co-Pilot
            </button>
            <button class="btn btn-primary btn-sm" id="run-ai-btn" onclick="runAITriage(${inc.id})">
              ${latestAi ? 'Re-run AI Triage' : '⚡ Run AI Triage'}
            </button>
          </div>
        </div>

        <div id="ai-triage-result">
          ${latestAi ? renderAIResultCard(latestAi) : `
            <div style="padding:16px;background:rgba(255,255,255,0.02);border:1px dashed var(--glass-border);border-radius:var(--radius-lg);text-align:center;color:var(--text-muted);font-size:13px;">
              Click <strong>Run AI Triage</strong> to synthesize root cause, extract IOCs, and generate containment playbooks.
            </div>
          `}
        </div>
      </div>

      <!-- IOCs & MITRE Section -->
      <div style="display:grid;grid-template-columns:1fr;gap:16px;margin-bottom:28px;">
        <div class="glass-card" style="padding:16px;">
          <div style="font-size:12px;font-weight:600;color:var(--text-muted);text-transform:uppercase;margin-bottom:8px;">Identified Indicators of Compromise (IOCs)</div>
          <div id="drawer-iocs-container">${iocsHtml || '<span style="color:var(--text-muted);font-size:12px;">No IOCs recorded yet.</span>'}</div>
        </div>

        <div class="glass-card" style="padding:16px;">
          <div style="font-size:12px;font-weight:600;color:var(--text-muted);text-transform:uppercase;margin-bottom:8px;">MITRE ATT&CK Mapping</div>
          <div id="drawer-mitre-container">${mitreHtml || '<span style="color:var(--text-muted);font-size:12px;">No MITRE techniques mapped yet.</span>'}</div>
        </div>
      </div>

      <!-- Raw Telemetry Feed -->
      <div style="margin-bottom:24px;">
        <div style="font-size:12px;font-weight:600;color:var(--text-muted);text-transform:uppercase;margin-bottom:8px;">Raw Telemetry Stream</div>
        <div style="background:#04060A;border:1px solid var(--glass-border);border-radius:var(--radius-lg);padding:14px 18px;max-height:220px;overflow-y:auto;">
          ${rawLogsHtml || '<div style="color:var(--text-dim);font-size:12px;">No logs recorded.</div>'}
        </div>
      </div>
    </div>
  `;
}

function renderAIResultCard(ai) {
  const isMock = ai.provider === 'mock' || !ai.provider;
  return `
    <div style="background:rgba(13,17,24,0.7);border:1px solid rgba(92,200,255,0.2);border-radius:var(--radius-lg);padding:18px;box-shadow:0 8px 30px rgba(0,0,0,0.4);">
      <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:12px;flex-wrap:wrap;gap:8px;">
        <div style="font-weight:600;color:var(--text-primary);font-size:14px;">
          ${escapeHtml(ai.threat_type || 'Threat Assessment')}
        </div>
        <div style="display:flex;gap:6px;align-items:center;">
          <span style="font-size:11px;padding:2px 7px;border-radius:4px;background:rgba(0,255,136,0.1);color:#00FF88;font-family:var(--font-mono);">
            Confidence: ${ai.confidence || 95}%
          </span>
          <span style="font-size:11px;padding:2px 7px;border-radius:4px;background:rgba(255,255,255,0.06);color:var(--text-muted);font-family:var(--font-mono);">
            ${isMock ? 'SIMULATED AI' : 'LIVE AI'}
          </span>
        </div>
      </div>

      <div style="font-size:13px;line-height:1.6;color:var(--text-secondary);margin-bottom:16px;">
        <strong>Root Cause Analysis:</strong> ${escapeHtml(ai.root_cause || '')}
      </div>

      <!-- Actionable Containment Playbook Recommendation -->
      <div style="background:rgba(0,0,0,0.3);border:1px solid var(--glass-border);border-radius:var(--radius-md);padding:14px;margin-top:12px;">
        <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:10px;">
          <div style="font-size:12.5px;font-weight:600;color:var(--text-primary);display:flex;align-items:center;gap:6px;">
            <span>🛡</span> Recommended Defensive Playbook
            <span style="font-size:10px;padding:1px 5px;border-radius:3px;background:rgba(255,170,0,0.15);color:#FFAA00;font-family:var(--font-mono);">SIMULATION MODE</span>
          </div>
          <button class="btn btn-primary btn-sm" style="font-size:11px;padding:4px 10px;" onclick="executeSimulatedPlaybook(${ai.incident_id || APP.currentIncident?.id})">
            Simulate Containment →
          </button>
        </div>
        <div style="font-size:12px;color:var(--text-muted);">
          Automated containment script execution under human analyst review.
        </div>
      </div>
    </div>
  `;
}

async function runAITriage(incidentId) {
  const btn = document.getElementById('run-ai-btn');
  if (btn) {
    btn.disabled = true;
    btn.textContent = 'Analyzing Telemetry...';
  }

  try {
    const result = await aiApi.triage(incidentId);
    showToast('AI Triage completed successfully', 'success');
    const updated = await incidentsApi.get(incidentId);
    APP.currentIncident = updated;
    renderDrawerBody(updated);
  } catch (err) {
    showToast(`AI Triage error: ${err.message}`, 'critical');
    if (btn) {
      btn.disabled = false;
      btn.textContent = '⚡ Run AI Triage';
    }
  }
}

async function executeSimulatedPlaybook(incidentId) {
  try {
    showToast('Simulating containment execution...', 'info');
    await playbooksApi.execute(incidentId, { execution_mode: 'SIMULATION' });
    const updated = await incidentsApi.get(incidentId);
    APP.currentIncident = updated;
    renderDrawerBody(updated);
  } catch (err) {
    showToast(`Playbook error: ${err.message}`, 'critical');
  }
}

async function handleStatusChange(incidentId, newStatus) {
  try {
    await incidentsApi.updateStatus(incidentId, newStatus);
    showToast(`Status updated to ${newStatus}`, 'info');
  } catch (err) {
    showToast(`Status error: ${err.message}`, 'critical');
  }
}

// ============================================================
// CREATE NEW INCIDENT MODAL
// ============================================================
function showNewIncidentModal() {
  const overlay = document.getElementById('new-incident-overlay');
  const modal = document.getElementById('new-incident-modal');
  if (overlay) overlay.style.display = 'block';
  if (modal) modal.style.display = 'block';
}

function closeNewIncidentModal() {
  const overlay = document.getElementById('new-incident-overlay');
  const modal = document.getElementById('new-incident-modal');
  if (overlay) overlay.style.display = 'none';
  if (modal) modal.style.display = 'none';
}

async function createNewIncident() {
  const title = document.getElementById('ni-title')?.value.trim();
  const severity = document.getElementById('ni-severity')?.value || 'MEDIUM';
  const source = document.getElementById('ni-source')?.value || 'Manual Ingest';
  const source_ip = document.getElementById('ni-ip')?.value.trim() || 'Unknown';
  const target_system = document.getElementById('ni-target')?.value.trim() || 'Unknown';
  const assignee = document.getElementById('ni-assign')?.value || 'Unassigned';

  if (!title) {
    showToast('Please enter an incident title or indicator', 'critical');
    return;
  }

  const btn = document.getElementById('create-incident-btn');
  if (btn) btn.disabled = true;

  try {
    const newInc = await incidentsApi.create({
      title,
      severity,
      source,
      source_ip,
      target_system,
      assignee,
      category: 'General Threat',
    });

    closeNewIncidentModal();
    showToast(`Incident ${newInc.public_id} created successfully!`, 'success');
    
    // Clear inputs
    if (document.getElementById('ni-title')) document.getElementById('ni-title').value = '';
    if (document.getElementById('ni-ip')) document.getElementById('ni-ip').value = '';
    if (document.getElementById('ni-target')) document.getElementById('ni-target').value = '';

    // Refresh list
    await fetchIncidentsData();
    if (APP.currentPage === 'incidents') renderIncidents();
  } catch (err) {
    showToast(`Failed to create incident: ${err.message}`, 'critical');
  } finally {
    if (btn) btn.disabled = false;
  }
}

// ============================================================
// PAGE: ANALYTICS & HEATMAP
// ============================================================
function renderAnalytics() {
  const page = document.getElementById('page-analytics');
  if (!page) return;

  const a = APP.analyticsData || {
    attack_vectors: [],
    heatmap: { systems: [], categories: [], scores: [] },
  };

  const vectorRows = (a.attack_vectors || []).map(v => `
    <div style="margin-bottom:12px;">
      <div style="display:flex;justify-content:space-between;font-size:12.5px;margin-bottom:4px;">
        <span style="color:var(--text-primary);">${escapeHtml(v.name)}</span>
        <span style="color:var(--text-muted);font-family:var(--font-mono);">${v.count} alerts (${v.pct}%)</span>
      </div>
      <div style="height:6px;background:rgba(255,255,255,0.06);border-radius:3px;overflow:hidden;">
        <div style="height:100%;width:${v.pct}%;background:var(--accent);border-radius:3px;"></div>
      </div>
    </div>
  `).join('');

  // Heatmap Cells
  const heatmap = a.heatmap || { systems: [], categories: [], scores: [] };
  const heatmapHeader = (heatmap.categories || []).map(c => `
    <th style="font-size:11px;padding:6px 4px;text-align:center;font-family:var(--font-mono);">${escapeHtml(c)}</th>
  `).join('');

  const heatmapRows = (heatmap.systems || []).map((sys, rIdx) => {
    const cells = (heatmap.categories || []).map((cat, cIdx) => {
      const score = (heatmap.scores && heatmap.scores[rIdx] && heatmap.scores[rIdx][cIdx]) || 1;
      const alpha = Math.min(score / 10, 0.95);
      const bg = score >= 8 ? `rgba(255,51,102,${alpha})` : score >= 5 ? `rgba(255,170,0,${alpha})` : `rgba(0,212,255,${alpha * 0.7})`;
      return `
        <td style="padding:4px;text-align:center;">
          <div class="heatmap-cell" style="background:${bg};padding:8px 0;font-size:11px;font-weight:600;font-family:var(--font-mono);color:#fff;" title="${sys} vs ${cat}: Risk Score ${score}/10">
            ${score}
          </div>
        </td>
      `;
    }).join('');
    return `
      <tr>
        <td style="font-size:12px;font-weight:500;color:var(--text-primary);white-space:nowrap;padding:6px 10px;">${escapeHtml(sys)}</td>
        ${cells}
      </tr>
    `;
  }).join('');

  page.innerHTML = `
    <!-- Top 30-Day Trend Chart -->
    <div class="glass-card mb-4" style="padding:22px;">
      <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:16px;">
        <div>
          <div style="font-weight:600;font-size:15px;color:var(--text-primary);">30-Day Threat Vector Frequency</div>
          <div style="font-size:12px;color:var(--text-muted);">Historical telemetry counts aggregated from PostgreSQL database</div>
        </div>
        <span style="font-size:11.5px;color:var(--accent);font-family:var(--font-mono);">Live Database Sync</span>
      </div>
      <div style="height:220px;position:relative;">
        <canvas id="analyticsTrendChart"></canvas>
      </div>
    </div>

    <!-- Attack Vectors and Heatmap Row -->
    <div class="grid-2 mb-4">
      <div class="glass-card" style="padding:22px;">
        <div style="font-weight:600;font-size:14.5px;color:var(--text-primary);margin-bottom:16px;">Attack Vector Distribution</div>
        ${vectorRows}
      </div>

      <div class="glass-card" style="padding:22px;">
        <div style="font-weight:600;font-size:14.5px;color:var(--text-primary);margin-bottom:6px;">Infrastructure Exposure Matrix</div>
        <div style="font-size:12px;color:var(--text-muted);margin-bottom:14px;">System assets mapped against threat classifications</div>
        <div style="overflow-x:auto;">
          <table style="width:100%;border-collapse:collapse;">
            <thead>
              <tr>
                <th style="font-size:11px;padding:6px 10px;text-align:left;color:var(--text-muted);">System</th>
                ${heatmapHeader}
              </tr>
            </thead>
            <tbody>
              ${heatmapRows}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  `;

  setTimeout(renderAnalyticsCharts, 40);
}

function renderAnalyticsCharts() {
  const trendCanvas = document.getElementById('analyticsTrendChart');
  if (trendCanvas && window.Chart) {
    if (APP.charts.analyticsTrend) APP.charts.analyticsTrend.destroy();
    const t = APP.analyticsData?.trends || {
      labels: ['D1', 'D2', 'D3'],
      critical: [2, 1, 3],
      high: [5, 4, 6],
      medium: [8, 7, 9],
    };

    APP.charts.analyticsTrend = new Chart(trendCanvas.getContext('2d'), {
      type: 'bar',
      data: {
        labels: t.labels,
        datasets: [
          { label: 'Critical', data: t.critical, backgroundColor: '#FF3366', borderRadius: 3 },
          { label: 'High', data: t.high, backgroundColor: '#FFAA00', borderRadius: 3 },
          { label: 'Medium', data: t.medium, backgroundColor: '#00D4FF', borderRadius: 3 },
        ]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        scales: {
          x: { stacked: true, grid: { display: false }, ticks: { color: 'rgba(255,255,255,0.4)', font: { size: 9.5 } } },
          y: { stacked: true, grid: { color: 'rgba(255,255,255,0.04)' }, ticks: { color: 'rgba(255,255,255,0.4)', font: { size: 10 } } }
        },
        plugins: {
          legend: { position: 'top', labels: { color: 'rgba(255,255,255,0.7)', font: { size: 11 } } }
        }
      }
    });
  }
}

// ============================================================
// PAGE: ADMIN (USERS, API KEYS, AUDIT LOGS)
// ============================================================
function renderAdmin(tab = 'users') {
  APP.adminTab = tab;
  const page = document.getElementById('page-admin');
  if (!page) return;

  const isViewer = (APP.user?.role || '').toLowerCase() === 'viewer';

  let contentHtml = '';
  if (tab === 'users') {
    const rows = (APP.users || []).map(u => `
      <tr>
        <td style="font-weight:600;color:var(--text-primary);">${escapeHtml(u.full_name)}</td>
        <td style="color:var(--text-secondary);font-size:12.5px;">${escapeHtml(u.email)}</td>
        <td>
          <span style="padding:3px 8px;border-radius:4px;font-size:11px;font-weight:600;background:rgba(92,200,255,0.1);color:var(--accent);font-family:var(--font-mono);">
            ${u.role}
          </span>
        </td>
        <td>
          <span style="color:${u.is_active ? '#00FF88' : '#FF3366'};font-size:12px;">● ${u.is_active ? 'Active' : 'Inactive'}</span>
        </td>
        <td style="font-size:12px;color:var(--text-muted);font-family:var(--font-mono);">${timeAgo(u.last_login)}</td>
      </tr>
    `).join('');

    contentHtml = `
      <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:16px;">
        <div style="font-weight:600;font-size:14.5px;color:var(--text-primary);">Registered SOC Operators</div>
      </div>
      <table class="data-table">
        <thead>
          <tr>
            <th>Name</th>
            <th>Email</th>
            <th>Role</th>
            <th>Status</th>
            <th>Last Active</th>
          </tr>
        </thead>
        <tbody>
          ${rows.length ? rows : '<tr><td colspan="5" style="text-align:center;padding:24px;color:var(--text-muted);">No users found.</td></tr>'}
        </tbody>
      </table>
    `;
  } else if (tab === 'keys') {
    const rows = (APP.apiKeys || []).map(k => `
      <tr>
        <td style="font-weight:600;color:var(--text-primary);">${escapeHtml(k.name)}</td>
        <td style="font-family:var(--font-mono);font-size:12px;color:var(--accent);">${escapeHtml(k.key_prefix)}</td>
        <td style="font-size:12px;color:var(--text-secondary);">${escapeHtml(k.created_by_name)}</td>
        <td>
          <span style="color:${k.status === 'active' ? '#00FF88' : '#FF3366'};font-size:12px;">● ${k.status}</span>
        </td>
        <td style="font-size:12px;font-family:var(--font-mono);color:var(--text-muted);">${k.request_count.toLocaleString()}</td>
        <td>
          ${k.status === 'active' && !isViewer ? `
            <button class="btn btn-secondary btn-sm" style="color:#FF3366;font-size:11px;" onclick="revokeApiKey(${k.id})">Revoke</button>
          ` : '—'}
        </td>
      </tr>
    `).join('');

    contentHtml = `
      <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:16px;">
        <div>
          <div style="font-weight:600;font-size:14.5px;color:var(--text-primary);">Hashed API Access Keys</div>
          <div style="font-size:12px;color:var(--text-muted);">Plaintext keys are hashed with SHA-256 and never stored</div>
        </div>
        ${!isViewer ? `<button class="btn btn-primary btn-sm" onclick="showNewApiKeyModal()">+ Generate API Key</button>` : ''}
      </div>
      <table class="data-table">
        <thead>
          <tr>
            <th>Key Name</th>
            <th>Key Identifier</th>
            <th>Creator</th>
            <th>Status</th>
            <th>Requests</th>
            <th>Action</th>
          </tr>
        </thead>
        <tbody>
          ${rows.length ? rows : '<tr><td colspan="6" style="text-align:center;padding:24px;color:var(--text-muted);">No API keys found.</td></tr>'}
        </tbody>
      </table>
    `;
  } else if (tab === 'audit') {
    const rows = (APP.auditLogs || []).map(l => `
      <tr>
        <td style="font-family:var(--font-mono);font-size:11.5px;color:var(--accent);">${escapeHtml(l.public_id)}</td>
        <td style="font-size:12px;font-weight:600;color:var(--text-primary);font-family:var(--font-mono);">${escapeHtml(l.action)}</td>
        <td style="font-size:12.5px;color:var(--text-secondary);">${escapeHtml(l.user_email || 'System')}</td>
        <td style="font-size:12px;color:var(--text-muted);max-width:300px;" class="truncate">${escapeHtml(l.detail)}</td>
        <td style="font-size:11.5px;font-family:var(--font-mono);color:var(--text-dim);">${escapeHtml(l.ip_address || '127.0.0.1')}</td>
        <td style="font-size:11.5px;font-family:var(--font-mono);color:var(--text-muted);">${timeAgo(l.timestamp)}</td>
      </tr>
    `).join('');

    contentHtml = `
      <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:16px;">
        <div>
          <div style="font-weight:600;font-size:14.5px;color:var(--text-primary);">Tamper-Evident Audit Trail</div>
          <div style="font-size:12px;color:var(--text-muted);">Immutable security event logging stored in PostgreSQL</div>
        </div>
      </div>
      <table class="data-table">
        <thead>
          <tr>
            <th>Audit ID</th>
            <th>Action</th>
            <th>Actor</th>
            <th>Details</th>
            <th>IP Address</th>
            <th>Timestamp</th>
          </tr>
        </thead>
        <tbody>
          ${rows.length ? rows : '<tr><td colspan="6" style="text-align:center;padding:24px;color:var(--text-muted);">No audit logs recorded yet.</td></tr>'}
        </tbody>
      </table>
    `;
  }

  page.innerHTML = `
    <div class="glass-card" style="padding:22px;">
      <div style="display:flex;gap:12px;border-bottom:1px solid var(--glass-border);padding-bottom:12px;margin-bottom:20px;">
        <button class="btn ${tab === 'users' ? 'btn-primary' : 'btn-secondary'} btn-sm" onclick="renderAdmin('users')">Operators & RBAC</button>
        <button class="btn ${tab === 'keys' ? 'btn-primary' : 'btn-secondary'} btn-sm" onclick="renderAdmin('keys')">API Credentials</button>
        <button class="btn ${tab === 'audit' ? 'btn-primary' : 'btn-secondary'} btn-sm" onclick="renderAdmin('audit')">Audit Logs</button>
      </div>
      ${contentHtml}
    </div>
  `;
}

async function revokeApiKey(id) {
  if (!confirm('Are you sure you want to revoke this API key?')) return;
  try {
    await apiKeysApi.revoke(id);
    showToast('API Key revoked successfully', 'info');
    await fetchAdminData();
    renderAdmin('keys');
  } catch (err) {
    showToast(`Revocation error: ${err.message}`, 'critical');
  }
}

async function showNewApiKeyModal() {
  const name = prompt('Enter a descriptive name for the new API Key:');
  if (!name) return;

  try {
    const res = await apiKeysApi.create({ name, permissions: ['incidents:read', 'incidents:write'] });
    alert(`API KEY GENERATED SUCCESSFULLY!\n\nToken:\n${res.raw_key}\n\nWARNING: Store this key securely. It will NEVER be shown again.`);
    await fetchAdminData();
    renderAdmin('keys');
  } catch (err) {
    showToast(`Key generation error: ${err.message}`, 'critical');
  }
}

// ============================================================
// PAGE: SETTINGS & CONNECTED INTEGRATIONS
// ============================================================
function renderSettings() {
  const page = document.getElementById('page-settings');
  if (!page) return;

  const cards = (APP.integrations || []).map(integ => {
    const isConn = integ.status === 'CONNECTED';
    const isSim = integ.status === 'SIMULATED';
    const statusColor = isConn ? '#00FF88' : isSim ? '#FFAA00' : '#FF3366';

    return `
      <div class="glass-card" style="padding:20px;display:flex;flex-direction:column;justify-content:space-between;">
        <div>
          <div style="display:flex;justify-content:space-between;align-items:flex-start;margin-bottom:8px;">
            <div style="font-weight:600;font-size:14.5px;color:var(--text-primary);">${escapeHtml(integ.name)}</div>
            <span style="font-size:11px;padding:2px 7px;border-radius:4px;background:rgba(255,255,255,0.06);color:${statusColor};font-family:var(--font-mono);font-weight:600;">
              ${integ.status}
            </span>
          </div>
          <div style="font-size:12px;color:var(--text-muted);margin-bottom:12px;">
            Provider: <span style="color:var(--text-secondary);text-transform:uppercase;">${escapeHtml(integ.provider)}</span> · Category: ${escapeHtml(integ.category)}
          </div>
          <div style="font-size:11.5px;color:var(--text-dim);font-family:var(--font-mono);margin-bottom:14px;" class="truncate">
            ${escapeHtml(integ.endpoint_url || 'https://api.internal.corp')}
          </div>
        </div>

        <div style="display:flex;gap:8px;justify-content:flex-end;border-top:1px solid rgba(255,255,255,0.04);padding-top:12px;">
          <button class="btn btn-secondary btn-sm" onclick="testIntegrationConnectivity(${integ.id})">Test Connection</button>
        </div>
      </div>
    `;
  }).join('');

  page.innerHTML = `
    <div style="margin-bottom:20px;">
      <div style="font-weight:600;font-size:15px;color:var(--text-primary);">Security Orchestration Connectors</div>
      <div style="font-size:12px;color:var(--text-muted);">Configured telemetry endpoints, SIEM streaming, and response connectors</div>
    </div>
    <div class="grid-3">
      ${cards.length ? cards : '<div style="color:var(--text-muted);">No integrations configured.</div>'}
    </div>
  `;
}

async function testIntegrationConnectivity(id) {
  try {
    showToast('Testing connectivity with endpoint...', 'info');
    const res = await integrationsApi.test(id);
    showToast(`${res.name}: ${res.message}`, res.status === 'CONNECTED' ? 'success' : 'info');
    await fetchSettingsData();
    renderSettings();
  } catch (err) {
    showToast(`Test error: ${err.message}`, 'critical');
  }
}

// ============================================================
// PAGE: AI THREAT ASSISTANT / CHATBOT
// ============================================================
function formatChatMarkdown(text) {
  if (!text) return '';
  let str = escapeHtml(text);
  // Code blocks: ```...```
  str = str.replace(/```([a-zA-Z0-9_-]*)\n?([\s\S]*?)```/g, (m, lang, code) => {
    return `<pre><code>${code.trim()}</code></pre>`;
  });
  // Inline code: `...`
  str = str.replace(/`([^`]+)`/g, '<code>$1</code>');
  // Bold: **...**
  str = str.replace(/\*\*([^*]+)\*\*/g, '<strong>$1</strong>');
  // Bullet items
  str = str.replace(/^\s*[-*]\s+(.+)$/gm, '<li>$1</li>');
  str = str.replace(/(<li>.*<\/li>)/gs, '<ul>$1</ul>');
  str = str.replace(/<\/ul>\s*<ul>/g, '');
  // Linebreaks outside pre blocks
  const parts = str.split(/(<pre>[\s\S]*?<\/pre>)/g);
  for (let i = 0; i < parts.length; i++) {
    if (!parts[i].startsWith('<pre>')) {
      parts[i] = parts[i].replace(/\n/g, '<br>');
    }
  }
  return parts.join('');
}

function renderChatbot() {
  const page = document.getElementById('page-chatbot');
  if (!page) return;

  const currentConv = APP.chatbot.conversations.find(c => c.id === APP.chatbot.currentConversationId);
  const aiCfg = APP.chatbot.aiConfig || { provider: 'mock', demo_mode: true };
  const isMock = aiCfg.demo_mode || aiCfg.provider === 'mock';

  const incidentOptions = (APP.incidents || []).map(inc => `
    <option value="${inc.id}" ${APP.chatbot.selectedIncidentId == inc.id ? 'selected' : ''}>
      ${escapeHtml(inc.public_id)} — ${escapeHtml(inc.title.substring(0, 36))}...
    </option>
  `).join('');

  const convListHtml = (APP.chatbot.conversations || []).map(conv => `
    <div class="chat-thread-item ${conv.id === APP.chatbot.currentConversationId ? 'active' : ''}" onclick="selectChatConversation(${conv.id})">
      <div style="flex:1;min-width:0;">
        <div class="chat-thread-title">${escapeHtml(conv.title || 'Threat Investigation')}</div>
        <div class="chat-thread-meta">${timeAgo(conv.updated_at || conv.created_at)} · ${conv.message_count || 0} msgs</div>
      </div>
      <button class="chat-thread-delete" title="Delete conversation" onclick="event.stopPropagation(); deleteChatConversation(${conv.id})">×</button>
    </div>
  `).join('');

  page.innerHTML = `
    <div class="chatbot-container">
      <!-- SIDEBAR -->
      <div class="chat-sidebar">
        <div class="chat-sidebar-header">
          <button class="chat-sidebar-btn" onclick="startNewChatConversation()">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><line x1="12" y1="5" x2="12" y2="19"/><line x1="5" y1="12" x2="19" y2="12"/></svg>
            New Threat Thread
          </button>
        </div>

        <div style="margin-bottom:12px;">
          <div style="font-size:11px;font-weight:600;text-transform:uppercase;color:var(--text-muted);margin-bottom:6px;">Incident Telemetry Context</div>
          <select class="form-select" id="chat-incident-select" style="font-size:12px;padding:6px 10px;height:auto;" onchange="setChatIncidentContext(this.value)">
            <option value="">No incident attached (General)</option>
            ${incidentOptions}
          </select>
        </div>

        <div style="font-size:11px;font-weight:600;text-transform:uppercase;color:var(--text-muted);margin-bottom:8px;">Recent Sessions</div>
        <div class="chat-threads-list" id="chat-threads-list">
          ${convListHtml || '<div style="color:var(--text-muted);font-size:12px;padding:8px 4px;">No previous conversations.</div>'}
        </div>

        <div class="chat-quick-prompts">
          <div class="chat-quick-prompts-label">Quick Threat Inquiries</div>
          <button class="quick-prompt-chip" onclick="quickPromptClick('Analyze Cobalt Strike beaconing intervals and recommend EDR block rules')">
            ✦ Cobalt Strike beaconing rules
          </button>
          <button class="quick-prompt-chip" onclick="quickPromptClick('Draft an immediate containment playbook for suspected ransomware activity')">
            ✦ Ransomware containment playbook
          </button>
          <button class="quick-prompt-chip" onclick="quickPromptClick('Explain how to deobfuscate PowerShell encoded commands in SIEM logs')">
            ✦ PowerShell deobfuscation
          </button>
          <button class="quick-prompt-chip" onclick="quickPromptClick('Draft an executive incident briefing for our CISO following NIST SP 800-61r2')">
            ✦ CISO executive briefing draft
          </button>
        </div>
      </div>

      <!-- MAIN CHAT AREA -->
      <div class="chat-main">
        <div class="chat-main-header">
          <div class="chat-header-info">
            <div class="chat-bot-avatar">
              <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                <path d="M12 2a2 2 0 0 1 2 2v2a2 2 0 0 1-2 2 2 2 0 0 1-2-2V4a2 2 0 0 1 2-2z"/>
                <path d="m4.93 10.93 1.41 1.41"/>
                <path d="M2 18h2"/>
                <path d="M20 18h2"/>
                <path d="m19.07 10.93-1.41 1.41"/>
                <path d="M22 22H2"/>
                <path d="m8 22 4-10 4 10"/>
              </svg>
            </div>
            <div>
              <div class="chat-header-title" id="chat-active-title">
                ${escapeHtml(currentConv ? currentConv.title : 'AI Threat Investigation Assistant')}
              </div>
              <div class="chat-header-status">
                <span class="status-dot live" style="width:6px;height:6px;background:var(--success);"></span>
                Active Co-Pilot · 
                <span style="font-family:var(--font-mono);color:${isMock ? 'var(--warning)' : 'var(--accent)'};font-weight:600;">
                  ${isMock ? '[SIMULATED MOCK AI]' : `[MODEL: ${aiCfg.provider.toUpperCase()}]`}
                </span>
                ${APP.chatbot.selectedIncidentId ? `· <span style="color:var(--accent-cyan);font-family:var(--font-mono);">Context: Inc #${APP.chatbot.selectedIncidentId}</span>` : ''}
              </div>
            </div>
          </div>

          <div style="display:flex;gap:8px;">
            <button class="btn btn-secondary btn-sm" onclick="startNewChatConversation()" title="Start New Session">
              + New Chat
            </button>
          </div>
        </div>

        <div class="chat-messages-container" id="chat-messages-container"></div>

        <div class="chat-input-area">
          <div class="chat-input-row">
            <textarea
              class="chat-textarea"
              id="chat-textarea"
              placeholder="Ask the AI co-pilot about IOCs, MITRE ATT&CK techniques, forensic queries, or containment playbooks... (Press Enter to send, Shift+Enter for newline)"
              rows="1"
              onkeydown="handleChatKeydown(event)"
            ></textarea>
            <button class="chat-send-btn" id="chat-send-btn" onclick="submitChatMessage()">
              <span>Send</span>
              <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><line x1="22" y1="2" x2="11" y2="13"/><polygon points="22 2 15 22 11 13 2 9 22 2"/></svg>
            </button>
          </div>
          <div style="display:flex;justify-content:space-between;align-items:center;font-size:11px;color:var(--text-muted);padding:0 4px;">
            <span>Input sanitized for security · Rate limited to 20 queries/min</span>
            <span>Shift + Enter for new line</span>
          </div>
        </div>
      </div>
    </div>
  `;

  renderChatMessages();
}

function renderChatMessages() {
  const container = document.getElementById('chat-messages-container');
  if (!container) return;

  const msgs = APP.chatbot.messages || [];

  if (msgs.length === 0 && !APP.chatbot.sending) {
    container.innerHTML = `
      <div style="background:var(--glass-subtle);border:1px dashed var(--glass-border);border-radius:var(--radius-lg);padding:32px 24px;text-align:center;max-width:540px;margin:auto;">
        <div class="chat-bot-avatar" style="margin:0 auto 14px auto;width:48px;height:48px;">
          <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <path d="M12 2a2 2 0 0 1 2 2v2a2 2 0 0 1-2 2 2 2 0 0 1-2-2V4a2 2 0 0 1 2-2z"/>
            <path d="m4.93 10.93 1.41 1.41"/><path d="M2 18h2"/><path d="M20 18h2"/><path d="m19.07 10.93-1.41 1.41"/>
            <path d="M22 22H2"/><path d="m8 22 4-10 4 10"/>
          </svg>
        </div>
        <div style="font-size:15px;font-weight:600;color:var(--text-primary);margin-bottom:6px;">CyberSentinel AI Threat Co-Pilot</div>
        <div style="font-size:12.5px;color:var(--text-secondary);line-height:1.6;margin-bottom:18px;">
          Your contextual incident co-pilot. I analyze telemetry, map attacker behaviors to MITRE ATT&CK techniques, provide IOC threat indicators, and draft NIST SP 800-61 containment playbooks.
        </div>
        <div style="display:flex;gap:8px;flex-wrap:wrap;justify-content:center;">
          <span class="badge" style="background:rgba(110,168,255,0.1);color:var(--accent);">MITRE ATT&CK Mapping</span>
          <span class="badge" style="background:rgba(103,232,249,0.1);color:var(--accent-cyan);">IOC Enrichment</span>
          <span class="badge" style="background:rgba(251,191,36,0.1);color:var(--warning);">SOAR Guidance</span>
        </div>
      </div>
    `;
    return;
  }

  let html = msgs.map(msg => {
    const isUser = msg.role === 'user';
    return `
      <div class="chat-message-row ${isUser ? 'user' : 'assistant'}">
        <div style="width:32px;height:32px;border-radius:var(--radius-sm);background:${isUser ? 'var(--glass-active)' : 'rgba(110,168,255,0.15)'};border:1px solid ${isUser ? 'var(--glass-border-accent)' : 'var(--glass-border)'};display:flex;align-items:center;justify-content:center;font-size:11px;font-weight:600;color:${isUser ? 'var(--accent)' : 'var(--accent-cyan)'};flex-shrink:0;">
          ${isUser ? 'YOU' : 'AI'}
        </div>
        <div class="chat-message-bubble">
          ${!isUser ? `
            <div class="chat-bubble-badge ${msg.is_mock ? 'simulated' : 'ai-real'}">
              ${msg.is_mock ? '[SIMULATED AI]' : '[AI GENERATED]'}
            </div>
          ` : ''}
          <div>${formatChatMarkdown(msg.content)}</div>
          <div style="font-size:10.5px;color:var(--text-dim);margin-top:6px;text-align:${isUser ? 'right' : 'left'};">
            ${timeAgo(msg.created_at)}
          </div>
        </div>
      </div>
    `;
  }).join('');

  if (APP.chatbot.sending) {
    html += `
      <div class="chat-message-row assistant">
        <div style="width:32px;height:32px;border-radius:var(--radius-sm);background:rgba(110,168,255,0.15);border:1px solid var(--glass-border);display:flex;align-items:center;justify-content:center;font-size:11px;font-weight:600;color:var(--accent-cyan);flex-shrink:0;">
          AI
        </div>
        <div class="chat-typing">
          <div class="chat-typing-dot"></div>
          <div class="chat-typing-dot"></div>
          <div class="chat-typing-dot"></div>
          <span style="font-size:11.5px;color:var(--text-muted);margin-left:6px;">Synthesizing threat intelligence...</span>
        </div>
      </div>
    `;
  }

  container.innerHTML = html;
  container.scrollTop = container.scrollHeight;
}

function handleChatKeydown(event) {
  if (event.key === 'Enter' && !event.shiftKey) {
    event.preventDefault();
    submitChatMessage();
  }
}

async function submitChatMessage(overrideText) {
  if (APP.chatbot.sending) return;

  const textarea = document.getElementById('chat-textarea');
  const text = (overrideText || (textarea ? textarea.value : '')).trim();
  if (!text) return;

  if (textarea) {
    textarea.value = '';
    textarea.style.height = '44px';
  }

  APP.chatbot.sending = true;

  // Add optimistic user message
  const userMsg = {
    id: 'temp-' + Date.now(),
    role: 'user',
    content: text,
    created_at: new Date().toISOString(),
    is_mock: false,
  };
  APP.chatbot.messages.push(userMsg);
  renderChatMessages();

  try {
    const res = await chatbotApi.send(
      text,
      APP.chatbot.currentConversationId,
      APP.chatbot.selectedIncidentId
    );

    if (!APP.chatbot.currentConversationId && res.conversation_id) {
      APP.chatbot.currentConversationId = res.conversation_id;
    }

    // Refresh conversation threads and full message list
    const [convs, msgs] = await Promise.all([
      chatbotApi.listConversations().catch(() => APP.chatbot.conversations),
      chatbotApi.getMessages(res.conversation_id).catch(() => [
        ...APP.chatbot.messages,
        {
          id: Date.now(),
          role: 'assistant',
          content: res.response,
          is_mock: res.is_mock,
          created_at: new Date().toISOString(),
        }
      ]),
    ]);

    APP.chatbot.conversations = convs;
    APP.chatbot.messages = msgs;
  } catch (err) {
    showToast(`AI Assistant error: ${err.message}`, 'critical');
  } finally {
    APP.chatbot.sending = false;
    renderChatbot();
    const container = document.getElementById('chat-messages-container');
    if (container) container.scrollTop = container.scrollHeight;
  }
}

async function selectChatConversation(id) {
  APP.chatbot.currentConversationId = id;
  try {
    const msgs = await chatbotApi.getMessages(id);
    APP.chatbot.messages = msgs || [];
  } catch (err) {
    showToast(`Error loading thread: ${err.message}`, 'critical');
  }
  renderChatbot();
}

function startNewChatConversation() {
  APP.chatbot.currentConversationId = null;
  APP.chatbot.messages = [];
  renderChatbot();
  const textarea = document.getElementById('chat-textarea');
  if (textarea) textarea.focus();
}

async function deleteChatConversation(id) {
  try {
    await chatbotApi.deleteConversation(id);
    showToast('Conversation deleted', 'info');
    if (APP.chatbot.currentConversationId === id) {
      APP.chatbot.currentConversationId = null;
      APP.chatbot.messages = [];
    }
    await fetchChatbotData();
    renderChatbot();
  } catch (err) {
    showToast(`Error deleting conversation: ${err.message}`, 'critical');
  }
}

function setChatIncidentContext(incId) {
  APP.chatbot.selectedIncidentId = incId ? parseInt(incId) : null;
  renderChatbot();
}

async function openIncidentInChatbot(incId, publicId) {
  closeDrawer();
  APP.chatbot.selectedIncidentId = incId;
  APP.chatbot.currentConversationId = null;
  APP.chatbot.messages = [];
  await navigate('chatbot');
  setTimeout(() => {
    submitChatMessage(`Please correlate all indicators, investigate attack progression, and recommend containment steps for incident ${publicId}.`);
  }, 300);
}

function quickPromptClick(promptText) {
  submitChatMessage(promptText);
}

// ============================================================
// PAGE: ALERT GENERATOR & SIMULATOR
// ============================================================
function renderAlertGen() {
  const page = document.getElementById('page-alertgen');
  if (!page) return;

  const cats = APP.alertGen.categories || [];
  const status = APP.alertGen.status || { simulated_incidents_total: 0, scheduler_running: true };

  const categoryCards = cats.map(cat => {
    const sev = cat.default_severity || 'HIGH';
    return `
      <div class="scenario-card">
        <div>
          <div class="scenario-card-header">
            ${severityBadge(sev)}
            <span class="scenario-pill">${escapeHtml(cat.source)}</span>
          </div>
          <div class="scenario-card-title">${escapeHtml(cat.label)}</div>
          <div class="scenario-card-desc">${escapeHtml(cat.description)}</div>
          <div class="scenario-meta-row">
            <span class="scenario-pill" style="color:var(--accent-cyan);">${escapeHtml(cat.mitre_technique || 'MITRE ATT&CK')}</span>
            <span class="scenario-pill" style="color:var(--warning);">[SIMULATED]</span>
          </div>
        </div>
        <div style="margin-top:14px;border-top:1px solid rgba(255,255,255,0.05);padding-top:12px;">
          <button class="btn btn-secondary btn-sm" style="width:100%;justify-content:center;" onclick="generateSingleScenario('${cat.key}', '${sev}')">
            ⚡ Simulate Incident
          </button>
        </div>
      </div>
    `;
  }).join('');

  const catOptions = cats.map(c => `<option value="${c.key}">${escapeHtml(c.label)}</option>`).join('');

  const recentRows = (APP.alertGen.recentGenerated || []).slice(0, 10).map(inc => `
    <tr>
      <td style="font-family:var(--font-mono);font-weight:600;color:var(--accent);">${escapeHtml(inc.public_id)}</td>
      <td style="font-weight:500;">
        ${escapeHtml(inc.title)}
        <span class="badge" style="background:rgba(251,191,36,0.12);color:var(--warning);font-size:10px;margin-left:6px;">SIMULATED</span>
      </td>
      <td>${severityBadge(inc.severity)}</td>
      <td style="font-family:var(--font-mono);font-size:12px;">${escapeHtml(inc.source)}</td>
      <td style="font-family:var(--font-mono);font-size:12px;color:var(--text-muted);">${escapeHtml(inc.target_system || '—')}</td>
      <td style="color:var(--text-muted);font-size:11.5px;">${timeAgo(inc.created_at)}</td>
      <td>
        <button class="btn btn-secondary btn-sm" onclick="openDrawer(${inc.id})">Inspect</button>
      </td>
    </tr>
  `).join('');

  page.innerHTML = `
    <!-- Top Hero Card -->
    <div class="alertgen-header-card">
      <div>
        <div style="display:flex;align-items:center;gap:10px;margin-bottom:6px;">
          <div class="status-dot live" style="background:var(--warning);box-shadow:0 0 10px var(--warning);"></div>
          <span style="font-size:16px;font-weight:600;color:var(--text-primary);">Synthetic Security Telemetry Simulator</span>
          <span class="badge" style="background:rgba(251,191,36,0.15);color:var(--warning);">TESTING HARNESS</span>
        </div>
        <div style="font-size:13px;color:var(--text-secondary);max-width:650px;">
          Inject realistic MITRE ATT&CK attack vectors directly into the telemetry pipeline, PostgreSQL database, and real-time WebSocket feeds. Perfect for validation of detection rules, triage workflows, and analyst readiness.
        </div>
      </div>

      <div style="display:flex;gap:12px;flex-wrap:wrap;">
        <div class="alertgen-kpi-badge">
          <div style="font-size:22px;font-weight:700;font-family:var(--font-mono);color:var(--accent);">${cats.length}</div>
          <div style="font-size:11.5px;color:var(--text-muted);line-height:1.2;">Threat<br>Templates</div>
        </div>
        <div class="alertgen-kpi-badge">
          <div style="font-size:22px;font-weight:700;font-family:var(--font-mono);color:var(--warning);" id="total-simulated-count">${status.simulated_incidents_total || 0}</div>
          <div style="font-size:11.5px;color:var(--text-muted);line-height:1.2;">Total Simulated<br>Incidents</div>
        </div>
      </div>
    </div>

    <!-- Batch Generator Form Bar -->
    <div class="glass-card" style="padding:18px 24px;margin-bottom:24px;">
      <div style="font-size:13px;font-weight:600;color:var(--text-primary);margin-bottom:12px;display:flex;align-items:center;gap:8px;">
        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/></svg>
        Bulk Telemetry Burst Generator
      </div>
      <div style="display:grid;grid-template-columns:1fr 1fr 1fr auto;gap:14px;align-items:flex-end;">
        <div class="form-group">
          <label class="form-label">Attack Category</label>
          <select class="form-select" id="batch-cat">
            <option value="">Random / Mixed Threat Vectors</option>
            ${catOptions}
          </select>
        </div>
        <div class="form-group">
          <label class="form-label">Severity Level</label>
          <select class="form-select" id="batch-sev">
            <option value="">Default per template</option>
            <option value="CRITICAL">Force CRITICAL</option>
            <option value="HIGH">Force HIGH</option>
            <option value="MEDIUM">Force MEDIUM</option>
            <option value="LOW">Force LOW</option>
          </select>
        </div>
        <div class="form-group">
          <label class="form-label">Incident Count (1-20): <span id="batch-count-val" style="color:var(--accent);font-family:var(--font-mono);font-weight:600;">5</span></label>
          <input type="range" class="form-input" id="batch-count" min="1" max="20" value="5" oninput="document.getElementById('batch-count-val').textContent = this.value" style="padding:4px 0;">
        </div>
        <div>
          <button class="btn btn-primary" id="btn-batch-gen" onclick="generateBatchScenarios()" style="height:40px;white-space:nowrap;">
            ⚡ Inject Batch Telemetry
          </button>
        </div>
      </div>
    </div>

    <!-- Threat Scenarios Library -->
    <div style="margin-bottom:14px;display:flex;justify-content:space-between;align-items:center;">
      <div style="font-size:14px;font-weight:600;color:var(--text-primary);">Pre-Configured Attack Scenarios</div>
      <div style="font-size:12px;color:var(--text-muted);">Clicking any scenario ingests immediate telemetry & broadcasts real-time events</div>
    </div>
    <div class="scenario-grid">
      ${categoryCards}
    </div>

    <!-- Recent Ingestion Feed -->
    <div class="card" style="margin-top:24px;">
      <div class="card-header" style="display:flex;justify-content:space-between;align-items:center;">
        <div class="card-title">Recent Simulated Alerts in Ingestion Queue</div>
        <span style="font-size:11px;color:var(--text-muted);font-family:var(--font-mono);">Real-Time DB State</span>
      </div>
      <div class="card-body" style="padding:0;">
        <div class="table-wrap">
          <table class="data-table">
            <thead>
              <tr>
                <th>Incident ID</th>
                <th>Title / Attack Pattern</th>
                <th>Severity</th>
                <th>Source</th>
                <th>Target Asset</th>
                <th>Generated</th>
                <th>Action</th>
              </tr>
            </thead>
            <tbody>
              ${recentRows || '<tr><td colspan="7" style="text-align:center;padding:24px;color:var(--text-muted);">No simulated incidents in current session. Click any scenario above to generate.</td></tr>'}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  `;
}

async function generateSingleScenario(catKey, sev) {
  try {
    showToast(`Injecting scenario: ${catKey}...`, 'info');
    const res = await alertGenApi.generateSingle(catKey, sev);
    const inc = res.incident;

    APP.alertGen.recentGenerated.unshift(inc);
    if (!APP.alertGen.status) APP.alertGen.status = { simulated_incidents_total: 0 };
    APP.alertGen.status.simulated_incidents_total = (APP.alertGen.status.simulated_incidents_total || 0) + 1;

    showToast(`[SIMULATED] Incident created: ${inc.public_id} (${inc.severity})`, 'success');
    await updateSidebarCounts();
    renderAlertGen();
  } catch (err) {
    showToast(`Scenario injection error: ${err.message}`, 'critical');
  }
}

async function generateBatchScenarios() {
  const cat = document.getElementById('batch-cat')?.value || null;
  const sev = document.getElementById('batch-sev')?.value || null;
  const count = parseInt(document.getElementById('batch-count')?.value || '5', 10);

  const btn = document.getElementById('btn-batch-gen');
  if (btn) {
    btn.disabled = true;
    btn.textContent = 'Injecting Stream...';
  }

  try {
    showToast(`Generating ${count} synthetic telemetry events...`, 'info');
    const res = await alertGenApi.generateBatch(count, cat, sev);
    const incs = res.incidents || [];

    incs.forEach(inc => APP.alertGen.recentGenerated.unshift(inc));
    if (!APP.alertGen.status) APP.alertGen.status = { simulated_incidents_total: 0 };
    APP.alertGen.status.simulated_incidents_total = (APP.alertGen.status.simulated_incidents_total || 0) + res.count;

    showToast(`Successfully injected ${res.count} simulated incidents into SOC queue`, 'success');
    await updateSidebarCounts();
    renderAlertGen();
  } catch (err) {
    showToast(`Batch generation error: ${err.message}`, 'critical');
  } finally {
    if (btn) {
      btn.disabled = false;
      btn.textContent = '⚡ Inject Batch Telemetry';
    }
  }
}

// ============================================================
// PAGE: EMAIL NOTIFICATIONS & DETECTION RULES
// ============================================================
function renderEmail() {
  const page = document.getElementById('page-email');
  if (!page) return;

  const cfg = APP.email.config || { email_enabled: false, demo_mode: true, sender_email: 'alerts@cybersentinel.local' };
  const tab = APP.email.currentTab || 'rules';

  const rulesHtml = (APP.email.rules || []).map(r => `
    <div class="rule-card">
      <div class="rule-header">
        <div>
          <div style="font-size:14.5px;font-weight:600;color:var(--text-primary);display:flex;align-items:center;gap:8px;">
            ${escapeHtml(r.name)}
            <span class="badge ${r.severity.toLowerCase()}">${escapeHtml(r.severity)}</span>
          </div>
          <div style="font-size:12px;color:var(--text-muted);margin-top:3px;">
            Type: <span style="font-family:var(--font-mono);color:var(--accent);">${escapeHtml(r.rule_type)}</span> · Cooldown: ${r.cooldown_minutes} min
            ${r.last_triggered_at ? ` · Last fired: ${timeAgo(r.last_triggered_at)}` : ''}
          </div>
        </div>
        <div style="display:flex;align-items:center;gap:14px;">
          <label class="rule-switch" title="Toggle rule active state">
            <input type="checkbox" ${r.enabled ? 'checked' : ''} onchange="toggleDetectionRule(${r.id}, this.checked)">
            <span class="rule-slider"></span>
          </label>
          <button class="btn btn-secondary btn-sm" style="color:var(--critical);border-color:rgba(248,113,113,0.3);" onclick="deleteDetectionRule(${r.id})" title="Delete rule">
            Delete
          </button>
        </div>
      </div>
      <div style="font-size:12.5px;color:var(--text-secondary);line-height:1.5;">
        ${escapeHtml(r.description || 'No description.')}
      </div>
    </div>
  `).join('');

  const logsRows = (APP.email.logs || []).map(log => `
    <tr>
      <td style="font-family:var(--font-mono);font-size:11.5px;color:var(--text-muted);">${fmtDate(log.created_at)}</td>
      <td style="font-weight:500;">${escapeHtml(log.recipient)}</td>
      <td>${escapeHtml(log.subject)}</td>
      <td>
        <span class="status-badge ${log.status === 'SENT' ? 'closed' : log.status === 'SIMULATION' ? 'investigating' : 'open'}">
          ${log.status}
        </span>
      </td>
      <td>
        <span class="badge" style="background:${log.is_simulation ? 'rgba(251,191,36,0.12)' : 'rgba(74,222,128,0.12)'};color:${log.is_simulation ? 'var(--warning)' : 'var(--success)'};">
          ${log.is_simulation ? 'SIMULATED' : 'LIVE SMTP'}
        </span>
      </td>
      <td style="font-family:var(--font-mono);font-size:11px;color:var(--text-dim);" class="truncate" style="max-width:200px;">
        ${escapeHtml(log.provider_response || '—')}
      </td>
    </tr>
  `).join('');

  page.innerHTML = `
    <!-- Top Configuration Hero -->
    <div class="email-hero-bar">
      <div>
        <div style="display:flex;align-items:center;gap:8px;margin-bottom:4px;">
          <div class="status-dot live" style="background:${cfg.email_enabled && !cfg.demo_mode ? 'var(--success)' : 'var(--warning)'};"></div>
          <span style="font-size:14px;font-weight:600;color:var(--text-primary);">
            Email Dispatch Engine: ${cfg.email_enabled && !cfg.demo_mode ? 'Production SMTP Active' : 'Simulation Mode'}
          </span>
          <span class="badge" style="background:${cfg.demo_mode ? 'rgba(251,191,36,0.15)' : 'rgba(74,222,128,0.15)'};color:${cfg.demo_mode ? 'var(--warning)' : 'var(--success)'};">
            ${cfg.demo_mode ? '[SIMULATED / DEMO]' : 'LIVE'}
          </span>
        </div>
        <div style="font-size:12px;color:var(--text-muted);">
          ${cfg.demo_mode ? 'Dispatches are logged and simulated without connecting to external SMTP servers.' : 'Configured to route security alerts through secure SMTP.'}
          Sender: <span style="font-family:var(--font-mono);color:var(--text-secondary);">${escapeHtml(cfg.sender_email || 'alerts@cybersentinel.local')}</span>
        </div>
      </div>

      <!-- Test Email Dispatcher -->
      <div style="display:flex;gap:8px;align-items:center;">
        <input type="email" id="test-email-input" class="form-input" style="width:230px;height:36px;font-size:12px;" placeholder="analyst@soc.corp" value="${APP.user ? escapeHtml(APP.user.email) : ''}">
        <button class="btn btn-secondary btn-sm" id="btn-test-email" onclick="sendTestSecurityEmail()" style="height:36px;">
          Send Test Alert
        </button>
      </div>
    </div>

    <!-- Tabs Navigation -->
    <div class="email-subtabs">
      <button class="email-subtab-btn ${tab === 'rules' ? 'active' : ''}" onclick="switchEmailTab('rules')">
        Detection & Alert Rules (${APP.email.rules.length})
      </button>
      <button class="email-subtab-btn ${tab === 'logs' ? 'active' : ''}" onclick="switchEmailTab('logs')">
        Dispatch Audit Trail (${APP.email.logs.length})
      </button>
    </div>

    <!-- Tab: Rules -->
    <div id="email-tab-rules" style="display:${tab === 'rules' ? 'block' : 'none'};">
      <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:16px;">
        <div>
          <div style="font-size:14px;font-weight:600;color:var(--text-primary);">Automated Notification Trigger Rules</div>
          <div style="font-size:12px;color:var(--text-muted);">Rules evaluate incoming telemetry and dispatch notifications according to cooldown policies</div>
        </div>
        <button class="btn btn-primary btn-sm" onclick="openCreateRuleModal()">
          + Add Detection Rule
        </button>
      </div>

      <div>
        ${rulesHtml || '<div style="padding:24px;text-align:center;color:var(--text-muted);background:var(--glass-card);border-radius:var(--radius-lg);">No detection rules defined. Click "+ Add Detection Rule" to configure an alert trigger.</div>'}
      </div>
    </div>

    <!-- Tab: Logs -->
    <div id="email-tab-logs" style="display:${tab === 'logs' ? 'block' : 'none'};">
      <div class="card">
        <div class="card-header" style="display:flex;justify-content:space-between;align-items:center;">
          <div class="card-title">Notification Delivery Logs</div>
          <button class="btn btn-secondary btn-sm" onclick="fetchEmailData().then(renderEmail)">Refresh Logs</button>
        </div>
        <div class="card-body" style="padding:0;">
          <div class="table-wrap">
            <table class="data-table">
              <thead>
                <tr>
                  <th>Timestamp</th>
                  <th>Recipient</th>
                  <th>Subject</th>
                  <th>Status</th>
                  <th>Delivery Mode</th>
                  <th>Provider Response</th>
                </tr>
              </thead>
              <tbody>
                ${logsRows || '<tr><td colspan="6" style="text-align:center;padding:24px;color:var(--text-muted);">No email logs recorded yet.</td></tr>'}
              </tbody>
            </table>
          </div>
        </div>
      </div>
    </div>
  `;
}

function switchEmailTab(tab) {
  APP.email.currentTab = tab;
  renderEmail();
}

async function sendTestSecurityEmail() {
  const input = document.getElementById('test-email-input');
  const recipient = (input ? input.value : '').trim();
  if (!recipient || !recipient.includes('@')) {
    showToast('Please enter a valid recipient email address', 'warning');
    return;
  }

  const btn = document.getElementById('btn-test-email');
  if (btn) {
    btn.disabled = true;
    btn.textContent = 'Sending...';
  }

  try {
    const res = await emailApi.sendTest(recipient);
    showToast(res.message, res.status === 'SENT' ? 'success' : 'info');
    await fetchEmailData();
    renderEmail();
  } catch (err) {
    showToast(`Test email error: ${err.message}`, 'critical');
  } finally {
    if (btn) {
      btn.disabled = false;
      btn.textContent = 'Send Test Alert';
    }
  }
}

async function toggleDetectionRule(ruleId, enabled) {
  try {
    await emailApi.updateRule(ruleId, { enabled });
    const rule = APP.email.rules.find(r => r.id === ruleId);
    if (rule) rule.enabled = enabled;
    showToast(`Detection rule ${enabled ? 'enabled' : 'disabled'}`, 'info');
  } catch (err) {
    showToast(`Error updating rule: ${err.message}`, 'critical');
    renderEmail();
  }
}

async function deleteDetectionRule(ruleId) {
  if (!confirm('Are you sure you want to delete this detection rule?')) return;
  try {
    await emailApi.deleteRule(ruleId);
    APP.email.rules = APP.email.rules.filter(r => r.id !== ruleId);
    showToast('Detection rule deleted', 'info');
    renderEmail();
  } catch (err) {
    showToast(`Error deleting rule: ${err.message}`, 'critical');
  }
}

function openCreateRuleModal() {
  const overlay = document.getElementById('new-rule-overlay');
  const modal = document.getElementById('new-rule-modal');
  if (overlay) overlay.style.display = 'block';
  if (modal) modal.style.display = 'block';
}

function closeCreateRuleModal() {
  const overlay = document.getElementById('new-rule-overlay');
  const modal = document.getElementById('new-rule-modal');
  if (overlay) overlay.style.display = 'none';
  if (modal) modal.style.display = 'none';
}

async function submitCreateRule() {
  const name = document.getElementById('nr-name')?.value?.trim();
  const ruleType = document.getElementById('nr-type')?.value;
  const severity = document.getElementById('nr-severity')?.value;
  const cooldown = parseInt(document.getElementById('nr-cooldown')?.value || '15', 10);
  const desc = document.getElementById('nr-desc')?.value?.trim();

  if (!name) {
    showToast('Please provide a name for the rule', 'warning');
    return;
  }

  const btn = document.getElementById('create-rule-btn');
  if (btn) {
    btn.disabled = true;
    btn.textContent = 'Saving...';
  }

  try {
    const newRule = await emailApi.createRule({
      name,
      rule_type: ruleType,
      severity,
      cooldown_minutes: cooldown,
      description: desc,
      actions: ['SEND_EMAIL'],
      enabled: true,
      conditions: {},
    });

    APP.email.rules.unshift(newRule);
    showToast('Detection rule created successfully', 'success');
    closeCreateRuleModal();
    renderEmail();
  } catch (err) {
    showToast(`Error creating rule: ${err.message}`, 'critical');
  } finally {
    if (btn) {
      btn.disabled = false;
      btn.textContent = 'Save Rule';
    }
  }
}

// ============================================================
// NOTIFICATIONS & TOASTS
// ============================================================
function toggleNotifications() {
  const dropdown = document.getElementById('notif-dropdown');
  if (dropdown) dropdown.classList.toggle('open');
}

function renderNotifications() {
  const badge = document.getElementById('notif-badge');
  const countEl = document.getElementById('unread-count');
  const list = document.getElementById('notif-list');

  if (badge) badge.textContent = APP.unreadNotifsCount;
  if (countEl) countEl.textContent = `${APP.unreadNotifsCount} unread`;

  if (list) {
    list.innerHTML = (APP.notifications || []).map(n => `
      <div class="notif-item ${n.read ? '' : 'unread'}" onclick="markNotifRead(${n.id}, ${n.incident_id})">
        <div style="width:7px;height:7px;border-radius:50%;background:${n.color || '#00D4FF'};margin-top:5px;flex-shrink:0;"></div>
        <div style="flex:1;">
          <div style="font-size:12.5px;font-weight:${n.read ? '400' : '600'};color:var(--text-primary);">${escapeHtml(n.title)}</div>
          <div style="font-size:11px;color:var(--text-muted);margin-top:2px;">${timeAgo(n.created_at)}</div>
        </div>
      </div>
    `).join('');
  }
}

async function markNotifRead(id, incidentId) {
  try {
    await notificationsApi.markRead(id);
    await fetchNotifications();
    if (incidentId) openDrawer(incidentId);
  } catch (e) {}
}

async function markAllRead() {
  try {
    await notificationsApi.markAllRead();
    await fetchNotifications();
  } catch (e) {}
}

function showToast(message, type = 'info') {
  const container = document.getElementById('toast-container');
  if (!container) return;

  const toast = document.createElement('div');
  toast.className = `toast ${type}`;
  toast.innerHTML = `
    <div style="display:flex;align-items:center;gap:8px;">
      <span class="status-dot live" style="background:${type === 'critical' ? '#FF3366' : type === 'success' ? '#00FF88' : '#00D4FF'};"></span>
      <span style="font-size:12.5px;color:var(--text-primary);font-weight:500;">${escapeHtml(message)}</span>
    </div>
  `;
  container.appendChild(toast);

  setTimeout(() => {
    toast.style.opacity = '0';
    toast.style.transform = 'translateY(10px)';
    setTimeout(() => toast.remove(), 300);
  }, 4500);
}

/**
 * showAutoAlertBanner — rich notification card for automated scheduler-generated alerts.
 * Displays prominently for 10 seconds, shows severity, incident ID, title, and email status.
 */
function showAutoAlertBanner(data) {
  const container = document.getElementById('toast-container');
  if (!container) return;

  const sevColors = {
    CRITICAL: { bg: 'rgba(255,51,102,0.15)', border: '#FF3366', dot: '#FF3366', badge: '#FF3366' },
    HIGH:     { bg: 'rgba(255,136,0,0.15)',  border: '#FF8800', dot: '#FF8800', badge: '#FF8800' },
    MEDIUM:   { bg: 'rgba(255,170,0,0.12)',  border: '#FFAA00', dot: '#FFAA00', badge: '#FFAA00' },
    LOW:      { bg: 'rgba(0,212,255,0.10)',  border: '#00D4FF', dot: '#00D4FF', badge: '#00D4FF' },
  };
  const sev = (data.severity || 'HIGH').toUpperCase();
  const colors = sevColors[sev] || sevColors.HIGH;

  const banner = document.createElement('div');
  banner.className = 'toast critical auto-alert-banner';
  banner.style.cssText = `
    background: ${colors.bg};
    border: 1px solid ${colors.border};
    border-left: 4px solid ${colors.border};
    border-radius: 10px;
    padding: 14px 16px;
    max-width: 380px;
    width: 380px;
    box-shadow: 0 8px 32px rgba(0,0,0,0.5), 0 0 20px ${colors.border}33;
    backdrop-filter: blur(20px);
    animation: autoAlertSlideIn 0.4s cubic-bezier(0.34,1.56,0.64,1);
  `;

  const shortTitle = (data.title || 'Security Alert').replace('[SIMULATED] ', '').substring(0, 70);

  banner.innerHTML = `
    <div style="display:flex;align-items:flex-start;gap:10px;">
      <div style="flex-shrink:0;margin-top:2px;">
        <div class="status-dot live" style="background:${colors.dot};box-shadow:0 0 8px ${colors.dot};width:10px;height:10px;"></div>
      </div>
      <div style="flex:1;min-width:0;">
        <div style="display:flex;align-items:center;gap:8px;margin-bottom:6px;">
          <span style="font-size:10px;font-weight:700;letter-spacing:0.08em;background:${colors.badge};color:#000;padding:2px 8px;border-radius:4px;">${sev}</span>
          <span style="font-size:10px;color:rgba(255,255,255,0.5);font-family:'JetBrains Mono',monospace;">${escapeHtml(data.public_id || '')}</span>
          <span style="font-size:10px;color:rgba(255,255,255,0.4);margin-left:auto;">AUTO</span>
        </div>
        <div style="font-size:12.5px;color:#fff;font-weight:600;margin-bottom:5px;line-height:1.4;">${escapeHtml(shortTitle)}</div>
        <div style="font-size:11px;color:rgba(255,255,255,0.55);display:flex;align-items:center;gap:5px;">
          <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M4 4h16c1.1 0 2 .9 2 2v12c0 1.1-.9 2-2 2H4c-1.1 0-2-.9-2-2V6c0-1.1.9-2 2-2z"/><polyline points="22,6 12,13 2,6"/></svg>
          Email dispatched → 2503A52483@sru.edu.in &amp; 2503A52499@sru.edu.in
        </div>
        <div style="font-size:10px;color:rgba(255,255,255,0.35);margin-top:4px;">
          🤖 Auto-Scheduler · ${new Date().toLocaleTimeString()}
        </div>
      </div>
      <button onclick="this.closest('.auto-alert-banner').remove()" style="background:none;border:none;color:rgba(255,255,255,0.4);cursor:pointer;font-size:16px;padding:0;line-height:1;flex-shrink:0;" title="Dismiss">×</button>
    </div>
  `;

  container.appendChild(banner);

  // Also show a brief standard toast for accessibility
  showToast(`🚨 Auto-Alert: ${data.public_id} (${sev}) — Email sent to SOC team`, 'critical');

  // Auto-dismiss after 10 seconds
  setTimeout(() => {
    banner.style.opacity = '0';
    banner.style.transform = 'translateY(10px)';
    banner.style.transition = 'opacity 0.4s, transform 0.4s';
    setTimeout(() => banner.remove(), 400);
  }, 10000);
}

function escapeHtml(str) {
  if (!str) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

