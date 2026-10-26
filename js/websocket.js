/**
 * AIAC Cyber — Centralized Real-Time WebSocket Client
 * Connects to FastAPI WebSocket endpoint, handles auto-reconnection with backoff,
 * maintains live status indicators, and dispatches real-time security events without UI page refresh.
 */

class WebSocketClient {
  constructor() {
    this.ws = null;
    this.reconnectAttempts = 0;
    this.maxReconnectAttempts = 15;
    this.baseDelayMs = 1500;
    this.pingInterval = null;
    this.listeners = new Map();
    this.status = 'DISCONNECTED'; // CONNECTED, CONNECTING, RECONNECTING, OFFLINE
  }

  getWsUrl() {
    const defaultHost = window.location.hostname || 'localhost';
    const wsProto = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const baseWs = window.WS_BASE_URL || `${wsProto}//${defaultHost}:8000/api/ws`;
    const token = localStorage.getItem('aiac_access_token');
    return token ? `${baseWs}?token=${encodeURIComponent(token)}` : baseWs;
  }

  connect() {
    if (this.ws && (this.ws.readyState === WebSocket.OPEN || this.ws.readyState === WebSocket.CONNECTING)) {
      return;
    }

    const url = this.getWsUrl();
    this.updateStatus(this.reconnectAttempts > 0 ? 'RECONNECTING' : 'CONNECTING');

    try {
      this.ws = new WebSocket(url);

      this.ws.onopen = () => {
        console.log('[WS] Real-Time stream connected');
        this.reconnectAttempts = 0;
        this.updateStatus('CONNECTED');
        this.startHeartbeat();
      };

      this.ws.onmessage = (event) => {
        if (event.data === 'pong') return;
        try {
          const payload = JSON.parse(event.data);
          this.handleEvent(payload);
        } catch (e) {
          console.warn('[WS] Non-JSON payload received:', event.data);
        }
      };

      this.ws.onclose = (event) => {
        console.warn(`[WS] Connection closed (code: ${event.code})`);
        this.stopHeartbeat();
        this.updateStatus('DISCONNECTED');
        this.scheduleReconnect();
      };

      this.ws.onerror = (err) => {
        console.warn('[WS] Connection error occurred');
      };
    } catch (e) {
      console.warn('[WS] Failed to initiate WebSocket connection:', e);
      this.scheduleReconnect();
    }
  }

  startHeartbeat() {
    this.stopHeartbeat();
    this.pingInterval = setInterval(() => {
      if (this.ws && this.ws.readyState === WebSocket.OPEN) {
        this.ws.send('ping');
      }
    }, 25000);
  }

  stopHeartbeat() {
    if (this.pingInterval) {
      clearInterval(this.pingInterval);
      this.pingInterval = null;
    }
  }

  scheduleReconnect() {
    if (this.reconnectAttempts >= this.maxReconnectAttempts) {
      this.updateStatus('OFFLINE');
      console.warn('[WS] Max reconnection attempts reached. Switching to polling fallback.');
      return;
    }

    const jitter = Math.floor(Math.random() * 500);
    const delay = Math.min(this.baseDelayMs * Math.pow(1.5, this.reconnectAttempts) + jitter, 15000);
    this.reconnectAttempts++;
    this.updateStatus('RECONNECTING');

    setTimeout(() => {
      this.connect();
    }, delay);
  }

  updateStatus(newStatus) {
    this.status = newStatus;
    const badge = document.getElementById('live-indicator-badge');
    if (!badge) return;

    if (newStatus === 'CONNECTED') {
      badge.innerHTML = '<span class="status-dot live"></span> LIVE';
      badge.className = 'live-badge live';
      badge.title = 'Real-time telemetry stream connected';
    } else if (newStatus === 'RECONNECTING' || newStatus === 'CONNECTING') {
      badge.innerHTML = '<span class="status-dot reconnecting"></span> RECONNECTING';
      badge.className = 'live-badge reconnecting';
      badge.title = 'Reconnecting to real-time telemetry stream...';
    } else {
      badge.innerHTML = '<span class="status-dot offline"></span> OFFLINE';
      badge.className = 'live-badge offline';
      badge.title = 'Operating in polling mode';
    }
  }

  on(eventType, callback) {
    if (!this.listeners.has(eventType)) {
      this.listeners.set(eventType, new Set());
    }
    this.listeners.get(eventType).add(callback);
  }

  off(eventType, callback) {
    if (this.listeners.has(eventType)) {
      this.listeners.get(eventType).delete(callback);
    }
  }

  handleEvent(payload) {
    const { type, data, timestamp } = payload;
    console.log(`[WS Event] ${type}`, data);

    // Call registered listeners
    if (this.listeners.has(type)) {
      this.listeners.get(type).forEach((cb) => {
        try {
          cb(data, timestamp);
        } catch (err) {
          console.error(`[WS Handler Error] for ${type}:`, err);
        }
      });
    }

    // Call wildcard listeners
    if (this.listeners.has('*')) {
      this.listeners.get('*').forEach((cb) => cb(payload));
    }

    // Dispatch DOM CustomEvent for loose coupling
    window.dispatchEvent(new CustomEvent('aiac:realtime', { detail: payload }));
  }
}

const realtimeWS = new WebSocketClient();
