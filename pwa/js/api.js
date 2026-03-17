/**
 * api.js — Quishing Guard REST API Client
 *
 * Provides typed wrappers over the Flask back-end endpoints:
 *   POST /api/v1/analyse  → analyseUrl()
 *   POST /api/v1/report   → reportPhishing()
 *   GET  /api/v1/health   → checkHealth()
 *
 * Features:
 *   - AbortController timeout (15 s default)
 *   - Structured ApiError with HTTP status
 *   - Offline detection + queue fallback for reports
 */

import { queueReport, getQueuedReports, clearQueuedReport } from './db.js';

const DEFAULT_TIMEOUT_MS = 15_000;

// ── Config ────────────────────────────────────────────────────────────────────
let _apiBase = window.QG_CONFIG?.apiBase || 'http://localhost:5000';

export function setApiBase(base) {
  _apiBase = base.replace(/\/$/, '');
}

export function getApiBase() { return _apiBase; }


// ── Error class ───────────────────────────────────────────────────────────────

export class ApiError extends Error {
  /** @param {string} message @param {number} status */
  constructor(message, status = 0) {
    super(message);
    this.name   = 'ApiError';
    this.status = status;
  }
}


// ── Core fetch wrapper ────────────────────────────────────────────────────────

async function apiFetch(path, options = {}, timeoutMs = DEFAULT_TIMEOUT_MS) {
  const controller = new AbortController();
  const timer      = setTimeout(() => controller.abort(), timeoutMs);

  try {
    const response = await fetch(`${_apiBase}${path}`, {
      ...options,
      signal: controller.signal,
      headers: {
        'Content-Type': 'application/json',
        'Accept':       'application/json',
        ...options.headers,
      },
    });

    clearTimeout(timer);

    if (!response.ok) {
      let errMsg = `HTTP ${response.status}`;
      try {
        const body = await response.json();
        errMsg = body.error || errMsg;
      } catch { /* ignore parse error */ }
      throw new ApiError(errMsg, response.status);
    }

    return response.json();
  } catch (err) {
    clearTimeout(timer);
    if (err.name === 'AbortError') {
      throw new ApiError('Request timed out. The server took too long to respond.', 408);
    }
    if (err instanceof ApiError) throw err;
    throw new ApiError(err.message || 'Network error', 0);
  }
}


// ── Public API ────────────────────────────────────────────────────────────────

/**
 * Analyse a QR-decoded URL payload.
 *
 * @param {string} url  The URL decoded from the QR code.
 * @returns {Promise<AnalysisResult>}
 */
export async function analyseUrl(url) {
  return apiFetch('/api/v1/analyse', {
    method: 'POST',
    body:   JSON.stringify({ url }),
  });
}

/**
 * Submit a phishing report. If offline, queues the report for later retry.
 *
 * @param {{ url: string, reason?: string, scanId?: string }} report
 * @returns {Promise<{ status: string }>}
 */
export async function reportPhishing(report) {
  if (!navigator.onLine) {
    await queueReport(report);
    return { status: 'queued', message: 'Report queued — will be submitted when you reconnect.' };
  }
  return apiFetch('/api/v1/report', {
    method: 'POST',
    body:   JSON.stringify(report),
  });
}

/**
 * Flush all queued offline reports to the server.
 * Called on reconnect or via BackgroundSync message.
 */
export async function flushQueuedReports() {
  const queued = await getQueuedReports();
  for (const item of queued) {
    try {
      await apiFetch('/api/v1/report', {
        method: 'POST',
        body:   JSON.stringify({ url: item.url, reason: item.reason }),
      });
      await clearQueuedReport(item.id);
    } catch {
      // If still offline, leave in queue
      break;
    }
  }
}

/**
 * Check backend health.
 * @returns {Promise<{ status: string, version: string }>}
 */
export async function checkHealth() {
  return apiFetch('/api/v1/health', { method: 'GET' }, 5_000);
}

/**
 * Validate that a payload looks like a URL (client-side pre-check).
 * @param {string} payload
 * @returns {boolean}
 */
export function isValidUrl(payload) {
  if (!payload) return false;
  const nonUrl = ['WIFI:', 'BEGIN:VCARD', 'BEGIN:VCALENDAR', 'tel:', 'sms:', 'geo:', 'mailto:'];
  if (nonUrl.some(p => payload.startsWith(p))) return false;
  try {
    const url = new URL(payload.startsWith('http') ? payload : 'https://' + payload);
    return ['http:', 'https:'].includes(url.protocol);
  } catch {
    return false;
  }
}
