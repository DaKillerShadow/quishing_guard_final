/**
 * db.js — IndexedDB Persistence Layer
 *
 * Provides a clean, Promise-based API over IndexedDB for:
 *   - scan_history  : up to 500 scan results, auto-pruned
 *   - settings      : user preferences with defaults
 *   - queued_reports: offline report queue for background sync
 */

const DB_NAME    = 'quishing-guard';
const DB_VERSION = 1;
const MAX_HIST   = 500;

let _db = null;

/**
 * Open (or create) the IndexedDB database.
 * @returns {Promise<IDBDatabase>}
 */
function openDB() {
  if (_db) return Promise.resolve(_db);
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(DB_NAME, DB_VERSION);

    req.onupgradeneeded = e => {
      const db = e.target.result;

      // Scan history
      if (!db.objectStoreNames.contains('scan_history')) {
        const store = db.createObjectStore('scan_history', { keyPath: 'id' });
        store.createIndex('by_date', 'scannedAt', { unique: false });
        store.createIndex('by_risk', 'risk_label', { unique: false });
      }

      // Settings key-value
      if (!db.objectStoreNames.contains('settings')) {
        db.createObjectStore('settings');
      }

      // Offline report queue
      if (!db.objectStoreNames.contains('queued_reports')) {
        db.createObjectStore('queued_reports', { keyPath: 'id', autoIncrement: true });
      }
    };

    req.onsuccess = e => { _db = e.target.result; resolve(_db); };
    req.onerror   = ()  => reject(req.error);
  });
}

const pfy = r => new Promise((res, rej) => {
  r.onsuccess = () => res(r.result);
  r.onerror   = () => rej(r.error);
});

async function tx(storeName, mode = 'readonly') {
  const db = await openDB();
  return db.transaction(storeName, mode).objectStore(storeName);
}


// ══════════════════════════════════════════════════════════════
//  SCAN HISTORY
// ══════════════════════════════════════════════════════════════

/**
 * Save a scan result to history. Auto-prunes oldest entries above MAX_HIST.
 * @param {Object} result  The analysis result object from the API.
 */
export async function saveResult(result) {
  const store = await tx('scan_history', 'readwrite');
  await pfy(store.put({ ...result, scannedAt: result.scannedAt || new Date().toISOString() }));
  await _pruneHistory();
}

/** Retrieve all scan history, newest first. */
export async function getAllResults() {
  const store = await tx('scan_history');
  const all   = await pfy(store.getAll());
  return all.sort((a, b) => new Date(b.scannedAt) - new Date(a.scannedAt));
}

/** Retrieve a single scan result by ID. */
export async function getResult(id) {
  const store = await tx('scan_history');
  return pfy(store.get(id));
}

/** Mark a scan result as reported. */
export async function markReported(id) {
  const store  = await tx('scan_history', 'readwrite');
  const record = await pfy(store.get(id));
  if (record) {
    record.reported = true;
    await pfy(store.put(record));
  }
}

/** Delete a single scan result. */
export async function deleteResult(id) {
  const store = await tx('scan_history', 'readwrite');
  return pfy(store.delete(id));
}

/** Clear all scan history. */
export async function clearHistory() {
  const store = await tx('scan_history', 'readwrite');
  return pfy(store.clear());
}

/**
 * Compute aggregate statistics over the history.
 * @returns {{ total, safe, warning, danger, reported, today }}
 */
export async function getStats() {
  const all     = await getAllResults();
  const today   = new Date(); today.setHours(0, 0, 0, 0);
  return {
    total:    all.length,
    safe:     all.filter(r => r.risk_label === 'safe').length,
    warning:  all.filter(r => r.risk_label === 'warning').length,
    danger:   all.filter(r => r.risk_label === 'danger').length,
    reported: all.filter(r => r.reported).length,
    today:    all.filter(r => new Date(r.scannedAt) >= today).length,
  };
}

async function _pruneHistory() {
  const all = await getAllResults();
  if (all.length <= MAX_HIST) return;
  const toDelete = all.slice(MAX_HIST);
  const store    = await tx('scan_history', 'readwrite');
  for (const r of toDelete) await pfy(store.delete(r.id));
}


// ══════════════════════════════════════════════════════════════
//  SETTINGS
// ══════════════════════════════════════════════════════════════

const DEFAULTS = {
  notifications: true,
  autoLesson:    true,
  haptics:       true,
  analytics:     false,
  apiBase:       'http://localhost:5000',
};

/** Get a setting value, returning the default if not set. */
export async function getSetting(key) {
  const store = await tx('settings');
  const val   = await pfy(store.get(key));
  return val !== undefined ? val : DEFAULTS[key];
}

/** Persist a setting value. */
export async function setSetting(key, value) {
  const store = await tx('settings', 'readwrite');
  return pfy(store.put(value, key));
}

/** Get all settings as a plain object (merged with defaults). */
export async function getAllSettings() {
  const out = { ...DEFAULTS };
  for (const key of Object.keys(DEFAULTS)) {
    out[key] = await getSetting(key);
  }
  return out;
}


// ══════════════════════════════════════════════════════════════
//  OFFLINE REPORT QUEUE
// ══════════════════════════════════════════════════════════════

/** Queue a phishing report for later submission when back online. */
export async function queueReport(report) {
  const store = await tx('queued_reports', 'readwrite');
  return pfy(store.add({ ...report, queuedAt: new Date().toISOString() }));
}

/** Retrieve all queued reports. */
export async function getQueuedReports() {
  const store = await tx('queued_reports');
  return pfy(store.getAll());
}

/** Remove a queued report by its auto-increment id. */
export async function clearQueuedReport(id) {
  const store = await tx('queued_reports', 'readwrite');
  return pfy(store.delete(id));
}
