/**
 * app.js — Quishing Guard PWA Main Application
 *
 * Architecture:
 *   SPA Router  — hash-based, no library
 *   State Store — lightweight pub/sub
 *   Renders     — pure functions producing HTML strings
 *   Scanner     — QRScanner wrapper (scanner.js)
 *   Persistence — IndexedDB via db.js
 *   API         — REST client via api.js
 */

import { QRScanner }       from './scanner.js';
import { analyseUrl, reportPhishing, flushQueuedReports, setApiBase } from './api.js';
import {
  saveResult, getAllResults, getResult, deleteResult, clearHistory,
  getStats, markReported, getAllSettings, setSetting,
} from './db.js';

// ══════════════════════════════════════════════════════════════
//  MICRO-LESSON CONTENT  (§3.9 of project report)
// ══════════════════════════════════════════════════════════════

const LESSONS = {
  dga_entropy: {
    emoji: '🎲',
    type:  'DGA / High-Entropy Domain',
    title: 'Algorithmically Generated Domain',
    summary: "This link's domain looks like random gibberish — a sign it was machine-generated to evade blocklists.",
    body: 'Legitimate businesses choose memorable names like "paypal.com" or "google.com". Attackers use Domain Generation Algorithms (DGA) to create thousands of disposable random domains, making blocklisting impractical. Shannon Entropy — a mathematical measure of randomness developed by Claude Shannon in 1948 — detects this pattern. Domains scoring above 3.2 bits per character are flagged as suspicious.',
    example: 'kzxwmqbvptjd.ru',
    tip: 'If a domain name looks like keyboard mashing, do not proceed. Navigate to the official site by typing its address directly into your browser instead of following the QR link.',
  },
  punycode: {
    emoji: '🎭',
    type:  'IDN Homograph Attack',
    title: 'Visual Impersonation Attempt',
    summary: 'This link uses internationally encoded characters to visually clone a trusted brand.',
    body: 'The IDN Homograph Attack replaces familiar Latin letters with visually identical characters from other alphabets — for example, the Cyrillic "а" (U+0430) looks identical to the Latin "a" (U+0061). Browsers encode these substitutions as Punycode, which always starts with "xn--". On a small mobile screen the URL looks completely legitimate.',
    example: 'xn--pple-43d.com  →  looks like: apple.com',
    tip: 'Before tapping any link, check the address bar for "xn--". Any link using Punycode to impersonate a known brand is an active attack. Report it immediately.',
  },
  ip_literal: {
    emoji: '🔢',
    type:  'Raw IP Address',
    title: 'IP Address Used Instead of Domain',
    summary: 'This link points to a numbered server address — real companies never do this for customer-facing pages.',
    body: 'Legitimate organisations invest in memorable domain names. A link pointing directly to "http://185.220.101.52/login" skips the domain name system entirely and goes to an anonymous server. Phishing kits frequently use raw IP addresses for short-lived credential-harvesting pages that are abandoned before investigators can act.',
    example: 'http://185.220.101.52/secure/account/verify',
    tip: 'Never enter your credentials on a page whose URL consists of numbers in the format 0–255.0–255.0–255.0–255. This is a near-certain indicator of malicious intent.',
  },
  redirect_depth: {
    emoji: '🔀',
    type:  'Deep Redirect Chain',
    title: 'Suspicious Redirect Chain Detected',
    summary: 'This link bounced through 3 or more servers before reaching its destination — a classic URL-cloaking technique.',
    body: 'Attackers chain redirects through legitimate-looking services (link shorteners, marketing trackers, analytics platforms) to conceal the final malicious destination from email security scanners. By the time your browser arrives at the phishing page, the trail through legitimate services is cold. Quishing Guard followed the full chain safely so you can see exactly where you would have ended up.',
    example: 'bit.ly/3xyz → tracker.io/hop → redirect.net → evil.ru/login',
    tip: 'When a QR code needs 3 or more redirects to reach its destination, that is a major red flag. Only proceed if the final URL belongs to a domain you recognise and expected to visit.',
  },
  suspicious_tld: {
    emoji: '🚩',
    type:  'Suspicious Top-Level Domain',
    title: 'High-Risk Domain Extension',
    summary: 'This link uses a domain extension statistically associated with phishing and malware.',
    body: "Certain top-level domains (TLDs) are disproportionately used for malicious purposes because they are cheap, easy to register anonymously, and have weak abuse-reporting processes. TLDs like .tk, .ml, .ga, .xyz, and .ru appear in phishing URLs far more frequently than their legitimate usage share would predict.",
    example: 'secure-login-paypal.tk/verify',
    tip: "This doesn't mean all .ru or .xyz sites are malicious — but extra caution is warranted. Cross-check the domain name against the brand it claims to represent.",
  },
  generic: {
    emoji: '⚠️',
    type:  'Multiple Risk Signals',
    title: 'Suspicious QR Code Detected',
    summary: 'Several independent risk signals were detected in this QR code.',
    body: "Quishing (QR phishing) embeds malicious URLs inside QR codes to bypass traditional email link scanners. QR codes are particularly dangerous because humans cannot visually read them — the destination URL is completely hidden until the code is scanned. Always verify where a QR code leads before opening the destination.",
    example: 'QR code on a parking meter directing to a counterfeit payment portal',
    tip: 'Treat unexpected QR codes in emails, PDFs, posters, or physical surfaces with scepticism. If you did not seek out this QR code deliberately, do not open the link it contains.',
  },
};

// ══════════════════════════════════════════════════════════════
//  HELPERS
// ══════════════════════════════════════════════════════════════

const esc = s => !s ? '' : String(s)
  .replace(/&/g, '&amp;').replace(/</g, '&lt;')
  .replace(/>/g, '&gt;').replace(/"/g, '&quot;');

const rClass = s => s < 30 ? 'safe' : s < 60 ? 'warning' : 'danger';
const rLabel = s => s < 30 ? 'SAFE' : s < 60 ? 'WARNING' : 'DANGER';

const hostname = url => {
  try { return new URL(url.startsWith('http') ? url : 'https://' + url).hostname; }
  catch { return url.slice(0, 40); }
};

const fmtDate = iso => {
  try {
    const d = new Date(iso);
    return d.toLocaleDateString(undefined, { day: '2-digit', month: 'short', year: 'numeric' })
      + '  ' + d.toLocaleTimeString(undefined, { hour: '2-digit', minute: '2-digit' });
  } catch { return iso; }
};

const uid = () => (crypto.randomUUID?.()) ||
  Date.now().toString(36) + Math.random().toString(36).slice(2);

// ══════════════════════════════════════════════════════════════
//  TOAST NOTIFICATIONS
// ══════════════════════════════════════════════════════════════

function toast(msg, type = 'ok', ms = 3600) {
  const container = document.getElementById('toasts');
  const el = document.createElement('div');
  el.className = `toast ${type}`;
  el.setAttribute('role', 'status');
  el.innerHTML = `<span class="toast-icon" aria-hidden="true">${{ ok: '✓', warn: '⚠', bad: '✕' }[type] ?? 'ℹ'}</span><span>${esc(msg)}</span>`;
  container.appendChild(el);
  setTimeout(() => {
    el.style.cssText = 'opacity:0;transform:translateY(6px);transition:all .28s ease';
    setTimeout(() => el.remove(), 280);
  }, ms);
}

// ══════════════════════════════════════════════════════════════
//  OVERLAY LOADER
// ══════════════════════════════════════════════════════════════

function setLoader(on, msg = 'Analysing link safety…') {
  document.getElementById('ov-msg').textContent = msg;
  document.getElementById('overlay').classList.toggle('on', on);
}

// ══════════════════════════════════════════════════════════════
//  ROUTER
// ══════════════════════════════════════════════════════════════

let currentPage = 'scanner';
const PAGE_IDS = ['scanner', 'preview', 'lesson', 'history', 'settings'];
const onEnter = {
  history:  renderHistory,
  settings: renderSettings,
  lesson:   () => currentResult && renderLesson(currentResult),
};

function navigate(to) {
  if (!PAGE_IDS.includes(to)) to = 'scanner';
  document.getElementById(`pg-${currentPage}`)?.classList.remove('active');
  document.getElementById(`pg-${to}`)?.classList.add('active');

  document.querySelectorAll('.nav-btn').forEach(b => {
    const active = b.dataset.pg === to;
    b.classList.toggle('active', active);
    b.setAttribute('aria-current', active ? 'page' : 'false');
  });

  if (to === 'scanner') scanner?.resume();
  else if (currentPage === 'scanner') scanner?.pause();

  currentPage = to;
  onEnter[to]?.();
  history.replaceState(null, '', `#${to}`);
}

// ══════════════════════════════════════════════════════════════
//  SCAN RESULT STATE
// ══════════════════════════════════════════════════════════════

let currentResult = null;
let historyCache  = [];

async function refreshStats() {
  const stats = await getStats();
  const el = id => document.getElementById(id);
  if (el('st-total'))  el('st-total').textContent  = stats.total;
  if (el('st-danger')) el('st-danger').textContent = stats.danger;
  if (el('st-today'))  el('st-today').textContent  = stats.today;
}

// ══════════════════════════════════════════════════════════════
//  SCAN FLOW
// ══════════════════════════════════════════════════════════════

async function onQRDetected(payload) {
  setLoader(true, 'Resolving URL and scoring…');
  try {
    const result = await analyseUrl(payload);
    result.scannedAt = result.analysed_at || new Date().toISOString();
    result.reported  = false;
    currentResult    = result;
    await saveResult(result);
    await refreshStats();
    setLoader(false);
    renderPreview(result);
    navigate('preview');

    const cfg = await getAllSettings();
    if (result.risk_score >= 30 && cfg.autoLesson) {
      // Show lesson nudge on preview, not auto-navigate
    }
  } catch (err) {
    setLoader(false);
    const msg = err.message || 'Analysis failed';
    toast(msg.includes('offline') ? 'You are offline — cannot analyse' : msg, 'bad');
    scanner?.resume();
  }
}

// ══════════════════════════════════════════════════════════════
//  RENDER: PREVIEW
// ══════════════════════════════════════════════════════════════

function renderPreview(r) {
  const cls    = rClass(r.risk_score);
  const lbl    = rLabel(r.risk_score);
  const icon   = r.risk_score < 30 ? '✓' : r.risk_score < 60 ? '⚠' : '✕';
  const lesson = r.top_threat ? LESSONS[r.top_threat] : null;

  const checksHtml = (r.checks || []).map((c, i) => `
    <div class="chk" style="animation-delay:${i * 40}ms">
      <div class="chk-dot ${c.triggered ? 'hit' : 'ok'}" aria-hidden="true">${c.triggered ? '✕' : '✓'}</div>
      <div class="chk-body">
        <div class="chk-name">${esc(c.label)}</div>
        <div class="chk-desc">${esc(c.description)}</div>
        ${c.detail ? `<div class="chk-detail">${esc(c.detail)}</div>` : ''}
      </div>
      <div class="chk-pts ${c.triggered ? 'hit' : 'ok'}">${c.score > 0 ? '+' + c.score : '✓'}</div>
    </div>`).join('');

  const chainHtml = r.redirect_chain?.length ? `
    <div class="card" style="animation-delay:.1s">
      <div class="card-head"><span class="card-ico" aria-hidden="true">🔀</span>
        <span class="card-title">Redirect Chain
          <span class="card-sub">(${r.redirect_chain.length} hop${r.redirect_chain.length !== 1 ? 's' : ''})</span>
        </span>
      </div>
      <div class="card-body">
        <ol class="chain-list">${r.redirect_chain.map((u, i) => `
          <li class="chain-item">
            <span class="chain-num" aria-hidden="true">${i + 1}</span>
            <span class="chain-url">${esc(u)}</span>
          </li>`).join('')}</ol>
      </div>
    </div>` : '';

  const lessonNudge = (lesson && r.risk_score >= 30) ? `
    <div class="lesson-nudge">
      <div class="nudge-head">
        <div class="nudge-chip">📚 Security Lesson</div>
        <div class="nudge-title">${esc(lesson.title)}</div>
        <div class="nudge-summary">${esc(lesson.summary)}</div>
      </div>
      <div class="nudge-foot">
        <button class="btn btn-ghost btn-sm" id="btn-to-lesson">View Full Lesson →</button>
      </div>
    </div>` : '';

  document.getElementById('preview-root').innerHTML = `
    <div class="risk-hero ${cls}" role="status"
         aria-label="Risk score ${r.risk_score} out of 100 — ${lbl}">
      <div class="risk-icon" aria-hidden="true">${icon}</div>
      <div class="risk-num">${r.risk_score}</div>
      <div class="risk-lbl">/100 — ${lbl}</div>
      <div class="risk-ts">${fmtDate(r.scannedAt)}</div>
    </div>

    <div class="preview-body">
      <div class="card" style="animation-delay:.04s">
        <div class="card-head"><span class="card-ico" aria-hidden="true">🔗</span>
          <span class="card-title">Destination URL</span>
        </div>
        <div class="card-body">
          <div class="url-box" id="url-display">
            <button class="url-copy" onclick="copyUrl()" aria-label="Copy URL">Copy</button>
            ${esc(r.resolved_url)}
          </div>
          <p class="url-meta">${r.hop_count || 0} redirect hop${(r.hop_count || 0) !== 1 ? 's' : ''} followed safely</p>
        </div>
      </div>

      ${chainHtml}

      <div class="card" style="animation-delay:.18s">
        <div class="card-head"><span class="card-ico" aria-hidden="true">🔬</span>
          <span class="card-title">Security Analysis</span>
          <span class="risk-badge ${cls}">${lbl}</span>
        </div>
        <div class="card-body">${checksHtml}</div>
      </div>

      ${lessonNudge}

      <div class="action-row">
        <button class="btn ${cls === 'danger' ? 'btn-danger' : 'btn-primary'}" id="btn-open">
          ${cls === 'danger' ? '⚠️ Open Anyway (High Risk)' : '↗ Open Link'}
        </button>
        <div class="action-row-2">
          <button class="btn btn-ghost" id="btn-report">🚩 Report</button>
          <button class="btn btn-ghost" id="btn-share">⬆ Share</button>
        </div>
      </div>
    </div>`;

  // ── Wire events ──────────────────────────────────────────────────────────
  window.copyUrl = () => {
    navigator.clipboard.writeText(r.resolved_url)
      .then(() => toast('URL copied!', 'ok', 2000))
      .catch(() => toast('Copy failed', 'bad'));
  };

  document.getElementById('btn-to-lesson')?.addEventListener('click', () => navigate('lesson'));

  document.getElementById('btn-open')?.addEventListener('click', () => {
    if (cls === 'danger') {
      if (!confirm('⚠️ HIGH RISK\n\nThis link is flagged as highly suspicious.\nOpening it may lead to a phishing page designed to steal your credentials.\n\nContinue anyway?')) return;
    }
    window.open(r.resolved_url, '_blank', 'noopener,noreferrer');
  });

  document.getElementById('btn-report')?.addEventListener('click', async () => {
    const btn = document.getElementById('btn-report');
    if (!btn || btn.dataset.done) return;
    btn.disabled = true;
    btn.textContent = '⏳ Submitting…';
    try {
      await reportPhishing({ url: r.resolved_url, reason: 'user_report', scanId: r.id });
      await markReported(r.id);
      btn.textContent = '✓ Reported';
      btn.dataset.done = '1';
      toast('Report submitted. Thank you!', 'ok');
    } catch {
      btn.disabled = false;
      btn.textContent = '🚩 Report';
      toast('Report failed — check your connection', 'bad');
    }
  });

  document.getElementById('btn-share')?.addEventListener('click', () => {
    const text = `🛡️ Quishing Guard\nURL: ${r.resolved_url}\nRisk: ${lbl} (${r.risk_score}/100)`;
    if (navigator.share) navigator.share({ title: 'Quishing Guard', text }).catch(() => {});
    else navigator.clipboard.writeText(text).then(() => toast('Result copied!', 'ok'));
  });
}

// ══════════════════════════════════════════════════════════════
//  RENDER: LESSON
// ══════════════════════════════════════════════════════════════

function renderLesson(r) {
  const lesson = (r?.top_threat && LESSONS[r.top_threat]) || LESSONS.generic;
  let bookmarked = false;

  document.getElementById('lesson-root').innerHTML = `
    <div class="lesson-page">
      <div class="lesson-hero">
        <div class="lesson-emoji" aria-hidden="true">${lesson.emoji}</div>
        <div class="lesson-chip">📚 ${esc(lesson.type)}</div>
        <h1 class="lesson-title">${esc(lesson.title)}</h1>
        <button class="bkmk-btn" id="bkmk-btn" aria-pressed="false" aria-label="Bookmark this lesson">
          📌 Bookmark
        </button>
      </div>

      <div class="lesson-body">
        <div class="lesson-summary">${esc(lesson.summary)}</div>

        <div class="lesson-section">
          <div class="section-label">How it works</div>
          <p class="section-body">${esc(lesson.body)}</p>
        </div>

        <div class="lesson-section">
          <div class="section-label">Real-world example</div>
          <div class="lesson-example">${esc(lesson.example)}</div>
        </div>

        <div class="lesson-section">
          <div class="section-label">What to do</div>
          <div class="lesson-tip">
            <span class="tip-icon" aria-hidden="true">💡</span>
            <p>${esc(lesson.tip)}</p>
          </div>
        </div>

        <div class="lesson-actions">
          <button class="btn btn-primary" id="btn-lesson-done">Got it ✓</button>
          <button class="btn btn-ghost" id="btn-lesson-back">← Back to Result</button>
        </div>
      </div>
    </div>`;

  document.getElementById('btn-lesson-done')?.addEventListener('click', () => navigate('scanner'));
  document.getElementById('btn-lesson-back')?.addEventListener('click', () => navigate('preview'));
  document.getElementById('bkmk-btn')?.addEventListener('click', function () {
    bookmarked = !bookmarked;
    this.textContent   = bookmarked ? '🔖 Bookmarked' : '📌 Bookmark';
    this.style.borderColor = bookmarked ? 'var(--arc)' : '';
    this.style.color       = bookmarked ? 'var(--arc)' : '';
    this.setAttribute('aria-pressed', bookmarked);
    toast(bookmarked ? 'Lesson bookmarked!' : 'Bookmark removed', bookmarked ? 'ok' : 'warn', 2000);
  });
}

// ══════════════════════════════════════════════════════════════
//  RENDER: HISTORY
// ══════════════════════════════════════════════════════════════

async function renderHistory() {
  historyCache = await getAllResults();
  const stats  = await getStats();
  const today  = new Date(); today.setHours(0, 0, 0, 0);
  let filter   = 'all';

  const listHtml = items => {
    if (!items.length) return `
      <div class="empty-state" role="status">
        <div class="empty-icon" aria-hidden="true">📭</div>
        <p>No scans match this filter.</p>
      </div>`;
    return items.map((r, i) => {
      const cls  = rClass(r.risk_score);
      const host = hostname(r.resolved_url || r.raw_url || '');
      return `<div class="h-item" data-id="${esc(r.id)}" tabindex="0" role="listitem"
                   style="animation-delay:${Math.min(i, 10) * 28}ms"
                   aria-label="${esc(host)}, ${cls}">
        <div class="h-score ${cls}" aria-hidden="true">${r.risk_score}</div>
        <div class="h-body">
          <div class="h-host">${esc(host)}</div>
          <div class="h-meta">
            <span class="badge ${cls}">${rLabel(r.risk_score)}</span>
            <span>${fmtDate(r.scannedAt)}</span>
            ${r.reported ? '<span class="reported-tag">🚩 Reported</span>' : ''}
          </div>
        </div>
        <button class="h-del" data-del="${esc(r.id)}" aria-label="Delete">🗑</button>
      </div>`;
    }).join('');
  };

  const filtered = () => filter === 'all' ? historyCache
    : historyCache.filter(r => rClass(r.risk_score) === filter);

  document.getElementById('history-root').innerHTML = `
    <div class="h-stats" aria-label="Scan statistics">
      <div class="h-stat"><div class="h-val" style="color:var(--arc)">${stats.total}</div><div class="h-lbl">Total</div></div>
      <div class="h-stat"><div class="h-val" style="color:var(--ember)">${stats.danger}</div><div class="h-lbl">Dangerous</div></div>
      <div class="h-stat"><div class="h-val">${stats.today}</div><div class="h-lbl">Today</div></div>
    </div>

    <div class="filter-row" role="group" aria-label="Filter by risk">
      ${['all', 'safe', 'warning', 'danger'].map(f => `
        <button class="fchip ${f === 'all' ? 'active' : ''}" data-f="${f}"
                aria-pressed="${f === 'all'}">${f[0].toUpperCase() + f.slice(1)}</button>`).join('')}
    </div>

    <div class="h-list" id="h-list" role="list">
      ${historyCache.length ? listHtml(historyCache) : `
        <div class="empty-state" role="status">
          <div class="empty-icon" aria-hidden="true">📭</div>
          <p>No scans yet.<br>Press <strong>Demo</strong> on the scanner tab to try a sample analysis.</p>
        </div>`}
    </div>

    ${historyCache.length ? `<div class="h-clear-row">
      <button class="btn btn-ghost btn-sm danger-btn" id="btn-clr-hist">🗑 Clear All History</button>
    </div>` : ''}`;

  // Filters
  document.querySelectorAll('.fchip').forEach(chip => {
    chip.addEventListener('click', () => {
      filter = chip.dataset.f;
      document.querySelectorAll('.fchip').forEach(c => {
        c.classList.toggle('active', c === chip);
        c.setAttribute('aria-pressed', c === chip);
      });
      document.getElementById('h-list').innerHTML = listHtml(filtered());
      wireHistItems();
    });
  });

  // Clear all
  document.getElementById('btn-clr-hist')?.addEventListener('click', async () => {
    if (!confirm('Delete all scan history? This cannot be undone.')) return;
    await clearHistory();
    await refreshStats();
    toast('History cleared', 'ok');
    renderHistory();
  });

  wireHistItems();
}

function wireHistItems() {
  document.querySelectorAll('.h-item').forEach(el => {
    el.addEventListener('click', async e => {
      if (e.target.closest('.h-del')) return;
      const r = historyCache.find(x => x.id === el.dataset.id);
      if (r) { currentResult = r; renderPreview(r); navigate('preview'); }
    });
    el.addEventListener('keydown', e => { if (e.key === 'Enter' || e.key === ' ') el.click(); });
  });
  document.querySelectorAll('.h-del').forEach(btn => {
    btn.addEventListener('click', async e => {
      e.stopPropagation();
      await deleteResult(btn.dataset.del);
      historyCache = historyCache.filter(r => r.id !== btn.dataset.del);
      await refreshStats();
      toast('Scan deleted', 'warn', 2000);
      renderHistory();
    });
  });
}

// ══════════════════════════════════════════════════════════════
//  RENDER: SETTINGS
// ══════════════════════════════════════════════════════════════

async function renderSettings() {
  const cfg = await getAllSettings();

  document.getElementById('settings-root').innerHTML = `
    <h1 class="s-title">Settings</h1>

    <div class="s-group">
      <div class="s-label">API Configuration</div>
      <div class="s-card">
        <div class="s-row">
          <div class="s-ico" aria-hidden="true">🌐</div>
          <div class="s-body">
            <div class="s-name">Backend API URL</div>
            <div class="s-sub">Flask server address (change for production)</div>
          </div>
        </div>
        <div style="padding:0 16px 14px">
          <input class="api-input" id="api-base-input"
                 value="${esc(cfg.apiBase)}"
                 placeholder="http://localhost:5000"
                 aria-label="Backend API URL">
          <button class="btn btn-ghost btn-sm" id="btn-save-api" style="margin-top:8px">Save</button>
        </div>
      </div>
    </div>

    <div class="s-group">
      <div class="s-label">Notifications & Learning</div>
      <div class="s-card">
        ${[
          ['notifications', '🔔', 'Scan alert notifications', 'Alert when a cached link is newly flagged'],
          ['autoLesson',    '📚', 'Auto-show micro-lessons', 'Show a relevant lesson after high-risk scans'],
        ].map(([key, ico, name, sub]) => `
          <div class="s-row">
            <div class="s-ico" aria-hidden="true">${ico}</div>
            <div class="s-body"><div class="s-name">${name}</div><div class="s-sub">${sub}</div></div>
            <label class="tog" aria-label="Toggle ${name}">
              <input type="checkbox" class="tog-input" data-key="${key}"
                     ${cfg[key] ? 'checked' : ''} role="switch" aria-checked="${cfg[key]}">
              <span class="tog-slider"></span>
            </label>
          </div>`).join('')}
      </div>
    </div>

    <div class="s-group">
      <div class="s-label">Privacy</div>
      <div class="s-card">
        <div class="s-row">
          <div class="s-ico" aria-hidden="true">📊</div>
          <div class="s-body">
            <div class="s-name">Analytics opt-in</div>
            <div class="s-sub">Share anonymous usage data to improve detection</div>
          </div>
          <label class="tog" aria-label="Toggle analytics">
            <input type="checkbox" class="tog-input" data-key="analytics"
                   ${cfg.analytics ? 'checked' : ''} role="switch" aria-checked="${cfg.analytics}">
            <span class="tog-slider"></span>
          </label>
        </div>
        <div class="s-row">
          <div class="s-ico" aria-hidden="true">🗑</div>
          <div class="s-body">
            <div class="s-name">Clear scan history</div>
            <div class="s-sub">Permanently delete all locally stored scan records</div>
          </div>
          <button class="btn btn-ghost btn-sm danger-btn" id="btn-clr-s">Clear</button>
        </div>
      </div>
    </div>

    <div class="s-group">
      <div class="s-label">System Architecture</div>
      <div class="s-card s-arch">
        ${[
          ['📷', 'Camera API + jsQR',         'MediaDevices.getUserMedia → real-time QR decode'],
          ['⚙️', 'Service Worker (sw.js)',     'Cache-First shell, Network-First API, background sync'],
          ['🗄️', 'IndexedDB',                 '500-entry history + settings, auto-pruned'],
          ['🌐', 'Flask REST API',             'POST /api/v1/analyse  ·  POST /api/v1/report'],
          ['🔬', 'Heuristic Engine (7 checks)','Entropy, Punycode, IP, TLD, subdomain, redirect, HTTPS'],
          ['📱', 'PWA Manifest',               'Installable, standalone, shortcuts, push notifications'],
        ].map(([ico, name, desc]) => `
          <div class="arch-row">
            <span class="arch-ico" aria-hidden="true">${ico}</span>
            <div><div class="arch-name">${name}</div><div class="arch-desc">${desc}</div></div>
          </div>`).join('')}
      </div>
    </div>

    <div class="about-card">
      ${[
        ['App',         'Quishing Guard'],
        ['Version',     '1.0.0 PWA'],
        ['Course',      'TM471'],
        ['Student ID',  '22510076'],
        ['Network',     navigator.onLine ? '● Online' : '● Offline'],
        ['SW Support',  'serviceWorker' in navigator ? '✓' : '✕'],
        ['IDB Support', 'indexedDB'     in window    ? '✓' : '✕'],
      ].map(([k, v]) => `
        <div class="about-row">
          <span class="about-k">${k}</span>
          <span class="about-v" ${k === 'Network' ? `style="color:${navigator.onLine ? 'var(--jade)' : 'var(--amber)'}"` : ''}>${v}</span>
        </div>`).join('')}
    </div>`;

  // Toggle handlers
  document.querySelectorAll('.tog-input').forEach(inp => {
    inp.addEventListener('change', async () => {
      await setSetting(inp.dataset.key, inp.checked);
      inp.setAttribute('aria-checked', inp.checked);
      toast('Setting saved', 'ok', 1600);
    });
  });

  // API base save
  document.getElementById('btn-save-api')?.addEventListener('click', async () => {
    const val = document.getElementById('api-base-input')?.value?.trim();
    if (val) {
      await setSetting('apiBase', val);
      setApiBase(val);
      toast('API URL saved', 'ok', 2000);
    }
  });

  // Clear history
  document.getElementById('btn-clr-s')?.addEventListener('click', async () => {
    if (!confirm('Delete all scan history?')) return;
    await clearHistory();
    await refreshStats();
    toast('History cleared', 'ok');
  });
}

// ══════════════════════════════════════════════════════════════
//  SCANNER SETUP
// ══════════════════════════════════════════════════════════════

let scanner = null;
const DEMO_URLS = [
  'https://bit.ly/3qrdemo1',   // → will be treated as unknown
  'https://xn--pple-43d.com/account/login',
  'https://www.google.com/maps',
  'http://x7z9q2mwpb.ru/verify',
];
let _demoIdx = 0;

function initScanner() {
  const video  = document.getElementById('cam-video');
  const canvas = document.getElementById('scan-canvas');

  scanner = new QRScanner({
    videoEl:        video,
    canvasEl:       canvas,
    onDetected:     onQRDetected,
    onStatusChange: msg => {
      const el = document.getElementById('cam-status');
      if (el) el.textContent = (msg.includes('detected') || msg.includes('✓') ? '✓ ' : '🔍 ') + msg;
    },
    onError: msg => toast(msg, 'warn'),
  });

  // Torch button
  document.getElementById('btn-torch')?.addEventListener('click', async () => {
    const btn = document.getElementById('btn-torch');
    if (!scanner.torchSupported) { toast('Torch not available on this device', 'warn'); return; }
    const state = await scanner.toggleTorch();
    btn.classList.toggle('lit', state);
    btn.setAttribute('aria-pressed', state);
  });

  // Gallery button
  document.getElementById('btn-gallery')?.addEventListener('click', () => {
    document.getElementById('file-input')?.click();
  });
  document.getElementById('file-input')?.addEventListener('change', async e => {
    const file = e.target.files?.[0];
    if (!file) return;
    try {
      const payload = await scanner.scanFile(file);
      await onQRDetected(payload);
    } catch (err) {
      toast(err.message, 'bad');
    }
    e.target.value = '';
  });

  // Demo button
  document.getElementById('btn-demo')?.addEventListener('click', () => {
    const url = DEMO_URLS[_demoIdx % DEMO_URLS.length];
    _demoIdx++;
    onQRDetected(url);
  });

  // Start camera
  scanner.start();
}

// ══════════════════════════════════════════════════════════════
//  OFFLINE / ONLINE
// ══════════════════════════════════════════════════════════════

function setupOffline() {
  const banner = document.getElementById('off-banner');
  window.addEventListener('offline', () => {
    banner?.classList.add('on');
    toast('You are offline', 'warn');
  });
  window.addEventListener('online', async () => {
    banner?.classList.remove('on');
    toast('Back online', 'ok', 2000);
    await flushQueuedReports();
  });
  if (!navigator.onLine) banner?.classList.add('on');
}

// ══════════════════════════════════════════════════════════════
//  PWA INSTALL PROMPT
// ══════════════════════════════════════════════════════════════

let deferredInstall = null;
window.addEventListener('beforeinstallprompt', e => {
  e.preventDefault();
  deferredInstall = e;
  document.getElementById('install-bar')?.classList.add('show');
});
window.addEventListener('appinstalled', () => {
  document.getElementById('install-bar')?.classList.remove('show');
});

// ══════════════════════════════════════════════════════════════
//  SERVICE WORKER — listen for flush messages
// ══════════════════════════════════════════════════════════════

if ('serviceWorker' in navigator) {
  navigator.serviceWorker.addEventListener('message', e => {
    if (e.data?.type === 'FLUSH_REPORTS') flushQueuedReports();
  });
}

// ══════════════════════════════════════════════════════════════
//  BOOTSTRAP
// ══════════════════════════════════════════════════════════════

async function init() {
  // Splash animation
  const fill = document.getElementById('sp-fill');
  if (fill) fill.style.width = '100%';
  await new Promise(r => setTimeout(r, 1200));
  document.getElementById('splash')?.classList.add('gone');
  setTimeout(() => document.getElementById('splash')?.remove(), 550);
  document.getElementById('app')?.classList.add('ready');

  // Load persisted API base
  const savedBase = await getAllSettings().then(s => s.apiBase).catch(() => null);
  if (savedBase) setApiBase(savedBase);

  // First data load
  await refreshStats();
  setupOffline();

  // Nav wiring
  document.querySelectorAll('.nav-btn').forEach(btn => {
    btn.addEventListener('click', () => navigate(btn.dataset.pg));
  });
  document.getElementById('hdr-settings')?.addEventListener('click', () => navigate('settings'));
  document.getElementById('logo-link')?.addEventListener('click', e => {
    e.preventDefault(); navigate('scanner');
  });

  // Install prompt buttons
  document.getElementById('btn-install')?.addEventListener('click', async () => {
    if (!deferredInstall) return;
    deferredInstall.prompt();
    const { outcome } = await deferredInstall.userChoice;
    if (outcome === 'accepted') toast('Quishing Guard installed!', 'ok');
    deferredInstall = null;
    document.getElementById('install-bar')?.classList.remove('show');
  });
  document.getElementById('btn-install-x')?.addEventListener('click', () => {
    document.getElementById('install-bar')?.classList.remove('show');
  });

  // Hash routing
  const hash = location.hash.replace('#', '');
  if (hash && hash !== 'scanner') navigate(hash);

  // Init scanner
  initScanner();

  // Register SW
  if ('serviceWorker' in navigator) {
    navigator.serviceWorker.register('/sw.js', { scope: '/' })
      .then(reg => {
        reg.addEventListener('updatefound', () => {
          reg.installing?.addEventListener('statechange', () => {
            if (reg.installing?.state === 'installed' && navigator.serviceWorker.controller) {
              toast('App updated — refresh for the latest version', 'warn', 7000);
            }
          });
        });
      })
      .catch(e => console.warn('[SW] Registration failed:', e));
  }

  // Expose toast globally for inline handlers
  window.toast = toast;

  console.log('[QG] Quishing Guard PWA ready ✓');
}

document.addEventListener('DOMContentLoaded', init);
