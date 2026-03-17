/**
 * sw.js — Quishing Guard Service Worker
 *
 * Caching strategies (§3.1.2 — offline / PWA requirements):
 *   SHELL assets  → Cache First   (instant offline loads)
 *   API requests  → Network First with offline JSON fallback
 *   Images/icons  → Stale-While-Revalidate
 *
 * Background Sync:
 *   Queued phishing reports are retried on reconnect via BackgroundSync API.
 */

const CACHE_VER   = 'qg-v1.0.0';
const SHELL_CACHE = `${CACHE_VER}-shell`;
const IMG_CACHE   = `${CACHE_VER}-images`;

const SHELL_ASSETS = [
  '/',
  '/index.html',
  '/manifest.json',
  '/css/main.css',
  '/css/animations.css',
  '/js/app.js',
  '/js/api.js',
  '/js/scanner.js',
  '/js/db.js',
  '/offline.html',
];

// ── Install: pre-cache shell ──────────────────────────────────────────────────
self.addEventListener('install', event => {
  event.waitUntil(
    caches.open(SHELL_CACHE)
      .then(cache => cache.addAll(SHELL_ASSETS))
      .then(() => self.skipWaiting())
  );
});

// ── Activate: purge old caches ────────────────────────────────────────────────
self.addEventListener('activate', event => {
  event.waitUntil(
    caches.keys().then(keys =>
      Promise.all(
        keys.filter(k => k.startsWith('qg-') && k !== SHELL_CACHE && k !== IMG_CACHE)
            .map(k => caches.delete(k))
      )
    ).then(() => self.clients.claim())
  );
});

// ── Fetch: route by strategy ──────────────────────────────────────────────────
self.addEventListener('fetch', event => {
  const url = new URL(event.request.url);

  // API calls → Network First
  if (url.pathname.startsWith('/api/')) {
    event.respondWith(networkFirst(event.request));
    return;
  }

  // Images → Stale-While-Revalidate
  if (/\.(png|jpg|jpeg|gif|webp|svg|ico)$/i.test(url.pathname)) {
    event.respondWith(staleWhileRevalidate(event.request, IMG_CACHE));
    return;
  }

  // Shell + everything else → Cache First
  event.respondWith(cacheFirst(event.request));
});

// ── Background Sync: retry queued reports ────────────────────────────────────
self.addEventListener('sync', event => {
  if (event.tag === 'sync-reports') {
    event.waitUntil(flushQueuedReports());
  }
});

// ── Push notifications ────────────────────────────────────────────────────────
self.addEventListener('push', event => {
  const data = event.data ? event.data.json() : {};
  event.waitUntil(
    self.registration.showNotification(data.title || 'Quishing Guard', {
      body:    data.body || 'A previously scanned link has been newly flagged.',
      icon:    '/icons/icon-192.png',
      badge:   '/icons/icon-72.png',
      vibrate: [200, 100, 200],
      data:    data.url ? { url: data.url } : {},
    })
  );
});

self.addEventListener('notificationclick', event => {
  event.notification.close();
  const url = event.notification.data?.url || '/';
  event.waitUntil(clients.openWindow(url));
});

// ── Strategies ────────────────────────────────────────────────────────────────

async function cacheFirst(request) {
  const cached = await caches.match(request);
  if (cached) return cached;
  try {
    const response = await fetch(request);
    if (response.ok) {
      const cache = await caches.open(SHELL_CACHE);
      cache.put(request, response.clone());
    }
    return response;
  } catch {
    return caches.match('/offline.html') || new Response('Offline', { status: 503 });
  }
}

async function networkFirst(request) {
  try {
    const response = await fetch(request);
    return response;
  } catch {
    // Return a structured offline error for API calls
    return new Response(
      JSON.stringify({ error: 'You are offline. This scan could not be analysed.' }),
      { status: 503, headers: { 'Content-Type': 'application/json' } }
    );
  }
}

async function staleWhileRevalidate(request, cacheName) {
  const cache  = await caches.open(cacheName);
  const cached = await cache.match(request);
  const fetchPromise = fetch(request).then(response => {
    if (response.ok) cache.put(request, response.clone());
    return response;
  }).catch(() => cached);
  return cached || fetchPromise;
}

async function flushQueuedReports() {
  // Communicate with the main thread to flush IndexedDB queued reports
  const allClients = await self.clients.matchAll({ type: 'window' });
  for (const client of allClients) {
    client.postMessage({ type: 'FLUSH_REPORTS' });
  }
}
