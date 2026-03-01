/**
 * JDINJAX Service Worker — PWA Support
 * Version: 3.4.7
 *
 * Handles:
 *   - App shell caching for offline/fast load
 *   - Cache-first strategy for static assets
 *   - Network-first strategy for API calls
 */

const CACHE_NAME    = 'jdinjax-v3.4.7';
const APP_SHELL     = ['/', '/manifest.json'];

// ── Install: cache app shell ────────────────────────────────────────────────
self.addEventListener('install', event => {
    event.waitUntil(
        caches.open(CACHE_NAME).then(cache => cache.addAll(APP_SHELL))
    );
    self.skipWaiting();
});

// ── Activate: clear old caches ───────────────────────────────────────────────
self.addEventListener('activate', event => {
    event.waitUntil(
        caches.keys().then(keys =>
            Promise.all(keys.filter(k => k !== CACHE_NAME).map(k => caches.delete(k)))
        )
    );
    self.clients.claim();
});

// ── Fetch strategy ────────────────────────────────────────────────────────────
self.addEventListener('fetch', event => {
    const url = new URL(event.request.url);

    // API calls → always network, never cache
    if (url.pathname.startsWith('/api/') || url.pathname === '/health') {
        event.respondWith(fetch(event.request));
        return;
    }

    // External resources (Firebase, Cloudinary, CDNs) → network only
    if (url.origin !== self.location.origin) {
        event.respondWith(fetch(event.request));
        return;
    }

    // App shell → cache first, fall back to network
    event.respondWith(
        caches.match(event.request).then(cached => {
            if (cached) return cached;
            return fetch(event.request).then(response => {
                // Cache successful GET responses for app shell
                if (response.ok && event.request.method === 'GET') {
                    const clone = response.clone();
                    caches.open(CACHE_NAME).then(cache => cache.put(event.request, clone));
                }
                return response;
            }).catch(() => caches.match('/'));
        })
    );
});
