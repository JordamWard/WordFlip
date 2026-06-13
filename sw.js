// WordFlip Service Worker
// Strategy: cache-first for app shell, network-first for everything else
const CACHE_NAME = "wordflip-v1";

// Everything needed to run offline
const PRECACHE = [
  "/",
  "/index.html",
  "/wordflip-icon.svg",
  "/icon-192.png",
  "/icon-512.png",
  "/apple-touch-icon.png",
  "/manifest.json",
  "https://unpkg.com/react@18/umd/react.production.min.js",
  "https://unpkg.com/react-dom@18/umd/react-dom.production.min.js",
  "https://unpkg.com/@babel/standalone/babel.min.js",
  "https://fonts.googleapis.com/css2?family=Fraunces:ital,wght@0,400;0,700;0,900;1,700&family=JetBrains+Mono:wght@400;700;800&display=swap",
];

// ── Install: cache everything we need ────────────────────────────────────────
self.addEventListener("install", (event) => {
  event.waitUntil(
    caches.open(CACHE_NAME).then((cache) => {
      // Cache local files strictly; CDN files best-effort
      const local = PRECACHE.filter(u => u.startsWith("/"));
      const cdn   = PRECACHE.filter(u => !u.startsWith("/"));
      return cache.addAll(local).then(() =>
        Promise.allSettled(cdn.map(u => cache.add(u)))
      );
    }).then(() => self.skipWaiting())
  );
});

// ── Activate: clean up old caches ────────────────────────────────────────────
self.addEventListener("activate", (event) => {
  event.waitUntil(
    caches.keys().then(keys =>
      Promise.all(keys.filter(k => k !== CACHE_NAME).map(k => caches.delete(k)))
    ).then(() => self.clients.claim())
  );
});

// ── Fetch: cache-first for app shell, passthrough for everything else ─────────
self.addEventListener("fetch", (event) => {
  // Only handle GET requests
  if (event.request.method !== "GET") return;

  const url = new URL(event.request.url);

  // App shell + CDN assets: cache first, fall back to network
  const isCached =
    url.origin === self.location.origin ||
    url.hostname === "unpkg.com" ||
    url.hostname === "fonts.googleapis.com" ||
    url.hostname === "fonts.gstatic.com";

  if (isCached) {
    event.respondWith(
      caches.match(event.request).then(cached => {
        if (cached) return cached;
        return fetch(event.request).then(response => {
          if (response && response.status === 200) {
            const clone = response.clone();
            caches.open(CACHE_NAME).then(cache => cache.put(event.request, clone));
          }
          return response;
        }).catch(() => caches.match("/index.html")); // offline fallback
      })
    );
  }
});
