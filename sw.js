// WordFlip Service Worker
// !! Bump this version number every time you deploy a new version !!
// This is what forces home screen installs to update automatically.
const VERSION = "wordflip-v51";
const CACHE_NAME = VERSION;

// Everything needed to run offline
const PRECACHE = [
  "/",
  "/index.html",
  "/react.min.js",
  "/react-dom.min.js",
  "/babel.min.js",
  "/supabase.min.js",
  "/wordflip-icon.svg",
  "/icon-192.png",
  "/icon-512.png",
  "/apple-touch-icon.png",
  "/manifest.json",
  "https://fonts.googleapis.com/css2?family=Fraunces:ital,wght@0,400;0,700;0,900;1,700&family=JetBrains+Mono:wght@400;700;800&display=swap",
];

// ── Install: pre-cache everything, activate immediately ──────────────────────
self.addEventListener("install", (event) => {
  event.waitUntil(
    caches.open(CACHE_NAME).then((cache) => {
      const local = PRECACHE.filter(u => u.startsWith("/"));
      const cdn   = PRECACHE.filter(u => !u.startsWith("/"));
      return cache.addAll(local).then(() =>
        Promise.allSettled(cdn.map(u => cache.add(u)))
      );
    // skipWaiting forces the new SW to take over immediately
    // instead of waiting for all tabs to close
    }).then(() => self.skipWaiting())
  );
});

// ── Activate: delete ALL old caches, claim clients immediately ───────────────
self.addEventListener("activate", (event) => {
  event.waitUntil(
    caches.keys().then(keys =>
      Promise.all(
        keys
          .filter(k => k !== CACHE_NAME) // delete anything that isn't current version
          .map(k => {
            console.log("[SW] Deleting old cache:", k);
            return caches.delete(k);
          })
      )
    // clients.claim makes the new SW control all open tabs right away
    ).then(() => self.clients.claim())
    // Tell all open tabs to reload so they get the new version
    .then(() => self.clients.matchAll({ type: "window" }))
    .then(clients => {
      clients.forEach(client => {
        client.postMessage({ type: "SW_UPDATED", version: VERSION });
      });
    })
  );
});

// ── Fetch: network-first for HTML (always fresh), cache-first for assets ─────
self.addEventListener("fetch", (event) => {
  if (event.request.method !== "GET") return;

  const url = new URL(event.request.url);

  // Never intercept Supabase API calls (direct or via the same-origin proxy)
  if (url.hostname.includes("supabase.co")) return;
  if (url.pathname.startsWith("/sb-proxy/")) return;

  const isLocal = url.origin === self.location.origin;
  const isCDN =
    url.hostname === "fonts.googleapis.com" ||
    url.hostname === "fonts.gstatic.com";

  // index.html: network-first so updates are always picked up
  // Falls back to cache if offline
  if (isLocal && (url.pathname === "/" || url.pathname === "/index.html")) {
    event.respondWith(
      fetch(event.request)
        .then(response => {
          if (response && response.status === 200) {
            const clone = response.clone();
            caches.open(CACHE_NAME).then(cache => cache.put(event.request, clone));
          }
          return response;
        })
        .catch(() => caches.match("/index.html"))
    );
    return;
  }

  // All other local + CDN assets: cache-first (they don't change often)
  if (isLocal || isCDN) {
    event.respondWith(
      caches.match(event.request).then(cached => {
        if (cached) return cached;
        return fetch(event.request).then(response => {
          if (response && response.status === 200) {
            const clone = response.clone();
            caches.open(CACHE_NAME).then(cache => cache.put(event.request, clone));
          }
          return response;
        }).catch(() => caches.match("/index.html"));
      })
    );
  }
});
