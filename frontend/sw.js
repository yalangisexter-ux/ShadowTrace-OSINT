// ShadowTrace OSINT Service Worker for Offline / Air-Gapped Execution
const CACHE_NAME = "shadowtrace-v2.1";
const STATIC_ASSETS = [
  "/",
  "/index.html",
  "/osint-tools.json",
  "/healthz",
  "/api/v1/system/mode"
];

self.addEventListener("install", (event) => {
  event.waitUntil(
    caches.open(CACHE_NAME).then((cache) => {
      return cache.addAll(STATIC_ASSETS).catch((err) => {
        console.warn("ServiceWorker pre-cache notice:", err);
      });
    })
  );
  self.skipWaiting();
});

self.addEventListener("activate", (event) => {
  event.waitUntil(
    caches.keys().then((keys) => {
      return Promise.all(
        keys.filter((k) => k !== CACHE_NAME).map((k) => caches.delete(k))
      );
    })
  );
  self.clients.claim();
});

self.addEventListener("fetch", (event) => {
  const url = new URL(event.request.url);

  // For navigation and static files, use Cache-First / Stale-While-Revalidate
  if (event.request.method === "GET") {
    if (url.pathname === "/" || url.pathname === "/index.html" || url.pathname === "/osint-tools.json") {
      event.respondWith(
        caches.match(event.request).then((cached) => {
          const fetchPromise = fetch(event.request).then((networkRes) => {
            if (networkRes && networkRes.status === 200) {
              const clone = networkRes.clone();
              caches.open(CACHE_NAME).then((c) => c.put(event.request, clone));
            }
            return networkRes;
          }).catch(() => cached);
          return cached || fetchPromise;
        })
      );
      return;
    }
  }

  // Pass-through with graceful offline fallback
  event.respondWith(
    fetch(event.request).catch((err) => {
      return caches.match(event.request).then((matched) => {
        if (matched) return matched;
        throw err;
      });
    })
  );
});
