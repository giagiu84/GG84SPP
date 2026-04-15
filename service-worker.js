const GG84_CACHE = "gg84-pwa-v2-15-04-26";

const APP_SHELL = [
  "./",
  "./index.html",
  "./intro.html",
  "./setup.html",
  "./chiave.html",
  "./identita.html",
  "./cifra.html",
  "./cifra_share.html",
  "./pro.html",
  "./script.js",
  "./gg84_ux.js",
  "./gg84_ux.css",
  "./manifest.json",
  "./logo3.png",
  "./icon-192.png",
  "./icon-512.png"
];

self.addEventListener("install", (event) => {
  event.waitUntil(
    caches.open(GG84_CACHE).then(async (cache) => {
      for (const asset of APP_SHELL) {
        try {
          await cache.add(asset);
        } catch (error) {
          console.warn("SW cache skip:", asset, error);
        }
      }
    })
  );
  self.skipWaiting();
});

self.addEventListener("activate", (event) => {
  event.waitUntil(
    caches.keys().then((keys) =>
      Promise.all(
        keys.map((key) => {
          if (key !== GG84_CACHE) {
            return caches.delete(key);
          }
          return Promise.resolve();
        })
      )
    )
  );
  self.clients.claim();
});

self.addEventListener("fetch", (event) => {
  const request = event.request;

  if (request.method !== "GET") {
    return;
  }

  const requestUrl = new URL(request.url);

  if (requestUrl.origin !== self.location.origin) {
    return;
  }

  if (request.mode === "navigate") {
    event.respondWith(
      fetch(request)
        .then((response) => {
          const responseClone = response.clone();
          caches.open(GG84_CACHE).then((cache) => {
            cache.put("./index.html", responseClone).catch(() => {});
          });
          return response;
        })
        .catch(async () => {
          const cachedIndex = await caches.match("./index.html");
          return cachedIndex || Response.error();
        })
    );
    return;
  }

  event.respondWith(
    caches.match(request).then((cachedResponse) => {
      if (cachedResponse) {
        return cachedResponse;
      }

      return fetch(request)
        .then((networkResponse) => {
          if (!networkResponse || networkResponse.status !== 200) {
            return networkResponse;
          }

          const responseClone = networkResponse.clone();
          caches.open(GG84_CACHE).then((cache) => {
            cache.put(request, responseClone).catch(() => {});
          });

          return networkResponse;
        })
        .catch(() => caches.match("./index.html"));
    })
  );
});