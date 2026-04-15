<!DOCTYPE html>
<html lang="it">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>service-worker.js aligned - GG84_V.2_15.04.2026</title>
<style>
body { margin:0; font-family: Arial, sans-serif; background:#f4f4f2; color:#111; }
header { padding:14px 16px; background:#111; color:#fff; font-weight:700; }
main { padding:16px; }
pre { white-space: pre-wrap; word-break: break-word; background:#fff; border:1px solid #ddd; border-radius:12px; padding:14px; font-size:12px; line-height:1.45; }
</style>
</head>
<body>
<header>service-worker.js aligned - GG84_V.2_15.04.2026</header>
<main><pre>const GG84_CACHE = &quot;gg84-pwa-v2-15-04-26&quot;;

const APP_SHELL = [
  &quot;./&quot;,
  &quot;./index.html&quot;,
  &quot;./intro.html&quot;,
  &quot;./setup.html&quot;,
  &quot;./chiave.html&quot;,
  &quot;./identita.html&quot;,
  &quot;./cifra.html&quot;,
  &quot;./pro.html&quot;,
  &quot;./cifra_share.html&quot;,
  &quot;./script.js&quot;,
  &quot;./gg84_ux.css&quot;,
  &quot;./manifest.json&quot;,
  &quot;./logo3.png&quot;,
  &quot;./icon-192.png&quot;,
  &quot;./icon-512.png&quot;
];

self.addEventListener(&quot;install&quot;, (event) =&gt; {
  event.waitUntil(
    caches.open(GG84_CACHE).then(async (cache) =&gt; {
      for (const asset of APP_SHELL) {
        try {
          await cache.add(asset);
        } catch (error) {
          console.warn(&quot;SW cache skip:&quot;, asset, error);
        }
      }
    })
  );
  self.skipWaiting();
});

self.addEventListener(&quot;activate&quot;, (event) =&gt; {
  event.waitUntil(
    caches.keys().then((keys) =&gt;
      Promise.all(
        keys.map((key) =&gt; {
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

self.addEventListener(&quot;fetch&quot;, (event) =&gt; {
  const request = event.request;

  if (request.method !== &quot;GET&quot;) {
    return;
  }

  const requestUrl = new URL(request.url);

  if (requestUrl.origin !== self.location.origin) {
    return;
  }

  if (request.mode === &quot;navigate&quot;) {
    event.respondWith(
      fetch(request)
        .then((response) =&gt; {
          const responseClone = response.clone();
          caches.open(GG84_CACHE).then((cache) =&gt; {
            cache.put(&quot;./index.html&quot;, responseClone).catch(() =&gt; {});
          });
          return response;
        })
        .catch(async () =&gt; {
          const cachedIndex = await caches.match(&quot;./index.html&quot;);
          return cachedIndex || Response.error();
        })
    );
    return;
  }

  event.respondWith(
    caches.match(request).then((cachedResponse) =&gt; {
      if (cachedResponse) {
        return cachedResponse;
      }

      return fetch(request)
        .then((networkResponse) =&gt; {
          if (!networkResponse || networkResponse.status !== 200) {
            return networkResponse;
          }

          const responseClone = networkResponse.clone();
          caches.open(GG84_CACHE).then((cache) =&gt; {
            cache.put(request, responseClone).catch(() =&gt; {});
          });

          return networkResponse;
        })
        .catch(() =&gt; caches.match(&quot;./index.html&quot;));
    })
  );
});</pre></main>
</body>
</html>