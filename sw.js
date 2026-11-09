// Service worker minimo: serve per installare l'app. Prende sempre la versione online;
// solo se manca la rete usa l'ultima copia salvata delle pagine di questa app.
const CACHE = 'app-v1';
self.addEventListener('install', () => self.skipWaiting());
self.addEventListener('activate', e => e.waitUntil(self.clients.claim()));
self.addEventListener('fetch', e => {
  const r = e.request;
  if (r.method !== 'GET' || new URL(r.url).origin !== location.origin) return; // Firebase, Maps ecc.: invariati
  e.respondWith(fetch(r).then(res => {
    if (res.ok) { const c = res.clone(); caches.open(CACHE).then(k => k.put(r.url.split("?")[0], c)); }
    return res;
  }).catch(() => caches.match(r.url.split("?")[0])));
});
