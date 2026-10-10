// Northeast Encyclopedia - app helper (service worker).
// It stores NOTHING: every page, photo and API call always comes fresh from the
// server, so a new upload shows straight away, also inside the installed app.
// Its only jobs: let phones install the site as an app, and show a short
// "You are offline" page when there is no internet.
var NE_OFFLINE_PAGE = '<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Northeast Encyclopedia</title></head>' +
  '<body style="margin:0;font-family:Arial,sans-serif;background:#fbf6e9;color:#14532d;display:flex;align-items:center;justify-content:center;min-height:100vh;text-align:center;padding:24px;box-sizing:border-box">' +
  '<div><div style="width:88px;height:88px;margin:0 auto;border-radius:20px;background:#14532d;color:#fbf6e9;font:700 34px Georgia,serif;line-height:88px">NE</div><h1 style="font-size:22px;margin:18px 0 8px">You are offline</h1>' +
  '<p style="font-size:15px;color:#374151;margin:0 0 20px">Please check your internet connection and try again.</p>' +
  '<button onclick="location.reload()" style="background:#14532d;color:#fff;border:0;border-radius:999px;height:44px;padding:0 26px;font-size:15px;font-weight:700">Try again</button></div></body></html>';

self.addEventListener('install', function () { self.skipWaiting(); });
self.addEventListener('activate', function (event) { event.waitUntil(self.clients.claim()); });
self.addEventListener('fetch', function (event) {
  var req = event.request;
  // Only full page loads are touched; everything else (API, photos, Google
  // sign-in, ads) goes straight to the network exactly as before.
  if (req.mode !== 'navigate' || req.method !== 'GET') return;
  event.respondWith(fetch(req).catch(function () {
    return new Response(NE_OFFLINE_PAGE, { status: 503, headers: { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store' } });
  }));
});
