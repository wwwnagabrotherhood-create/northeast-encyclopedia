// Northeast Encyclopedia - app helper (service worker).
// Pages, photos and API calls always come fresh from the server, so a new
// upload shows straight away, also inside the installed app.
// Its jobs: let phones install the site as an app, show a short
// "You are offline" page when there is no internet, and show the
// new-upload alerts (tapping one opens the site or the app).
var NE_OFFLINE_PAGE = '<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Northeast Encyclopedia</title></head>' +
  '<body style="margin:0;font-family:Arial,sans-serif;background:#fbf6e9;color:#14532d;display:flex;align-items:center;justify-content:center;min-height:100vh;text-align:center;padding:24px;box-sizing:border-box">' +
  '<div><div style="width:88px;height:88px;margin:0 auto;border-radius:20px;background:#14532d;color:#fbf6e9;font:700 34px Georgia,serif;line-height:88px">NE</div><h1 style="font-size:22px;margin:18px 0 8px">You are offline</h1>' +
  '<p style="font-size:15px;color:#374151;margin:0 0 20px">Please check your internet connection and try again.</p>' +
  '<button onclick="location.reload()" style="background:#14532d;color:#fff;border:0;border-radius:999px;height:44px;padding:0 26px;font-size:15px;font-weight:700">Try again</button></div></body></html>';
var NE_FLAG = '/__ne_app_installed';

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

// The installed app tells us it is installed, so alerts stop offering "Install app".
self.addEventListener('message', function (event) {
  if (event.data && event.data.neStandalone) {
    event.waitUntil(caches.open('ne-flags').then(function (c) { return c.put(NE_FLAG, new Response('1')); }).catch(function () {}));
  }
});

// New-upload alert: the message itself is empty, so ask the site what is new.
self.addEventListener('push', function (event) {
  event.waitUntil(
    fetch('/api/push/latest', { cache: 'no-store' })
      .then(function (r) { return r.json(); })
      .then(function (d) { return d && d.alert; })
      .catch(function () { return null; })
      .then(function (a) {
        return caches.match(NE_FLAG).catch(function () { return null; }).then(function (installed) {
          var title = (a && a.title) || 'New on Northeast Encyclopedia';
          var body = a ? (a.body || 'Tap to read it now.') : 'Something new was added. Tap to read it now.';
          if (a && a.more > 0) body += '\n+' + a.more + ' more new upload' + (a.more > 1 ? 's' : '');
          var actions = [{ action: 'open', title: 'Open' }];
          if (!installed) actions.push({ action: 'install', title: 'Install app' });
          return self.registration.showNotification(title, {
            body: body,
            icon: '/icon-192.png',
            tag: 'ne-new',
            renotify: true,
            data: { url: (a && a.url) || '/' },
            actions: actions
          });
        });
      })
  );
});

// Tapping the alert opens the new item in the app (or the website);
// "Install app" opens the site and offers to install it.
self.addEventListener('notificationclick', function (event) {
  event.notification.close();
  var url = (event.notification.data && event.notification.data.url) || '/';
  if (event.action === 'install') url += (url.indexOf('?') >= 0 ? '&' : '?') + 'install=1';
  var target = new URL(url, self.location.origin).href;
  event.waitUntil(self.clients.matchAll({ type: 'window', includeUncontrolled: true }).then(function (list) {
    for (var i = 0; i < list.length; i++) {
      var c = list[i];
      if (new URL(c.url).origin === self.location.origin && 'focus' in c) {
        return c.focus().then(function (w) {
          var win = w || c;
          return win.navigate ? win.navigate(target) : self.clients.openWindow(target);
        }).catch(function () { return self.clients.openWindow(target); });
      }
    }
    return self.clients.openWindow(target);
  }));
});
