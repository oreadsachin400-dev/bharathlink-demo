'use strict';
self.addEventListener('install', () => self.skipWaiting());
self.addEventListener('activate', event => event.waitUntil(self.clients.claim()));
self.addEventListener('notificationclick', event => {
  event.notification.close();
  const target = (event.notification.data && event.notification.data.url) || './#/mail';
  event.waitUntil((async () => {
    const list = await self.clients.matchAll({type:'window', includeUncontrolled:true});
    for (const client of list) {
      if ('focus' in client) {
        try { await client.navigate(target); } catch (_) {}
        return client.focus();
      }
    }
    if (self.clients.openWindow) return self.clients.openWindow(target);
  })());
});
