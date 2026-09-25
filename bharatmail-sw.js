'use strict';

self.addEventListener('install', () => self.skipWaiting());

self.addEventListener('activate', event => {
  event.waitUntil(self.clients.claim());
});

self.addEventListener('push', event => {
  let payload = {};

  try {
    if (event.data) payload = event.data.json();
  } catch (_) {}

  const mailId = payload && payload.mail_id
    ? String(payload.mail_id)
    : '';

  event.waitUntil(
    self.registration.showNotification('New BharatMail', {
      body: 'You have received a new BharatMail.',
      tag: mailId ? `bharatmail-${mailId}` : 'bharatmail-new',
      data: {
        url: './#/mail',
        mail_id: mailId
      }
    })
  );
});

self.addEventListener('notificationclick', event => {
  event.notification.close();

  const target =
    (event.notification.data && event.notification.data.url) ||
    './#/mail';

  event.waitUntil((async () => {
    const list = await self.clients.matchAll({
      type: 'window',
      includeUncontrolled: true
    });

    for (const client of list) {
      if ('focus' in client) {
        try {
          await client.navigate(target);
        } catch (_) {}

        return client.focus();
      }
    }

    if (self.clients.openWindow) {
      return self.clients.openWindow(target);
    }
  })());
});
