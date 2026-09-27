'use strict';

self.addEventListener('install', () => self.skipWaiting());

self.addEventListener('activate', event => {
  event.waitUntil(self.clients.claim());
});

self.addEventListener('push', event => {
  let payload = {};

  try {
    payload = event.data ? event.data.json() : {};
  } catch (_) {
    payload = {};
  }

  /* BharatLink Reminder */
  if (payload.type === 'reminder') {
    const reminderId =
      typeof payload.reminder_id === 'string'
        ? payload.reminder_id
        : '';

    const title =
      typeof payload.title === 'string' && payload.title.trim()
        ? payload.title
        : 'BharatLink Reminder';

    const body =
      typeof payload.body === 'string' && payload.body.trim()
        ? payload.body
        : 'You have a reminder.';

    const url =
      typeof payload.url === 'string' && payload.url
        ? payload.url
        : './#/home';

    event.waitUntil(
      self.registration.showNotification(title, {
        body,
        tag: reminderId
          ? `bharatlink-reminder-${reminderId}`
          : 'bharatlink-reminder',
        data: {
          url,
          type: 'reminder',
          reminder_id: reminderId
        }
      })
    );

    return;
  }

  /* Existing BharatMail push */
  const mailId =
    typeof payload.mail_id === 'string'
      ? payload.mail_id
      : '';

  const options = {
    body: 'You have a new BharatMail.',
    tag: mailId
      ? `bharatmail-${mailId}`
      : 'bharatmail-new',
    data: {
      url: './#/mail',
      mail_id: mailId,
      type: 'bharatmail'
    }
  };

  event.waitUntil(
    self.registration.showNotification(
      'New BharatMail',
      options
    )
  );
});

self.addEventListener('notificationclick', event => {
  event.notification.close();

  const target =
    (event.notification.data &&
      event.notification.data.url) ||
    './#/home';

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
