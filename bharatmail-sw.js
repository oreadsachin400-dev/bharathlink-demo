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

  /* BharathMail push */
  const mailId =
    typeof payload.mail_id === 'string'
      ? payload.mail_id
      : '';

  const options = {
    body: 'You have a new message.',
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
      'New BharathMail',
      options
    )
  );
});

self.addEventListener('notificationclick', event => {
  event.notification.close();

  const data = event.notification.data || {};
  const route =
    data.type === 'bharatmail'
      ? './#/mail'
      : (typeof data.url === 'string' && data.url
          ? data.url
          : './#/home');

  const targetUrl = new URL(route, self.registration.scope).href;

  event.waitUntil((async () => {
    const list = await self.clients.matchAll({
      type: 'window',
      includeUncontrolled: true
    });

    for (const client of list) {
      if ('navigate' in client) {
        try {
          const navigated = await client.navigate(targetUrl);
          if (navigated && 'focus' in navigated) {
            return navigated.focus();
          }
        } catch (_) {
          /* If navigation fails, do not focus the wrong route. */
        }
      }
    }

    if (self.clients.openWindow) {
      return self.clients.openWindow(targetUrl);
    }
  })());
});
