'use strict';

/**
 * Notification URLs are attacker-controlled push data until validated.
 * Never open another origin, a path outside this SW scope or an unreviewed
 * in-app route. Revalidate even on notificationclick.
 * TEST-only source change: no deployed sites or E2EE keys are affected.
 */
const SAFE_NOTIFICATION_HASH = /^#\/(?:home|chats|mail|reminders?|calls|profile)(?:\/[A-Za-z0-9_-]{1,128})?$/;
function safeNotificationUrl(raw, fallback = './#/home') {
  const scope = new URL(self.registration.scope);
  const safeFallback = new URL(fallback, scope).href;
  if (typeof raw !== 'string' || raw.length > 300 || /[\u0000-\u001f\u007f]/.test(raw)) {
    return safeFallback;
  }
  try {
    const url = new URL(raw, scope);
    if (url.origin !== scope.origin || url.pathname !== scope.pathname ||
        url.search !== '' || !SAFE_NOTIFICATION_HASH.test(url.hash)) {
      return safeFallback;
    }
    return url.href;
  } catch (_) {
    return safeFallback;
  }
}

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

  if (!payload || typeof payload !== 'object' || Array.isArray(payload)) {
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

    const url = safeNotificationUrl(payload.url, './#/home');

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

  /* BharatLink Messaging */
  if (payload.type === 'message') {
    const eventId =
      typeof payload.event_id === 'string'
        ? payload.event_id
        : '';

    event.waitUntil(
      self.registration.showNotification(
        'New BharathLink message',
        {
          body: 'You have a new encrypted message.',
          tag: eventId
            ? `bharathlink-message-${eventId}`
            : 'bharathlink-message-new',
          data: {
            url: safeNotificationUrl('./#/chats'),
            type: 'message',
            event_id: eventId
          }
        }
      )
    );

    return;
  }

  /* Existing BharathMail push */
  const mailId =
    typeof payload.mail_id === 'string'
      ? payload.mail_id
      : '';

  event.waitUntil(
    self.registration.showNotification(
      'New BharathMail',
      {
        body: 'You have a new message.',
        tag: mailId
          ? `bharatmail-${mailId}`
          : 'bharatmail-new',
        data: {
          url: safeNotificationUrl('./#/mail'),
          mail_id: mailId,
          type: 'bharatmail'
        }
      }
    )
  );
});

self.addEventListener('notificationclick', event => {
  event.notification.close();

  const data = event.notification.data || {};
  const fallback = data.type === 'message' ? './#/chats' :
    data.type === 'bharatmail' ? './#/mail' : './#/home';
  const target = safeNotificationUrl(data.url, fallback);

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
