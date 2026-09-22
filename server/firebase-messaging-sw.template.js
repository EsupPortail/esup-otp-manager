importScripts('/javascripts/push-storage.js');

// The service worker cannot read Vue state. It receives all data through the
// Firebase payload, then opens this manager-side fallback page when notification
// action buttons are unavailable or ignored by the browser.
function confirmationUrl(data) {
    const params = new URLSearchParams({
        apiUrl: data.url,
        uid: data.uid,
        lt: data.lt,
        message: data.message || data.text || '',
    });
    return self.location.origin + '/push-confirm?' + params;
}

async function performAuthenticationAction(data, reject) {
    // tokenSecret is stored locally in IndexedDB when this browser is enrolled.
    // It proves to the API that this exact browser is allowed to answer.
    const registration = await PushStorage.get(data.url, data.uid);
    if (!registration?.tokenSecret) {
        throw new Error('No local Push registration was found.');
    }

    const suffix = reject ? '/reject' : '';
    const endpoint = PushStorage.normalizeApiUrl(data.url)
        + '/users/' + encodeURIComponent(data.uid)
        + '/methods/push/' + encodeURIComponent(data.lt)
        + '/' + encodeURIComponent(registration.tokenSecret)
        + suffix;
    const response = await fetch(endpoint, { method: 'POST', headers: { Accept: 'application/json' } });
    if (!response.ok) {
        throw new Error('The authentication request failed with status ' + response.status + '.');
    }
}

self.addEventListener('notificationclick', event => {
    const data = event.notification.data || {};
    event.notification.close();

    if (data.action === 'desync') {
        event.waitUntil(PushStorage.remove(data.url, data.uid));
        return;
    }

    // Chromium exposes action buttons; Safari often only opens the notification.
    if (event.action === 'accept' || event.action === 'reject') {
        event.waitUntil(performAuthenticationAction(data, event.action === 'reject'));
        return;
    }

    const url = confirmationUrl(data);
    event.waitUntil(clients.openWindow(url).catch(async error => {
        console.error('Unable to open the push confirmation page from notification click', error);
        const clientList = await clients.matchAll({ type: 'window', includeUncontrolled: true });
        const existingClient = clientList.find(client => client.url.startsWith(self.location.origin));

        if (existingClient?.navigate) {
            const navigatedClient = await existingClient.navigate(url);
            return navigatedClient?.focus?.();
        }
        if (existingClient?.focus) {
            return existingClient.focus();
        }
    }));
});

importScripts('/js/firebase-app-compat.js');
importScripts('/js/firebase-messaging-compat.js');

firebase.initializeApp(__FIREBASE_CONFIG__);
const messaging = firebase.messaging();

messaging.onBackgroundMessage(async payload => {
    const data = payload.data || {};
    const isAuthentication = data.action === 'auth';
    const canDisplayActions = Notification.maxActions > 0;
    const body = data.body || data.message || '';
    if (data.action === 'desync') {
        await PushStorage.remove(data.url, data.uid);
    }
    // In background mode the page is closed, so the worker builds the browser
    // notification itself from the data-only Firebase message.
    return self.registration.showNotification(data.title || 'Esup Auth', {
        body: isAuthentication && !canDisplayActions ? body + ' Cliquez pour valider ou refuser.' : body,
        icon: '/images/web_push.svg',
        tag: isAuthentication ? 'esup-otp-auth-' + data.uid + '-' + data.lt : 'esup-otp-' + data.uid,
        renotify: true,
        requireInteraction: isAuthentication,
        data,
        actions: isAuthentication && canDisplayActions ? [
            { action: 'accept', title: 'Accepter' },
            { action: 'reject', title: 'Refuser' },
        ] : [],
    });
});
