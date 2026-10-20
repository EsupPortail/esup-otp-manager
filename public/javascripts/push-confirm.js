/* global PushStorage, document, location */
(function () {
    'use strict';

    const params = new URLSearchParams(location.search);
    const apiUrl = params.get('apiUrl');
    const uid = params.get('uid');
    const loginTicket = params.get('lt');
    const message = params.get('message');
    const result = document.getElementById('web-push-result');
    const actions = document.getElementById('web-push-actions');

    document.getElementById('web-push-message').textContent = message || 'Demande de connexion à votre compte';

    // Fallback for browsers that do not expose notification action buttons:
    // clicking the notification opens this page, which answers with the local
    // browser token_secret.
    async function respond(reject) {
        actions.hidden = true;
        result.textContent = 'Traitement en cours...';
        try {
            const registration = await PushStorage.get(apiUrl, uid);
            if (!registration?.tokenSecret) {
                throw new Error('Ce navigateur n’est plus associé à votre compte.');
            }
            const suffix = reject ? '/reject' : '';
            const endpoint = PushStorage.normalizeApiUrl(apiUrl)
                + '/users/' + encodeURIComponent(uid)
                + '/methods/push/' + encodeURIComponent(loginTicket)
                + '/' + encodeURIComponent(registration.tokenSecret)
                + suffix;
            const response = await fetch(endpoint, { method: 'POST', headers: { Accept: 'application/json' } });
            if (!response.ok) {
                throw new Error('La demande n’est plus valide.');
            }
            result.textContent = reject ? 'Connexion refusée.' : 'Connexion acceptée.';
        } catch (error) {
            result.textContent = error.message || 'Impossible de traiter cette demande.';
            actions.hidden = false;
        }
    }

    document.getElementById('web-push-accept').addEventListener('click', () => respond(false));
    document.getElementById('web-push-reject').addEventListener('click', () => respond(true));
})();
