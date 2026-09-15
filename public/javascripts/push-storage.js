/* global indexedDB, self, window */
(function (root) {
    'use strict';

    const databaseName = 'esup-otp-push';
    const storeName = 'registrations';

    // IndexedDB is available both to the manager page and to the service
    // worker. It keeps the browser token_secret out of cookies and localStorage.
    function normalizeApiUrl(apiUrl) {
        return String(apiUrl || '').replace(/\/+$/, '');
    }

    function registrationKey(apiUrl, uid) {
        return normalizeApiUrl(apiUrl) + '|' + uid;
    }

    function openDatabase() {
        return new Promise((resolve, reject) => {
            const request = indexedDB.open(databaseName, 1);
            request.onupgradeneeded = () => {
                const database = request.result;
                if (!database.objectStoreNames.contains(storeName)) {
                    database.createObjectStore(storeName, { keyPath: 'key' });
                }
            };
            request.onsuccess = () => resolve(request.result);
            request.onerror = () => reject(request.error);
        });
    }

    async function withStore(mode, callback) {
        const database = await openDatabase();
        try {
            return await new Promise((resolve, reject) => {
                const transaction = database.transaction(storeName, mode);
                const request = callback(transaction.objectStore(storeName));
                request.onsuccess = () => resolve(request.result);
                request.onerror = () => reject(request.error);
                transaction.onerror = () => reject(transaction.error);
            });
        } finally {
            database.close();
        }
    }

    const storage = {
        normalizeApiUrl,
        registrationKey,
        put(registration) {
            const value = {
                ...registration,
                apiUrl: normalizeApiUrl(registration.apiUrl),
                key: registrationKey(registration.apiUrl, registration.uid),
            };
            return withStore('readwrite', store => store.put(value));
        },
        get(apiUrl, uid) {
            return withStore('readonly', store => store.get(registrationKey(apiUrl, uid)));
        },
        remove(apiUrl, uid) {
            return withStore('readwrite', store => store.delete(registrationKey(apiUrl, uid)));
        },
    };

    root.PushStorage = storage;
})(typeof self !== 'undefined' ? self : window);
