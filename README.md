# esup-otp-manager

Manager for the esup-otp-api. Allow users to edit their preferences and admins to administrate ;)

## Version

2.0 **Require `npm install`**

## Requirements

- [esup-otp-api](https://github.com/EsupPortail/esup-otp-api)

## Installation

```sh
# Download esup-otp-manager
git clone https://github.com/EsupPortail/esup-otp-manager.git
# Install required libraries
npm install
# change the fields values in properties/esup.json to your installation, some explanations are in `#how_to` attributes
# Start server
npm start
```

### Push notifications

The `push` method can register both Esup Auth mobile devices and browsers. Browser notifications require a Firebase Web application and a public Web Push VAPID key. Add their public values to `properties/esup.json`:

```json
"push": {
  "firebaseConfig": {
    "apiKey": "...",
    "authDomain": "...",
    "projectId": "...",
    "storageBucket": "...",
    "messagingSenderId": "...",
    "appId": "..."
  },
  "vapidKey": "..."
}
```

The Firebase service account and its private key belong only in `esup-otp-api`. The Manager configuration above is public browser configuration. Browser push requires HTTPS in production; `localhost` is accepted for local development. The reverse proxy must expose `/firebase-messaging-sw.js` at the Manager origin root.

For local tests on macOS, make sure notifications are allowed both in the browser and in macOS settings:

- Chrome site setting: allow notifications for the Manager origin, for example `http://localhost:4000`.
- macOS System Settings > Notifications: allow notifications for `Google Chrome`.
- macOS System Settings > Notifications: allow notifications for `Google Chrome Helper (Alerts)` when it appears. Chrome may have `Notification.permission === "granted"` while macOS still blocks the displayed notification through this helper.

Safari supports Web Push but does not display notification action buttons consistently. When action buttons are not available, users should click the notification itself; the Manager opens a confirmation page with accept/reject buttons.

Useful browser console checks on the Manager origin:

```js
Notification.permission
navigator.serviceWorker.ready.then(r => console.log(r.scope, r.active?.scriptURL, r.active?.state))
fetch('/manager/infos')
  .then(r => r.json())
  .then(i => PushStorage.get(i.api_url, i.uid))
  .then(console.log)
```

### Behind Apache

- https

```apache
RequestHeader set X-Forwarded-Proto https
RequestHeader set X-Forwarded-Port 443

RewriteEngine On

RewriteCond %{QUERY_STRING} transport=websocket [NC]
RewriteRule /(.*) ws://127.0.0.1:4000/$1 [P]


<Location />
ProxyPass http://127.0.0.1:4000/ retry=1
ProxyPassReverse http://127.0.0.1:4000/
</Location>
```

### Systemd

```ini
[Unit]
Description=esup-otp-manager nodejs app
Documentation=https://github.com/EsupPortail/esup-otp-manager
After=network.target

[Service]
Type=simple
User=esup
WorkingDirectory=/opt/esup-otp-manager
ExecStart=/usr/bin/node run
Restart=on-failure

[Install]
WantedBy=multi-user.target
```

## License

Please see the file called `LICENSE`.
