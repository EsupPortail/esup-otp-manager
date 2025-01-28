# esup-otp-manager

Manager for the esup-otp-api. Allow users to edit their preferences and admins to administrate ;)

## Version

1.5 **Require `npm install`**

- You can now **redirect a manager to a user's page** using a link like `http://localhost:4000/login?user=toto`
- You can now **prevent users from using their professional e-mail addresses** to *random_code_mail* transport.<br />
For this, in *properties/esup.json*, uncomment *transport_regexes.mail*, and modify the associated regex.<br />
(For example, the regex `^(?!.*(?:univ[.]fr|univ-paris[.]fr)$).*$` prevents e-mail addresses ending with "univ.fr" or "univ-paris.fr")
- Improve user search performance
- Update dependencies
- Some refactors

## Requirements

- [esup-otp-api](https://github.com/EsupPortail/esup-otp-api)

## Installation

```sh
# Download esup-otp-manager
git clone https://github.com/EsupPortail/esup-otp-manager.git
# Install required libraries
npm install
# Copy the default configuration
cp properties/esup-dist.json properties/esup.json
# change the fields values in properties/esup.json to your installation, some explanations are in `#how_to` attributes
# Start server
npm start
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

MIT
   [EsupPortail]: <https://www.esup-portail.org/>
