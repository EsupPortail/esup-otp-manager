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

## Configuration

### Authentication

esup-otp-manager support either CAS or SAML authentication.

#### CAS

CAS authentication require the presence of a CAS object in the configuration file:
```
"authentication": "CAS",
"CAS": {
    "version": "CAS3.0",
    "casBaseURL": "http://localhost/cas",
    "serviceBaseURL": "http://localhost:4000/"
},
```

This object has the following keys:
- `version`: "CAS1.0" | "CAS2.0" | "CAS3.0"
- `casBaseURL`: CAS server public URL
- `serviceBaseURL`: esup-otp-manager public URL

#### SAML

SAML authentication require the presence of a SAML object in the configuration file:

```
"authentication": "SAML",
"SAML": {
    "sp": {
        "callbackUrl": "http://localhost:4000/login",
        "entityID": "esup-otp-manager",
        "signatureKeyPath": "certs/key.pem",
        "signatureCertPath": "certs/cert.pem",
        "uidAttribute": "urn:oid:1.3.6.1.4.1.5923.1.1.1.6",
        "nameAttribute": "urn:oid:2.16.840.1.113730.3.1.241",
        "metadataUrl": "Metadata",
    },
    "idp": {
        "metadataUrl": "https://example.com/idp/shibboleth",
    }
},
```

This object has the following keys:
- `sp`: a single SP object, describing esup-otp-manager SAML behavior, with the following keys:
    - `callbackUrl`: absolute URL to redirect the user, after login on IdP
    - `logoutCallbackUrl`: absolute URL to redirect the user, after logout from IdP
    - `entityID`: the SAML identifier (entityID) for this SP
    - `signatureKeyPath`: path to the signature key
    - `signatureCertPath`: path to the signature certificate
    - `encryptionKeyPath`: path to the encryption key
    - `encryptionCertPath`: path to the encryption certificate
    - `uidAttribute`: OID of SAML attribute used as user identifier (default: urn:oid:1.3.6.1.4.1.5923.1.1.1.6)
    - `nameAttribute`: OID of SAML attribute used as user name (default: urn:oid:2.16.840.1.113730.3.1.241)
    - `metadataUrl`: if defined, relative URL where to expose metadata for this SP
    - `initialAuthnContext`: if defined, AuthnContext to use in SAML request for a non-initialized user
    - `normalAuthnContext`: if defined, AuthnContext to use in SAML request for an initialized user
    - `identifierFormat`: identifier format to use in SAML request (default: urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified)
- `idp`: a single IdP object
    - `metadataURL`: URL from which to retrieve IdP metadata

### Logging

esup-otp-manager provides two different log types.

Generic logs, for generic messages, are configured with the following key:
```
"logs": {
    "main": {
        "level": "info",
        "type": "file",
        "file": "logs/main.log"
    }
}
```
This object has the following keys:
- `level`: logging level
- `type`: either 'console' or 'file' (default: 'console')
- `file`: target file, if type is set to 'file'

If `logs.main` key is not defined, no message will be logged.

Traffic logs, for HTTP queries, are configured with the following key:
```
"logs": {
    "access": {
        "format": "dev",
        "type": "file",
        "file": "logs/access.log"
    }
}
```

This object has the following keys:
- `format`: logging format,  see https://github.com/expressjs/morgan#predefined-formats for details (default: 'dev')
- `type`: either 'console' or 'file' (default: 'console')
- `file`: target file, if type is set to 'file'

If `logs.access` key is not defined, no traffic will be logged.

## License

MIT
   [EsupPortail]: <https://www.esup-portail.org/>
