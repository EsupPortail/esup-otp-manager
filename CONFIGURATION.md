# esup-otp-manager configuration

## Authentication

esup-otp-manager support either CAS or SAML authentication.

### CAS

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

### SAML

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

## Logging

esup-otp-manager provides two different log types.

Generic logs, for generic messages, are configured with the following key:
```
"logs": {
    "main": {
        "level": "info",
        "console": false,
        "file": "logs/main.log"
    }
}
```
This object has the following keys:
- `level`: logging level
- `console`: log to console (true/false, default to false)
- `file`: log to given file

If `logs.main` key is not defined, no message will be logged.

Traffic logs, for HTTP queries, are configured with the following key:
```
"logs": {
    "access": {
        "format": "dev",
        "console": false,
        "file": "logs/access.log"
    }
}
```

This object has the following keys:
- `format`: logging format,  see https://github.com/expressjs/morgan#predefined-formats for details (default: 'dev')
- `console`: log to console (true/false, default to false)
- `file`: log to given file

If `logs.access` key is not defined, no traffic will be logged.
