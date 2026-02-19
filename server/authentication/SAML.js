import { MultiSamlStrategy } from "@node-saml/passport-saml";
import { fetch, toPassportConfig } from 'passport-saml-metadata';
import { Cache } from 'file-system-cache';
import os from 'os';
import path from 'path';
import * as fs from 'fs';
import logger from '../../services/logger.js';

/*
 * maps of SAML attribute name/identifiers
 * source: https://registry.federation.renater.fr/attributes
 */
const mappings = {
    "urn:oid:0.9.2342.19200300.100.1.1":             "uid",
    "urn:oid:0.9.2342.19200300.100.1.3":             "mail",
    "urn:oid:1.3.6.1.4.1.5923.1.1.1.1":              "eduPersonAffiliation",
    "urn:oid:1.3.6.1.4.1.5923.1.1.1.2":              "eduPersonNickname",
    "urn:oid:1.3.6.1.4.1.5923.1.1.1.3":              "eduPersonOrgDN",
    "urn:oid:1.3.6.1.4.1.5923.1.1.1.4":              "eduPersonOrgUnitDN",
    "urn:oid:1.3.6.1.4.1.5923.1.1.1.5":              "eduPersonPrimaryAffiliation",
    "urn:oid:1.3.6.1.4.1.5923.1.1.1.6":              "eduPersonPrincipalName",
    "urn:oid:1.3.6.1.4.1.5923.1.1.1.7":              "eduPersonEntitlement",
    "urn:oid:1.3.6.1.4.1.5923.1.1.1.8":              "eduPersonPrimaryOrgUnitDN",
    "urn:oid:1.3.6.1.4.1.5923.1.1.1.9":              "eduPersonScopedAffiliation",
    "urn:oid:1.3.6.1.4.1.5923.1.1.1.10":             "eduPersonTargetedID",
    "urn:oid:1.3.6.1.4.1.5923.1.1.1.11":             "eduPersonAssurance",
    "urn:oid:1.3.6.1.4.1.5923.1.1.1.12":             "eduPersonPrincipalNamePrior",
    "urn:oid:1.3.6.1.4.1.5923.1.1.1.13":             "eduPersonUniqueId",
    "urn:oid:2.5.4.3":                               "cn",
    "urn:oid:2.5.4.4":                               "sn",
    "urn:oid:2.5.4.7":                               "l",
    "urn:oid:2.5.4.10":                              "o",
    "urn:oid:2.5.4.11":                              "ou",
    "urn:oid:2.5.4.12":                              "title",
    "urn:oid:2.5.4.13":                              "description",
    "urn:oid:2.5.4.16":                              "postalAddress",
    "urn:oid:2.5.4.20":                              "telephoneNumber",
    "urn:oid:2.5.4.23":                              "facsimileTelephoneNumber",
    "urn:oid:2.5.4.42":                              "givenName",
    "urn:oid:2.16.840.1.113730.3.1.39":              "preferredLanguage",
    "urn:oid:2.16.840.1.113730.3.1.241":             "displayName",
    "urn:oasis:names:tc:SAML:attribute:subject-id":  "subject-id",
    "urn:oasis:names:tc:SAML:attribute:pairwise-id": "pairwise-id"
};

/**
 * @param {import('@node-saml/passport-saml/lib/types').PassportSamlConfig & {printServiceProviderMetadata: boolean}} properties
 */
export default async function authentication(properties) {

    if (!properties.sp) {
        throw new Error("SAML.sp must be defined in properties/esup.json");
    }

    if (!properties.sp.entityID) {
        throw new Error("SAML.sp.entityID must be defined in properties/esup.json");
    }

    const options = {
        issuer:             properties.sp.entityID,
        callbackUrl:        properties.sp.callbackUrl        || "http://localhost/login",
        logoutCallbackUrl:  properties.sp.logoutCallbackUrl  || "http://localhost/logout",
        identifierFormat:   properties.sp.identifierFormat   || "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified",
        signatureAlgorithm: properties.sp.signatureAlgorithm || "sha256",
        racComparison:      properties.sp.racComparison      || "exact",
    };

    if (properties.sp.signatureCertPath) {
        const value = fs.readFileSync(path.resolve(properties.sp.signatureCertPath)).toString();
        options["publicCert"] = value;
    }

    if (properties.sp.signatureKeyPath) {
        const value = fs.readFileSync(path.resolve(properties.sp.signatureKeyPath)).toString();
        options["privateKey"] = value;
    }

    if (properties.sp.encryptionCertPath) {
        const value = fs.readFileSync(path.resolve(properties.sp.encryptionCertPath)).toString();
        options["decryptionPbc"] = value;
    }

    if (properties.sp.encryptionKeyPath) {
        const value = fs.readFileSync(path.resolve(properties.sp.encryptionKeyPath)).toString();
        options["decryptionPvk"] = value;
    }

    if (!properties.idp) {
        throw new Error("SAML.idp must be defined in properties/esup.json");
    }

    if (properties.idp.metadataUrl) {
        const reader = await fetch({ url: properties.idp.metadataUrl, backupStore: new Cache({ basePath: os.tmpdir() }) });

        const config = toPassportConfig(reader);
        for (const conf in config) {
            options[conf] ||= config[conf];
        }
    } else if (properties.idp.cert && properties.idp.entryPoint) {
        // https://github.com/node-saml/node-saml/issues/361
        options["cert"]       = properties.idp.cert.replace(/\s/g, '');
        options["entryPoint"] = properties.idp.entryPoint;
        options["logoutUrl"]  = properties.idp.logoutUrl;
    } else {
        throw new Error("either SAML.idp.metadataUrl or (SAML.idp.cert and SAML.idp.entryPoint) must be defined in properties/esup.json");
    }

    options['passReqToCallback'] = true;
    options['getSamlOptions'] = function (req, done) {
        let options;
        if (req.query.authnContext) {
            options = { authnContext: [ req.query.authnContext ] };
        } else {
            options = { disableRequestedAuthnContext: true };
        }
        return done(null, options);
    };

    /**
         * @param {import('@node-saml/node-saml/lib/types').Profile} profile
         * @param {import('@node-saml/passport-saml/lib/types').VerifiedCallback} done 
         */

    const strategy = new MultiSamlStrategy(
        options,
        function(req, profile, done) {
            logger.debug("raw profile: " + JSON.stringify(profile, null, 2));
            const context = profile.getAssertion().Assertion.AuthnStatement[0].AuthnContext[0].AuthnContextClassRef[0]._;
            // reindex SAML attributes by name, instead of identifiers, for ACL usage
            const attributes = {};
            for (const [key, value] of Object.entries(profile.attributes)) {
                attributes[mappings[key]] = value;
            };
            const uidAttribute = properties.sp.uidAttribute   || 'eduPersonPrincipalName';
            const nameAttribute = properties.sp.nameAttribute || 'displayName';
            return done(null, {
                uid:          attributes[uidAttribute],
                name:         attributes[nameAttribute],
                attributes:   attributes,
                issuer:       profile.issuer,
                context:      context,
                nameID:       profile.nameID,
                nameIDFormat: profile.nameIDFormat,
            });
        }
    );

    return {
        name: "saml",
        strategy: strategy,
        metadata: {
            signatureCert: options.publicCert,
            encryptionCert: options.decryptionPbc,
        }
    };
}
