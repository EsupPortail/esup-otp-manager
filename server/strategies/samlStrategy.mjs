import { Strategy as SamlStrategy } from "@node-saml/passport-saml";
import { fetch, toPassportConfig } from 'passport-saml-metadata';
import { Cache } from 'file-system-cache';
import os from 'os';
import * as utils from "../../services/utils.js";
import * as fs from 'fs';

/**
 * @param {import('@node-saml/passport-saml/lib/types').PassportSamlConfig & {printServiceProviderMetadata: boolean}} samlProperties
 * 
 * @param {(login: {user: String, attributes: {}}, done: Function) => void} verifyFunction 
 */
export default async function strategy(samlProperties, verifyFunction) {

    if (!samlProperties.identifierFormat) {
        samlProperties.identifierFormat = "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified";
    }

    if (samlProperties.idpMetadataUrl) {
        const reader = await fetch({ url: samlProperties.idpMetadataUrl, backupStore: new Cache({ basePath: os.tmpdir() }) });

        const config = toPassportConfig(reader);
        for (const conf in config) {
            samlProperties[conf] ||= config[conf];
        }
    }

    // https://github.com/node-saml/node-saml/issues/361
    if (samlProperties.idpCert) {
        samlProperties.idpCert = samlProperties.idpCert.replace(/\s/g, '');
    }

    for (const certType of ["publicCert", "privateKey"]) {
        const certPathPropertyName = certType + "Path";
        const declaredPath = samlProperties[certPathPropertyName];
        if (declaredPath) {
            delete samlProperties[certPathPropertyName];
            const path = utils.resolvePath(declaredPath);

            const cert = fs.readFileSync(path).toString()
            samlProperties[certType] = cert;
        }
    }

    /**
         * @param {import('@node-saml/node-saml/lib/types').Profile} profile
         * @param {import('@node-saml/passport-saml/lib/types').VerifiedCallback} done 
         */
    function verify(profile, done) {
        verifyFunction({
            user: profile[samlProperties.uidSamlAttribute],
            attributes: profile
        }, done);
    }

    const samlStrategy = new SamlStrategy(samlProperties, verify, verify);

    return {
        name: "saml",
        strategy: samlStrategy,
        spMetadata: samlStrategy.generateServiceProviderMetadata(null, samlProperties.publicCert),
    };
}
