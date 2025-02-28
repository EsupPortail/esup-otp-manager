import { MultiSamlStrategy } from "@node-saml/passport-saml";
import { fetch, toPassportConfig } from 'passport-saml-metadata';
import { Cache } from 'file-system-cache';
import os from 'os';
import * as utils from "../../services/utils.js";
import * as fs from 'fs';
import { promisify } from 'node:util';

const passportSamlConfigMap = new Map();

/**
 * @typedef {import('@node-saml/passport-saml/lib/types').PassportSamlConfig & {printServiceProviderMetadata: boolean, idpMetadataUrl: String}} SamlProperties
 */

/**
 * @param {SamlProperties} samlProperties
 */
async function samlPropertiesToPassportSamlConfig(samlProperties) {
    const passportSamlConfig = { ...samlProperties };

    if (!passportSamlConfig.identifierFormat) {
        passportSamlConfig.identifierFormat = "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified";
    }

    if (passportSamlConfig.idpMetadataUrl) {
        const reader = await fetch({ url: passportSamlConfig.idpMetadataUrl, backupStore: new Cache({ basePath: os.tmpdir() }) });

        const config = toPassportConfig(reader);
        for (const conf in config) {
            passportSamlConfig[conf] ||= config[conf];
        }
    }

    // https://github.com/node-saml/node-saml/issues/361
    if (passportSamlConfig.idpCert) {
        passportSamlConfig.idpCert = passportSamlConfig.idpCert.replace(/\s/g, '');
    }

    for (const certType of ["publicCert", "privateKey"]) {
        const certPathPropertyName = certType + "Path";
        const declaredPath = passportSamlConfig[certPathPropertyName];
        if (declaredPath) {
            delete passportSamlConfig[certPathPropertyName];
            const path = utils.resolvePath(declaredPath);

            const cert = fs.readFileSync(path).toString()
            passportSamlConfig[certType] = cert;
        }
    }

    return passportSamlConfig;
}

/**
 * @param {import('express').Request} req
 * @param {[SamlProperties]} samlPropertiesArray
 */
async function getPassportSamlConfig(req, samlPropertiesArray) {
    const hostname = req.hostname;
    let passportSamlConfig = passportSamlConfigMap.get(hostname);
    if (!passportSamlConfig) {
        const samlPropertiesForHost = samlPropertiesArray.find(properties => {
            try {
                return hostname == new URL(properties.callbackUrl).hostname;
            } catch (error) {
                console.error(error);
            }
        });

        if (!samlPropertiesForHost) {
            throw new Error("No SAML properties found for manager_domain_name: " + hostname);
        }

        passportSamlConfig = await samlPropertiesToPassportSamlConfig(samlPropertiesForHost);
        passportSamlConfigMap.set(hostname, passportSamlConfig);
    }

    return passportSamlConfig;
}

/**
 * @param {[SamlProperties]} samlPropertiesArray
 * @param {(login: {user: String, attributes: {}}, done: Function) => void} verifyFunction 
 */
export default async function strategy(samlPropertiesArray, verifyFunction) {
    /**
     * @param {import('express').Request} req
     * @param {import('@node-saml/passport-saml/lib/types').VerifiedCallback} done 
     */
    async function getSamlOptions(req, done) {
        try {
            const passportSamlConfig = await getPassportSamlConfig(req, samlPropertiesArray);
            return done(null, passportSamlConfig);
        } catch (error) {
            return done(error);
        }
    }

    /**
     * @param {import('express').Request} req
     * @param {import('@node-saml/node-saml/lib/types').Profile} profile
     * @param {import('@node-saml/passport-saml/lib/types').VerifiedCallback} done 
     */
    async function verify(req, profile, done) {
        const passportSamlConfig = await getPassportSamlConfig(req, samlPropertiesArray);
        verifyFunction({
            user: /** @type {String} */ (profile[passportSamlConfig.uidSamlAttribute]),
            attributes: profile
        }, done);
    }

    const samlStrategy = new MultiSamlStrategy({ passReqToCallback: true, getSamlOptions }, verify, verify);

    /**
     * @param {import('express').Request} req
     * @param {(err: Error | null, metadata?: string) => void} callback 
     */
    async function spMetadata(req, callback) {
        samlStrategy.generateServiceProviderMetadata(req, null, (await getPassportSamlConfig(req, samlPropertiesArray)).publicCert, callback);
    }

    return {
        name: "saml",
        strategy: samlStrategy,
        spMetadata: promisify(spMetadata),
    };
}
