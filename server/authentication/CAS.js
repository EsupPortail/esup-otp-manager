import { Strategy as PassportCasStrategy } from "@coursetable/passport-cas";
import logger from '../../services/logger.js';

/**
 * @param {Object}  casProperties 
 * @param {("CAS1.0"|"CAS2.0"|"CAS2.0-with-saml"|"CAS3.0"|"CAS3.0-with-saml")=} casProperties.version
 * @param {String}  casProperties.casBaseURL
 * @param {String=} casProperties.serviceBaseURL
 */
export default function authentication(properties) {
    for (const property of ["casBaseURL", "serviceBaseURL"]) {
        if (properties[property]?.endsWith('/')) {
            properties[property] = properties[property].slice(0, -1);
        }
    }

    const options = {
        version: properties.version,
        ssoBaseURL: properties.casBaseURL,
        serverBaseURL: properties.serviceBaseURL,
        performBackChannelSLO: true,
    };

    return {
        name: "cas",
        strategy: new PassportCasStrategy(options, function(profile, done) {
            logger.debug("raw profile: " + JSON.stringify(profile, null, 2));
            return done(null, {
                uid:        profile.user,
                name:       profile.attributes[properties.nameAttribute || 'displayname'],
                attributes: profile.attributes,
                profile:    profile,
            });
        })
    };
}
