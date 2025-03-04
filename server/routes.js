import express from 'express';
const router = express.Router();
import properties from '../properties/properties.js';
import * as utils from '../services/utils.js';
import * as aclUtils from '../services/aclUtils.js';
import * as apiRoutes from './routes/apiRoutes.js';
const isUser = apiRoutes.isUser;
import * as pagesRoutes from './routes/pagesRoutes.js';
import logger from '../services/logger.js';
import { Strategy as CasStrategy } from '@coursetable/passport-cas';

let passport;


function routing() {
    router.get('/status', function(req,res) {
        res.status(200);
        res.send({
            code: 'Ok'
        });
    });

    router.get('/manager/messages/{:language}', isUser, function(req, res) {
        res.json(utils.getMessagesForRequest(req));
    });

    router.get('/manager/users_methods', isUser, function(req, res) {
        res.send({ unauthorized: aclUtils.getUnauthorizedMethods(req.user) });
    });

    router.get('/manager/infos', isUser, function(req, res) {
        res.send({
            api_url: properties.esup.api_url,
            uid: req.session.passport.user.uid,
            transport_regexes: properties.esup.transport_regexes,
        });
    });

    pagesRoutes.routing(router, passport);
    apiRoutes.routing(router);
}

export default function(_passport) {
    passport = _passport;

    // used to serialize the user for the session
    passport.serializeUser(function(user, done) {
        const _user = {};
        _user.uid=user.uid;
        _user.attributes=user.attributes;
        aclUtils.prepareUserForAcl(_user);
        if (aclUtils.is_admin(user)) _user.role = "admin";
        else if (aclUtils.is_manager(user)) _user.role = "manager";
        else _user.role = "user";
        done(null, _user);
    });

    // used to deserialize the user
    passport.deserializeUser(function(user, done) {
            done(null, user);
    });

    const CAS = properties.esup.CAS;
    if (CAS.casBaseURL.endsWith('/')) {
        CAS.casBaseURL = CAS.casBaseURL.slice(0, -1);
    }

    const passportCasOpts = {
        version: CAS.version,
        ssoBaseURL: CAS.casBaseURL,
        serverBaseURL: CAS.serviceBaseURL,
    }

    passport.use(new CasStrategy(passportCasOpts, function(profile, done) {
        if(logger.isDebugEnabled) {
            logger.debug("profile : " + JSON.stringify(profile, null ,2));
        }
        return done(null, {uid:profile.user, attributes:profile.attributes});
    }));

    routing();

    return router
}
