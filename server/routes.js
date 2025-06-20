import express from 'express';
const router = express.Router();
import properties from '../properties/properties.js';
import * as utils from '../services/utils.js';
import * as aclUtils from '../services/aclUtils.js';
import * as apiRoutes from './routes/apiRoutes.js';
const isUser = apiRoutes.isUser;
import * as pagesRoutes from './routes/pagesRoutes.js';

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
            name: req.session.passport.user.name,
            transport_regexes: properties.esup.transport_regexes,
        });
    });

    pagesRoutes.routing(router, passport);
    apiRoutes.routing(router);
}

export default async function(_passport) {
    passport = _passport;

    // used to serialize the user for the session
    passport.serializeUser(function(user, done) {
        const _user = {
            uid:          user.uid,
            name:         user.name,
            attributes:   user.attributes,
            issuer:       user.issuer,
            context:      user.context,
            nameID:       user.nameID,
            nameIDFormat: user.nameIDFormat
        };
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

    const authenticationName = properties.esup.authentication || "CAS";
    const authenticationProperties = properties.esup[authenticationName];
    if (!authenticationProperties) {
        throw new Error("No authentication backend defined in esup.properties");
    }
    const { default: authentication } = await import(`./authentication/${authenticationName}.js`);
    properties.authentication = await authentication(authenticationProperties);

    passport.use(properties.authentication.strategy);

    routing();

    return router
}
