import express from 'express';
const router = express.Router();
import properties from '../properties/properties.js';
import * as utils from '../services/utils.js';
import * as aclUtils from '../services/aclUtils.js';
import * as apiRoutes from './routes/apiRoutes.js';
const isUser = apiRoutes.isUser;
import * as pagesRoutes from './routes/pagesRoutes.js';
import logger from '../services/logger.js';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

let passport;
const __dirname = path.dirname(fileURLToPath(import.meta.url));
const pushServiceWorkerTemplate = fs.readFileSync(path.join(__dirname, 'firebase-messaging-sw.template.js'), 'utf8');


function routing() {
    router.get('/status', function(req,res) {
        res.status(200);
        res.send({
            code: 'Ok'
        });
    });

    router.get('/firebase-messaging-sw.js', function(req, res) {
        const firebaseConfig = properties.esup.push?.firebaseConfig;
        if (!firebaseConfig) {
            return res.status(404).send('// Firebase Push is not configured.');
        }
        res.set('Cache-Control', 'no-store');
        res.type('application/javascript');
        res.send(pushServiceWorkerTemplate.replace('__FIREBASE_CONFIG__', JSON.stringify(firebaseConfig)));
    });

    router.get('/push-confirm', function(req, res) {
        res.render('push-confirm', { lang: properties.esup.default_language || 'en' });
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
            push: properties.esup.push,
        });
    });

    pagesRoutes.routing(router, passport);
    apiRoutes.routing(router);
}

function updateApiUser(user) {
    if (!user.name) {
        return;
    }

    const values = {
        displayName: user.name,
    };

    return apiRoutes.fetch_otp_api({
        method: 'PUT',
        relUrl: '/protected/users/' + user.uid,
        bearerAuth: true,
        body: values,
    });
}

export default async function(_passport) {
    passport = _passport;

    // used to serialize the user for the session
    passport.serializeUser(function(user, done) {
        // async
        updateApiUser(user);

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
        if (aclUtils.is_admin(user)) {
            _user.role = "admin";
            _user.isManager = true;
        } else if (aclUtils.is_manager(user)) {
            _user.role = "manager";
            _user.isManager = true;
        } else {
            _user.role = "user";
        }

        logger.debug("final user: " + JSON.stringify(_user, null, 2));
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
