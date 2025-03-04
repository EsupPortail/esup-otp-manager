import properties from '../../properties/properties.js';
import * as utils from '../../services/utils.js';
import logger from '../../services/logger.js';

function isUser(req, res, next) {
    if (utils.isAuthenticated(req)) return next();
    res.redirect('/login'); // can't use 401 because of https://www.rfc-editor.org/rfc/rfc7235#section-3.1 (302 is used by default)
}

export function routing(router, passport) {
    router.get('/', function(req, res) {
        const reqMessages = utils.getMessagesForRequest(req);
        res.render('index', {
            title: 'ESUP OTP Manager',
            messages: reqMessages.messages,
            lang: reqMessages.lang
        });
    });

    router.get('/forbidden', isUser, function(req, res) {
        res.render('forbidden', {
            title: 'Esup Otp Manager',
            user: req.session.passport.user
        });
    });

    router.get('/preferences', isUser, function(req, res) {
        res.render('dashboard', {
            title: 'Esup Otp Manager : Test',
            user: req.session.passport.user,
            right: req.session.passport.user.role
        });
    });

    router.get('/login', function(req, res, next) {
        passport.authenticate('cas', function(err, user, info) {
            if (err) {
                logger.error(err);
                return next(err);
            }

            if (!user) {
                logger.info(info?.message);
                return res.redirect('/');
            }

            req.logIn(user, function(err) {
                if (err) {
                    logger.error(err);
                    return next(err);
                }
                req.session.messages = '';

                let params = new URLSearchParams()
                for (const param of ['user']) {
                    const val = req.query[param]
                    if (val) params.set(param, val)
                }
                return res.redirect('/preferences' + (params.size ? "?" + params : ""));
            });
        })(req, res, next);
    });

    router.get('/logout', function(req, res, next) {
        req.logout(function(err) {
            if (err) { return next(err); }
            res.redirect(properties.esup.CAS.casBaseURL + '/logout');
        });
    });
}
