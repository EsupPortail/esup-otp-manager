import properties from '../../properties/properties.js';
import * as utils from '../../services/utils.js';
import * as tenants from '../tenants.js';
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

    function logUser(req, res, next, user) {
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
    };

    if (properties.authentication.name == 'cas') {
        router.all('/login', function(req, res, next) {
            passport.authenticate('cas', function(err, user, info) {
                if (err) {
                    logger.error(err);
                    return next(err);
                }

                if (!user) {
                    console.log(info.message);
                    return res.redirect('/');
                }

                return logUser(req, res, next, user);
            })(req, res, next);
        });

        router.get('/logout', function(req, res, next) {
            req.logout(function(err) {
                if (err) { return next(err); }
                res.redirect(properties.esup.CAS.casBaseURL + 'logout');
            });
        });
    } else if (properties.authentication.name == 'saml') {

        async function getUserActiveMethods(user) {
            // TODO: do it on API-side
            const tenant = user.issuer;
            const password = await tenants.getApiPassword(tenant);

            const response = await fetch(properties.esup.api_url + '/protected/users/' + user.uid, {headers: {
                'Content-Type': 'application/json',
                'X-Tenant': tenant,
                'Authorization':  'Bearer ' + password
            }});
            const data = await response.json();
            const methods = data.user.methods;

            var active_methods = [];
            for (const method of ['random_code', 'random_code_mail', 'bypass', 'passcode_grid', 'totp', 'push', 'esupnfc', 'webauthn']) {
                if (method in methods && methods[method].active === true) {
                    active_methods.push(method);
                }
            }

            return active_methods;
        }

        async function logOrReauthUser(req, res, next, user) {
            const methods = await getUserActiveMethods(user);
            if (methods.length) {
                if (user.context == properties.esup.SAML.sp.normalAuthnContext) {
                    return logUser(req, res, next, user);
                } else {
                    console.log(`authentication context ${user.context} insufficient for user ${user.uid}, reauthentication required`);
                    let params = new URLSearchParams();
                    params.set('authnContext', properties.esup.SAML.sp.normalAuthnContext);
                    return res.redirect('/login' + "?" + params);
                }
            } else {
                return logUser(req, res, next, user);
            }
        }

        router.get('/login', function(req, res, next) {
            console.log("initiating login");
            passport.authenticate('saml')(req, res, next);
        });

        router.post('/login', function(req, res, next) {
            console.log("completing login");
            passport.authenticate('saml', function(err, user, info) {
                if (err) {
                    console.log(err);
                    return next(err);
                }

                if (!user) {
                    console.log(info.message);
                    return res.redirect('/');
                }

                return logOrReauthUser(req, res, next, user);
            })(req, res, next);
        });

        router.get('/logout', function(req, res, next) {
            if (!req.user) { res.redirect('/') };
            console.log(`initiating logout for user ${req.user.uid}`);
            return properties.authentication.strategy.logout(req, function(err, url) {
                return res.redirect(url);
            });
        });

        router.post('/logout', function(req, res, next) {
            console.log(`completing logout for user ${req.user.uid}`);
            req.logout(function(err) {
                if (err) { return next(err); }
                res.redirect('/');
            });
        });

        const spMetadataUrl = properties.esup.SAML.sp.metadataUrl;
        if (spMetadataUrl) {
            router.get("/" + spMetadataUrl, function(req, res, next) {
                res.send(
                    properties.authentication.strategy.generateServiceProviderMetadata(
                        req,
                        properties.authentication.metadata.encryptionCert,
                        properties.authentication.metadata.signatureCert,
                        function (err, data) {
                            if (err) {
                                return next();
                            }
                            res.type('xml');
                            res.send(data);
                        }
                    )
                );
            });
        }
    }
}
