const properties = require(__dirname + '/../../properties/properties');
const utils = require(__dirname + '/../../services/utils');

function isUser(req, res, next) {
    if (utils.isAuthenticated(req)) return next();
    res.redirect('/login'); // can't use 401 because of https://www.rfc-editor.org/rfc/rfc7235#section-3.1 (302 is used by default)
}

exports.routing = function(router, passport) {
    router.get('/', function(req, res) {
        res.render('index', {
            title: 'Esup Otp Manager',
            messages: utils.getMessagesForRequest(req).messages,
        });
    });

    router.get('/forbidden', isUser, function(req, res) {
        res.render('forbidden', {
            title: 'Esup Otp Manager',
            user: req.session.passport.user
        });
    });

    router.get('/preferences', isUser, function(req, res) {
        var right = "user";
        if (utils.is_manager(req.session.passport.user)) right = "manager";
        if (utils.is_admin(req.session.passport.user)) right = "admin";
        res.render('dashboard', {
            title: 'Esup Otp Manager : Test',
            user: req.session.passport.user,
            right: right
        });
    });

    router.all('/login', function(req, res, next) {
        passport.authenticate(properties.strategy.name, function(err, user, info) {
            if (err) {
                console.log(err);
                return next(err);
            }

            if (!user) {
                console.log(info.message);
                return res.redirect('/');
            }

            req.logIn(user, function(err) {
                if (err) {
                    console.log(err);
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

    if (properties.strategy.name == 'cas') {
        router.get('/logout', function(req, res, next) {
            req.logout(function(err) {
                if (err) { return next(err); }
                res.redirect(properties.esup.CAS.casBaseURL + 'logout');
            });
        });
    } else if (properties.strategy.name == 'saml') {
        router.get('/logout', function(req, res, next) {
            properties.strategy.strategy.logout(req, (err, logoutUrl) => {
                if (err) { return next(err); }
                req.logout(function(err) {
                    if (err) { return next(err); }
                    res.redirect(logoutUrl);
                });
            });
        });

        const spMetadataUrl = properties.esup.SAML.spMetadataUrl;
        if (spMetadataUrl) {
            router.get("/" + spMetadataUrl, function(req, res, next) {
                res.type('xml');
                res.send(properties.strategy.spMetadata);
            });
        }
    }
}