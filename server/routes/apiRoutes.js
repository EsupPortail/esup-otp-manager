const { request } = require('undici');
const properties = require(__dirname + '/../../properties/properties');
const utils = require(__dirname + '/../../services/utils');
const logger = require(__dirname + '/../../services/logger');

function redirect(req, res, status, path) {
    res
        .status(status)
        .send({
            "code": "REDIRECT",
            "path": path,
        });
}

function redirectLogin(req, res) {
    redirect(req, res, 401, '/login');
}

function redirectForbidden(req, res) {
    redirect(req, res, 401, '/forbidden');
}

function isUser(req, res, next) {
    if (utils.isAuthenticated(req)) return next();
    redirectLogin(req, res);
}

exports.isUser = isUser;

function isManager(req, res, next) {
    isUser(req, res, () => {
        if (utils.is_manager(req.session.passport.user) || utils.is_admin(req.session.passport.user)) {
            return next();
        } else {
            redirectForbidden(req, res);
        }
    });
}

function isAdmin(req, res, next) {
    isUser(req, res, () => {
        if (utils.is_admin(req.session.passport.user)) {
            return next();
        } else {
            redirectForbidden(req, res);
        }
    });
}

/** @param {{ relUrl: string, queryParams?: Object; bearerAuth?: true, method?: 'GET'|'POST'|'PUT'|'DELETE' }} opts_ */
async function request_otp_api(req, res, opts_) {
    logger.info("requesting api");
    const clientIP = req.ip;
    const userAgent = req.headers['user-agent'];
    /**
     * @typedef {import('undici').Dispatcher.RequestOptions} RequestOptions
     * @type {Omit<RequestOptions, 'origin' | 'path'>}
     */
    let opts = {
        method: opts_.method || 'GET',
    }

    if (req.body && Object.keys(req.body).length) {
        opts.body = JSON.stringify(req.body);
    }
    opts_.queryParams ||= {};
    opts_.queryParams.managerUser = req.session.passport.user.uid;

    const url = properties.esup.api_url + opts_.relUrl + "?" + new URLSearchParams(opts_.queryParams);

    opts.headers = {
        'X-Client-IP': clientIP,
        'Client-User-Agent': userAgent,
        'Content-Type': 'application/json'
    };

    if (opts_.bearerAuth) {
        opts.headers.Authorization = 'Bearer ' + properties.esup.api_password;
    }

    //logger.info(opts.method +':'+ opts.url);
    //logger.info(req.session.passport);
    let response;
    try {
        response = await request(url, opts);
    } catch (error) {
        res.status(503);
        return res.send({
            "code": "Error",
            "message": error.message || "Api did not give a response"
        });
    }
    
    
    // forward the status code, because if the request failed
    // it should not be responding with 200 ("everything is fine !")
    //
    // this helps to have clearer error messages, because getting
    // "error, code 200" with a message containing just "Error" is
    // kind of frustrating.
    res.status(response.statusCode);
    /** @type {Object} */
    const infos = await response.body.json();
    //logger.info(infos)
    res.send(infos);
}

exports.routing = function(router) {
    router.get('/api/user', isUser, function(req, res) {
        request_otp_api(req, res, {
            relUrl: '/protected/users/' + req.session.passport.user.uid,
            bearerAuth: true,
        });
    });

    router.get('/api/methods', isUser, function(req, res) {
        request_otp_api(req, res, {
            relUrl: '/protected/methods/',
            bearerAuth: true,
        });
    });

    router.put('/api/:method/activate', isUser, function(req, res) {
        request_otp_api(req, res, {
            method: 'PUT',
            relUrl: '/protected/users/'+req.session.passport.user.uid+'/methods/'+req.params.method+'/activate',
            bearerAuth: true,
        });
    });
    
    router.post('/api/:method/activate/confirm/:activation_code', isUser, function(req, res) {
        request_otp_api(req, res, {
            method: 'POST',
            relUrl: '/protected/users/' + req.session.passport.user.uid + '/methods/' + req.params.method + '/activate/' + req.params.activation_code,
            bearerAuth: true,
        });
    });
    
    router.post('/api/admin/:method/activate/confirm/:activation_code/:uid', isManager, function(req, res) {
        request_otp_api(req, res, {
            method: 'POST',
            relUrl: '/protected/users/' + req.params.uid + '/methods/' + req.params.method + '/activate/' + req.params.activation_code,
            bearerAuth: true,
        });
    });

    router.post('/api/:method/confirm_activate', isUser, function(req, res) {
        request_otp_api(req, res, {
            method: 'POST',
            relUrl: '/protected/users/' + req.session.passport.user.uid + '/methods/' + req.params.method + '/confirm_activate/',
            bearerAuth: true,
        });
    });

    router.post('/api/:method/auth/:authenticator_id', isUser, function(req, res) {
        request_otp_api(req, res, {
            method: 'POST',
            relUrl: `/protected/users/${req.session.passport.user.uid}/methods/${req.params.method}/auth/${req.params.authenticator_id}`,
            bearerAuth: true,
        });
    });

    router.delete('/api/:method/auth/:authenticator_id', isUser, function(req, res) {
        request_otp_api(req, res, {
            method: 'DELETE',
            relUrl: `/protected/users/${req.session.passport.user.uid}/methods/${req.params.method}/auth/${req.params.authenticator_id}`,
            bearerAuth: true,
        });
    });
    
    router.post('/api/admin/:method/confirm_activate/:uid', isManager, function(req, res) {
        request_otp_api(req, res, {
            method: 'POST',
            relUrl: '/protected/users/' + req.params.uid + '/methods/' + req.params.method + '/confirm_activate/',
            bearerAuth: true,
        });
    });

    router.post('/api/admin/:method/auth/:authenticator_id/:uid', isManager, function(req, res) {
        request_otp_api(req, res, {
            method: 'POST',
            relUrl: `/protected/users/${req.params.uid}/methods/${req.params.method}/auth/${req.params.authenticator_id}/`,
            bearerAuth: true,
        });
    });

    router.delete('/api/admin/:method/auth/:authenticator_id/:uid', isManager, function(req, res) {
        request_otp_api(req, res, {
            method: 'DELETE',
            relUrl: `/protected/users/${req.params.uid}/methods/${req.params.method}/auth/${req.params.authenticator_id}/`,
            bearerAuth: true,
        });
    });

    router.put('/api/:method/deactivate', isUser, function(req, res) {
        request_otp_api(req, res, {
            method: 'PUT',
            relUrl: '/protected/users/'+req.session.passport.user.uid+'/methods/'+req.params.method+'/deactivate/',
            bearerAuth: true,
        });
    });

    router.put('/api/transport/:transport/:new_transport', isUser, function(req, res) {
        request_otp_api(req, res, {
            method: 'PUT',
            relUrl: '/protected/users/'+ req.session.passport.user.uid +'/transports/'+req.params.transport+'/'+req.params.new_transport,
            bearerAuth: true,
        });
    });

    router.put('/api/admin/transport/:transport/:new_transport/:uid', isManager, function(req, res) {
        request_otp_api(req, res, {
            method: 'PUT',
            relUrl: '/protected/users/'+ req.params.uid +'/transports/'+req.params.transport+'/'+req.params.new_transport+'/',
            bearerAuth: true,
        });
    });

    router.get('/api/transport/:transport/:new_transport/test', isUser, function(req, res) {
        request_otp_api(req, res, {
            method: 'GET',
            relUrl: '/protected/users/' + req.session.passport.user.uid + '/transports/' + req.params.transport + '/' + req.params.new_transport + '/test/',
            bearerAuth: true,
        });
    });

    router.get('/api/admin/transport/:transport/:new_transport/test/:uid', isManager, function(req, res) {
        request_otp_api(req, res, {
            method: 'GET',
            relUrl: '/protected/users/' + req.params.uid + '/transports/' + req.params.transport + '/' + req.params.new_transport + '/test',
            bearerAuth: true,
        });
    });

    router.delete('/api/transport/:transport/', isUser, function(req, res) {
        request_otp_api(req, res, {
            method: 'DELETE',
            relUrl: '/protected/users/'+ req.session.passport.user.uid +'/transports/'+req.params.transport,
            bearerAuth: true,
        });
    });

    router.delete('/api/admin/transport/:transport/:uid', isManager, function(req, res) {
        request_otp_api(req, res, {
            method: 'DELETE',
            relUrl: '/protected/users/'+ req.params.uid +'/transports/'+req.params.transport+'/',
            bearerAuth: true,
        });
    });

    router.post('/api/generate/:method', isUser, function(req, res) {
        const uri = '/protected/users/'+ req.session.passport.user.uid + '/methods/' + req.params.method + '/secret';
        const queryParams = {};
        if (req.query.require_method_validation === 'true') {
            queryParams.require_method_validation = true;
        }
        request_otp_api(req, res, {
            method: 'POST',
            relUrl: uri,
            bearerAuth: true,
            queryParams,
        });
    });

    router.get('/api/admin/users', isManager, function(req, res) {
        request_otp_api(req, res, {
            relUrl: '/admin/users/',
            bearerAuth: true,
        });
    });

    router.get('/api/admin/user/:uid', isManager, function(req, res) {
        request_otp_api(req, res, {
            relUrl: '/protected/users/' + req.params.uid,
            bearerAuth: true,
        });
    });

    router.put('/api/admin/:uid/:method/activate', isManager, function(req, res) {
        request_otp_api(req, res, {
            method: 'PUT',
            relUrl: '/protected/users/'+ req.params.uid + '/methods/' + req.params.method + '/activate/',
            bearerAuth: true,
        });
    });

    router.put('/api/admin/:uid/:method/deactivate', isManager, function(req, res) {
        request_otp_api(req, res, {
            method: 'PUT',
            relUrl: '/protected/users/'+ req.params.uid + '/methods/' + req.params.method + '/deactivate/',
            bearerAuth: true,
        });
    });

    router.put('/api/admin/:method/activate', isAdmin, function(req, res) {
        request_otp_api(req, res, {
            method: 'PUT',
            relUrl: '/admin/methods/' + req.params.method + '/activate/',
            bearerAuth: true,
        });
    });

    router.put('/api/admin/:method/deactivate', isAdmin, function(req, res) {
        request_otp_api(req, res, {
            method: 'PUT',
            relUrl: '/admin/methods/' + req.params.method + '/deactivate/',
            bearerAuth: true,
        });
    });

    router.put('/api/admin/:method/transport/:transport/activate', isAdmin, function(req, res) {
        request_otp_api(req, res, {
            method: 'PUT',
            relUrl: '/admin/methods/' + req.params.method + '/transports/'+req.params.transport+'/activate/',
            bearerAuth: true,
        });
    });

    router.put('/api/admin/:method/transport/:transport/deactivate', isAdmin, function(req, res) {
        request_otp_api(req, res, {
            method: 'PUT',
            relUrl: '/admin/methods/' + req.params.method + '/transports/'+req.params.transport+'/deactivate/',
            bearerAuth: true,
        });
    });

    router.post('/api/admin/generate/:method/:uid', isManager, function(req, res) {
        const uri = '/protected/users/'+ req.params.uid + '/methods/' + req.params.method + '/secret/';
        const queryParams = {};
        if (req.query.require_method_validation === 'true') {
            queryParams.require_method_validation = true;
        }
        request_otp_api(req, res, {
            method: 'POST',
            relUrl: uri,
            bearerAuth: true,
            queryParams,
        });
    });

    router.delete('/api/admin/delete_method_secret/:method/:uid', isManager, function(req, res) {
        request_otp_api(req, res, {
            method: 'DELETE',
            relUrl: '/admin/users/'+req.params.uid +'/methods/' + req.params.method+ '/secret/',
            bearerAuth: true,
        });
    });
}
