import { request } from 'undici';
import properties from '../../properties/properties.js';
import * as utils from '../../services/utils.js';
import * as aclUtils from '../../services/aclUtils.js';
import logger from '../../services/logger.js';

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

export function isUser(req, res, next) {
    if (utils.isAuthenticated(req)) return next();
    redirectLogin(req, res);
}

function isManager(req, res, next) {
    isUser(req, res, () => {
        if (req.session.passport.user.isManager) {
            req.routeForManagers = true
            return next();
        } else {
            redirectForbidden(req, res);
        }
    });
}

function isAdmin(req, res, next) {
    isUser(req, res, () => {
        if (req.session.passport.user.role == "admin") {
            return next();
        } else {
            redirectForbidden(req, res);
        }
    });
}

function canAccessUserMethod(req, res, next) {
    isUser(req, res, () => {
        if (aclUtils.is_authorized(req.session.passport.user, req.params.method)) {
            return next();
        } else {
            redirectForbidden(req, res);
        }
    });
}

/** 
 *  @typedef {{ 
 *      relUrl: string,
 *      queryParams?: Object,
 *      body?: Object,
 *      bearerAuth?: boolean,
 *      headers?: Object,
 *      method?: 'GET' | 'POST' | 'PUT' | 'DELETE',
 *  }} opts_
 */

/**
 * @param { opts_ } opts_
 */
export function fetch_otp_api(opts_) {
    logger.info("requesting api");
    /**
     * @typedef {import('undici').Dispatcher.RequestOptions} RequestOptions
     * @type {Omit<RequestOptions, 'origin' | 'path'>}
     */
    const opts = {
        method: opts_.method || 'GET',
    }

    if (opts_.body && Object.keys(opts_.body).length) {
        opts.body = JSON.stringify(opts_.body);
    }

    const url = properties.esup.api_url + opts_.relUrl + "?" + new URLSearchParams(opts_.queryParams);

    opts.headers = opts_.headers || {};
    opts.headers['Content-Type'] ||= 'application/json';

    if (opts_.bearerAuth) {
        opts.headers.Authorization = 'Bearer ' + properties.esup.api_password;
    }

    logger.debug(opts.method + ':' + url);
    logger.debug(JSON.stringify(opts.headers, null, 2));

    return request(url, opts);
}

/** @param {Omit<opts_, 'body' | 'headers'>} opts_ */
async function request_otp_api(req, res, opts_) {
    const clientIP = req.ip;
    const userAgent = req.headers['user-agent'];

    opts_.body = req.body;
    opts_.queryParams ||= {};
    if (req.routeForManagers) {
        opts_.queryParams.managerUser = req.session.passport.user.uid;
    }

    opts_.headers = {
        'X-Client-IP': clientIP,
        'Client-User-Agent': userAgent,
        'User-Agent': 'esup-otp-manager',
    };

    logger.debug(req.session.passport)

    let response;
    try {
        response = await fetch_otp_api(opts_);
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
    logger.debug(infos);
    res.send(infos);
}

export function routing(router) {
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

    router.put('/api/:method/activate', canAccessUserMethod, function(req, res) {
        request_otp_api(req, res, {
            method: 'PUT',
            relUrl: '/protected/users/'+req.session.passport.user.uid+'/methods/'+req.params.method+'/activate',
            bearerAuth: true,
        });
    });
    
    router.post('/api/:method/activate/confirm/:activation_code', canAccessUserMethod, function(req, res) {
        request_otp_api(req, res, {
            method: 'POST',
            relUrl: '/protected/users/' + req.session.passport.user.uid + '/methods/' + req.params.method + '/activate/' + req.params.activation_code,
            bearerAuth: true,
        });
    });
    
    router.post('/api/admin/:uid/:method/activate/confirm/:activation_code', isManager, function(req, res) {
        request_otp_api(req, res, {
            method: 'POST',
            relUrl: '/protected/users/' + req.params.uid + '/methods/' + req.params.method + '/activate/' + req.params.activation_code,
            bearerAuth: true,
        });
    });

    router.post('/api/:method/confirm_activate', canAccessUserMethod, function(req, res) {
        request_otp_api(req, res, {
            method: 'POST',
            relUrl: '/protected/users/' + req.session.passport.user.uid + '/methods/' + req.params.method + '/confirm_activate/',
            bearerAuth: true,
        });
    });

    router.post('/api/:method/auth/:authenticator_id', canAccessUserMethod, function(req, res) {
        request_otp_api(req, res, {
            method: 'POST',
            relUrl: `/protected/users/${req.session.passport.user.uid}/methods/${req.params.method}/auth/${req.params.authenticator_id}`,
            bearerAuth: true,
        });
    });

    router.delete('/api/:method/auth/:authenticator_id', canAccessUserMethod, function(req, res) {
        request_otp_api(req, res, {
            method: 'DELETE',
            relUrl: `/protected/users/${req.session.passport.user.uid}/methods/${req.params.method}/auth/${req.params.authenticator_id}`,
            bearerAuth: true,
        });
    });
    
    router.post('/api/admin/:uid/:method/confirm_activate', isManager, function(req, res) {
        request_otp_api(req, res, {
            method: 'POST',
            relUrl: '/protected/users/' + req.params.uid + '/methods/' + req.params.method + '/confirm_activate/',
            bearerAuth: true,
        });
    });

    router.post('/api/admin/:uid/:method/auth/:authenticator_id', isManager, function(req, res) {
        request_otp_api(req, res, {
            method: 'POST',
            relUrl: `/protected/users/${req.params.uid}/methods/${req.params.method}/auth/${req.params.authenticator_id}/`,
            bearerAuth: true,
        });
    });

    router.delete('/api/admin/:uid/:method/auth/:authenticator_id', isManager, function(req, res) {
        request_otp_api(req, res, {
            method: 'DELETE',
            relUrl: `/protected/users/${req.params.uid}/methods/${req.params.method}/auth/${req.params.authenticator_id}/`,
            bearerAuth: true,
        });
    });

    router.put('/api/:method/deactivate', canAccessUserMethod, function(req, res) {
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

    router.put('/api/admin/:uid/transport/:transport/:new_transport', isManager, function(req, res) {
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

    router.get('/api/admin/:uid/transport/:transport/:new_transport/test', isManager, function(req, res) {
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

    router.delete('/api/admin/:uid/transport/:transport', isManager, function(req, res) {
        request_otp_api(req, res, {
            method: 'DELETE',
            relUrl: '/protected/users/'+ req.params.uid +'/transports/'+req.params.transport+'/',
            bearerAuth: true,
        });
    });

    router.post('/api/generate/:method', canAccessUserMethod, function(req, res) {
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

    router.delete('/api/delete_method_secret/:method', canAccessUserMethod, function(req, res) {
        request_otp_api(req, res, {
            method: 'DELETE',
            relUrl: '/protected/users/' + req.session.passport.user.uid + '/methods/' + req.params.method + '/secret',
            bearerAuth: true,
        });
    });

    router.get('/api/admin/user/:uid/exists', isManager, function(req, res) {
        request_otp_api(req, res, {
            relUrl: '/protected/users/' + req.params.uid + "/exists",
            bearerAuth: true,
        });
    });

    router.get('/api/admin/users', isManager, function(req, res) {
        request_otp_api(req, res, {
            relUrl: '/protected/users/',
            bearerAuth: true,
            queryParams: { token: req.query.token },
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

    router.post('/api/admin/:uid/generate/:method', isManager, function(req, res) {
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

    router.delete('/api/admin/:uid/delete_method_secret/:method', isManager, function(req, res) {
        request_otp_api(req, res, {
            method: 'DELETE',
            relUrl: '/protected/users/' + req.params.uid + '/methods/' + req.params.method + '/secret/',
            bearerAuth: true,
        });
    });

    router.get('/api/admin/stats', isManager, function(req, res) {
        request_otp_api(req, res, {
            relUrl: '/admin/stats',
            bearerAuth: true,
        });
    });
}
