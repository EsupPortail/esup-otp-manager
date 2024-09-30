var express = require('express');
var router = express.Router();
var properties = require(__dirname+'/../properties/properties');
var utils = require(__dirname+'/../services/utils');
const apiRoutes = require('./routes/apiRoutes');
const isUser = apiRoutes.isUser;

var passport;


function routing() {
    router.get('/manager/messages', function(req, res) {
        res.json(utils.getMessagesForRequest(req));
    });

    router.get('/manager/messages/:language', isUser, function(req, res) {
        switch (req.params.language) {
            case "français": res.json(properties.messages_fr); break;
            case "english": res.json(properties.messages_en); break;
            default: res.json(properties.messages); break;
        }
    });

    router.get('/manager/users_methods', isUser, function(req, res) {
        res.send({ ...properties.esup.users_methods, user: req.user });
    });
    
    router.get('/manager/infos', isUser, function(req, res) {
        res.send({
            api_url: properties.esup.api_url,
            uid: req.session.passport.user.uid,
            transport_regexes: properties.esup.transport_regexes,
        });
    });

    require('./routes/pagesRoutes').routing(router, passport);
    apiRoutes.routing(router);
}

module.exports = function(_passport) {
    passport = _passport;

    // used to serialize the user for the session
    passport.serializeUser(function(user, done) {
        var _user = {};
        _user.uid=user.uid;
        _user.attributes=user.attributes;
        if(utils.is_admin(user))_user.role="admin";
        else if(utils.is_manager(user))_user.role="manager";
        else _user.role="user";
        done(null, _user);
    });

    // used to deserialize the user
    passport.deserializeUser(function(user, done) {
            done(null, user);
    });

    passport.use(new(require('passport-apereo-cas').Strategy)(properties.esup.CAS, function(profile, done) {
	// console.log("profile : " + JSON.stringify(profile, null ,2));
        return done(null, {uid:profile.user, attributes:profile.attributes});
    }));

    routing();

    return router
};
