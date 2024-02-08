var properties = require(__dirname + '/../properties/properties');
var express = require('express');
var expressSession = require('express-session')({
    secret: properties.esup.session_secret_key,
    resave: true,
    saveUninitialized: true
});
var path = require('path');
var favicon = require('serve-favicon');
var logger = require('morgan');
var cookieParser = require('cookie-parser');
var bodyParser = require('body-parser');
var passport = require('passport');

var app = express();
var sockets = require('./sockets');

// view engine setup
app.set('views', path.join(__dirname + '/..', 'views'));
app.engine('jade', require('pug').__express); // to avoid renaming all .jade to .pug
app.set('view engine', 'jade');
app.set('trust proxy', properties.esup.trustedProxies);

//
app.use('/css/materialize.min.css', express.static(path.join(__dirname + '/..', '/node_modules/materialize-css/dist/css/materialize.min.css')));
app.use('/fonts/roboto/', express.static(path.join(__dirname + '/..', '/node_modules/materialize-css/dist/fonts/roboto/')));
app.use('/js/jquery.min.js', express.static(path.join(__dirname + '/..', '/node_modules/jquery/dist/jquery.min.js')));
app.use('/js/socket.io.min.js', express.static(path.join(__dirname + '/..', '/node_modules/socket.io-client/dist/socket.io.min.js')));
app.use('/js/materialize.min.js', express.static(path.join(__dirname + '/..', '/node_modules/materialize-css/dist/js/materialize.min.js')));
app.use('/js/vue.js', express.static(path.join(__dirname + '/..', '/node_modules/vue/dist/vue.js')));

// uncomment after placing your favicon in /public
//app.use(favicon(path.join(__dirname, 'public', 'favicon.ico')));
app.use(logger('dev'));
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: false }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname + '/..', 'public')));

app.use(expressSession);
app.use(passport.initialize());
app.use(passport.session());
sockets.sharedSession(expressSession);

app.use(function(req, res, next) {
    res.locals.session = req.session;
    next();
});

var routes = require('./routes');
app.use('/', routes(passport));

// catch 404 and forward to error handler
app.use(function(req, res, next) {
    var err = new Error('Not Found');
    err.status = 404;
    next(err);
});

// error handlers

// development error handler
// will print stacktrace
if (app.get('env') === 'development') {
    app.use(function(err, req, res, next) {
        res.status(err.status || 500);
        res.render('error', {
            message: err.message,
            error: err
        });
    });
}

// production error handler
// no stacktraces leaked to user
app.use(function(err, req, res, next) {
    res.status(err.status || 500);
    res.render('error', {
        message: err.message,
        error: {}
    });
});


module.exports = app;
