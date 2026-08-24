import properties from '../properties/properties.js';
import logger from '../services/logger.js';
import express from 'express';
import session from 'express-session';
import memorystore from 'memorystore';
const MemoryStore = memorystore(session);
import { fileURLToPath } from 'node:url';
const expressSession = session({
    secret: properties.esup.session_secret_key,
    resave: false,
    saveUninitialized: true,
    cookie: {
        secure: "auto", // secure if httpS connection
        sameSite: "lax",
    },
    store: new MemoryStore({
        checkPeriod: 86400000, // prune expired entries every 24h
    }),
});
import fs from 'fs';
import path from 'path';
import morgan from 'morgan';
import cookieParser from 'cookie-parser';
import bodyParser from 'body-parser';
import passport from 'passport';

const app = express();
import * as sockets from './sockets.js';

const __dirname = import.meta.dirname || path.dirname(fileURLToPath(import.meta.url));
const baseUrl = properties.esup.baseUrl || "";

// view engine setup
app.set('views', path.join(__dirname + '/..', 'views'));
app.set('view engine', 'pug');
app.set('trust proxy', properties.esup.trustedProxies);

app.locals.baseUrl = baseUrl;

// Middleware to add the prefix baseUrl to the originalUrl
if(baseUrl) {
    app.use((req, res, next) => {
        if (!req.originalUrl.startsWith(baseUrl) && !req.originalUrl.startsWith("/sockets/")) {
            req.url = `${baseUrl}${req.originalUrl}`;
            logger.debug('Original URL:' + req.originalUrl);
            logger.debug('Modified URL:' + req.url);
        } else {
            logger.debug('Original URL:' + req.originalUrl);
            logger.debug('Not Modified URL:' + req.url);
        }
        next();
    });
}

//
app.use(baseUrl + '/css/materialize.min.css', express.static(path.join(__dirname + '/..', '/node_modules/materialize-css/dist/css/materialize.min.css')));
app.use(baseUrl + '/fonts/roboto/', express.static(path.join(__dirname + '/..', '/node_modules/materialize-css/dist/fonts/roboto/')));
app.use(baseUrl + '/js/jquery.min.js', express.static(path.join(__dirname + '/..', '/node_modules/jquery/dist/jquery.min.js')));
app.use(baseUrl + '/js/socket.io.min.js', express.static(path.join(__dirname + '/..', '/node_modules/socket.io-client/dist/socket.io.min.js')));
app.use(baseUrl + '/js/socket.io.min.js.map', express.static(path.join(__dirname + '/..', '/node_modules/socket.io-client/dist/socket.io.min.js.map')));
app.use(baseUrl + '/js/materialize.min.js', express.static(path.join(__dirname + '/..', '/node_modules/materialize-css/dist/js/materialize.min.js')));
app.use(baseUrl + '/js/vue.js', express.static(path.join(__dirname + '/..', '/node_modules/vue/dist/vue.global.prod.js')));
app.use(baseUrl + '/js/sweetalert2.all.min.js', express.static(path.join(__dirname + '/..', '/node_modules/sweetalert2/dist/sweetalert2.all.min.js')));
app.use(baseUrl + '/js/chart.js', express.static(path.join(__dirname + '/..', '/node_modules/chart.js/dist/chart.umd.min.js')));
app.use(baseUrl + '/js/chartjs-plugin-datalabels.min.js', express.static(path.join(__dirname + '/..', '/node_modules/chartjs-plugin-datalabels/dist/chartjs-plugin-datalabels.min.js')));

// uncomment after placing your favicon in /public
//import favicon from 'serve-favicon';
//app.use(baseUrl, favicon(path.join(__dirname, 'public', 'favicon.ico')));

const logProperties = properties.esup.logs?.access;

if (logProperties) {
    const format = logProperties.format || 'dev';
    if (logProperties.console) {
        app.use(morgan(format, { stream: process.stdout }));
    }
    if (logProperties.file) {
        app.use(morgan(format, { stream: fs.createWriteStream(logProperties.file, { flags: 'a' }) }));
    }
}

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: false }));
app.use(cookieParser());
//app.use(express.static(path.join(__dirname + '/..', 'public')));
app.use(baseUrl, express.static(path.join(__dirname, '/..', 'public')));

app.use(expressSession);
app.use(passport.initialize());
app.use(passport.session());
sockets.setSharedSession(expressSession);

app.use(function(req, res, next) {
    res.locals.session = req.session;
    next();
});

import routes from './routes.js';
app.use(baseUrl + '/', await routes(passport));

// catch 404 and forward to error handler
app.use(function(req, res, next) {
    const err = new Error('Not Found');
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


export default app;
