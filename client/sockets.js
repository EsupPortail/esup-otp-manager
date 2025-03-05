/**
 * Created by abousk01 on 07/09/2016.
 */
var properties = require(__dirname+'/../properties/properties');
const logger = require(__dirname + '/../services/logger');

var apiSockets = require("socket.io-client").connect(properties.esup.api_url, {reconnect: true, path: "/sockets", query: 'app=manager', extraHeaders: {
    Authorization: "Bearer " + properties.esup.api_password,
}});
var sockets = require('../server/sockets');
var users = {};

apiSockets.on('connect', function () {
    logger.info("Api Sockets connected");
    apiSockets.emit('managers',properties.esup.admins.concat(properties.esup.managers));
});

apiSockets.on('userUpdate', function (data) {
    if(users[data.uid])sockets.emit(users[data.uid], 'userUpdate');
});

apiSockets.on('userPushActivate', function (data) {
    if(users[data.uid])sockets.emit(users[data.uid], 'userPushActivate');
});

apiSockets.on('userPushDeactivate', function (data) {
    if(users[data.uid])sockets.emit(users[data.uid], 'userPushDeactivate');
});

apiSockets.on('userPushActivateManager', function (data) {
    if(users[data.uid])sockets.emit(users[data.uid], 'userPushActivateManager', {uid : data.target});
});

apiSockets.on('userPushDeactivateManager', function (data) {
    if(users[data.uid])sockets.emit(users[data.uid], 'userPushDectivateManager', {uid : data.target});
});

exports.userConnection = function(uid, idSocket){
    users[uid]=idSocket;
};

exports.userDisconnection = function(idSocket){
    for(user in users){
        if(users[user]==idSocket)delete users[user];
    }
};

exports.emit = function(emit, data){
    apiSockets.emit(emit, data);
};
