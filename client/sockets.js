import properties from '../properties/properties.js';
import logger from '../services/logger.js'

import io from 'socket.io-client';

const apiSockets = io.connect(properties.esup.api_url, {reconnect: true, path: "/sockets", query: 'app=manager', extraHeaders: {
    Authorization: "Bearer " + properties.esup.api_password,
}});
import * as sockets from '../server/sockets.js';
const users = {};

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

export function userConnection(uid, idSocket) {
    users[uid] = idSocket;
}

export function userDisconnection(idSocket) {
    for (const user in users) {
        if (users[user] == idSocket) {
            delete users[user];
        }
    }
}

export function emit(emit, data) {
    apiSockets.emit(emit, data);
}
