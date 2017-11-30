'use strict';

const config = require(`${process.cwd()}/config.json`);
const tokenMng = require('../../managers/token');
const sessionRequest = require('./session');
const log = require('../../logger/service.js');

module.exports = function (req, res, next) {
	let authHeader = req.header('Authorization');
	if (!authHeader) {
		log.error({err: 'invalid_access_token', des: 'no authorization header'});
		res.send(401, {err: 'invalid_access_token', des: 'unable to read token info'});
		return next(false);
	}

	if ( authHeader.length <= config.authHeaderKey.length ||
		authHeader.substring(0,config.authHeaderKey.length).toLowerCase() !== config.authHeaderKey.toLowerCase()){

		log.error({err: 'invalid_access_token', des: 'invalid header identifier'});
		res.send(401, {err: 'invalid_access_token', des: 'unable to read token info'});
		return next(false);
	}

	let accessToken = authHeader.substring(config.authHeaderKey.length);

	tokenMng.getAccessTokenInfo(accessToken, function (err, tokenInfo) {
		if (err) {
			log.error({err});
			log.error({err: 'invalid_access_token', des: accessToken});
			res.send(401, {err: 'invalid_access_token', des: 'unable to read token info'});
			return next(false);
		}
			let userAgent = String(req.headers['user-agent']);
			let userId = tokenInfo.userId;
			let deviceId = tokenInfo.data.deviceId;
			tokenMng.invalidateAccessToken(accessToken, function (invalidateError) {
				if (invalidateError){
					log.error({err: 'Error while invalidating token'});
				} else {
					log.error({err: 'Token invalidated'});
				}
				sessionRequest(deviceId, userId, 'DELETE', userAgent, function (err, result) {
					if (err) {
						log.error({ err, result}, 'RemoveDeviceResponse');
						res.send(500, {err: 'internal_session_error', des: 'unable to close session'});
						return next(false);
					}
					res.send(204);
					return next();
				});
			});
	});
};
