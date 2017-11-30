'use strict';

const async = require('async');
const isFunction = require('lodash/isFunction');
const ciphertoken = require('ciphertoken');
const config = require('../../config');
const redis = require('./redis');

const log = require('../logger/service');

const accessTokenSettings = {
	cipherKey: config.accessToken.cipherKey,
	firmKey: config.accessToken.signKey,
	tokenExpirationMinutes: config.accessToken.expiration * 60
};

const refreshTokenSettings = {
	cipherKey: config.refreshToken.cipherKey,
	firmKey: config.refreshToken.signKey,
	tokenExpirationMinutes: 1440 * 1000
};

function createAccessToken(userId, dataIn, cbkIn) {
	let data = dataIn;
	let cbk = cbkIn;
	if (isFunction(dataIn)) {
		cbk = data;
		data = {};
	}

	ciphertoken.createToken(accessTokenSettings, userId, null, data, cbk);
}

function getAccessTokenInfo(accessToken, cbk) {
	try {
		ciphertoken.getTokenSet(accessTokenSettings, accessToken, cbk);
	} catch(err) {
		log.error({err_info: err, access_token: accessToken}, 'error getting accessToken info');
		return cbk(err);
	}

}

function getRefreshTokenInfo(refreshToken, cbk) {
	try {
		ciphertoken.getTokenSet(refreshTokenSettings, refreshToken, cbk);
	} catch (err){
		log.error({err_info: err, refresh_token: refreshToken}, 'error getting refreshToken info');
		return cbk(err);
	}
}

function createRefreshToken(userId, dataIn, cbkIn) {
	let data = dataIn;
	let cbk = cbkIn;
	if (isFunction(dataIn)) {
		cbk = data;
		data = {};
	}
	ciphertoken.createToken(refreshTokenSettings, userId, null, data, cbk);
}

function createBothTokens(userId, data, cbk) {
	const tokens = {};

	async.parallel([
		function (done) {
			createAccessToken(userId, data, function (err, token) {
				tokens.accessToken = token;
				return done(err);
			});
		},
		function (done) {
			createRefreshToken(userId, data, function (err, token) {
				tokens.refreshToken = token;
				return done(err);
			});
		}
	], function (err) {
		cbk(err, tokens);
	});
}

function invalidateAccessToken(accessToken, callback) {
	redis.getKeyValue(accessToken, function (notFoundErr, res){
		if ( notFoundErr){
			log.error({err_notFoundErr: notFoundErr});
		}
		if ( res ){
			return callback({err: 'already invalidated'});
		}
		getAccessTokenInfo(accessToken, function (infoErr, info ){
			let ttl = info.expiresAtTimestamp ?
				Math.floor(info.expiresAtTimestamp /1000) - Math.floor(new Date().getTime()/1000):
				config.accessToken.expiration;
			redis.insertKeyValue(accessToken, accessToken, ttl, function (err, data) {
				if ( err ){
					log.error({err_info: err, data_err: data});
				}
				return callback();
			});
		});

	});
}

function isInvalidatedAccessToken(accessToken, callback) {
	redis.getKeyValue(accessToken.toString(), function (err, tokenData) {
		if(err) {
			return callback(err);
		}
		return callback(null, tokenData);
	});
}

module.exports = {
	createAccessToken,
	getAccessTokenInfo,
	createRefreshToken,
	createBothTokens,
	getRefreshTokenInfo,
	invalidateAccessToken,
	isInvalidatedAccessToken
};
