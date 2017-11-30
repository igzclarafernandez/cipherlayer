'use strict';

const crypto = require('crypto');
const _ = require('lodash');
const RandExp = require('randexp');

const defaultSettings = {
	algorithm: 'sha256',
	encryptPassword: 'password'
};

let _settings = {};
//Si se usa un algoritmo de encriptacion reversible como aes hay que descomentar esta funcion encrypt y comentar la otra
/*function encrypt(text, cbk) {
 if (!text) {
 return cbk();
 }
 const cipher = crypto.createCipher(_settings.algorithm, _settings.encryptPassword);
 let crypted = cipher.update(text, 'utf8', 'hex');
 crypted += cipher.final('hex');
 return cbk(crypted);
 }*/

//Esta función se usa con algoritmos de encriptacion no reversibles como sha
function encrypt(text, cbk) {
	if (!text) {
		return cbk();
	}
	const hmac = crypto.createHmac(_settings.algorithm, _settings.encryptPassword);
	hmac.update(text, 'utf8', 'hex');
	return cbk(hmac.digest('hex'));
}


function verify(original, encrypted, cbk) {
	encrypt(original, function (crypted) {
		if (encrypted === crypted) {
			return cbk();
		}

		return cbk(new Error('Invalid password'));
	});
}

function randomPassword(passwordRegex) {
	return new RandExp(passwordRegex).gen();
}


function decryptAES(text){
	const algorithm = 'aes-256-ctr';

	let decipher = crypto.createDecipher(algorithm,_settings.encryptPassword);
	let dec = decipher.update(text,'hex','utf8');
	dec += decipher.final('utf8');
	return dec;
}

module.exports = function (settings) {
	_settings = _.extend({}, defaultSettings, settings);

	return {
		encrypt,
		verify,
		randomPassword,
		decryptAES
	};
};
