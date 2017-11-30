/**
 * Created by clarafernandez on 29/11/17.
 */
const userDao = require('../src/managers/dao');
const log = require('../src/logger/service');
const crypto = require('../src/managers/crypto');
const async = require('async');
const config = require('../config');
const cryptoMng = crypto(config.password);

if (!module.parent) { // Run as CLI command exec
	async.series([
		// Start cipherLayer components (mongodb, redis...)
		userDao.connect,

		function drop(done) {
			userDao.getAllUsers(function(err, users){
				users.forEach(function (user) {
					userDao.getAllUserFields(user.username, function (err, result) {
						let decriptPass =  cryptoMng.decryptAES(result.password);
						cryptoMng.encrypt(decriptPass, function (encryptedPwd){
							if (!encryptedPwd){
								log.error({err: 'no se ha devuelto ninguna contraseña para encriptar para el usuario '+ user.username , result: ''});
							}
							userDao.updateField(user._id, 'password', encryptedPwd, function (err, result) {
								log.error({err: err, result: ' el usauio ' + user.username +'ha termindo con resultado ' + result});
							});
						});
					});
				});
			});
		},
		userDao.disconnect
	], err => {
		if (err) {
			console.error(err);
			process.exit(1);
		}

		console.info('Fixtures loaded');
		process.exit();
	});

}

