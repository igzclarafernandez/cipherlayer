/**
 * Created by clarafernandez on 29/11/17.
 */
const userDao = require('../src/managers/dao');
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
							userDao.updateField(user._id, 'password', encryptedPwd, function (err, result) {
								console.log( "errror " + err + " result " +result);
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

