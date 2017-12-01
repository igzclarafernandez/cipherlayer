'use strict';

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



			userDao.getAllUsers( function(err, users){
				if(err) return done();

				function updatePass(user, encryptedPwd, cbk){
					userDao.updateField(user._id, 'password', encryptedPwd, function (err, result) {
						if (result == 0){
							log.error({result: ' no se ha actualizado nada para el usauio ' + user._id + " " + user.username });
						} else {
							log.info({result: 'usuario actualizado ' + user._id + " " + user.username });
						}
						return cbk()
					});
				}

				function processUser(err, user) {
					if(!user || err) {
						log.info({result: 'no hay mas usuarios ++++++++++++++++++++', err });
						return done();
					}

					let decriptPass = cryptoMng.decryptAES(user.password);
					log.error({err: 'contraseña del usuario  ' + user.username + " es " + decriptPass});
					cryptoMng.encrypt(decriptPass, function (encryptedPwd) {
						if (!encryptedPwd) {
							log.error({err: 'no se ha devuelto ninguna contraseña para encriptar para el usuario ' + user.username});
						}
						log.error({err: 'la contraseña encriptada del usuario ' + user.username + " es " + encryptedPwd});
						updatePass(user, encryptedPwd, function(){
							users.nextObject(processUser);
						})
					});
				}

				users.nextObject(processUser);
			})

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

