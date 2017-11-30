'use strict';

const assert = require('assert');
const config = require('../config');



describe('crypto', function () {



	it('creates a valid random password', function () {

		const crypto = require('../src/managers/crypto');
		const cryptoMng = crypto(config.password);

		const newRandomPassword = cryptoMng.randomPassword(config.password.generatedRegex);
		const testRe = new RegExp(config.password.regexValidation);

		assert.ok(newRandomPassword.match(testRe), 'Random password does not match with config regexp');

	});

});
