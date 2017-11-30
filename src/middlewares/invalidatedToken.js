const tokenMng = require('../managers/token');
const config = require(`${process.cwd()}/config.json`);
const log = require('../logger/service.js');

function invalidatedToken(req, res, next) {
	if (!req.auth) {
		log.error({err: 'invalid_access_token', des: 'access token required'});
		res.send(401, {err: 'invalid_access_token', des: 'access token required'});
		return next(false);
	}
	let accessToken = req.auth.substring(config.authHeaderKey.length);
	req.accessToken = accessToken;
	tokenMng.isInvalidatedAccessToken(accessToken, function (err, data) {
		if (err) {
			log.error(err);
			log.error({err: 'invalid_access_token', des: accessToken});
			res.send(401, {err: 'invalid_access_token', des: 'unable to read token info in invalidatedTokenMiddleware'});
			return next(false);
		}
			if ( data ) {
				res.send(401, {err: 'invalidated_access_token', des: 'the token used in request is invalidated'});
				return next(false);
			}
			return next();


	});
}

module.exports = invalidatedToken;
