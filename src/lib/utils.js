const crypto = require('crypto');
const logger = require('./logger');

/*
 * Generate an XSRF token which will be validated by the authorization server.
 * This contains elements which can practically not be used by the attacker:
 *   - The IP address of the end user
 *   - The referer. This can be spoofed, but not in browser attacks
 *   - The state coming from the client, which only exists in the user's browser
 */
module.exports.generateXsrfToken = (req) => {
  const xsrfToken = [
    req.query.state,
    req.ip,
    req.headers.accept,
    req.headers['user-agent'],
    req.headers.referer
  ];

  logger.info(xsrfToken, 'Creating XSRF token.');

  return crypto.createHash('sha256')
    .update(xsrfToken.join('|'))
    .digest('base64');
};
