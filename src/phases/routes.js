const uuid = require('node-uuid');
const crypto = require('crypto');

const utils = require('../lib/utils');
const logger = require('../lib/logger');

const sessions = { };
const authorizationCodes = { };

module.exports = function phase() {
  this.post('/login', (req, res) => {
    /*
     * Ideally, the POST should only be initiated from the trusted domain.
     * The referrer might be disabled, spoofed, ... so this is only a first layer of defense.
     */
    if (req.headers.referrer && req.headers.referrer.indexOf(process.env.TRUSTED_DOMAIN) !== 0) {
      res.redirect(`${req.query.redirect_uri}?error=only_trusted_domains_are_allowed`);
    }

    // We also need to validate the redirect url.
    if (req.query.redirect_uri && req.query.redirect_uri.indexOf(process.env.TRUSTED_DOMAIN) !== 0) {
      return res.status(400).json({
        error_code: 'invalid_redirect_uri',
        error_description: 'Invalid redirect URI'
      });
    }

    /*
     * Validate XSRF token.
     * This contains the user's user-agent, referer, IP, client state.
     * Is this unique enough? Maybe add an expiration to it + crypto hash to make it really unique?
     */
    const xsrfToken = utils.generateXsrfToken(req);
    if (xsrfToken !== req.body.xsrf_token) {
      res.redirect(`${req.query.redirect_uri}?error=invalid_csrf_token`);
    }

    // Create a session, but set it to pending.
    const sessionId = crypto.createHash('sha256').digest('base64');
    sessions[sessionId] = {
      sessionId,
      username: req.body.username,
      status: 'pending'
    };

    // Generate an authorization code and link it to the session.
    const authorizationCode = uuid.v4();
    authorizationCodes[authorizationCode] = {
      sessionId
    };

    // Persist the session as a cookie.
    res.cookie('session', sessionId);

    logger.info({ code: authorizationCode, session: sessions[sessionId] },
      `Login started for "${req.body.username}"`);

    // Redirect back to the client.
    res.redirect(`${req.query.redirect_uri}?state=${req.query.state}&code=${authorizationCode}`);
  });

  this.post('/oauth/token', (req, res) => {
    logger.info(req.body, 'Token Exchange');

    if (req.body.grant_type !== 'authorization_code_extended') {
      return res.status(400).json({
        error_code: 'invalid_grant_type',
        error_description: 'Invalid grant type'
      });
    }

    // Authorization code does not exist.
    const authorizationCode = authorizationCodes[req.body.code];
    if (!authorizationCode) {
      return res.status(400).json({
        error_code: 'invalid_authorization_code',
        error_description: 'Invalid authorization code'
      });
    }

    // Authorization code can only be used once.
    delete authorizationCodes[req.body.code];

    // Session does not exist.
    const session = sessions[authorizationCode.sessionId];
    if (!session) {
      return res.status(400).json({
        error_code: 'unknown_session',
        error_description: 'Session does not exist'
      });
    }

    // Approve the session.
    session.status = 'active';

    // Return the token.
    res.json({
      access_token: `sub|${session.username}`
    });
  });

  /*
   * Sessions are only really active after the code exchange has taken place.
   */
  this.get('/session', (req, res) => {
    const sessionId = req.cookies.session;
    const session = sessions[sessionId];
    if (!session || session.status !== 'active') {
      return res.status(200);
    }

    return res.send(JSON.stringify(session, null, 2));
  });

  this.get('/logout', (req, res) => {
    res.cookie('session', '', { expires: new Date() });
    res.send('Logged out');
  });

  this.get('/test', (req, res) => {
    res.sendStatus(200).end();
  });
};
