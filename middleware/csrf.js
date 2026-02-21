/**
 * CSRF Middleware — Double-Submit Cookie Pattern
 *
 * On any request: if the csrf_token cookie is absent, set one.
 * On state-mutating requests: validate that X-CSRF-Token header matches the cookie.
 */

const crypto = require('crypto');

const COOKIE_NAME = 'csrf_token';
const HEADER_NAME = 'x-csrf-token';

function generateToken() {
  return crypto.randomBytes(32).toString('hex');
}

/**
 * setToken — runs on all requests.
 * Sets a csrf_token cookie if one doesn't already exist.
 */
function setToken(req, res, next) {
  if (!req.cookies || !req.cookies[COOKIE_NAME]) {
    const token = generateToken();
    res.cookie(COOKIE_NAME, token, {
      httpOnly: false,   // Must be readable by JS for double-submit pattern
      sameSite: 'strict',
      path: '/',
    });
  }
  next();
}

/**
 * validate — runs on state-mutating routes (POST/PUT/PATCH/DELETE).
 * Rejects if the X-CSRF-Token header doesn't match the csrf_token cookie.
 */
function validate(req, res, next) {
  const cookieToken = req.cookies && req.cookies[COOKIE_NAME];
  const headerToken = req.headers[HEADER_NAME];

  if (!cookieToken || !headerToken || cookieToken !== headerToken) {
    return res.status(403).json({ error: 'Invalid or missing CSRF token' });
  }
  next();
}

module.exports = { setToken, validate, generateToken, COOKIE_NAME };
