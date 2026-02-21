/**
 * Origin Check Middleware
 * Rejects requests whose Origin header doesn't match the server host.
 * Server-to-server requests (no Origin header) are allowed.
 * Override allowed origins via ALLOWED_ORIGINS env var (comma-separated).
 */

module.exports = function originCheck(req, res, next) {
  const origin = req.headers.origin;

  // No origin header → server-to-server or same-origin navigation → allow
  if (!origin) return next();

  // Explicit allowlist via env var
  if (process.env.ALLOWED_ORIGINS) {
    const allowed = process.env.ALLOWED_ORIGINS.split(',').map(s => s.trim());
    if (allowed.includes(origin)) return next();
    return res.status(403).json({ error: 'Forbidden: origin not allowed' });
  }

  // Default: only allow requests from the same host
  const host = req.headers.host;
  const expectedOrigin = `${req.protocol}://${host}`;
  if (origin === expectedOrigin) return next();

  return res.status(403).json({ error: 'Forbidden: origin not allowed' });
};
