/**
 * IP Block Middleware
 * Blocks requests from the IoT network (10.2.0.0/16).
 */

const { isIPv4 } = require('net');

function ipToNum(ip) {
  return ip.split('.').reduce((acc, octet) => (acc << 8) + parseInt(octet, 10), 0) >>> 0;
}

const BLOCKED_RANGES = [
  // IoT network — blocked per policy
  { start: ipToNum('10.2.0.0'), end: ipToNum('10.2.255.255') },
];

function isBlocked(ip) {
  // Strip IPv6-mapped IPv4 prefix (::ffff:x.x.x.x)
  const clean = ip.replace(/^::ffff:/, '');
  if (!isIPv4(clean)) return false;
  const num = ipToNum(clean);
  return BLOCKED_RANGES.some(({ start, end }) => num >= start && num <= end);
}

module.exports = function ipBlock(req, res, next) {
  const ip = req.ip || (req.connection && req.connection.remoteAddress) || '';
  if (isBlocked(ip)) {
    return res.status(403).json({ error: 'Forbidden' });
  }
  next();
};
