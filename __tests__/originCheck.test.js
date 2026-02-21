const originCheck = require('../middleware/originCheck');

function makeReq(origin, host = 'localhost:3000', protocol = 'http') {
  return {
    headers: origin ? { origin, host } : { host },
    protocol,
  };
}

function makeRes() {
  const res = {
    status: jest.fn().mockReturnThis(),
    json: jest.fn(),
  };
  return res;
}

describe('Origin Check Middleware', () => {
  afterEach(() => {
    delete process.env.ALLOWED_ORIGINS;
  });

  test('allows same-host origin', () => {
    const req = makeReq('http://localhost:3000');
    const res = makeRes();
    const next = jest.fn();
    originCheck(req, res, next);
    expect(next).toHaveBeenCalled();
    expect(res.status).not.toHaveBeenCalled();
  });

  test('blocks foreign origin', () => {
    const req = makeReq('http://evil.com');
    const res = makeRes();
    const next = jest.fn();
    originCheck(req, res, next);
    expect(res.status).toHaveBeenCalledWith(403);
    expect(next).not.toHaveBeenCalled();
  });

  test('allows no origin header (server-to-server)', () => {
    const req = makeReq(null);
    const res = makeRes();
    const next = jest.fn();
    originCheck(req, res, next);
    expect(next).toHaveBeenCalled();
    expect(res.status).not.toHaveBeenCalled();
  });

  test('blocks origin with different port', () => {
    const req = makeReq('http://localhost:9999');
    const res = makeRes();
    const next = jest.fn();
    originCheck(req, res, next);
    expect(res.status).toHaveBeenCalledWith(403);
    expect(next).not.toHaveBeenCalled();
  });

  test('respects ALLOWED_ORIGINS env — allows listed origin', () => {
    process.env.ALLOWED_ORIGINS = 'http://example.com,http://trusted.io';
    const req = makeReq('http://example.com');
    const res = makeRes();
    const next = jest.fn();
    originCheck(req, res, next);
    expect(next).toHaveBeenCalled();
  });

  test('respects ALLOWED_ORIGINS env — blocks unlisted origin', () => {
    process.env.ALLOWED_ORIGINS = 'http://example.com';
    const req = makeReq('http://evil.com');
    const res = makeRes();
    const next = jest.fn();
    originCheck(req, res, next);
    expect(res.status).toHaveBeenCalledWith(403);
  });
});
