const ipBlock = require('../middleware/ipBlock');

function makeReq(ip) {
  return { ip };
}

function makeRes() {
  const res = {
    status: jest.fn().mockReturnThis(),
    json: jest.fn(),
  };
  return res;
}

describe('IP Block Middleware - 10.2.0.0/16', () => {
  test('blocks an IP inside the range (10.2.5.100)', () => {
    const req = makeReq('10.2.5.100');
    const res = makeRes();
    const next = jest.fn();
    ipBlock(req, res, next);
    expect(res.status).toHaveBeenCalledWith(403);
    expect(next).not.toHaveBeenCalled();
  });

  test('blocks lower boundary (10.2.0.0)', () => {
    const req = makeReq('10.2.0.0');
    const res = makeRes();
    const next = jest.fn();
    ipBlock(req, res, next);
    expect(res.status).toHaveBeenCalledWith(403);
    expect(next).not.toHaveBeenCalled();
  });

  test('blocks upper boundary (10.2.255.255)', () => {
    const req = makeReq('10.2.255.255');
    const res = makeRes();
    const next = jest.fn();
    ipBlock(req, res, next);
    expect(res.status).toHaveBeenCalledWith(403);
    expect(next).not.toHaveBeenCalled();
  });

  test('blocks IPv6-mapped 10.2.x.x (::ffff:10.2.5.1)', () => {
    const req = makeReq('::ffff:10.2.5.1');
    const res = makeRes();
    const next = jest.fn();
    ipBlock(req, res, next);
    expect(res.status).toHaveBeenCalledWith(403);
    expect(next).not.toHaveBeenCalled();
  });

  test('allows 10.1.0.1 (different subnet)', () => {
    const req = makeReq('10.1.0.1');
    const res = makeRes();
    const next = jest.fn();
    ipBlock(req, res, next);
    expect(next).toHaveBeenCalled();
    expect(res.status).not.toHaveBeenCalled();
  });

  test('allows 10.3.0.1 (different subnet)', () => {
    const req = makeReq('10.3.0.1');
    const res = makeRes();
    const next = jest.fn();
    ipBlock(req, res, next);
    expect(next).toHaveBeenCalled();
    expect(res.status).not.toHaveBeenCalled();
  });

  test('allows 192.168.1.1', () => {
    const req = makeReq('192.168.1.1');
    const res = makeRes();
    const next = jest.fn();
    ipBlock(req, res, next);
    expect(next).toHaveBeenCalled();
    expect(res.status).not.toHaveBeenCalled();
  });

  test('allows 127.0.0.1 (loopback)', () => {
    const req = makeReq('127.0.0.1');
    const res = makeRes();
    const next = jest.fn();
    ipBlock(req, res, next);
    expect(next).toHaveBeenCalled();
    expect(res.status).not.toHaveBeenCalled();
  });

  test('allows ::1 (IPv6 loopback)', () => {
    const req = makeReq('::1');
    const res = makeRes();
    const next = jest.fn();
    ipBlock(req, res, next);
    expect(next).toHaveBeenCalled();
    expect(res.status).not.toHaveBeenCalled();
  });
});
