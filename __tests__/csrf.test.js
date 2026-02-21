const request = require('supertest');
const app = require('../app');

describe('CSRF Protection on POST /api/chat', () => {
  const TOKEN = 'test-csrf-token-abc123';

  test('rejects request with no CSRF cookie and no header → 403', async () => {
    const res = await request(app)
      .post('/api/chat')
      .set('Content-Type', 'application/json')
      .send({ messages: [], sessionId: 'test' });
    expect(res.status).toBe(403);
  });

  test('rejects request with cookie but no header → 403', async () => {
    const res = await request(app)
      .post('/api/chat')
      .set('Cookie', `csrf_token=${TOKEN}`)
      .set('Content-Type', 'application/json')
      .send({ messages: [], sessionId: 'test' });
    expect(res.status).toBe(403);
  });

  test('rejects request with header but no cookie → 403', async () => {
    const res = await request(app)
      .post('/api/chat')
      .set('X-CSRF-Token', TOKEN)
      .set('Content-Type', 'application/json')
      .send({ messages: [], sessionId: 'test' });
    expect(res.status).toBe(403);
  });

  test('rejects request with mismatched cookie and header → 403', async () => {
    const res = await request(app)
      .post('/api/chat')
      .set('Cookie', `csrf_token=${TOKEN}`)
      .set('X-CSRF-Token', 'wrong-token')
      .set('Content-Type', 'application/json')
      .send({ messages: [], sessionId: 'test' });
    expect(res.status).toBe(403);
  });

  test('passes CSRF check when cookie and header match (may fail upstream, not 403)', async () => {
    const res = await request(app)
      .post('/api/chat')
      .set('Cookie', `csrf_token=${TOKEN}`)
      .set('X-CSRF-Token', TOKEN)
      .set('Content-Type', 'application/json')
      .send({ messages: [], sessionId: 'test' });
    // CSRF check passes; upstream (OpenClaw) may return 5xx — that's fine.
    expect(res.status).not.toBe(403);
  });

  test('GET /api/csrf-token returns a token and sets cookie', async () => {
    const res = await request(app).get('/api/csrf-token');
    expect(res.status).toBe(200);
    expect(res.body).toHaveProperty('token');
    expect(res.headers['set-cookie']).toBeDefined();
    const cookieHeader = res.headers['set-cookie'].join('');
    expect(cookieHeader).toContain('csrf_token=');
  });
});
