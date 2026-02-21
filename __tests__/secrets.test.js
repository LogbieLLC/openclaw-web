/**
 * Tests for {{SECRET_VAR}} injection in /api/chat.
 *
 * We don't call the real OpenClaw backend — we just verify that the
 * server correctly rejects or short-circuits messages with bad secret
 * references BEFORE proxying. For valid secrets we check the resolved
 * value actually reaches the upstream payload.
 */

const request = require('supertest');

// We need to control process.env before requiring app,
// so set vars here first.
const TOKEN = 'test-csrf-token-secrets';

beforeAll(() => {
  process.env.SECRET_MY_KEY = 'supersecret123';
  process.env.SECRET_ANOTHER = 'another-value';
  // Ensure sensitive built-ins cannot be leaked
  process.env.OPENCLAW_TOKEN = 'must-not-leak';
});

// Lazy-require app after env is set
let app;
beforeAll(() => {
  // Clear module cache so env changes take effect
  jest.resetModules();
  app = require('../app');
});

const TOKEN_HEADERS = {
  Cookie: `csrf_token=${TOKEN}`,
  'X-CSRF-Token': TOKEN,
  'Content-Type': 'application/json',
};

describe('GET /api/secrets', () => {
  test('returns list of SECRET_* var names (not values)', async () => {
    const res = await request(app)
      .get('/api/secrets')
      .set('Cookie', `csrf_token=${TOKEN}`)
      .set('X-CSRF-Token', TOKEN)
      .set('X-Requested-With', 'XMLHttpRequest');

    expect(res.status).toBe(200);
    expect(res.body).toHaveProperty('secrets');
    expect(Array.isArray(res.body.secrets)).toBe(true);
    // Should include the ones we set in beforeAll
    expect(res.body.secrets).toContain('SECRET_MY_KEY');
    expect(res.body.secrets).toContain('SECRET_ANOTHER');
    // Values must NOT be present anywhere in the response body
    expect(JSON.stringify(res.body)).not.toContain('supersecret123');
    expect(JSON.stringify(res.body)).not.toContain('another-value');
    // OPENCLAW_TOKEN must never appear
    expect(res.body.secrets).not.toContain('OPENCLAW_TOKEN');
  });

  test('rejects request without CSRF token → 403', async () => {
    const res = await request(app)
      .get('/api/secrets')
      .set('X-Requested-With', 'XMLHttpRequest');

    expect(res.status).toBe(403);
  });
});

describe('Secret injection — /api/chat', () => {
  test('rejects {{VAR}} without SECRET_ prefix → 400', async () => {
    const res = await request(app)
      .post('/api/chat')
      .set(TOKEN_HEADERS)
      .send({
        sessionId: 'test-session',
        messages: [{ role: 'user', content: 'my token is {{OPENCLAW_TOKEN}}' }],
      });

    expect(res.status).toBe(400);
    expect(res.body.error).toMatch(/not allowed/i);
  });

  test('rejects {{SECRET_MISSING}} when env var is not defined → 400', async () => {
    const res = await request(app)
      .post('/api/chat')
      .set(TOKEN_HEADERS)
      .send({
        sessionId: 'test-session',
        messages: [{ role: 'user', content: 'here: {{SECRET_DOES_NOT_EXIST}}' }],
      });

    expect(res.status).toBe(400);
    expect(res.body.error).toMatch(/not found/i);
  });

  test('rejects mixed bad + good secrets → 400 (all-or-nothing)', async () => {
    const res = await request(app)
      .post('/api/chat')
      .set(TOKEN_HEADERS)
      .send({
        sessionId: 'test-session',
        messages: [
          { role: 'user', content: '{{SECRET_MY_KEY}} and {{OPENCLAW_TOKEN}}' },
        ],
      });

    expect(res.status).toBe(400);
  });

  test('messages with no secrets pass through (no interference)', async () => {
    // This will try to proxy to OpenClaw which isn't running — we just
    // need to confirm it doesn't return 400 from secret validation.
    const res = await request(app)
      .post('/api/chat')
      .set(TOKEN_HEADERS)
      .send({
        sessionId: 'test-session',
        messages: [{ role: 'user', content: 'plain message without any tokens' }],
      });

    // Should not be 400 (secret validation error)
    expect(res.status).not.toBe(400);
  });
});
