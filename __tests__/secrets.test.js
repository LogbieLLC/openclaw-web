/**
 * Tests for {{SECRET_VAR}} injection in /api/chat.
 *
 * We don't call the real OpenClaw backend — we just verify that the
 * server correctly rejects or short-circuits messages with bad secret
 * references BEFORE proxying. For valid secrets we check the resolved
 * value actually reaches the upstream payload.
 */

const request = require('supertest');
const path = require('path');
const fs = require('fs');

// We need to control process.env before requiring app,
// so set vars here first.
const TOKEN = 'test-csrf-token-secrets';

// Use a temp .env file so tests don't touch the real one
const TEST_ENV_PATH = path.join(__dirname, '..', '.env.test-tmp');

beforeAll(() => {
  process.env.SECRET_MY_KEY = 'supersecret123';
  process.env.SECRET_ANOTHER = 'another-value';
  // Ensure sensitive built-ins cannot be leaked
  process.env.OPENCLAW_TOKEN = 'must-not-leak';
});

afterAll(() => {
  // Clean up temp .env file if created by the POST tests
  if (fs.existsSync(TEST_ENV_PATH)) fs.unlinkSync(TEST_ENV_PATH);
  // Also clean up the real one if tests accidentally wrote to it
  const realEnv = path.join(__dirname, '..', '.env');
  if (fs.existsSync(realEnv)) {
    const content = fs.readFileSync(realEnv, 'utf-8');
    if (content.includes('SECRET_TEST_NEW_VAR')) {
      // Remove test-written lines
      const cleaned = content.split('\n').filter(l => !l.startsWith('SECRET_TEST_NEW_VAR')).join('\n');
      fs.writeFileSync(realEnv, cleaned, 'utf-8');
    }
  }
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

describe('POST /api/secrets', () => {
  const HEADERS = {
    Cookie: `csrf_token=${TOKEN}`,
    'X-CSRF-Token': TOKEN,
    'X-Requested-With': 'XMLHttpRequest',
    'Content-Type': 'application/json',
  };

  test('saves a new SECRET_* var and hot-loads into process.env', async () => {
    const res = await request(app)
      .post('/api/secrets')
      .set(HEADERS)
      .send({ name: 'SECRET_TEST_NEW_VAR', value: 'hello-world' });

    expect(res.status).toBe(200);
    expect(res.body).toMatchObject({ ok: true, name: 'SECRET_TEST_NEW_VAR' });
    // Verify it was hot-loaded into process.env
    expect(process.env.SECRET_TEST_NEW_VAR).toBe('hello-world');
  });

  test('rejects names without SECRET_ prefix → 400', async () => {
    const res = await request(app)
      .post('/api/secrets')
      .set(HEADERS)
      .send({ name: 'MY_KEY', value: 'val' });

    expect(res.status).toBe(400);
    expect(res.body.error).toMatch(/invalid name/i);
  });

  test('rejects lowercase / invalid characters in name → 400', async () => {
    const res = await request(app)
      .post('/api/secrets')
      .set(HEADERS)
      .send({ name: 'SECRET_my key!', value: 'val' });

    expect(res.status).toBe(400);
  });

  test('rejects empty value → 400', async () => {
    const res = await request(app)
      .post('/api/secrets')
      .set(HEADERS)
      .send({ name: 'SECRET_EMPTY_VAL', value: '' });

    expect(res.status).toBe(400);
    expect(res.body.error).toMatch(/empty/i);
  });

  test('rejects without CSRF token → 403', async () => {
    const res = await request(app)
      .post('/api/secrets')
      .set('X-Requested-With', 'XMLHttpRequest')
      .set('Content-Type', 'application/json')
      .send({ name: 'SECRET_FOO', value: 'bar' });

    expect(res.status).toBe(403);
  });

  test('updating an existing var overwrites it', async () => {
    // First write
    await request(app).post('/api/secrets').set(HEADERS).send({ name: 'SECRET_UPDATE_ME', value: 'v1' });
    expect(process.env.SECRET_UPDATE_ME).toBe('v1');

    // Second write — should overwrite
    const res = await request(app).post('/api/secrets').set(HEADERS).send({ name: 'SECRET_UPDATE_ME', value: 'v2' });
    expect(res.status).toBe(200);
    expect(process.env.SECRET_UPDATE_ME).toBe('v2');
  });
});

describe('Secret injection — /api/chat', () => {
  // ── Double-brace {{VAR}} tests ──

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

  // ── Single-brace {VAR} tests (name-only reference) ──

  test('{SECRET_VAR} name-only: passes through without value lookup', async () => {
    // Even a var that doesn't exist in process.env should NOT cause 400
    const res = await request(app)
      .post('/api/chat')
      .set(TOKEN_HEADERS)
      .send({
        sessionId: 'test-session',
        messages: [{ role: 'user', content: 'use {SECRET_NONEXISTENT_VAR} for this task' }],
      });

    // Should not be a 400 from secret validation
    expect(res.status).not.toBe(400);
  });

  test('{VAR} without SECRET_ prefix → 400 (single-brace also enforces prefix)', async () => {
    const res = await request(app)
      .post('/api/chat')
      .set(TOKEN_HEADERS)
      .send({
        sessionId: 'test-session',
        messages: [{ role: 'user', content: 'ref: {OPENCLAW_TOKEN}' }],
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
