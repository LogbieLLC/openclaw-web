const request = require('supertest');
const path = require('path');
const fs = require('fs');
const app = require('../app');

const TOKEN = 'test-csrf-token-upload';

// Helper: create a temporary file of a given size (bytes)
function tmpFile(name, sizeBytes, content) {
  const dir = path.join(__dirname, 'fixtures');
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
  const fp = path.join(dir, name);
  if (content) {
    fs.writeFileSync(fp, content);
  } else {
    // Write a buffer of the requested size
    fs.writeFileSync(fp, Buffer.alloc(sizeBytes, 0x41)); // fill with 'A'
  }
  return fp;
}

afterAll(() => {
  // Clean up fixture files
  const dir = path.join(__dirname, 'fixtures');
  if (fs.existsSync(dir)) fs.rmSync(dir, { recursive: true, force: true });

  // Clean up any uploaded files from tests
  const uploadsDir = path.join(__dirname, '..', 'uploads');
  if (fs.existsSync(uploadsDir)) fs.rmSync(uploadsDir, { recursive: true, force: true });
});

describe('POST /api/upload', () => {
  test('rejects oversized files (>10 MB) → 413', async () => {
    const bigFile = tmpFile('big.txt', 11 * 1024 * 1024); // 11 MB

    const res = await request(app)
      .post('/api/upload')
      .set('Cookie', `csrf_token=${TOKEN}`)
      .set('X-CSRF-Token', TOKEN)
      .attach('file', bigFile);

    expect(res.status).toBe(413);
  });

  test('rejects disallowed file types → 415', async () => {
    const exeFile = tmpFile('malware.exe', 100);

    const res = await request(app)
      .post('/api/upload')
      .set('Cookie', `csrf_token=${TOKEN}`)
      .set('X-CSRF-Token', TOKEN)
      .attach('file', exeFile);

    expect(res.status).toBe(415);
  });

  test('rejects request without CSRF token → 403', async () => {
    const txtFile = tmpFile('hello.txt', 0, 'hello world');

    const res = await request(app)
      .post('/api/upload')
      .attach('file', txtFile);

    expect(res.status).toBe(403);
  });

  test('accepts valid file upload → 200 with expected JSON shape', async () => {
    const txtFile = tmpFile('notes.txt', 0, 'some notes');

    const res = await request(app)
      .post('/api/upload')
      .set('Cookie', `csrf_token=${TOKEN}`)
      .set('X-CSRF-Token', TOKEN)
      .attach('file', txtFile);

    expect(res.status).toBe(200);
    expect(res.body).toHaveProperty('fileId');
    expect(res.body).toHaveProperty('name', 'notes.txt');
    expect(res.body).toHaveProperty('type');
    expect(res.body).toHaveProperty('data');
    expect(typeof res.body.fileId).toBe('string');
    expect(typeof res.body.data).toBe('string');
  });

  test('accepts valid image upload → 200', async () => {
    // Create a minimal 1x1 PNG
    const pngHeader = Buffer.from(
      '89504e470d0a1a0a0000000d49484452000000010000000108060000001f15c489' +
      '0000000a49444154789c626000000002000198e195280000000049454e44ae426082',
      'hex'
    );
    const pngFile = tmpFile('test.png', 0, pngHeader);

    const res = await request(app)
      .post('/api/upload')
      .set('Cookie', `csrf_token=${TOKEN}`)
      .set('X-CSRF-Token', TOKEN)
      .attach('file', pngFile);

    expect(res.status).toBe(200);
    expect(res.body.name).toBe('test.png');
    expect(res.body.type).toMatch(/image\/png|application\/octet-stream/);
  });

  test('rejects request with no file attached → 400', async () => {
    const res = await request(app)
      .post('/api/upload')
      .set('Cookie', `csrf_token=${TOKEN}`)
      .set('X-CSRF-Token', TOKEN)
      .send({});

    expect(res.status).toBe(400);
  });
});
