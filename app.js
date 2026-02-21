const express = require('express');
const cookieParser = require('cookie-parser');
const multer = require('multer');
const crypto = require('crypto');
const path = require('path');
const fs = require('fs');

const ipBlock = require('./middleware/ipBlock');
const originCheck = require('./middleware/originCheck');
const csrf = require('./middleware/csrf');

const OPENCLAW_URL = process.env.OPENCLAW_URL || 'http://127.0.0.1:18789/v1/chat/completions';
const OPENCLAW_TOKEN = process.env.OPENCLAW_TOKEN || '';

const app = express();

// Trust proxy headers (so req.ip reflects the real client IP behind a reverse proxy)
app.set('trust proxy', true);

// Security middleware — applied to all routes
app.use(ipBlock);
app.use(cookieParser());
app.use(csrf.setToken);

// Parse JSON bodies
app.use(express.json());

// Static files
app.use(express.static(path.join(__dirname, 'public')));

// ── Upload configuration ──
const UPLOADS_DIR = path.join(__dirname, 'uploads');
if (!fs.existsSync(UPLOADS_DIR)) fs.mkdirSync(UPLOADS_DIR);

const ALLOWED_MIMES = new Set([
  'image/jpeg', 'image/png', 'image/gif', 'image/webp',
  'application/pdf', 'text/plain', 'text/markdown', 'text/csv',
  'application/json',
]);

const ALLOWED_EXTS = new Set([
  '.jpg', '.jpeg', '.png', '.gif', '.webp',
  '.pdf', '.txt', '.md', '.csv', '.json',
]);

const MAX_FILE_SIZE = 10 * 1024 * 1024; // 10 MB

const storage = multer.diskStorage({
  destination: (_req, _file, cb) => cb(null, UPLOADS_DIR),
  filename: (_req, file, cb) => {
    const id = crypto.randomBytes(16).toString('hex');
    const ext = path.extname(file.originalname).toLowerCase();
    cb(null, `${id}${ext}`);
  },
});

const upload = multer({
  storage,
  limits: { fileSize: MAX_FILE_SIZE },
  fileFilter: (_req, file, cb) => {
    const ext = path.extname(file.originalname).toLowerCase();
    if (ALLOWED_EXTS.has(ext)) {
      cb(null, true);
    } else {
      cb(Object.assign(new Error('File type not allowed'), { code: 'UNSUPPORTED_TYPE' }));
    }
  },
});

// Auto-cleanup files older than 1 hour
setInterval(() => {
  if (!fs.existsSync(UPLOADS_DIR)) return;
  const cutoff = Date.now() - 60 * 60 * 1000;
  for (const file of fs.readdirSync(UPLOADS_DIR)) {
    const fp = path.join(UPLOADS_DIR, file);
    try {
      const stat = fs.statSync(fp);
      if (stat.mtimeMs < cutoff) fs.unlinkSync(fp);
    } catch { /* ignore */ }
  }
}, 10 * 60 * 1000); // check every 10 minutes

// Health check (no CSRF needed)
app.get('/health', (_req, res) => res.json({ ok: true }));

// CSRF token endpoint — client calls this on page load to get a token
app.get('/api/csrf-token', (req, res) => {
  const token = req.cookies[csrf.COOKIE_NAME] || (() => {
    const t = csrf.generateToken();
    res.cookie(csrf.COOKIE_NAME, t, { httpOnly: false, sameSite: 'strict', path: '/' });
    return t;
  })();
  res.json({ token });
});

// ── File upload endpoint ──
app.post('/api/upload', originCheck, csrf.validate, (req, res) => {
  upload.single('file')(req, res, (err) => {
    if (err) {
      if (err.code === 'LIMIT_FILE_SIZE') {
        return res.status(413).json({ error: 'File too large (max 10 MB)' });
      }
      if (err.code === 'UNSUPPORTED_TYPE') {
        return res.status(415).json({ error: 'File type not allowed' });
      }
      return res.status(500).json({ error: err.message });
    }

    if (!req.file) {
      return res.status(400).json({ error: 'No file provided' });
    }

    const filePath = req.file.path;
    const data = fs.readFileSync(filePath).toString('base64');

    res.json({
      fileId: path.basename(filePath, path.extname(filePath)),
      name: req.file.originalname,
      type: req.file.mimetype,
      data,
    });
  });
});

// ── Chat proxy — CSRF + origin check required ──
app.post('/api/chat', originCheck, csrf.validate, async (req, res) => {
  const { messages, sessionId, attachments } = req.body;

  // Build message array, injecting attachments into the last user message
  let finalMessages = messages;
  if (Array.isArray(attachments) && attachments.length > 0) {
    finalMessages = [...messages];
    const lastUserIdx = finalMessages.map(m => m.role).lastIndexOf('user');

    if (lastUserIdx !== -1) {
      const lastUser = finalMessages[lastUserIdx];
      const contentParts = [];

      // Add attachment content blocks
      for (const att of attachments) {
        if (att.mimeType && att.mimeType.startsWith('image/')) {
          // Image: send as base64 image content block
          contentParts.push({
            type: 'image_url',
            image_url: { url: `data:${att.mimeType};base64,${att.data}` },
          });
        } else {
          // Document: decode base64 and prepend as text
          let text;
          try {
            text = Buffer.from(att.data, 'base64').toString('utf-8');
          } catch {
            text = att.data;
          }
          contentParts.push({
            type: 'text',
            text: `[Attached file: ${att.name}]\n${text}`,
          });
        }
      }

      // Add original user text
      contentParts.push({ type: 'text', text: lastUser.content });

      finalMessages[lastUserIdx] = { role: 'user', content: contentParts };
    }
  }

  try {
    const response = await fetch(OPENCLAW_URL, {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${OPENCLAW_TOKEN}`,
        'Content-Type': 'application/json',
        'x-openclaw-agent-id': 'main',
      },
      body: JSON.stringify({
        model: 'openclaw',
        messages: finalMessages,
        stream: true,
        user: sessionId || 'webchat',
      }),
    });

    if (!response.ok) {
      const err = await response.text();
      return res.status(response.status).json({ error: err });
    }

    res.setHeader('Content-Type', 'text/event-stream');
    res.setHeader('Cache-Control', 'no-cache');
    res.setHeader('Connection', 'keep-alive');

    const reader = response.body.getReader();
    const decoder = new TextDecoder();

    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      res.write(decoder.decode(value, { stream: true }));
    }

    res.end();
  } catch (err) {
    console.error('Proxy error:', err);
    res.status(500).json({ error: err.message });
  }
});

module.exports = app;
