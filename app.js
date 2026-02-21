const express = require('express');
const cookieParser = require('cookie-parser');
const multer = require('multer');
const crypto = require('crypto');
const path = require('path');
const fs = require('fs');

const ipBlock = require('./middleware/ipBlock');
const originCheck = require('./middleware/originCheck');
const csrf = require('./middleware/csrf');

// ── Load .env at startup ──
// Secrets added via the modal are written to .env. This loads them into
// process.env on startup so they survive service restarts.
// Existing process.env vars (e.g. from systemd Environment= lines) are NOT overwritten.
(function loadDotEnv() {
  const envPath = path.join(__dirname, '.env');
  let raw;
  try { raw = fs.readFileSync(envPath, 'utf-8'); }
  catch { return; } // no .env file — that's fine

  for (const line of raw.split('\n')) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#')) continue;
    const eqIdx = trimmed.indexOf('=');
    if (eqIdx < 1) continue;
    const key = trimmed.slice(0, eqIdx).trim();
    let val = trimmed.slice(eqIdx + 1).trim();
    // Strip surrounding quotes and unescape
    if ((val.startsWith('"') && val.endsWith('"')) ||
        (val.startsWith("'") && val.endsWith("'"))) {
      val = val.slice(1, -1).replace(/\\"/g, '"').replace(/\\\\/g, '\\');
    }
    if (!(key in process.env)) {
      process.env[key] = val; // don't clobber systemd-set vars
    }
  }
})();

const OPENCLAW_URL = process.env.OPENCLAW_URL || 'http://127.0.0.1:18789/v1/chat/completions';
const OPENCLAW_TOKEN = process.env.OPENCLAW_TOKEN || '';

// ── Secret injection ──
// Two syntaxes:
//   {{SECRET_VAR}}  → "[SECRET_VAR: <actual value>]"  (name + value; Jun knows both)
//   {SECRET_VAR}    → "SECRET_VAR"                    (name only; value stays in webchat)
//
// Only vars with SECRET_ prefix are allowed.
const SECRET_PREFIX = 'SECRET_';

// Matches {{VAR}} (group 1) or {VAR} (group 2). Double-brace alternative is first
// so {{VAR}} never gets partially matched by the single-brace branch.
const SECRET_PATTERN = /\{\{([A-Z][A-Z0-9_]*)\}\}|\{([A-Z][A-Z0-9_]*)\}/g;

function resolveSecrets(text) {
  const missing = [];
  const notAllowed = [];
  SECRET_PATTERN.lastIndex = 0;
  const resolved = text.replace(SECRET_PATTERN, (_match, doubleVar, singleVar) => {
    const varName = doubleVar || singleVar;
    const isDouble = Boolean(doubleVar); // true → send name+value; false → send name only

    if (!varName.startsWith(SECRET_PREFIX)) {
      notAllowed.push(varName);
      return _match;
    }

    if (!isDouble) {
      // Name-only reference — no value lookup, just send the label
      return varName;
    }

    // Double-brace: look up and embed value
    const value = process.env[varName];
    if (value === undefined) {
      missing.push(varName);
      return _match;
    }
    return `[${varName}: ${value}]`;
  });
  return { resolved, missing, notAllowed };
}

// Apply secret resolution to all user message strings in a messages array.
// Returns { messages, errors } where errors is an array of human-readable strings.
function injectSecrets(messages) {
  const errors = [];
  const out = messages.map(msg => {
    if (msg.role !== 'user') return msg;
    if (typeof msg.content === 'string') {
      const { resolved, missing, notAllowed } = resolveSecrets(msg.content);
      if (notAllowed.length) errors.push(`Variable(s) not allowed (must start with SECRET_): ${notAllowed.join(', ')}`);
      if (missing.length) errors.push(`Secret env var(s) not found: ${missing.join(', ')}`);
      return { ...msg, content: resolved };
    }
    if (Array.isArray(msg.content)) {
      const parts = msg.content.map(part => {
        if (part.type === 'text' && typeof part.text === 'string') {
          const { resolved, missing, notAllowed } = resolveSecrets(part.text);
          if (notAllowed.length) errors.push(`Variable(s) not allowed (must start with SECRET_): ${notAllowed.join(', ')}`);
          if (missing.length) errors.push(`Secret env var(s) not found: ${missing.join(', ')}`);
          return { ...part, text: resolved };
        }
        return part;
      });
      return { ...msg, content: parts };
    }
    return msg;
  });
  return { messages: out, errors };
}

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

// ── .env file helpers ──
const ENV_FILE = path.join(__dirname, '.env');
const SECRET_NAME_RE = /^SECRET_[A-Z0-9_]+$/;

function readEnvFile() {
  try { return fs.readFileSync(ENV_FILE, 'utf-8'); }
  catch { return ''; }
}

function writeSecretToEnvFile(name, value) {
  const raw = readEnvFile();
  const lines = raw.split('\n');
  const escaped = value.replace(/\\/g, '\\\\').replace(/"/g, '\\"');
  const newLine = `${name}="${escaped}"`;

  let found = false;
  const updated = lines.map(line => {
    // Match KEY= or KEY ="..." or KEY='...' at start of line (skip comments)
    if (/^\s*#/.test(line) || !/=/.test(line)) return line;
    const key = line.split('=')[0].trim();
    if (key === name) { found = true; return newLine; }
    return line;
  });

  if (!found) {
    // Append, with a blank line separator if file isn't empty
    if (updated.length && updated[updated.length - 1].trim() !== '') updated.push('');
    updated.push(newLine);
  }

  fs.writeFileSync(ENV_FILE, updated.join('\n'), 'utf-8');
}

// ── Secrets list endpoint ──
// Returns the NAMES of available SECRET_* env vars (never the values).
// Requires CSRF + origin check so random sites can't enumerate your secrets.
app.get('/api/secrets', originCheck, csrf.validate, (_req, res) => {
  const names = Object.keys(process.env)
    .filter(k => k.startsWith(SECRET_PREFIX))
    .sort();
  res.json({ secrets: names });
});

// ── Add/update secret endpoint ──
// Writes a new SECRET_* var to .env and hot-loads it into process.env.
app.post('/api/secrets', originCheck, csrf.validate, (req, res) => {
  const { name, value } = req.body || {};

  if (!name || typeof name !== 'string' || !SECRET_NAME_RE.test(name.trim())) {
    return res.status(400).json({
      error: 'Invalid name. Must match SECRET_[A-Z0-9_]+ (uppercase, no spaces).',
    });
  }

  if (value === undefined || value === null || String(value).length === 0) {
    return res.status(400).json({ error: 'Value cannot be empty.' });
  }

  const safeName  = name.trim();
  const safeValue = String(value);

  try {
    writeSecretToEnvFile(safeName, safeValue);
    process.env[safeName] = safeValue; // hot-load — no restart needed
  } catch (err) {
    console.error('Failed to write .env:', err);
    return res.status(500).json({ error: 'Could not save secret: ' + err.message });
  }

  res.json({ ok: true, name: safeName });
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

  // Resolve {{SECRET_VAR}} placeholders in user messages
  const { messages: secretResolved, errors: secretErrors } = injectSecrets(messages);
  if (secretErrors.length) {
    return res.status(400).json({ error: secretErrors.join('; ') });
  }

  // Build message array, injecting attachments into the last user message
  let finalMessages = secretResolved;
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
