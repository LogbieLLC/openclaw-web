const express = require('express');
const cookieParser = require('cookie-parser');
const path = require('path');

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

// Chat proxy — CSRF + origin check required
app.post('/api/chat', originCheck, csrf.validate, async (req, res) => {
  const { messages, sessionId } = req.body;

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
        messages,
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
