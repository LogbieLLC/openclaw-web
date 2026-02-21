const express = require('express');
const path = require('path');
const app = express();

const OPENCLAW_URL = process.env.OPENCLAW_URL || 'http://127.0.0.1:18789/v1/chat/completions';
const OPENCLAW_TOKEN = process.env.OPENCLAW_TOKEN || '';

app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

app.post('/api/chat', async (req, res) => {
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

const PORT = 3000;
app.listen(PORT, '0.0.0.0', () => {
  console.log(`Jun web chat running on http://0.0.0.0:${PORT}`);
});
