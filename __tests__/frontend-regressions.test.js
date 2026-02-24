const fs = require('fs');
const path = require('path');

describe('frontend regressions', () => {
  const htmlPath = path.join(__dirname, '..', 'public', 'index.html');
  const html = fs.readFileSync(htmlPath, 'utf8');

  test('persists user message immediately after send (before assistant stream)', () => {
    const sendFlowRegex = /history\.push\(\{\s*role:\s*'user',\s*content:\s*text\s*\|\|\s*'\(see attached files\)'\s*\}\);[\s\S]{0,220}?saveCurrentConversation\(\);[\s\S]{0,220}?showTyping\(\);/;
    expect(html).toMatch(sendFlowRegex);
  });

  test('SSE parser supports alternate chunk shapes used by tool/subagent updates', () => {
    // chat-completions style
    expect(html).toContain("const delta = choice?.delta?.content;");
    expect(html).toContain("if (typeof delta === 'string')");
    expect(html).toContain("else if (Array.isArray(delta))");

    // final/non-stream choice message content
    expect(html).toContain("const messageContent = choice?.message?.content;");
    expect(html).toContain("if (!chunk && typeof messageContent === 'string')");
    expect(html).toContain("else if (!chunk && Array.isArray(messageContent))");

    // responses-style fallback fields
    expect(html).toContain("if (!chunk && typeof obj.output_text === 'string')");
    expect(html).toContain("if (!chunk && typeof obj.delta === 'string')");
  });
});
