import test from 'node:test';
import assert from 'node:assert/strict';
import net from 'node:net';
import { sendMail, mailConfigured, mailConfig } from '../lib/mail.js';

/* A fake SMTP server on a random port: enough of the protocol to record what
   the client sends, so the test checks the conversation, not just a boolean. */
function fakeSmtp({ rejectRcpt = false } = {}) {
  const seen = [];
  let data = '';
  const server = net.createServer((sock) => {
    let inData = false;
    sock.write('220 fake.test ESMTP\r\n');
    sock.on('data', (chunk) => {
      const text = chunk.toString('utf8');
      if (inData) {
        data += text;
        if (data.includes('\r\n.\r\n')) { inData = false; sock.write('250 queued\r\n'); }
        return;
      }
      for (const line of text.split('\r\n').filter(Boolean)) {
        seen.push(line);
        if (line.startsWith('EHLO')) sock.write('250-fake.test\r\n250-AUTH PLAIN LOGIN\r\n250 OK\r\n');
        else if (line.startsWith('AUTH PLAIN')) sock.write('235 ok\r\n');
        else if (line.startsWith('MAIL FROM')) sock.write('250 ok\r\n');
        else if (line.startsWith('RCPT TO')) sock.write(rejectRcpt ? '550 no such user\r\n' : '250 ok\r\n');
        else if (line === 'DATA') { inData = true; sock.write('354 go\r\n'); }
        else if (line === 'QUIT') { sock.write('221 bye\r\n'); sock.end(); }
        else sock.write('500 what\r\n');
      }
    });
  });
  return new Promise((resolve) => server.listen(0, '127.0.0.1', () => resolve({
    server, seen, data: () => data,
    env: {
      SMTP_HOST: '127.0.0.1', SMTP_PORT: String(server.address().port), SMTP_SECURE: 'none',
      SMTP_USER: 'robot@example.sg', SMTP_PASS: 'pw', SMTP_FROM: 'Fun Game <robot@example.sg>'
    }
  })));
}

test('unconfigured means not configured, and the defaults follow the port', () => {
  assert.equal(mailConfigured({}), false);
  assert.equal(mailConfig({ SMTP_HOST: 'x' }).secure, 'tls');
  assert.equal(mailConfig({ SMTP_HOST: 'x', SMTP_PORT: '587' }).secure, 'starttls');
  assert.equal(mailConfig({ SMTP_HOST: 'x', SMTP_USER: 'a@b.c' }).from, 'a@b.c');
});

test('a message is authenticated, addressed and dot-stuffed', async () => {
  const f = await fakeSmtp();
  try {
    await sendMail({ to: 'parent@example.com', subject: 'Your password 🔑', text: 'Hello\n.hidden line\nBye' }, f.env);
    assert.ok(f.seen.some((l) => l.startsWith('AUTH PLAIN ')));
    assert.ok(f.seen.includes('MAIL FROM:<robot@example.sg>'));
    assert.ok(f.seen.includes('RCPT TO:<parent@example.com>'));
    const body = f.data();
    assert.match(body, /^From: Fun Game <robot@example.sg>\r\n/);
    assert.match(body, /Subject: =\?UTF-8\?B\?/);
    assert.ok(body.includes('\r\n..hidden line\r\n'), 'a leading dot is doubled');
    assert.ok(body.endsWith('\r\n.\r\n'));
  } finally { f.server.close(); }
});

test('a refused recipient is an error carrying the server reply', async () => {
  const f = await fakeSmtp({ rejectRcpt: true });
  try {
    await assert.rejects(sendMail({ to: 'nobody@example.com', subject: 's', text: 't' }, f.env), /550 no such user/);
  } finally { f.server.close(); }
});

test('with an API key the message goes to Brevo over HTTPS, not SMTP', async () => {
  const calls = [];
  const fakeFetch = async (url, opts) => { calls.push({ url, opts }); return { ok: true, status: 201, json: async () => ({ messageId: 'x' }) }; };
  const env = { BREVO_API_KEY: 'xkeysib-test', MAIL_FROM: 'Fun Game <hello@example.sg>', SMTP_HOST: 'ignored.example' };
  assert.equal(mailConfig(env).transport, 'brevo-api');
  assert.equal(mailConfigured(env), true);
  await sendMail({ to: 'parent@example.com', subject: 'Hi', text: 'Body' }, env, { fetchImpl: fakeFetch });
  assert.equal(calls.length, 1);
  assert.equal(calls[0].url, 'https://api.brevo.com/v3/smtp/email');
  assert.equal(calls[0].opts.headers['api-key'], 'xkeysib-test');
  const body = JSON.parse(calls[0].opts.body);
  assert.deepEqual(body.sender, { name: 'Fun Game', email: 'hello@example.sg' });
  assert.deepEqual(body.to, [{ email: 'parent@example.com' }]);
  assert.equal(body.textContent, 'Body');
});

test('a Brevo API refusal carries its message', async () => {
  const fakeFetch = async () => ({ ok: false, status: 401, json: async () => ({ code: 'unauthorized', message: 'Key not found' }) });
  await assert.rejects(
    sendMail({ to: 'a@b.co', subject: 's', text: 't' }, { BREVO_API_KEY: 'bad', MAIL_FROM: 'a@b.co' }, { fetchImpl: fakeFetch }),
    /brevo api: 401 Key not found/);
});
