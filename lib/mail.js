import net from 'node:net';
import tls from 'node:tls';

/**
 * Just enough SMTP to send a plain-text email, with no dependency. Configured
 * from the environment:
 *
 *   SMTP_HOST   e.g. smtp.hostinger.com
 *   SMTP_PORT   465 (TLS from the first byte, the default) or 587 (STARTTLS)
 *   SMTP_USER   the mailbox that sends
 *   SMTP_PASS   its password
 *   SMTP_FROM   optional "Fun Game <hello@example.sg>"; defaults to SMTP_USER
 *   SMTP_SECURE optional: "tls" (default on 465), "starttls" (default
 *               otherwise) or "none" (plain — for tests, never for a real mailbox)
 *
 * With SMTP_HOST unset nothing here is used and the app falls back to letting
 * people choose a password on the sign-up sheet.
 */

/* Two ways out, picked from the environment:
 *
 *   BREVO_API_KEY  send over HTTPS through Brevo's API (port 443). Hosts such
 *                  as Railway block outbound SMTP ports, and this route is
 *                  never blocked. MAIL_FROM (or SMTP_FROM) names the sender,
 *                  which must be a sender Brevo has verified.
 *   SMTP_HOST      plain SMTP, as above.
 *
 * With an API key set it wins, so a site can keep its SMTP settings around. */
export function mailConfig(env = process.env) {
  const apiKey = String(env.BREVO_API_KEY || '').trim();
  const host = String(env.SMTP_HOST || '').trim();
  const from = String(env.MAIL_FROM || env.SMTP_FROM || env.SMTP_USER || '').trim();
  if (apiKey) return { transport: 'brevo-api', host: 'api.brevo.com', port: 443, secure: 'https', user: '', pass: apiKey, from };
  if (!host) return null;
  const port = Number(env.SMTP_PORT) || 465;
  const secure = String(env.SMTP_SECURE || (port === 465 ? 'tls' : 'starttls')).toLowerCase();
  return {
    transport: 'smtp', host, port, secure,
    user: String(env.SMTP_USER || ''),
    pass: String(env.SMTP_PASS || ''),
    from
  };
}

export function mailConfigured(env = process.env) {
  const c = mailConfig(env);
  return !!(c && c.from);
}

/** "Name <addr>" -> { name, email }; a bare address gets no name. */
function splitAddress(s) {
  const m = String(s).match(/^\s*(.*?)\s*<([^>]+)>\s*$/);
  return m ? { name: m[1].replace(/^"|"$/g, '') || undefined, email: m[2].trim() } : { email: String(s).trim() };
}

async function sendViaBrevoApi({ to, subject, text }, cfg, { fetchImpl = fetch, timeoutMs = 15000 } = {}) {
  const sender = splitAddress(cfg.from);
  const res = await fetchImpl('https://api.brevo.com/v3/smtp/email', {
    method: 'POST',
    headers: { 'api-key': cfg.pass, 'content-type': 'application/json', accept: 'application/json' },
    body: JSON.stringify({ sender, to: [{ email: bareAddress(to) }], subject, textContent: text }),
    signal: AbortSignal.timeout(timeoutMs)
  });
  if (res.ok) return true;
  let detail = '';
  try { const body = await res.json(); detail = body.message || body.code || JSON.stringify(body); }
  catch { detail = await res.text().catch(() => ''); }
  throw new Error(`brevo api: ${res.status} ${detail}`.trim());
}

/** The bare address inside "Name <addr>" (or the string itself). */
function bareAddress(s) {
  const m = String(s).match(/<([^>]+)>/);
  return (m ? m[1] : String(s)).trim();
}

/* A line-oriented SMTP conversation. Every command waits for a reply that
   starts with the expected status digit; anything else is an error carrying
   the server's own words, which is what an admin needs to see in the log. */
class Smtp {
  constructor(socket) {
    this.socket = socket;
    this.buffer = '';
    this.waiting = null;
    socket.setEncoding('utf8');
    socket.on('data', (chunk) => this.onData(chunk));
    socket.on('error', (err) => this.fail(err));
    socket.on('close', () => this.fail(new Error('connection closed')));
  }
  attach(socket) {
    // After STARTTLS the conversation continues on the wrapped socket.
    this.socket = socket;
    socket.setEncoding('utf8');
    socket.on('data', (chunk) => this.onData(chunk));
    socket.on('error', (err) => this.fail(err));
  }
  onData(chunk) {
    this.buffer += chunk;
    // A reply is complete when its last line reads "250 text" rather than "250-text".
    const lines = this.buffer.split('\r\n');
    const complete = [];
    for (const line of lines.slice(0, -1)) {
      complete.push(line);
      if (/^\d{3} /.test(line)) {
        this.buffer = lines.slice(complete.length).join('\r\n');
        const w = this.waiting; this.waiting = null;
        if (w) w.resolve(complete);
        return;
      }
    }
  }
  fail(err) {
    const w = this.waiting; this.waiting = null;
    if (w) w.reject(err);
  }
  reply() {
    return new Promise((resolve, reject) => { this.waiting = { resolve, reject }; });
  }
  async expect(code, lines) {
    const last = lines[lines.length - 1] || '';
    if (!last.startsWith(String(code))) throw new Error(`smtp: expected ${code}, got "${last}"`);
    return lines;
  }
  async command(line, code) {
    const p = this.reply();
    this.socket.write(line + '\r\n');
    return this.expect(code, await p);
  }
}

function dotStuff(text) {
  return String(text).replace(/\r?\n/g, '\r\n').split('\r\n').map((l) => (l.startsWith('.') ? '.' + l : l)).join('\r\n');
}

function encodeHeader(s) {
  // RFC 2047 for anything outside ASCII (a subject with an emoji, say).
  return /^[\x20-\x7e]*$/.test(s) ? s : `=?UTF-8?B?${Buffer.from(s, 'utf8').toString('base64')}?=`;
}

/**
 * Send one plain-text message. Resolves when the server has accepted it for
 * delivery; rejects with the server's reply on any refusal.
 */
export async function sendMail({ to, subject, text }, env = process.env, { timeoutMs = 15000, fetchImpl } = {}) {
  const cfg = mailConfig(env);
  if (!cfg || !cfg.from) throw new Error('smtp: not configured');
  if (cfg.transport === 'brevo-api') return sendViaBrevoApi({ to, subject, text }, cfg, { fetchImpl, timeoutMs });

  const connect = () => new Promise((resolve, reject) => {
    const onError = (err) => reject(err);
    const socket = cfg.secure === 'tls'
      ? tls.connect({ host: cfg.host, port: cfg.port, servername: cfg.host }, () => resolve(socket))
      : net.connect({ host: cfg.host, port: cfg.port }, () => resolve(socket));
    socket.once('error', onError);
    socket.setTimeout(timeoutMs, () => { socket.destroy(new Error('smtp: timed out')); });
  });

  const socket = await connect();
  const smtp = new Smtp(socket);
  const finish = () => { try { socket.end(); } catch { /* already gone */ } };
  try {
    await smtp.expect(220, await smtp.reply());
    let ehlo = await smtp.command('EHLO funfame.local', 250);

    if (cfg.secure === 'starttls') {
      if (!ehlo.some((l) => /STARTTLS/i.test(l))) throw new Error('smtp: server does not offer STARTTLS');
      await smtp.command('STARTTLS', 220);
      const secured = await new Promise((resolve, reject) => {
        const s = tls.connect({ socket, servername: cfg.host }, () => resolve(s));
        s.once('error', reject);
      });
      smtp.attach(secured);
      ehlo = await smtp.command('EHLO funfame.local', 250);
    } else if (cfg.secure !== 'tls' && cfg.secure !== 'none') {
      throw new Error(`smtp: unknown SMTP_SECURE "${cfg.secure}"`);
    }

    if (cfg.user) {
      const plain = Buffer.from(`\0${cfg.user}\0${cfg.pass}`, 'utf8').toString('base64');
      if (ehlo.some((l) => /AUTH .*PLAIN/i.test(l))) {
        await smtp.command(`AUTH PLAIN ${plain}`, 235);
      } else {
        await smtp.command('AUTH LOGIN', 334);
        await smtp.command(Buffer.from(cfg.user, 'utf8').toString('base64'), 334);
        await smtp.command(Buffer.from(cfg.pass, 'utf8').toString('base64'), 235);
      }
    }

    await smtp.command(`MAIL FROM:<${bareAddress(cfg.from)}>`, 250);
    await smtp.command(`RCPT TO:<${bareAddress(to)}>`, 250);
    await smtp.command('DATA', 354);
    const headers = [
      `From: ${cfg.from}`,
      `To: <${bareAddress(to)}>`,
      `Subject: ${encodeHeader(subject)}`,
      `Date: ${new Date().toUTCString()}`,
      `Message-ID: <${Date.now()}.${Math.random().toString(36).slice(2)}@${cfg.host}>`,
      'MIME-Version: 1.0',
      'Content-Type: text/plain; charset=utf-8',
      'Content-Transfer-Encoding: 8bit',
      'Auto-Submitted: auto-generated'
    ];
    await smtp.command(headers.join('\r\n') + '\r\n\r\n' + dotStuff(text) + '\r\n.', 250);
    try { await smtp.command('QUIT', 221); } catch { /* accepted already */ }
    return true;
  } finally {
    finish();
  }
}
