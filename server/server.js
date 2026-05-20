const express = require('express');
const path = require('path');
const { ImapFlow } = require('imapflow');
const { simpleParser } = require('mailparser');

const app = express();
const PORT = 3000;

app.use('/otp', express.static(path.join(__dirname, 'public')));
app.use(express.static(path.join(__dirname, '..')));
app.use(express.json());

function extractOTPs(text) {
  const found = [];
  const patterns = [
    /\b(\d{4,8})\b/g,
    /\b([A-Z0-9]{4,8})\b/g,
  ];
  for (const pat of patterns) {
    let m;
    while ((m = pat.exec(text)) !== null) {
      const val = m[1];
      if (val.length >= 4 && val.length <= 8) {
        if (/^\d+$/.test(val) || /^[A-Z0-9]+$/.test(val)) {
          found.push(val);
        }
      }
    }
  }
  return [...new Set(found)];
}

app.post('/api/fetch', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) {
    return res.json({ error: 'Email and App Password required' });
  }

  const client = new ImapFlow({
    host: 'imap.gmail.com',
    port: 993,
    secure: true,
    auth: { user: email, pass: password },
    logger: false,
  });

  try {
    await client.connect();
    const lock = await client.getMailboxLock('INBOX');
    const results = [];

    try {
      const search = await client.search({
        subject: ['otp', 'one time', 'verification code', '2fa', 'security code', 'login code'],
        from: ['noreply', 'no-reply', 'notification'],
        answered: false,
      });

      const fetchIds = search.slice(-20);

      for (const uid of fetchIds) {
        const msg = await client.fetchOne(uid, {
          envelope: true,
          source: true,
          uid: true,
        });

        const parsed = await simpleParser(msg.source);
        const bodyText = parsed.text || parsed.html || '';
        const otps = extractOTPs(bodyText);

        results.push({
          id: uid.toString(),
          from: parsed.from?.text || 'Unknown',
          date: parsed.date?.toISOString() || '',
          subject: parsed.subject || '',
          otps,
          snippet: parsed.text?.slice(0, 200) || '',
        });
      }
    } finally {
      lock.release();
    }

    await client.logout();
    res.json({ otps: results.reverse() });

  } catch (err) {
    if (client?.graveyard) await client.logout().catch(() => {});
    res.json({ error: err.message });
  }
});

app.listen(PORT, () => {
  console.log(`\n  OTP Fetcher running at: http://localhost:${PORT}\n`);
});
