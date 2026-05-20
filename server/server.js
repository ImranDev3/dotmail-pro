const express = require('express');
const path = require('path');
const { ImapFlow } = require('imapflow');
const { simpleParser } = require('mailparser');
require('dotenv').config({ path: path.join(__dirname, '..', '.env') });

const app = express();
const PORT = 3000;
const POLL_TOKENS = new Map();

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
        or: [
          { subject: 'otp' },
          { subject: 'one time' },
          { subject: 'verification code' },
          { subject: '2fa' },
          { subject: 'security code' },
          { subject: 'login code' },
          { from: 'noreply' },
          { from: 'no-reply' },
          { from: 'notification' },
        ],
        answered: false,
      });

      const fetchIds = Array.isArray(search) ? search.slice(-20) : [];

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

function fetchOTPEmails(client, sinceDate) {
  return new Promise(async (resolve) => {
    try {
      const lock = await client.getMailboxLock('INBOX');
      const results = [];
      try {
        const criteria = {
          or: [
            { subject: 'otp' },
            { subject: 'one time' },
            { subject: 'verification code' },
            { subject: '2fa' },
            { subject: 'security code' },
            { subject: 'login code' },
            { from: 'noreply' },
            { from: 'no-reply' },
            { from: 'notification' },
          ],
          answered: false,
        };
        if (sinceDate) criteria.since = sinceDate;
        const search = await client.search(criteria);
        const fetchIds = Array.isArray(search) && search.length > 0 ? search.slice(-20) : [];
        for (const uid of fetchIds) {
          const msg = await client.fetchOne(uid, { envelope: true, source: true, uid: true });
          const parsed = await simpleParser(msg.source);
          const bodyText = parsed.text || parsed.html || '';
          const otps = extractOTPs(bodyText);
          results.push({
            id: uid.toString(), from: parsed.from?.text || 'Unknown',
            date: parsed.date?.toISOString() || '',
            subject: parsed.subject || '', otps,
            snippet: parsed.text?.slice(0, 200) || '',
          });
        }
      } finally { lock.release(); }
      resolve(results.reverse());
    } catch (e) { resolve({ error: e.message }); }
  });
}

app.get('/auth/google', (req, res) => {
  const { google } = require('googleapis');
  const oauth2Client = new google.auth.OAuth2(
    process.env.GOOGLE_CLIENT_ID,
    process.env.GOOGLE_CLIENT_SECRET,
    process.env.GOOGLE_REDIRECT_URI || `http://localhost:${PORT}/auth/google/callback`
  );
  const url = oauth2Client.generateAuthUrl({
    access_type: 'offline',
    prompt: 'consent',
    scope: ['https://mail.google.com/', 'https://www.googleapis.com/auth/userinfo.email'],
  });
  res.redirect(url);
});

app.get('/auth/google/callback', async (req, res) => {
  try {
    const { google } = require('googleapis');
    const oauth2Client = new google.auth.OAuth2(
      process.env.GOOGLE_CLIENT_ID,
      process.env.GOOGLE_CLIENT_SECRET,
      process.env.GOOGLE_REDIRECT_URI || `http://localhost:${PORT}/auth/google/callback`
    );
    const { tokens } = await oauth2Client.getToken(req.query.code);
    oauth2Client.setCredentials(tokens);
    const oauth2 = google.oauth2({ version: 'v2', auth: oauth2Client });
    const { data: { email } } = await oauth2.userinfo.get();
    const tokenId = Buffer.from(email + Date.now()).toString('base64').replace(/=/g, '');
    POLL_TOKENS.set(tokenId, { email, tokens });
    res.redirect(`/?oauth=success&token=${tokenId}`);
  } catch (e) {
    res.redirect(`/?oauth=error&msg=${encodeURIComponent(e.message)}`);
  }
});

app.post('/api/fetch-oauth', async (req, res) => {
  const { tokenId } = req.body;
  const session = POLL_TOKENS.get(tokenId);
  if (!session) return res.json({ error: 'Session expired. Sign in again.' });
  const { email, tokens } = session;
  if (tokens.expiry_date && tokens.expiry_date < Date.now()) {
    POLL_TOKENS.delete(tokenId);
    return res.json({ error: 'Token expired' });
  }
  const { google } = require('googleapis');
  const oauth2Client = new google.auth.OAuth2(
    process.env.GOOGLE_CLIENT_ID, process.env.GOOGLE_CLIENT_SECRET
  );
  oauth2Client.setCredentials(tokens);
  const accessToken = await oauth2Client.getAccessToken();
  const client = new ImapFlow({
    host: 'imap.gmail.com', port: 993, secure: true,
    auth: { user: email, accessToken: accessToken.token },
    logger: false,
  });
  try {
    await client.connect();
    const result = await fetchOTPEmails(client);
    res.json(result);
    await client.logout().catch(() => {});
  } catch (e) {
    if (client?.graveyard) await client.logout().catch(() => {});
    res.json({ error: e.message });
  }
});

app.listen(PORT, () => {
  console.log(`\n  OTP Fetcher running at: http://localhost:${PORT}\n`);
});
