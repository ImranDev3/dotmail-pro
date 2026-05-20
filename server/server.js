const express = require('express');
const { google } = require('googleapis');
const path = require('path');
const open = require('open');
const fs = require('fs');
const { promisify } = require('util');
const readFile = promisify(fs.readFile);
const writeFile = promisify(fs.writeFile);

const app = express();
const PORT = 3000;
const CRED_PATH = path.join(__dirname, 'credentials.json');
const TOKEN_PATH = path.join(__dirname, 'token.json');
const SCOPES = ['https://www.googleapis.com/auth/gmail.readonly'];

app.use(express.static(path.join(__dirname, 'public')));
app.use(express.json());

function loadCredentials() {
  try {
    const raw = fs.readFileSync(CRED_PATH, 'utf8');
    return JSON.parse(raw);
  } catch {
    return null;
  }
}

function getOAuth2Client(credentials) {
  const { client_secret, client_id, redirect_uris } = credentials.installed || credentials.web;
  return new google.auth.OAuth2(client_id, client_secret, redirect_uris[0]);
}

function getAuthUrl(oAuth2Client) {
  return oAuth2Client.generateAuthUrl({
    access_type: 'offline',
    scope: SCOPES,
  });
}

async function saveToken(token) {
  await writeFile(TOKEN_PATH, JSON.stringify(token));
}

async function loadToken() {
  try {
    const raw = await readFile(TOKEN_PATH, 'utf8');
    return JSON.parse(raw);
  } catch {
    return null;
  }
}

async function authenticate(oAuth2Client) {
  const savedToken = await loadToken();
  if (savedToken) {
    oAuth2Client.setCredentials(savedToken);
    return true;
  }
  return false;
}

async function fetchOTPs(auth) {
  const gmail = google.gmail({ version: 'v1', auth });

  const res = await gmail.users.messages.list({
    userId: 'me',
    maxResults: 20,
    q: 'subject:(otp OR "one time" OR "verification code" OR "2fa" OR "two factor" OR "security code" OR "login code" OR "verification") OR from:(noreply OR no-reply OR notification)',
  });

  const messages = res.data.messages || [];
  const results = [];

  for (const msg of messages) {
    const detail = await gmail.users.messages.get({
      userId: 'me',
      id: msg.id,
      format: 'full',
    });

    const payload = detail.data.payload;
    const headers = payload.headers || [];
    const subject = headers.find(h => h.name === 'From')?.value || '';
    const from = headers.find(h => h.name === 'From')?.value || '';
    const date = headers.find(h => h.name === 'Date')?.value || '';

    let body = '';
    if (payload.parts) {
      for (const part of payload.parts) {
        if (part.mimeType === 'text/plain' && part.body?.data) {
          body = Buffer.from(part.body.data, 'base64').toString('utf8');
          break;
        }
      }
    } else if (payload.body?.data) {
      body = Buffer.from(payload.body.data, 'base64').toString('utf8');
    }

    const otpPattern = /\b(\d{4,8})\b/g;
    const foundOTPs = [];
    let match;
    while ((match = otpPattern.exec(body)) !== null) {
      const num = match[1];
      if (num.length >= 4 && num.length <= 8) {
        foundOTPs.push(num);
      }
    }

    results.push({
      id: msg.id,
      from,
      date,
      snippet: detail.data.snippet || '',
      otps: foundOTPs,
      body: body.slice(0, 300),
    });
  }

  return results;
}

app.get('/api/auth-url', (req, res) => {
  const credentials = loadCredentials();
  if (!credentials) {
    return res.json({ error: 'credentials.json not found in server/' });
  }
  const oAuth2Client = getOAuth2Client(credentials);
  const url = getAuthUrl(oAuth2Client);
  res.json({ url });
});

app.get('/api/auth-callback', async (req, res) => {
  const { code } = req.query;
  if (!code) {
    return res.status(400).json({ error: 'No code provided' });
  }

  try {
    const credentials = loadCredentials();
    const oAuth2Client = getOAuth2Client(credentials);
    const { tokens } = await oAuth2Client.getToken(code);
    oAuth2Client.setCredentials(tokens);
    await saveToken(tokens);
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/otps', async (req, res) => {
  const credentials = loadCredentials();
  if (!credentials) {
    return res.json({ error: 'no_credentials' });
  }

  const oAuth2Client = getOAuth2Client(credentials);
  const authed = await authenticate(oAuth2Client);
  if (!authed) {
    return res.json({ error: 'not_authenticated' });
  }

  try {
    const otps = await fetchOTPs(oAuth2Client);
    res.json({ otps });
  } catch (err) {
    if (err.message?.includes('Token has expired') || err.message?.includes('invalid_grant')) {
      fs.unlinkSync(TOKEN_PATH);
      return res.json({ error: 'token_expired' });
    }
    res.status(500).json({ error: err.message });
  }
});

app.listen(PORT, () => {
  console.log(`\n  OTP Fetcher running at: http://localhost:${PORT}`);
  console.log(`  Open browser to access the dashboard.\n`);
});
