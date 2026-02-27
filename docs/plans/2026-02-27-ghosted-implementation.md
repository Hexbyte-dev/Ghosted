# Ghosted Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Build an email mass-unsubscribe web app that scans Gmail, lets users review subscriptions, and unsubscribes + archives in bulk.

**Architecture:** Monorepo with `server/` (Express.js backend) and `client/` (React + Vite frontend). Google OAuth 2.0 handles both auth and Gmail API access. PostgreSQL stores users, scan results, and subscription history. Backend talks to Gmail API, frontend talks to backend.

**Tech Stack:** Node.js 22, Express.js, React 18, Vite, PostgreSQL, Google OAuth 2.0, Gmail API, JWT sessions, AES-256 token encryption.

**Repo:** github.com/Hexbyte-dev/Ghosted (monorepo — `server/` and `client/` directories)

**Deploy:** Backend + DB on Railway (new project, separate from Stash). Frontend on Netlify.

---

## Task 1: Backend Scaffolding

**Files:**
- Create: `server/package.json`
- Create: `server/server.js`
- Create: `server/.env.example`
- Create: `server/.gitignore`

**Step 1: Initialize the backend project**

```bash
cd ghosted
mkdir server
cd server
npm init -y
```

Update `server/package.json`:

```json
{
  "name": "ghosted-server",
  "version": "1.0.0",
  "description": "Backend for Ghosted — email mass-unsubscribe tool",
  "main": "server.js",
  "scripts": {
    "start": "node server.js",
    "dev": "node --watch server.js",
    "test": "node --test tests/**/*.test.js"
  },
  "engines": {
    "node": ">=22.0.0"
  }
}
```

**Step 2: Install dependencies**

```bash
npm install express cors dotenv pg jsonwebtoken googleapis
```

- `express` — web framework (same as Stash)
- `cors` — allow frontend to call backend from different domain
- `dotenv` — load .env config
- `pg` — PostgreSQL client (same as Stash)
- `jsonwebtoken` — JWT session tokens (same as Stash)
- `googleapis` — Google's official SDK for OAuth + Gmail API

**Step 3: Create server.js with health check**

```js
// server/server.js
require('dotenv').config();
const express = require('express');
const cors = require('cors');

const app = express();
const PORT = process.env.PORT || 3001;

app.use(cors({
  origin: process.env.CLIENT_URL || 'http://localhost:5173',
  credentials: true
}));
app.use(express.json());

// Health check
app.get('/health', (req, res) => {
  res.json({ status: 'ok', service: 'ghosted-server' });
});

app.listen(PORT, () => {
  console.log(`Ghosted server running on port ${PORT}`);
});

module.exports = app;
```

**Step 4: Create .env.example and .gitignore**

`.env.example`:
```
PORT=3001
CLIENT_URL=http://localhost:5173

# Google OAuth (from Google Cloud Console)
GOOGLE_CLIENT_ID=
GOOGLE_CLIENT_SECRET=
GOOGLE_REDIRECT_URI=http://localhost:3001/auth/google/callback

# PostgreSQL
DATABASE_URL=

# JWT
JWT_SECRET=

# Encryption key for refresh tokens (32 bytes hex)
ENCRYPTION_KEY=
```

`.gitignore`:
```
node_modules/
.env
```

**Step 5: Test the server starts**

```bash
cp .env.example .env
# Fill in JWT_SECRET with any random string for now
node server.js
# Expected: "Ghosted server running on port 3001"
# Visit http://localhost:3001/health -> {"status":"ok","service":"ghosted-server"}
```

**Step 6: Commit**

```bash
cd ..
git add server/
git commit -m "feat: scaffold backend with Express + health check"
```

---

## Task 2: Frontend Scaffolding

**Files:**
- Create: `client/` (entire Vite + React scaffold)
- Create: `client/src/App.jsx`
- Create: `client/src/api/client.js`

**Step 1: Create the Vite + React app**

```bash
cd ghosted
npm create vite@latest client -- --template react
cd client
npm install
```

This creates a full React project with Vite. Unlike Stash (which loads React from a CDN), this uses proper ES module imports and a build step.

**Step 2: Create the API client helper**

Create `client/src/api/client.js`:

```js
const API_URL = import.meta.env.VITE_API_URL || 'http://localhost:3001';

export async function api(path, options = {}) {
  const token = localStorage.getItem('ghosted_token');
  const res = await fetch(`${API_URL}${path}`, {
    ...options,
    headers: {
      'Content-Type': 'application/json',
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
      ...options.headers,
    },
  });
  if (!res.ok) {
    const error = await res.json().catch(() => ({ message: 'Request failed' }));
    throw new Error(error.message || `HTTP ${res.status}`);
  }
  return res.json();
}
```

**Step 3: Replace default App.jsx with Ghosted shell**

Replace `client/src/App.jsx`:

```jsx
import { useState } from 'react';

function App() {
  return (
    <div className="app">
      <h1>Ghosted</h1>
      <p>Ghost your subscriptions.</p>
    </div>
  );
}

export default App;
```

**Step 4: Test the frontend starts**

```bash
npm run dev
# Expected: Vite dev server at http://localhost:5173
# Shows "Ghosted" heading and tagline
```

**Step 5: Commit**

```bash
cd ..
git add client/
git commit -m "feat: scaffold frontend with Vite + React"
```

---

## Task 3: Google Cloud Console Setup

> This task is **manual configuration** in Google Cloud Console, not code.

**Step 1: Create a Google Cloud project**

1. Go to https://console.cloud.google.com
2. Click "New Project" → name it "Ghosted"
3. Select the new project

**Step 2: Enable the Gmail API**

1. Go to APIs & Services → Library
2. Search "Gmail API" → click Enable

**Step 3: Configure OAuth consent screen**

1. Go to APIs & Services → OAuth consent screen
2. Choose "External" user type
3. Fill in:
   - App name: Ghosted
   - User support email: your email
   - Developer contact: your email
4. Add scopes:
   - `https://www.googleapis.com/auth/gmail.readonly`
   - `https://www.googleapis.com/auth/gmail.modify`
   - `https://www.googleapis.com/auth/gmail.send`
5. Add your Gmail as a test user (testing mode = no Google verification needed)

**Step 4: Create OAuth credentials**

1. Go to APIs & Services → Credentials
2. Click "Create Credentials" → OAuth client ID
3. Application type: Web application
4. Name: Ghosted Server
5. Authorized redirect URIs: `http://localhost:3001/auth/google/callback`
6. Copy the Client ID and Client Secret

**Step 5: Update .env with credentials**

```bash
# In server/.env, fill in:
GOOGLE_CLIENT_ID=<your-client-id>
GOOGLE_CLIENT_SECRET=<your-client-secret>
GOOGLE_REDIRECT_URI=http://localhost:3001/auth/google/callback
JWT_SECRET=<generate-a-random-string>
ENCRYPTION_KEY=<generate-32-byte-hex-key>
```

Generate the encryption key:
```bash
node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
```

**Step 6: Commit .env.example update (no secrets)**

```bash
git add -A
git commit -m "docs: note Google Cloud setup steps in plan"
```

---

## Task 4: Database Schema + Connection

**Files:**
- Create: `server/db/pool.js`
- Create: `server/db/schema.sql`
- Create: `server/db/migrate.js`

**Step 1: Create the database connection pool**

`server/db/pool.js`:

```js
const { Pool } = require('pg');

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
});

module.exports = pool;
```

**Step 2: Write the schema**

`server/db/schema.sql`:

```sql
CREATE TABLE IF NOT EXISTS users (
  id SERIAL PRIMARY KEY,
  google_id VARCHAR(255) UNIQUE NOT NULL,
  email VARCHAR(255) NOT NULL,
  display_name VARCHAR(255),
  encrypted_refresh_token TEXT,
  created_at TIMESTAMP DEFAULT NOW(),
  updated_at TIMESTAMP DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS scans (
  id SERIAL PRIMARY KEY,
  user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
  status VARCHAR(50) DEFAULT 'pending',
  total_messages INTEGER DEFAULT 0,
  processed_messages INTEGER DEFAULT 0,
  created_at TIMESTAMP DEFAULT NOW(),
  completed_at TIMESTAMP
);

CREATE TABLE IF NOT EXISTS subscriptions (
  id SERIAL PRIMARY KEY,
  scan_id INTEGER REFERENCES scans(id) ON DELETE CASCADE,
  user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
  sender_name VARCHAR(255),
  sender_email VARCHAR(255) NOT NULL,
  email_count INTEGER DEFAULT 0,
  last_received_at TIMESTAMP,
  unsubscribe_method VARCHAR(50),
  unsubscribe_value TEXT,
  status VARCHAR(50) DEFAULT 'active',
  ghosted_at TIMESTAMP,
  UNIQUE(user_id, sender_email)
);

CREATE INDEX idx_subscriptions_user_id ON subscriptions(user_id);
CREATE INDEX idx_scans_user_id ON scans(user_id);
```

**Step 3: Create migration runner**

`server/db/migrate.js`:

```js
require('dotenv').config();
const fs = require('fs');
const path = require('path');
const pool = require('./pool');

async function migrate() {
  const sql = fs.readFileSync(path.join(__dirname, 'schema.sql'), 'utf8');
  try {
    await pool.query(sql);
    console.log('Database migration complete');
  } catch (err) {
    console.error('Migration failed:', err.message);
    process.exit(1);
  } finally {
    await pool.end();
  }
}

migrate();
```

Add to `server/package.json` scripts:
```json
"migrate": "node db/migrate.js"
```

**Step 4: Test migration against local or Railway PostgreSQL**

```bash
cd server
# Set DATABASE_URL in .env first
npm run migrate
# Expected: "Database migration complete"
```

**Step 5: Commit**

```bash
cd ..
git add server/db/ server/package.json
git commit -m "feat: add database schema and migration (users, scans, subscriptions)"
```

---

## Task 5: Token Encryption Service

**Files:**
- Create: `server/services/crypto.js`
- Create: `server/tests/crypto.test.js`

**Step 1: Write the failing test**

`server/tests/crypto.test.js`:

```js
const { describe, it } = require('node:test');
const assert = require('node:assert');
const { encrypt, decrypt } = require('../services/crypto');

describe('crypto service', () => {
  // Set a test key (32 bytes hex = 64 hex chars)
  before(() => {
    process.env.ENCRYPTION_KEY = 'a'.repeat(64);
  });

  it('encrypts and decrypts a string', () => {
    const original = 'my-secret-refresh-token-12345';
    const encrypted = encrypt(original);
    assert.notStrictEqual(encrypted, original);
    const decrypted = decrypt(encrypted);
    assert.strictEqual(decrypted, original);
  });

  it('produces different ciphertext each time (random IV)', () => {
    const original = 'same-input';
    const a = encrypt(original);
    const b = encrypt(original);
    assert.notStrictEqual(a, b);
  });
});
```

**Step 2: Run test to verify it fails**

```bash
cd server
node --test tests/crypto.test.js
# Expected: FAIL — cannot find module '../services/crypto'
```

**Step 3: Write the implementation**

`server/services/crypto.js`:

```js
const crypto = require('crypto');

const ALGORITHM = 'aes-256-cbc';

function getKey() {
  return Buffer.from(process.env.ENCRYPTION_KEY, 'hex');
}

function encrypt(text) {
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv(ALGORITHM, getKey(), iv);
  let encrypted = cipher.update(text, 'utf8', 'hex');
  encrypted += cipher.final('hex');
  return iv.toString('hex') + ':' + encrypted;
}

function decrypt(encryptedText) {
  const [ivHex, encrypted] = encryptedText.split(':');
  const iv = Buffer.from(ivHex, 'hex');
  const decipher = crypto.createDecipheriv(ALGORITHM, getKey(), iv);
  let decrypted = decipher.update(encrypted, 'hex', 'utf8');
  decrypted += decipher.final('utf8');
  return decrypted;
}

module.exports = { encrypt, decrypt };
```

**Step 4: Run test to verify it passes**

```bash
node --test tests/crypto.test.js
# Expected: 2 tests passed
```

**Step 5: Commit**

```bash
cd ..
git add server/services/crypto.js server/tests/crypto.test.js
git commit -m "feat: add AES-256 encryption for refresh tokens"
```

---

## Task 6: Google OAuth Routes

**Files:**
- Create: `server/routes/auth.js`
- Modify: `server/server.js` (mount auth routes)

**Step 1: Create auth routes**

`server/routes/auth.js`:

```js
const express = require('express');
const { google } = require('googleapis');
const jwt = require('jsonwebtoken');
const pool = require('../db/pool');
const { encrypt } = require('../services/crypto');

const router = express.Router();

function getOAuthClient() {
  return new google.auth.OAuth2(
    process.env.GOOGLE_CLIENT_ID,
    process.env.GOOGLE_CLIENT_SECRET,
    process.env.GOOGLE_REDIRECT_URI
  );
}

// Step 1: Redirect user to Google consent screen
router.get('/google', (req, res) => {
  const oauth2Client = getOAuthClient();
  const url = oauth2Client.generateAuthUrl({
    access_type: 'offline',     // gets a refresh token
    prompt: 'consent',          // always show consent (ensures refresh token)
    scope: [
      'https://www.googleapis.com/auth/gmail.readonly',
      'https://www.googleapis.com/auth/gmail.modify',
      'https://www.googleapis.com/auth/gmail.send',
      'https://www.googleapis.com/auth/userinfo.email',
      'https://www.googleapis.com/auth/userinfo.profile',
    ],
  });
  res.redirect(url);
});

// Step 2: Google sends user back here with an auth code
router.get('/google/callback', async (req, res) => {
  const { code } = req.query;
  if (!code) {
    return res.redirect(`${process.env.CLIENT_URL}?error=no_code`);
  }

  try {
    const oauth2Client = getOAuthClient();
    const { tokens } = await oauth2Client.getToken(code);
    oauth2Client.setCredentials(tokens);

    // Get user info from Google
    const oauth2 = google.oauth2({ version: 'v2', auth: oauth2Client });
    const { data: profile } = await oauth2.userinfo.get();

    // Upsert user in database
    const encryptedRefreshToken = tokens.refresh_token
      ? encrypt(tokens.refresh_token)
      : null;

    const result = await pool.query(
      `INSERT INTO users (google_id, email, display_name, encrypted_refresh_token)
       VALUES ($1, $2, $3, $4)
       ON CONFLICT (google_id) DO UPDATE SET
         email = $2,
         display_name = $3,
         encrypted_refresh_token = COALESCE($4, users.encrypted_refresh_token),
         updated_at = NOW()
       RETURNING id, email, display_name`,
      [profile.id, profile.email, profile.name, encryptedRefreshToken]
    );

    const user = result.rows[0];

    // Create JWT session token
    const token = jwt.sign(
      { userId: user.id, email: user.email },
      process.env.JWT_SECRET,
      { expiresIn: '7d' }
    );

    // Redirect to frontend with token
    res.redirect(`${process.env.CLIENT_URL}/dashboard?token=${token}`);
  } catch (err) {
    console.error('OAuth callback error:', err.message);
    res.redirect(`${process.env.CLIENT_URL}?error=auth_failed`);
  }
});

module.exports = router;
```

**Step 2: Mount routes in server.js**

Add to `server/server.js` before the `app.listen`:

```js
const authRoutes = require('./routes/auth');
app.use('/auth', authRoutes);
```

**Step 3: Test the OAuth flow manually**

```bash
cd server && node server.js
# Visit http://localhost:3001/auth/google
# Should redirect to Google consent screen
# After consent, redirects to http://localhost:5173/dashboard?token=...
```

**Step 4: Commit**

```bash
cd ..
git add server/routes/auth.js server/server.js
git commit -m "feat: add Google OAuth login with JWT session"
```

---

## Task 7: Auth Middleware

**Files:**
- Create: `server/middleware/requireAuth.js`
- Create: `server/tests/requireAuth.test.js`

**Step 1: Write the failing test**

`server/tests/requireAuth.test.js`:

```js
const { describe, it, beforeEach } = require('node:test');
const assert = require('node:assert');
const jwt = require('jsonwebtoken');

// Set env before requiring middleware
process.env.JWT_SECRET = 'test-secret';
const requireAuth = require('../middleware/requireAuth');

describe('requireAuth middleware', () => {
  let mockReq, mockRes, nextCalled;

  beforeEach(() => {
    nextCalled = false;
    mockRes = {
      statusCode: null,
      body: null,
      status(code) { this.statusCode = code; return this; },
      json(data) { this.body = data; },
    };
  });

  it('rejects requests with no token', () => {
    mockReq = { headers: {} };
    requireAuth(mockReq, mockRes, () => { nextCalled = true; });
    assert.strictEqual(mockRes.statusCode, 401);
    assert.strictEqual(nextCalled, false);
  });

  it('rejects requests with invalid token', () => {
    mockReq = { headers: { authorization: 'Bearer bad-token' } };
    requireAuth(mockReq, mockRes, () => { nextCalled = true; });
    assert.strictEqual(mockRes.statusCode, 401);
    assert.strictEqual(nextCalled, false);
  });

  it('passes valid tokens and sets req.user', () => {
    const token = jwt.sign({ userId: 1, email: 'test@test.com' }, 'test-secret');
    mockReq = { headers: { authorization: `Bearer ${token}` } };
    requireAuth(mockReq, mockRes, () => { nextCalled = true; });
    assert.strictEqual(nextCalled, true);
    assert.strictEqual(mockReq.user.userId, 1);
  });
});
```

**Step 2: Run test to verify it fails**

```bash
cd server
node --test tests/requireAuth.test.js
# Expected: FAIL — cannot find module
```

**Step 3: Write the implementation**

`server/middleware/requireAuth.js`:

```js
const jwt = require('jsonwebtoken');

function requireAuth(req, res, next) {
  const header = req.headers.authorization;
  if (!header || !header.startsWith('Bearer ')) {
    return res.status(401).json({ message: 'No token provided' });
  }

  const token = header.split(' ')[1];
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded;
    next();
  } catch (err) {
    return res.status(401).json({ message: 'Invalid token' });
  }
}

module.exports = requireAuth;
```

**Step 4: Run test to verify it passes**

```bash
node --test tests/requireAuth.test.js
# Expected: 3 tests passed
```

**Step 5: Commit**

```bash
cd ..
git add server/middleware/requireAuth.js server/tests/requireAuth.test.js
git commit -m "feat: add JWT auth middleware with tests"
```

---

## Task 8: Gmail Scan Service

**Files:**
- Create: `server/services/gmail.js`

This is the core engine — it connects to Gmail API, scans email headers, and extracts subscription info.

**Step 1: Create the Gmail service**

`server/services/gmail.js`:

```js
const { google } = require('googleapis');
const { decrypt } = require('./crypto');
const pool = require('../db/pool');

function getAuthenticatedClient(refreshToken) {
  const oauth2Client = new google.auth.OAuth2(
    process.env.GOOGLE_CLIENT_ID,
    process.env.GOOGLE_CLIENT_SECRET,
    process.env.GOOGLE_REDIRECT_URI
  );
  oauth2Client.setCredentials({ refresh_token: refreshToken });
  return oauth2Client;
}

// Get a fresh Gmail API client for a user
async function getGmailClient(userId) {
  const result = await pool.query(
    'SELECT encrypted_refresh_token FROM users WHERE id = $1',
    [userId]
  );
  if (!result.rows[0]?.encrypted_refresh_token) {
    throw new Error('No refresh token found — user must re-authenticate');
  }
  const refreshToken = decrypt(result.rows[0].encrypted_refresh_token);
  const auth = getAuthenticatedClient(refreshToken);
  return google.gmail({ version: 'v1', auth });
}

// Scan emails from last 6 months, find subscriptions
async function scanForSubscriptions(userId, scanId) {
  const gmail = await getGmailClient(userId);

  // Calculate 6 months ago
  const sixMonthsAgo = new Date();
  sixMonthsAgo.setMonth(sixMonthsAgo.getMonth() - 6);
  const afterDate = sixMonthsAgo.toISOString().split('T')[0].replace(/-/g, '/');

  // Search for emails with List-Unsubscribe header
  // Gmail query: after:YYYY/MM/DD + has unsubscribe-related content
  const query = `after:${afterDate}`;

  const subscriptions = new Map(); // key: sender email, value: subscription info
  let pageToken = null;
  let totalProcessed = 0;

  do {
    // List messages (returns IDs only)
    const listRes = await gmail.users.messages.list({
      userId: 'me',
      q: query,
      maxResults: 100,
      pageToken,
    });

    const messages = listRes.data.messages || [];

    // Update scan progress
    await pool.query(
      'UPDATE scans SET total_messages = total_messages + $1 WHERE id = $2',
      [messages.length, scanId]
    );

    // Fetch headers for each message (batched)
    for (const msg of messages) {
      try {
        const detail = await gmail.users.messages.get({
          userId: 'me',
          id: msg.id,
          format: 'metadata',
          metadataHeaders: ['From', 'List-Unsubscribe', 'List-Unsubscribe-Post', 'Date'],
        });

        const headers = detail.data.payload.headers || [];
        const getHeader = (name) =>
          headers.find(h => h.name.toLowerCase() === name.toLowerCase())?.value;

        const listUnsub = getHeader('List-Unsubscribe');
        if (!listUnsub) continue; // Skip non-subscription emails

        const from = getHeader('From') || 'Unknown';
        const date = getHeader('Date');
        const hasOneClick = !!getHeader('List-Unsubscribe-Post');

        // Parse sender email from "Name <email>" format
        const emailMatch = from.match(/<([^>]+)>/);
        const senderEmail = emailMatch ? emailMatch[1] : from;
        const senderName = emailMatch ? from.replace(/<[^>]+>/, '').trim() : from;

        // Parse unsubscribe value
        let unsubMethod = 'none';
        let unsubValue = '';

        if (hasOneClick) {
          // Extract URL from List-Unsubscribe for one-click POST
          const urlMatch = listUnsub.match(/<(https?:\/\/[^>]+)>/);
          unsubMethod = 'one-click';
          unsubValue = urlMatch ? urlMatch[1] : '';
        } else if (listUnsub.includes('https://') || listUnsub.includes('http://')) {
          const urlMatch = listUnsub.match(/<(https?:\/\/[^>]+)>/);
          unsubMethod = 'url';
          unsubValue = urlMatch ? urlMatch[1] : '';
        } else if (listUnsub.includes('mailto:')) {
          const mailMatch = listUnsub.match(/<mailto:([^>]+)>/);
          unsubMethod = 'mailto';
          unsubValue = mailMatch ? mailMatch[1] : '';
        }

        // Aggregate by sender
        if (subscriptions.has(senderEmail)) {
          const existing = subscriptions.get(senderEmail);
          existing.emailCount += 1;
          if (date && new Date(date) > new Date(existing.lastReceivedAt)) {
            existing.lastReceivedAt = date;
          }
        } else {
          subscriptions.set(senderEmail, {
            senderName: senderName.replace(/"/g, ''),
            senderEmail,
            emailCount: 1,
            lastReceivedAt: date || null,
            unsubscribeMethod: unsubMethod,
            unsubscribeValue: unsubValue,
          });
        }

        totalProcessed++;
        if (totalProcessed % 50 === 0) {
          await pool.query(
            'UPDATE scans SET processed_messages = $1 WHERE id = $2',
            [totalProcessed, scanId]
          );
        }
      } catch (err) {
        // Skip individual message errors, continue scanning
        console.error(`Error processing message ${msg.id}:`, err.message);
      }
    }

    pageToken = listRes.data.nextPageToken;
  } while (pageToken);

  // Save all subscriptions to database
  for (const sub of subscriptions.values()) {
    await pool.query(
      `INSERT INTO subscriptions (scan_id, user_id, sender_name, sender_email, email_count, last_received_at, unsubscribe_method, unsubscribe_value, status)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
       ON CONFLICT (user_id, sender_email) DO UPDATE SET
         email_count = $5,
         last_received_at = $6,
         unsubscribe_method = $7,
         unsubscribe_value = $8,
         scan_id = $1`,
      [scanId, userId, sub.senderName, sub.senderEmail, sub.emailCount,
       sub.lastReceivedAt, sub.unsubscribeMethod, sub.unsubscribeValue,
       sub.unsubscribeMethod === 'none' ? 'no-unsub' : 'active']
    );
  }

  // Mark scan complete
  await pool.query(
    'UPDATE scans SET status = $1, processed_messages = $2, completed_at = NOW() WHERE id = $3',
    ['completed', totalProcessed, scanId]
  );

  return { totalProcessed, subscriptionCount: subscriptions.size };
}

module.exports = { getGmailClient, scanForSubscriptions };
```

**Step 2: Test with a manual script** (real Gmail API, not unit-testable without mocking)

```bash
cd server
node -e "
  require('dotenv').config();
  const { scanForSubscriptions } = require('./services/gmail');
  // Will test after auth flow works end-to-end
  console.log('Gmail service loaded OK');
"
# Expected: "Gmail service loaded OK" (no import errors)
```

**Step 3: Commit**

```bash
cd ..
git add server/services/gmail.js
git commit -m "feat: add Gmail scan service — finds subscriptions via List-Unsubscribe headers"
```

---

## Task 9: Scan API Routes

**Files:**
- Create: `server/routes/scan.js`
- Modify: `server/server.js` (mount scan routes)

**Step 1: Create scan routes**

`server/routes/scan.js`:

```js
const express = require('express');
const requireAuth = require('../middleware/requireAuth');
const pool = require('../db/pool');
const { scanForSubscriptions } = require('../services/gmail');

const router = express.Router();

// Start a new scan
router.post('/start', requireAuth, async (req, res) => {
  try {
    // Create scan record
    const result = await pool.query(
      'INSERT INTO scans (user_id, status) VALUES ($1, $2) RETURNING id',
      [req.user.userId, 'scanning']
    );
    const scanId = result.rows[0].id;

    // Run scan in background (don't make the user wait for the response)
    scanForSubscriptions(req.user.userId, scanId).catch(err => {
      console.error('Scan error:', err.message);
      pool.query('UPDATE scans SET status = $1 WHERE id = $2', ['failed', scanId]);
    });

    res.json({ scanId, status: 'scanning' });
  } catch (err) {
    console.error('Start scan error:', err.message);
    res.status(500).json({ message: 'Failed to start scan' });
  }
});

// Check scan progress
router.get('/status/:scanId', requireAuth, async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT id, status, total_messages, processed_messages, created_at, completed_at FROM scans WHERE id = $1 AND user_id = $2',
      [req.params.scanId, req.user.userId]
    );
    if (!result.rows[0]) {
      return res.status(404).json({ message: 'Scan not found' });
    }
    res.json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ message: 'Failed to get scan status' });
  }
});

// Get subscriptions from latest scan
router.get('/subscriptions', requireAuth, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT id, sender_name, sender_email, email_count, last_received_at, unsubscribe_method, status
       FROM subscriptions
       WHERE user_id = $1
       ORDER BY email_count DESC`,
      [req.user.userId]
    );
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ message: 'Failed to get subscriptions' });
  }
});

module.exports = router;
```

**Step 2: Mount in server.js**

Add to `server/server.js`:

```js
const scanRoutes = require('./routes/scan');
app.use('/scan', scanRoutes);
```

**Step 3: Commit**

```bash
git add server/routes/scan.js server/server.js
git commit -m "feat: add scan API routes (start, status, subscriptions)"
```

---

## Task 10: Unsubscribe + Archive Service

**Files:**
- Create: `server/services/unsubscriber.js`

**Step 1: Create the unsubscribe service**

`server/services/unsubscriber.js`:

```js
const { getGmailClient } = require('./gmail');
const pool = require('../db/pool');

// Perform unsubscribe based on method
async function unsubscribeFromSender(gmail, subscription) {
  const { unsubscribe_method, unsubscribe_value } = subscription;

  switch (unsubscribe_method) {
    case 'one-click': {
      // RFC 8058: POST to URL with List-Unsubscribe=One-Click-Unsubscribe
      const res = await fetch(unsubscribe_value, {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: 'List-Unsubscribe=One-Click-Unsubscribe',
      });
      return { success: res.ok, method: 'one-click' };
    }

    case 'url': {
      // Visit the unsubscribe URL
      const res = await fetch(unsubscribe_value, {
        method: 'GET',
        redirect: 'follow',
      });
      return { success: res.ok, method: 'url' };
    }

    case 'mailto': {
      // Send an email to the unsubscribe address
      const [address, params] = unsubscribe_value.split('?');
      let subject = 'Unsubscribe';
      if (params) {
        const parsed = new URLSearchParams(params);
        subject = parsed.get('subject') || 'Unsubscribe';
      }

      // Use Gmail API to send the unsubscribe email
      const raw = Buffer.from(
        `To: ${address}\r\nSubject: ${subject}\r\n\r\nUnsubscribe`
      ).toString('base64url');

      await gmail.users.messages.send({
        userId: 'me',
        requestBody: { raw },
      });
      return { success: true, method: 'mailto' };
    }

    default:
      return { success: false, method: 'none' };
  }
}

// Archive all emails from a sender
async function archiveEmailsFromSender(gmail, senderEmail) {
  let archived = 0;
  let pageToken = null;

  do {
    const listRes = await gmail.users.messages.list({
      userId: 'me',
      q: `from:${senderEmail} in:inbox`,
      maxResults: 100,
      pageToken,
    });

    const messages = listRes.data.messages || [];
    for (const msg of messages) {
      await gmail.users.messages.modify({
        userId: 'me',
        id: msg.id,
        requestBody: { removeLabelIds: ['INBOX'] },
      });
      archived++;
    }

    pageToken = listRes.data.nextPageToken;
  } while (pageToken);

  return archived;
}

// Ghost a list of subscriptions (unsubscribe + archive)
async function ghostSubscriptions(userId, subscriptionIds) {
  const gmail = await getGmailClient(userId);
  const results = [];

  for (const subId of subscriptionIds) {
    const subResult = await pool.query(
      'SELECT * FROM subscriptions WHERE id = $1 AND user_id = $2',
      [subId, userId]
    );
    const sub = subResult.rows[0];
    if (!sub) continue;

    try {
      // Step 1: Unsubscribe
      const unsubResult = await unsubscribeFromSender(gmail, sub);

      // Step 2: Archive old emails
      const archivedCount = await archiveEmailsFromSender(gmail, sub.sender_email);

      // Step 3: Update database
      await pool.query(
        'UPDATE subscriptions SET status = $1, ghosted_at = NOW() WHERE id = $2',
        ['ghosted', sub.id]
      );

      results.push({
        id: sub.id,
        senderEmail: sub.sender_email,
        senderName: sub.sender_name,
        unsubscribed: unsubResult.success,
        method: unsubResult.method,
        archived: archivedCount,
      });
    } catch (err) {
      console.error(`Failed to ghost ${sub.sender_email}:`, err.message);
      results.push({
        id: sub.id,
        senderEmail: sub.sender_email,
        senderName: sub.sender_name,
        unsubscribed: false,
        error: err.message,
        archived: 0,
      });
    }
  }

  return results;
}

module.exports = { ghostSubscriptions };
```

**Step 2: Commit**

```bash
git add server/services/unsubscriber.js
git commit -m "feat: add unsubscribe + archive service (one-click, URL, mailto)"
```

---

## Task 11: Unsubscribe API Route

**Files:**
- Create: `server/routes/ghost.js`
- Modify: `server/server.js` (mount ghost routes)

**Step 1: Create ghost route**

`server/routes/ghost.js`:

```js
const express = require('express');
const requireAuth = require('../middleware/requireAuth');
const { ghostSubscriptions } = require('../services/unsubscriber');

const router = express.Router();

// Ghost selected subscriptions
router.post('/', requireAuth, async (req, res) => {
  const { subscriptionIds } = req.body;

  if (!Array.isArray(subscriptionIds) || subscriptionIds.length === 0) {
    return res.status(400).json({ message: 'No subscriptions selected' });
  }

  try {
    const results = await ghostSubscriptions(req.user.userId, subscriptionIds);
    const ghosted = results.filter(r => r.unsubscribed).length;
    const failed = results.filter(r => !r.unsubscribed).length;
    const totalArchived = results.reduce((sum, r) => sum + (r.archived || 0), 0);

    res.json({
      results,
      summary: { ghosted, failed, totalArchived },
    });
  } catch (err) {
    console.error('Ghost error:', err.message);
    res.status(500).json({ message: 'Failed to ghost subscriptions' });
  }
});

module.exports = router;
```

**Step 2: Mount in server.js**

Add to `server/server.js`:

```js
const ghostRoutes = require('./routes/ghost');
app.use('/ghost', ghostRoutes);
```

**Step 3: Commit**

```bash
git add server/routes/ghost.js server/server.js
git commit -m "feat: add ghost API route (unsubscribe + archive selected)"
```

---

## Task 12: Frontend — Landing Page

**Files:**
- Create: `client/src/pages/Landing.jsx`
- Modify: `client/src/App.jsx`
- Create: `client/src/App.css`

**Step 1: Create the landing page component**

`client/src/pages/Landing.jsx`:

```jsx
export default function Landing() {
  const handleSignIn = () => {
    window.location.href = `${import.meta.env.VITE_API_URL || 'http://localhost:3001'}/auth/google`;
  };

  return (
    <div className="landing">
      <div className="landing-hero">
        <h1>Ghosted</h1>
        <p className="tagline">Ghost your subscriptions.</p>
        <p className="description">
          Tired of spam? Ghosted scans your Gmail, finds every subscription,
          and lets you mass-unsubscribe with one click. Your old emails get
          archived, not deleted.
        </p>
        <button className="btn-primary" onClick={handleSignIn}>
          Sign in with Google
        </button>
      </div>
    </div>
  );
}
```

**Step 2: Create basic styles**

`client/src/App.css`:

```css
* { box-sizing: border-box; margin: 0; padding: 0; }

body {
  font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
  background: #0a0a0a;
  color: #e0e0e0;
  min-height: 100vh;
}

.app { max-width: 800px; margin: 0 auto; padding: 2rem; }

.landing { display: flex; justify-content: center; align-items: center; min-height: 80vh; }
.landing-hero { text-align: center; }
.landing h1 { font-size: 3rem; margin-bottom: 0.5rem; }
.tagline { font-size: 1.2rem; color: #888; margin-bottom: 1.5rem; }
.description { max-width: 500px; margin: 0 auto 2rem; line-height: 1.6; color: #aaa; }

.btn-primary {
  background: #7c3aed;
  color: white;
  border: none;
  padding: 0.75rem 2rem;
  border-radius: 8px;
  font-size: 1rem;
  cursor: pointer;
  transition: background 0.2s;
}
.btn-primary:hover { background: #6d28d9; }

.btn-ghost {
  background: #7c3aed;
  color: white;
  border: none;
  padding: 0.75rem 2rem;
  border-radius: 8px;
  font-size: 1.1rem;
  cursor: pointer;
  display: flex;
  align-items: center;
  gap: 0.5rem;
  margin: 1rem auto;
}
.btn-ghost:hover { background: #6d28d9; }

.subscription-list { margin-top: 1.5rem; }
.sub-item {
  display: flex;
  align-items: center;
  gap: 1rem;
  padding: 0.75rem 1rem;
  border-bottom: 1px solid #222;
}
.sub-item label { flex: 1; cursor: pointer; }
.sub-name { font-weight: 600; }
.sub-meta { font-size: 0.85rem; color: #888; }
.sub-count { color: #7c3aed; font-weight: 600; min-width: 3rem; text-align: right; }

.toggle-all {
  background: none;
  border: 1px solid #444;
  color: #aaa;
  padding: 0.5rem 1rem;
  border-radius: 6px;
  cursor: pointer;
  margin-bottom: 1rem;
}

.progress-bar {
  width: 100%;
  height: 8px;
  background: #222;
  border-radius: 4px;
  overflow: hidden;
  margin: 1rem 0;
}
.progress-fill {
  height: 100%;
  background: #7c3aed;
  transition: width 0.3s;
}

.summary { text-align: center; margin-top: 2rem; }
.summary h2 { margin-bottom: 1rem; }
.summary-stat { font-size: 2rem; font-weight: 700; color: #7c3aed; }

.no-unsub { opacity: 0.5; }
.no-unsub .sub-meta { color: #f59e0b; }

.error { color: #ef4444; text-align: center; margin: 1rem 0; }
.loading { text-align: center; color: #888; margin: 2rem 0; }
```

**Step 3: Update App.jsx with routing**

```bash
cd client && npm install react-router-dom
```

Replace `client/src/App.jsx`:

```jsx
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import Landing from './pages/Landing';
import './App.css';

function App() {
  return (
    <BrowserRouter>
      <div className="app">
        <Routes>
          <Route path="/" element={<Landing />} />
        </Routes>
      </div>
    </BrowserRouter>
  );
}

export default App;
```

**Step 4: Test**

```bash
npm run dev
# Visit http://localhost:5173 — should show landing page
```

**Step 5: Commit**

```bash
cd ..
git add client/
git commit -m "feat: add landing page with sign-in button"
```

---

## Task 13: Frontend — Dashboard (Scan + Review + Ghost)

**Files:**
- Create: `client/src/pages/Dashboard.jsx`
- Modify: `client/src/App.jsx` (add dashboard route)

**Step 1: Create the dashboard page**

This is the main page after auth — handles scan, review, and ghost in one component.

`client/src/pages/Dashboard.jsx`:

```jsx
import { useState, useEffect } from 'react';
import { useSearchParams } from 'react-router-dom';
import { api } from '../api/client';

export default function Dashboard() {
  const [searchParams] = useSearchParams();
  const [subscriptions, setSubscriptions] = useState([]);
  const [selected, setSelected] = useState(new Set());
  const [scanning, setScanning] = useState(false);
  const [scanProgress, setScanProgress] = useState(null);
  const [ghosting, setGhosting] = useState(false);
  const [results, setResults] = useState(null);
  const [error, setError] = useState(null);

  // Grab token from URL on first load (sent by OAuth callback)
  useEffect(() => {
    const token = searchParams.get('token');
    if (token) {
      localStorage.setItem('ghosted_token', token);
      window.history.replaceState({}, '', '/dashboard');
    }
  }, [searchParams]);

  // Start scanning
  const startScan = async () => {
    setScanning(true);
    setError(null);
    try {
      const { scanId } = await api('/scan/start', { method: 'POST' });

      // Poll for progress
      const poll = setInterval(async () => {
        const status = await api(`/scan/status/${scanId}`);
        setScanProgress(status);
        if (status.status === 'completed' || status.status === 'failed') {
          clearInterval(poll);
          setScanning(false);
          if (status.status === 'completed') {
            const subs = await api('/scan/subscriptions');
            setSubscriptions(subs);
          } else {
            setError('Scan failed. Please try again.');
          }
        }
      }, 2000);
    } catch (err) {
      setScanning(false);
      setError(err.message);
    }
  };

  // Toggle subscription selection
  const toggleSub = (id) => {
    setSelected(prev => {
      const next = new Set(prev);
      next.has(id) ? next.delete(id) : next.add(id);
      return next;
    });
  };

  // Select/deselect all (only ghostable ones)
  const toggleAll = () => {
    const ghostable = subscriptions.filter(s => s.status !== 'no-unsub');
    if (selected.size === ghostable.length) {
      setSelected(new Set());
    } else {
      setSelected(new Set(ghostable.map(s => s.id)));
    }
  };

  // Ghost selected subscriptions
  const ghostSelected = async () => {
    setGhosting(true);
    setError(null);
    try {
      const data = await api('/ghost', {
        method: 'POST',
        body: JSON.stringify({ subscriptionIds: Array.from(selected) }),
      });
      setResults(data.summary);
      setSelected(new Set());
      // Refresh subscription list
      const subs = await api('/scan/subscriptions');
      setSubscriptions(subs);
    } catch (err) {
      setError(err.message);
    } finally {
      setGhosting(false);
    }
  };

  // Results summary screen
  if (results) {
    return (
      <div className="summary">
        <h2>Done!</h2>
        <p><span className="summary-stat">{results.ghosted}</span> subscriptions ghosted</p>
        <p><span className="summary-stat">{results.totalArchived}</span> emails archived</p>
        {results.failed > 0 && <p>{results.failed} failed (may need manual unsubscribe)</p>}
        <button className="btn-primary" onClick={() => setResults(null)} style={{ marginTop: '1.5rem' }}>
          Back to list
        </button>
      </div>
    );
  }

  // Scan in progress
  if (scanning) {
    const progress = scanProgress
      ? Math.round((scanProgress.processed_messages / Math.max(scanProgress.total_messages, 1)) * 100)
      : 0;
    return (
      <div className="loading">
        <h2>Scanning your email...</h2>
        <p>Checking the last 6 months for subscriptions</p>
        <div className="progress-bar">
          <div className="progress-fill" style={{ width: `${progress}%` }} />
        </div>
        <p>{scanProgress?.processed_messages || 0} emails processed</p>
      </div>
    );
  }

  // No subscriptions yet — show scan button
  if (subscriptions.length === 0) {
    return (
      <div style={{ textAlign: 'center', marginTop: '4rem' }}>
        <h2>Ready to scan</h2>
        <p style={{ color: '#888', margin: '1rem 0' }}>
          We'll check your last 6 months of email for subscriptions.
        </p>
        <button className="btn-primary" onClick={startScan}>Scan my email</button>
        {error && <p className="error">{error}</p>}
      </div>
    );
  }

  // Subscription review list
  const ghostable = subscriptions.filter(s => s.status === 'active');
  const noUnsub = subscriptions.filter(s => s.status === 'no-unsub');
  const alreadyGhosted = subscriptions.filter(s => s.status === 'ghosted');

  return (
    <div>
      <h2>Your Subscriptions</h2>
      <p style={{ color: '#888', marginBottom: '1rem' }}>
        {ghostable.length} active &middot; {alreadyGhosted.length} ghosted &middot; {noUnsub.length} no unsubscribe option
      </p>

      {ghostable.length > 0 && (
        <>
          <button className="toggle-all" onClick={toggleAll}>
            {selected.size === ghostable.length ? 'Deselect All' : 'Select All'}
          </button>

          <div className="subscription-list">
            {ghostable.map(sub => (
              <div key={sub.id} className="sub-item">
                <input
                  type="checkbox"
                  checked={selected.has(sub.id)}
                  onChange={() => toggleSub(sub.id)}
                />
                <label onClick={() => toggleSub(sub.id)}>
                  <div className="sub-name">{sub.sender_name || sub.sender_email}</div>
                  <div className="sub-meta">{sub.sender_email}</div>
                </label>
                <div className="sub-count">{sub.email_count}</div>
              </div>
            ))}
          </div>

          {selected.size > 0 && (
            <button className="btn-ghost" onClick={ghostSelected} disabled={ghosting}>
              {ghosting ? 'Ghosting...' : `Ghost them (${selected.size})`}
            </button>
          )}
        </>
      )}

      {noUnsub.length > 0 && (
        <>
          <h3 style={{ marginTop: '2rem', color: '#f59e0b' }}>No unsubscribe option</h3>
          <p style={{ color: '#888', fontSize: '0.9rem', marginBottom: '0.5rem' }}>
            Mark these as spam in Gmail manually.
          </p>
          <div className="subscription-list">
            {noUnsub.map(sub => (
              <div key={sub.id} className="sub-item no-unsub">
                <label>
                  <div className="sub-name">{sub.sender_name || sub.sender_email}</div>
                  <div className="sub-meta">No unsubscribe header found</div>
                </label>
                <div className="sub-count">{sub.email_count}</div>
              </div>
            ))}
          </div>
        </>
      )}

      {error && <p className="error">{error}</p>}
    </div>
  );
}
```

**Step 2: Add dashboard route to App.jsx**

Update `client/src/App.jsx`:

```jsx
import { BrowserRouter, Routes, Route } from 'react-router-dom';
import Landing from './pages/Landing';
import Dashboard from './pages/Dashboard';
import './App.css';

function App() {
  return (
    <BrowserRouter>
      <div className="app">
        <Routes>
          <Route path="/" element={<Landing />} />
          <Route path="/dashboard" element={<Dashboard />} />
        </Routes>
      </div>
    </BrowserRouter>
  );
}

export default App;
```

**Step 3: Test the frontend**

```bash
cd client && npm run dev
# Visit http://localhost:5173 — landing page
# Visit http://localhost:5173/dashboard — shows "Ready to scan"
```

**Step 4: Commit**

```bash
cd ..
git add client/
git commit -m "feat: add dashboard with scan, review, and ghost UI"
```

---

## Task 14: End-to-End Manual Test

**No new files.** This task is about running the full flow locally.

**Step 1: Start backend**

```bash
cd server
# Ensure .env has all values filled in (Google creds, DATABASE_URL, JWT_SECRET, ENCRYPTION_KEY)
npm run migrate
node server.js
```

**Step 2: Start frontend**

```bash
cd client
npm run dev
```

**Step 3: Walk through the flow**

1. Visit `http://localhost:5173`
2. Click "Sign in with Google"
3. Complete Google OAuth consent
4. Should redirect to `/dashboard?token=...`
5. Click "Scan my email"
6. Wait for scan to complete (progress bar)
7. Review subscription list
8. Select some subscriptions
9. Click "Ghost them"
10. Verify summary shows counts

**Step 4: Fix any issues found, commit**

```bash
git add -A
git commit -m "fix: address issues from end-to-end testing"
```

---

## Task 15: Deploy Backend to Railway

**Step 1: Create new Railway project**

1. Go to https://railway.app/new
2. Create new project named "Ghosted"
3. Add PostgreSQL plugin to the project
4. Add new service → Deploy from GitHub repo (Hexbyte-dev/Ghosted)
5. Set root directory to `server`

**Step 2: Set environment variables in Railway**

In the Railway service settings, add:
- `PORT` — Railway sets this automatically
- `CLIENT_URL` — your Netlify URL (set after Netlify deploy, or placeholder)
- `GOOGLE_CLIENT_ID` — from Google Cloud Console
- `GOOGLE_CLIENT_SECRET` — from Google Cloud Console
- `GOOGLE_REDIRECT_URI` — `https://<your-railway-url>/auth/google/callback`
- `DATABASE_URL` — Railway provides this automatically from the PostgreSQL plugin
- `JWT_SECRET` — same as local
- `ENCRYPTION_KEY` — same as local
- `NODE_ENV` — `production`

**Step 3: Run migration**

```bash
# In Railway shell or via railway CLI:
npm run migrate
```

**Step 4: Update Google Cloud Console**

Add the Railway callback URL to authorized redirect URIs:
`https://<your-railway-url>/auth/google/callback`

**Step 5: Verify deployment**

Visit `https://<your-railway-url>/health` — should return `{"status":"ok"}`

---

## Task 16: Deploy Frontend to Netlify

**Step 1: Create Netlify site**

1. Go to https://app.netlify.com
2. Add new site → Import from GitHub → Hexbyte-dev/Ghosted
3. Set:
   - Base directory: `client`
   - Build command: `npm run build`
   - Publish directory: `client/dist`

**Step 2: Set environment variables**

- `VITE_API_URL` — your Railway backend URL (e.g., `https://ghosted-server-production.up.railway.app`)

**Step 3: Add redirect rule for SPA routing**

Create `client/public/_redirects`:

```
/*    /index.html   200
```

This tells Netlify to serve `index.html` for all routes (needed for React Router).

**Step 4: Commit and push**

```bash
git add client/public/_redirects
git commit -m "feat: add Netlify SPA redirect rule"
git push
```

**Step 5: Update environment variables**

- In Railway: set `CLIENT_URL` to your Netlify URL
- In Google Cloud Console: add Netlify URL to authorized JavaScript origins

**Step 6: Test the live deployment**

Visit your Netlify URL and run through the full flow.

---

## Summary of All Tasks

| # | Task | Type |
|---|------|------|
| 1 | Backend scaffolding | Setup |
| 2 | Frontend scaffolding (Vite + React) | Setup |
| 3 | Google Cloud Console setup | Manual config |
| 4 | Database schema + connection | Backend |
| 5 | Token encryption service | Backend + TDD |
| 6 | Google OAuth routes | Backend |
| 7 | Auth middleware | Backend + TDD |
| 8 | Gmail scan service | Backend |
| 9 | Scan API routes | Backend |
| 10 | Unsubscribe + archive service | Backend |
| 11 | Unsubscribe API route | Backend |
| 12 | Landing page | Frontend |
| 13 | Dashboard (scan + review + ghost) | Frontend |
| 14 | End-to-end manual test | Testing |
| 15 | Deploy backend to Railway | DevOps |
| 16 | Deploy frontend to Netlify | DevOps |
