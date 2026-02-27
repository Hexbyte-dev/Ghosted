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

async function scanForSubscriptions(userId, scanId) {
  const gmail = await getGmailClient(userId);

  const sixMonthsAgo = new Date();
  sixMonthsAgo.setMonth(sixMonthsAgo.getMonth() - 6);
  const afterDate = sixMonthsAgo.toISOString().split('T')[0].replace(/-/g, '/');

  const query = `after:${afterDate}`;

  const subscriptions = new Map();
  let pageToken = null;
  let totalProcessed = 0;

  do {
    const listRes = await gmail.users.messages.list({
      userId: 'me',
      q: query,
      maxResults: 100,
      pageToken,
    });

    const messages = listRes.data.messages || [];

    await pool.query(
      'UPDATE scans SET total_messages = total_messages + $1 WHERE id = $2',
      [messages.length, scanId]
    );

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
        if (!listUnsub) continue;

        const from = getHeader('From') || 'Unknown';
        const date = getHeader('Date');
        const hasOneClick = !!getHeader('List-Unsubscribe-Post');

        const emailMatch = from.match(/<([^>]+)>/);
        const senderEmail = emailMatch ? emailMatch[1] : from;
        const senderName = emailMatch ? from.replace(/<[^>]+>/, '').trim() : from;

        let unsubMethod = 'none';
        let unsubValue = '';

        if (hasOneClick) {
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
        console.error(`Error processing message ${msg.id}:`, err.message);
      }
    }

    pageToken = listRes.data.nextPageToken;
  } while (pageToken);

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

  await pool.query(
    'UPDATE scans SET status = $1, processed_messages = $2, completed_at = NOW() WHERE id = $3',
    ['completed', totalProcessed, scanId]
  );

  return { totalProcessed, subscriptionCount: subscriptions.size };
}

module.exports = { getGmailClient, scanForSubscriptions };
