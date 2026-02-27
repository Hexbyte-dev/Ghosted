const { getGmailClient } = require('./gmail');
const pool = require('../db/pool');

async function unsubscribeFromSender(gmail, subscription) {
  const { unsubscribe_method, unsubscribe_value } = subscription;

  switch (unsubscribe_method) {
    case 'one-click': {
      const res = await fetch(unsubscribe_value, {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: 'List-Unsubscribe=One-Click-Unsubscribe',
      });
      return { success: res.ok, method: 'one-click' };
    }

    case 'url': {
      const res = await fetch(unsubscribe_value, {
        method: 'GET',
        redirect: 'follow',
      });
      return { success: res.ok, method: 'url' };
    }

    case 'mailto': {
      const [address, params] = unsubscribe_value.split('?');
      let subject = 'Unsubscribe';
      if (params) {
        const parsed = new URLSearchParams(params);
        subject = parsed.get('subject') || 'Unsubscribe';
      }

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
      const unsubResult = await unsubscribeFromSender(gmail, sub);
      const archivedCount = await archiveEmailsFromSender(gmail, sub.sender_email);

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
