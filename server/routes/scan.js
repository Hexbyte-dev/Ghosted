const express = require('express');
const requireAuth = require('../middleware/requireAuth');
const pool = require('../db/pool');
const { scanForSubscriptions } = require('../services/gmail');

const router = express.Router();

router.post('/start', requireAuth, async (req, res) => {
  try {
    const result = await pool.query(
      'INSERT INTO scans (user_id, status) VALUES ($1, $2) RETURNING id',
      [req.user.userId, 'scanning']
    );
    const scanId = result.rows[0].id;

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
