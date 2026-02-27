const express = require('express');
const requireAuth = require('../middleware/requireAuth');
const { ghostSubscriptions } = require('../services/unsubscriber');

const router = express.Router();

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
