// routes/admin.js - Admin Routes

const express = require('express');
const router = express.Router();

const User = require('../models/User');
const Contact = require('../models/Contact');
const Event = require('../models/Event');
const { authenticateToken, requireAdmin } = require('../middleware/auth');
const { validators } = require('../middleware/validators');

// Get stats (admin only)
router.get('/stats', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const totalUsers = await User.countDocuments();
    const totalContacts = await Contact.countDocuments();
    const totalEvents = await Event.countDocuments();

    const recentUsers = await User.find()
      .sort({ createdAt: -1 })
      .limit(10)
      .select('-password -failedLoginAttempts -lockUntil');

    const topEvents = await Event.aggregate([
      { $group: { _id: '$event', count: { $sum: 1 } } },
      { $sort: { count: -1 } },
      { $limit: 10 }
    ]);

    res.json({ totalUsers, totalContacts, totalEvents, recentUsers, topEvents });
  } catch (error) {
    console.error('Stats error:', error.message);
    res.status(500).json({ error: 'Failed to get stats' });
  }
});

// Submit feedback
router.post('/feedback', authenticateToken, async (req, res) => {
  try {
    const { rating, text, type } = req.body;
    await Event.create({
      userId: req.userId,
      event: 'feedback_submitted',
      properties: { rating, text: validators.sanitizeString(text, 2000), type }
    });
    res.json({ success: true });
  } catch (error) {
    console.error('Feedback error:', error.message);
    res.status(500).json({ error: 'Failed to save feedback' });
  }
});

// Track events
router.post('/events', authenticateToken, async (req, res) => {
  try {
    const { event, properties } = req.body;
    if (!event || typeof event !== 'string' || event.length > 100) {
      return res.status(400).json({ error: 'Invalid event name' });
    }
    await Event.create({ userId: req.userId, event: event.substring(0, 100), properties });
    res.json({ success: true });
  } catch (error) {
    console.error('Event tracking error:', error.message);
    res.status(500).json({ error: 'Failed to track event' });
  }
});

module.exports = router;