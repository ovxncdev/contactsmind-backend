// routes/auth.js - Authentication Routes

const express = require('express');
const bcrypt = require('bcrypt');
const { OAuth2Client } = require('google-auth-library');
const router = express.Router();

const config = require('../config');
const User = require('../models/User');
const Event = require('../models/Event');
const { generateToken, authenticateToken } = require('../middleware/auth');
const { authLimiter } = require('../middleware/rateLimiter');
const { validators, validateRegister, validateLogin } = require('../middleware/validators');

const googleClient = new OAuth2Client(config.GOOGLE_CLIENT_ID);

// Register
router.post('/register', authLimiter, async (req, res) => {
  try {
    const errors = validateRegister(req.body);
    if (errors.length > 0) {
      return res.status(400).json({ error: 'Validation failed', details: errors });
    }

    const email = req.body.email.toLowerCase().trim();
    const name = validators.sanitizeString(req.body.name, 100);

    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ error: 'User already exists' });
    }

    const hashedPassword = await bcrypt.hash(req.body.password, 12);

    const user = new User({ email, password: hashedPassword, name });
    await user.save();

    const token = generateToken(user._id, user.email);

    await Event.create({ userId: user._id, event: 'user_signed_up' });

    res.status(201).json({
      user: { id: user._id, email: user.email, name: user.name, plan: user.plan },
      token
    });
  } catch (error) {
    console.error('Register error:', error.message);
    res.status(500).json({ error: 'Registration failed' });
  }
});

// Login
router.post('/login', authLimiter, async (req, res) => {
  try {
    const errors = validateLogin(req.body);
    if (errors.length > 0) {
      return res.status(400).json({ error: 'Validation failed', details: errors });
    }

    const email = req.body.email.toLowerCase().trim();
    const user = await User.findOne({ email });
    
    if (!user) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    if (user.isLocked()) {
      return res.status(423).json({ error: 'Account temporarily locked. Try again later.' });
    }

    if (!user.password) {
      return res.status(401).json({ error: 'Please use Google sign-in for this account' });
    }

    const validPassword = await bcrypt.compare(req.body.password, user.password);
    if (!validPassword) {
      user.failedLoginAttempts += 1;
      if (user.failedLoginAttempts >= 5) {
        user.lockUntil = new Date(Date.now() + 15 * 60 * 1000);
      }
      await user.save();
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    user.failedLoginAttempts = 0;
    user.lockUntil = undefined;
    user.lastLogin = new Date();
    await user.save();

    const token = generateToken(user._id, user.email);

    await Event.create({ userId: user._id, event: 'user_logged_in' });

    res.json({
      user: { id: user._id, email: user.email, name: user.name, plan: user.plan },
      token
    });
  } catch (error) {
    console.error('Login error:', error.message);
    res.status(500).json({ error: 'Login failed' });
  }
});

// Get current user
router.get('/me', authenticateToken, async (req, res) => {
  try {
    const user = await User.findById(req.userId).select('-password -failedLoginAttempts -lockUntil');
    if (!user) return res.status(404).json({ error: 'User not found' });
    res.json(user);
  } catch (error) {
    res.status(500).json({ error: 'Failed to get user' });
  }
});

// Google OAuth
router.post('/google', authLimiter, async (req, res) => {
  try {
    const { credential } = req.body;
    if (!credential) return res.status(400).json({ error: 'Credential required' });
    if (!config.GOOGLE_CLIENT_ID) return res.status(500).json({ error: 'Google auth not configured' });
    
    const ticket = await googleClient.verifyIdToken({
      idToken: credential,
      audience: config.GOOGLE_CLIENT_ID
    });
    
    const payload = ticket.getPayload();
    const { sub: googleId, email, name, picture } = payload;
    
    let user = await User.findOne({ $or: [{ googleId }, { email }] });
    
    if (!user) {
      user = new User({
        name: name?.substring(0, 100),
        email,
        googleId,
        avatar: picture
      });
      await user.save();
    } else if (!user.googleId) {
      user.googleId = googleId;
      user.avatar = picture;
      await user.save();
    }
    
    const token = generateToken(user._id, user.email);
    
    res.json({
      token,
      user: { id: user._id, name: user.name, email: user.email, avatar: user.avatar }
    });
  } catch (error) {
    console.error('Google auth error:', error.message);
    res.status(401).json({ error: 'Google authentication failed' });
  }
});

module.exports = router;