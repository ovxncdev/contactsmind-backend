// routes/calendar.js - Google Calendar Integration

const express = require('express');
const { google } = require('googleapis');
const router = express.Router();

const config = require('../config');
const User = require('../models/User');
const Contact = require('../models/Contact');
const { authenticateToken } = require('../middleware/auth');

const calendarOAuth2Client = new google.auth.OAuth2(
  config.GOOGLE_CLIENT_ID,
  config.GOOGLE_CLIENT_SECRET,
  config.GOOGLE_CALENDAR_REDIRECT_URI || `${config.FRONTEND_URL}/calendar-callback.html`
);

// Get auth URL
router.get('/auth-url', authenticateToken, (req, res) => {
  try {
    const scopes = ['https://www.googleapis.com/auth/calendar.events'];
    
    const authUrl = calendarOAuth2Client.generateAuthUrl({
      access_type: 'offline',
      scope: scopes,
      state: req.userId,
      prompt: 'consent'
    });
    
    res.json({ authUrl });
  } catch (error) {
    console.error('Calendar auth URL error:', error);
    res.status(500).json({ error: 'Failed to generate auth URL' });
  }
});

// Exchange code for tokens
router.post('/callback', authenticateToken, async (req, res) => {
  try {
    const { code } = req.body;
    const { tokens } = await calendarOAuth2Client.getToken(code);
    
    await User.findByIdAndUpdate(req.userId, {
      googleCalendarTokens: tokens
    });
    
    res.json({ success: true });
  } catch (error) {
    console.error('Calendar auth error:', error);
    res.status(500).json({ error: 'Failed to connect calendar' });
  }
});

// Check status
router.get('/status', authenticateToken, async (req, res) => {
  try {
    const user = await User.findById(req.userId);
    const connected = !!(user?.googleCalendarTokens?.access_token);
    res.json({ connected });
  } catch (error) {
    res.status(500).json({ error: 'Failed to check calendar status' });
  }
});

// Disconnect
router.post('/disconnect', authenticateToken, async (req, res) => {
  try {
    await User.findByIdAndUpdate(req.userId, {
      $unset: { googleCalendarTokens: 1 }
    });
    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ error: 'Failed to disconnect calendar' });
  }
});

// Create event
router.post('/create-event', authenticateToken, async (req, res) => {
  try {
    const user = await User.findById(req.userId);
    
    if (!user?.googleCalendarTokens) {
      return res.status(401).json({ error: 'Calendar not connected' });
    }
    
    calendarOAuth2Client.setCredentials(user.googleCalendarTokens);
    
    // Refresh token if needed
    if (user.googleCalendarTokens.expiry_date < Date.now()) {
      const { credentials } = await calendarOAuth2Client.refreshAccessToken();
      await User.findByIdAndUpdate(req.userId, {
        googleCalendarTokens: credentials
      });
      calendarOAuth2Client.setCredentials(credentials);
    }
    
    const calendar = google.calendar({ version: 'v3', auth: calendarOAuth2Client });
    
    const { title, description, date, time, contactName } = req.body;
    
    const startDateTime = new Date(`${date}T${time || '09:00'}`);
    const endDateTime = new Date(startDateTime.getTime() + 30 * 60 * 1000);
    
    const event = {
      summary: `${title} - ${contactName}`,
      description: description || `Reminder for ${contactName} from ContactsMind`,
      start: {
        dateTime: startDateTime.toISOString(),
        timeZone: Intl.DateTimeFormat().resolvedOptions().timeZone
      },
      end: {
        dateTime: endDateTime.toISOString(),
        timeZone: Intl.DateTimeFormat().resolvedOptions().timeZone
      },
      reminders: {
        useDefault: false,
        overrides: [
          { method: 'popup', minutes: 30 },
          { method: 'popup', minutes: 10 }
        ]
      }
    };
    
    const result = await calendar.events.insert({
      calendarId: 'primary',
      resource: event
    });
    
    res.json({ 
      success: true, 
      eventId: result.data.id,
      eventLink: result.data.htmlLink
    });
  } catch (error) {
    console.error('Create event error:', error);
    res.status(500).json({ error: 'Failed to create event' });
  }
});

// Sync all reminders
router.post('/sync-reminders', authenticateToken, async (req, res) => {
  try {
    const user = await User.findById(req.userId);
    
    if (!user?.googleCalendarTokens) {
      return res.status(401).json({ error: 'Calendar not connected' });
    }
    
    calendarOAuth2Client.setCredentials(user.googleCalendarTokens);
    
    if (user.googleCalendarTokens.expiry_date < Date.now()) {
      const { credentials } = await calendarOAuth2Client.refreshAccessToken();
      await User.findByIdAndUpdate(req.userId, {
        googleCalendarTokens: credentials
      });
      calendarOAuth2Client.setCredentials(credentials);
    }
    
    const calendar = google.calendar({ version: 'v3', auth: calendarOAuth2Client });
    const contacts = await Contact.find({ userId: req.userId });
    let synced = 0;
    
    for (const contact of contacts) {
      for (const reminder of (contact.reminders || [])) {
        if (!reminder.calendarEventId) {
          try {
            const startDateTime = new Date(`${reminder.date}T${reminder.time || '09:00'}`);
            const endDateTime = new Date(startDateTime.getTime() + 30 * 60 * 1000);
            
            const event = {
              summary: `${reminder.title} - ${contact.name}`,
              description: reminder.notes || `Reminder for ${contact.name} from ContactsMind`,
              start: { dateTime: startDateTime.toISOString() },
              end: { dateTime: endDateTime.toISOString() },
              reminders: { useDefault: false, overrides: [{ method: 'popup', minutes: 30 }] }
            };
            
            const result = await calendar.events.insert({
              calendarId: 'primary',
              resource: event
            });
            
            reminder.calendarEventId = result.data.id;
            synced++;
          } catch (e) {
            console.error('Sync reminder error:', e.message);
          }
        }
      }
      await contact.save();
    }
    
    res.json({ success: true, synced });
  } catch (error) {
    console.error('Sync reminders error:', error);
    res.status(500).json({ error: 'Failed to sync reminders' });
  }
});

module.exports = router;