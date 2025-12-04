// server.js - ContactMind Backend API
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
require('dotenv').config();
const Contact = require('./models/Contact');
const app = express();

console.log('🔍 All ANTHROPIC vars:', Object.keys(process.env).filter(k => k.toUpperCase().includes('ANTHROPIC')));
console.log('🔍 Full env var names:', Object.keys(process.env).join(', '));

// Middleware
app.use(cors());
app.use(express.json());

// MongoDB Connection
const connectDB = async () => {
  try {
    await mongoose.connect(process.env.MONGODB_URI || 'mongodb://localhost:27017/contactmind', {
      useNewUrlParser: true,
      useUnifiedTopology: true
    });
    console.log('✅ MongoDB connected');
  } catch (error) {
    console.error('❌ MongoDB connection error:', error);
    process.exit(1);
  }
};

// User Schema
const userSchema = new mongoose.Schema({
  email: { type: String, required: true, unique: true, lowercase: true },
  password: { type: String, required: true },
  name: String,
  createdAt: { type: Date, default: Date.now },
  lastLogin: Date,
  plan: { type: String, default: 'free', enum: ['free', 'pro', 'business'] }
});

const User = mongoose.model('User', userSchema);

// Analytics Event Schema
const eventSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  event: { type: String, required: true },
  properties: mongoose.Schema.Types.Mixed,
  timestamp: { type: Date, default: Date.now }
});

const Event = mongoose.model('Event', eventSchema);

// Auth Middleware
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1]; // Bearer TOKEN

  if (!token) {
    return res.status(401).json({ error: 'Access token required' });
  }

  jwt.verify(token, process.env.JWT_SECRET || 'your-secret-key-change-in-production', (err, user) => {
    if (err) {
      return res.status(403).json({ error: 'Invalid or expired token' });
    }
    req.userId = user.userId;
    next();
  });
};

// =============================================
// ROUTES
// =============================================

// Health check
app.get('/health', (req, res) => {
  res.json({ 
    status: 'ok', 
    timestamp: new Date().toISOString(),
    uptime: process.uptime()
  });
});

// =============================================
// AUTH ROUTES
// =============================================

// Register
app.post('/api/auth/register', async (req, res) => {
  try {
    const { email, password, name } = req.body;

    // Validation
    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password required' });
    }

    // Check if user exists
    const existingUser = await User.findOne({ email: email.toLowerCase() });
    if (existingUser) {
      return res.status(400).json({ error: 'User already exists' });
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Create user
    const user = new User({
      email: email.toLowerCase(),
      password: hashedPassword,
      name
    });

    await user.save();

    // Generate token
    const token = jwt.sign(
      { userId: user._id },
      process.env.JWT_SECRET || 'your-secret-key-change-in-production',
      { expiresIn: '30d' }
    );

    // Track event
    await Event.create({
      userId: user._id,
      event: 'user_signed_up',
      properties: { email: user.email }
    });

    res.status(201).json({
      user: {
        id: user._id,
        email: user.email,
        name: user.name,
        plan: user.plan
      },
      token
    });
  } catch (error) {
    console.error('Register error:', error);
    res.status(500).json({ error: 'Registration failed' });
  }
});

// Login
app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    // Find user
    const user = await User.findOne({ email: email.toLowerCase() });
    if (!user) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    // Check password
    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    // Update last login
    user.lastLogin = new Date();
    await user.save();

    // Generate token
    const token = jwt.sign(
      { userId: user._id },
      process.env.JWT_SECRET || 'your-secret-key-change-in-production',
      { expiresIn: '30d' }
    );

    // Track event
    await Event.create({
      userId: user._id,
      event: 'user_logged_in'
    });

    res.json({
      user: {
        id: user._id,
        email: user.email,
        name: user.name,
        plan: user.plan
      },
      token
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Login failed' });
  }
});

// Get current user
app.get('/api/auth/me', authenticateToken, async (req, res) => {
  try {
    const user = await User.findById(req.userId).select('-password');
    res.json(user);
  } catch (error) {
    res.status(500).json({ error: 'Failed to get user' });
  }
});

// =============================================
// CONTACT ROUTES
// =============================================

// Sync contacts (bidirectional with smart duplicate handling)
app.post('/api/contacts/sync', authenticateToken, async (req, res) => {
  try {
    const { contacts } = req.body;

    if (!Array.isArray(contacts)) {
      return res.status(400).json({ error: 'Contacts must be an array' });
    }

    // Get server contacts
    const serverContacts = await Contact.find({ userId: req.userId });
    const serverContactMap = new Map(serverContacts.map(c => [c.id, c]));

    const toUpdate = [];
    const toCreate = [];
    const result = {
      synced: [],
      conflicts: []
    };

    // Process client contacts
    for (const clientContact of contacts) {
      const serverContact = serverContactMap.get(clientContact.id);

      if (!serverContact) {
        // New contact from client
        toCreate.push({
          userId: req.userId,
          ...clientContact
        });
      } else {
        // Conflict resolution: most recent wins
        const clientUpdated = new Date(clientContact.updatedAt);
        const serverUpdated = new Date(serverContact.updatedAt);

        if (clientUpdated > serverUpdated) {
          // Client is newer, update server
          toUpdate.push({
            filter: { userId: req.userId, id: clientContact.id },
            update: { ...clientContact, userId: req.userId }
          });
        }
      }
    }

    // Batch create (with duplicate name check and smart merge)
    let createdCount = 0;
    let mergedCount = 0;
    
    if (toCreate.length > 0) {
      for (const contact of toCreate) {
        // Check if contact with same name already exists
        const existingByName = await Contact.findOne({ 
          userId: req.userId, 
          name: contact.name.toLowerCase() 
        });
        
        if (existingByName) {
          // Merge payment methods first
          const existingTypes = (existingByName.paymentMethods || []).map(p => p.type);
          const newMethods = (contact.paymentMethods || []).filter(p => !existingTypes.includes(p.type));
          console.log(`💳 Existing types:`, existingTypes);
          console.log(`💳 New methods to add:`, newMethods);
          const mergedPaymentMethods = [...(existingByName.paymentMethods || []), ...newMethods];
          
          // Build update data WITHOUT spreading contact.paymentMethods
          const updateData = {
            name: contact.name,
            phone: contact.phone || existingByName.phone,
            email: contact.email || existingByName.email,
            skills: [...new Set([...(existingByName.skills || []), ...(contact.skills || [])])],
            notes: [...(existingByName.notes || []), ...(contact.notes || [])],
            debts: [...(existingByName.debts || []), ...(contact.debts || [])],
            reminders: [...(existingByName.reminders || []), ...(contact.reminders || [])],
            paymentMethods: mergedPaymentMethods,
            metadata: contact.metadata || existingByName.metadata || {},
            updatedAt: new Date().toISOString()
          };
  
          await Contact.updateOne(
            { userId: req.userId, name: contact.name.toLowerCase() }, 
            { $set: updateData }
          );
          console.log(`🔄 Merged into existing contact: ${contact.name}`);
          console.log(`💳 Payment methods after merge:`, mergedPaymentMethods);
          mergedCount++;
        } else {
                  // Truly new contact
                  await Contact.create(contact);
                  console.log(`✨ Created new contact: ${contact.name}`);
                  createdCount++;
                }
              }
            }

    // Batch update
    for (const { filter, update } of toUpdate) {
      await Contact.updateOne(filter, update);
    }

    // Get all contacts to return
    const allContacts = await Contact.find({ userId: req.userId }).lean();

    // Track event
    await Event.create({
      userId: req.userId,
      event: 'contacts_synced',
      properties: {
        total: allContacts.length,
        created: createdCount,
        merged: mergedCount,
        updated: toUpdate.length
      }
    });

    res.json({
      contacts: allContacts,
      stats: {
        total: allContacts.length,
        created: createdCount,
        merged: mergedCount,
        updated: toUpdate.length
      }
    });
  } catch (error) {
    console.error('Sync error:', error);
    res.status(500).json({ error: 'Sync failed' });
  }
});

// Get all contacts
app.get('/api/contacts', authenticateToken, async (req, res) => {
  try {
    const contacts = await Contact.find({ userId: req.userId })
      .sort({ updatedAt: -1 })
      .lean();

    res.json(contacts);
  } catch (error) {
    console.error('Get contacts error:', error);
    res.status(500).json({ error: 'Failed to get contacts' });
  }
});

// Delete contact
app.delete('/api/contacts/:id', authenticateToken, async (req, res) => {
  try {
    const contact = await Contact.findOneAndDelete({
      userId: req.userId,
      id: req.params.id
    });

    if (!contact) {
      return res.status(404).json({ error: 'Contact not found' });
    }

    // Track event
    await Event.create({
      userId: req.userId,
      event: 'contact_deleted',
      properties: { contactName: contact.name }
    });

    res.json({ message: 'Contact deleted' });
  } catch (error) {
    console.error('Delete error:', error);
    res.status(500).json({ error: 'Failed to delete contact' });
  }
});

// =============================================
// ANALYTICS ROUTES
// =============================================

// Track event
app.post('/api/events', authenticateToken, async (req, res) => {
  try {
    const { event, properties } = req.body;

    await Event.create({
      userId: req.userId,
      event,
      properties
    });

    res.json({ success: true });
  } catch (error) {
    console.error('Event tracking error:', error);
    res.status(500).json({ error: 'Failed to track event' });
  }
});

// Get user stats (for admin)
app.get('/api/admin/stats', authenticateToken, async (req, res) => {
  try {
    // TODO: Add admin role check

    const totalUsers = await User.countDocuments();
    const totalContacts = await Contact.countDocuments();
    const totalEvents = await Event.countDocuments();

    const recentUsers = await User.find()
      .sort({ createdAt: -1 })
      .limit(10)
      .select('-password');

    const topEvents = await Event.aggregate([
      {
        $group: {
          _id: '$event',
          count: { $sum: 1 }
        }
      },
      { $sort: { count: -1 } },
      { $limit: 10 }
    ]);

    res.json({
      totalUsers,
      totalContacts,
      totalEvents,
      recentUsers,
      topEvents
    });
  } catch (error) {
    console.error('Stats error:', error);
    res.status(500).json({ error: 'Failed to get stats' });
  }
});

// =============================================
// AI PARSING ROUTE
// =============================================

app.post('/api/contacts/parse-ai', authenticateToken, async (req, res) => {
  console.log('🚀 AI Parse endpoint hit!');
  try {
    const { text } = req.body;
    console.log('📥 AI Parse request:', text);
    
    if (!text) {
      return res.status(400).json({ error: 'Text required' });
    }

    // Check if API key exists
    const apiKey = process.env.ANTHROPIC_API_KEY;
    console.log('🔑 API Key exists:', !!apiKey);
    console.log('🔑 API Key starts with:', apiKey ? apiKey.substring(0, 10) + '...' : 'MISSING');

    if (!apiKey) {
      console.error('❌ ANTHROPIC_API_KEY is not set!');
      return res.json({ contacts: [], error: 'API key not configured' });
    }

    // Call Claude API
    console.log('📡 Calling Claude API...');
    const response = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-api-key': process.env.ANTHROPIC_API_KEY,
        'anthropic-version': '2023-06-01'
      },
      body: JSON.stringify({
        model: 'claude-sonnet-4-20250514',
        max_tokens: 1024,
        messages: [{
          role: 'user',
          content: `Extract contact information from this text and return ONLY valid JSON.

Text: "${text}"

RULES:
1. name: The person's name in lowercase (NOT "I" or "me")
2. skills: Extract as ARRAY of separate skills. "freelance graphic designer and UX consultant" becomes ["graphic designer", "UX consultant"]
3. phone: Any phone number found (like "415-555-8923")
4. email: Any email found
5. debts: Money owed. "He owes me $50" = they_owe_me. "I owe him $20" = i_owe_them
6. reminders: Future events like "lunch next Tuesday"
7. notes: Other personal info like "met at coffee shop", "old friend"
8. paymentMethods: Extract payment apps/methods when someone "has", "got", "get", "uses", or "is on" venmo, cashapp, paypal, zelle, etransfer, apple pay, google pay. Format: {"type": "venmo", "username": "their_username"} or just {"type": "venmo"} if no username given

EXAMPLE:
Input: "Met John at cafe. He's a photographer. His venmo is @johnpay and he got cashapp."
Output:
{"contacts":[{"name":"john","skills":["photographer"],"phone":null,"email":null,"debts":[],"reminders":[],"notes":["met at cafe"],"paymentMethods":[{"type":"venmo","username":"@johnpay"},{"type":"cashapp"}]}]}

Now extract from the text. Return ONLY JSON, no explanation:`
        }]
      })
    });

    const data = await response.json();
    console.log('🤖 Claude API response:', JSON.stringify(data, null, 2));
    
    if (data.content && data.content[0]) {
      let jsonText = data.content[0].text;
      console.log('🤖 AI RAW RESPONSE:', jsonText);
      
      // Clean the response (remove markdown code blocks)
      jsonText = jsonText.trim();
      
      // Remove ```json at start
      if (jsonText.startsWith('```json')) {
        jsonText = jsonText.slice(7);
      } else if (jsonText.startsWith('```')) {
        jsonText = jsonText.slice(3);
      }
      
      // Remove ``` at end
      if (jsonText.endsWith('```')) {
        jsonText = jsonText.slice(0, -3);
      }
      
      // Trim again after removing markdown
      jsonText = jsonText.trim();
      
      console.log('🧹 Cleaned JSON:', jsonText);
      
      // Parse the JSON response
      const parsed = JSON.parse(jsonText);
      console.log('✅ Parsed contacts:', parsed.contacts.length);
      
      // Add required fields
      parsed.contacts = parsed.contacts.map((contact, index) => ({
        ...contact,
        id: `ai-${Date.now()}-${index}-${Math.random().toString(36).substr(2, 9)}`,
        skills: contact.skills || [],
        notes: (contact.notes || []).map(note => 
          typeof note === 'string' 
            ? { text: note, date: new Date().toISOString() }
            : note
        ),
        debts: contact.debts || [],
        reminders: contact.reminders || [],
        paymentMethods: contact.paymentMethods || [],
        metadata: {},
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString()
      }));
      
      console.log('✅ Returning contacts:', parsed.contacts);
      res.json(parsed);
    } else {
      console.log('⚠️ No content in Claude response');
      res.json({ contacts: [] });
    }
  } catch (error) {
    console.error('❌ AI parsing error:', error.message);
    console.error('❌ Full error:', error);
    res.json({ contacts: [] }); // Fallback to empty on error
  }
});


// =============================================
// AI SEARCH ROUTE
// =============================================

app.post('/api/contacts/search-ai', authenticateToken, async (req, res) => {
  console.log('🔍 AI Search endpoint hit!');
  try {
    const { query, contacts } = req.body;
    
    if (!query || !contacts) {
      return res.status(400).json({ error: 'Query and contacts required' });
    }

    const apiKey = process.env.ANTHROPIC_API_KEY;
    if (!apiKey) {
      return res.status(500).json({ error: 'API key not configured' });
    }

    // Build contacts summary for AI
    const contactsSummary = contacts.map(c => ({
      name: c.name,
      skills: c.skills || [],
      phone: c.phone,
      email: c.email,
      paymentMethods: (c.paymentMethods || []).map(p => p.type + (p.username ? `: ${p.username}` : '')),
      debts: (c.debts || []).map(d => `${d.direction === 'i_owe_them' ? 'I owe them' : 'They owe me'} $${d.amount}`),
      notes: (c.notes || []).map(n => typeof n === 'string' ? n : n.text)
    }));

    const response = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-api-key': apiKey,
        'anthropic-version': '2023-06-01'
      },
      body: JSON.stringify({
        model: 'claude-sonnet-4-20250514',
        max_tokens: 1024,
        messages: [{
          role: 'user',
          content: `You are a helpful contact search assistant. Search through the user's contacts and answer their question.

CONTACTS DATABASE:
${JSON.stringify(contactsSummary, null, 2)}

USER QUESTION: "${query}"

RULES:
1. Search the contacts and find relevant matches
2. Be conversational and friendly
3. Format names in UPPERCASE
4. If asking about debts, calculate totals
5. If asking about payment methods, list who has what
6. If no matches found, say so politely
7. Keep response concise but informative

Respond naturally as if chatting with the user:`
        }]
      })
    });

    const data = await response.json();
    
    if (data.content && data.content[0]) {
      console.log('✅ AI Search response generated');
      res.json({ response: data.content[0].text });
    } else {
      res.json({ response: "I couldn't search right now. Try again!" });
    }
  } catch (error) {
    console.error('❌ AI Search error:', error);
    res.json({ response: "Search failed. Please try again." });
  }
});
// =============================================
// AI INTENT DETECTION ROUTE
// =============================================

app.post('/api/detect-intent', authenticateToken, async (req, res) => {
  try {
    const { text } = req.body;
    
    if (!text) {
      return res.status(400).json({ error: 'Text required' });
    }

    const apiKey = process.env.ANTHROPIC_API_KEY;
    if (!apiKey) {
      return res.json({ intent: 'unknown' });
    }

    const response = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-api-key': apiKey,
        'anthropic-version': '2023-06-01'
      },
      body: JSON.stringify({
        model: 'claude-sonnet-4-20250514',
        max_tokens: 50,
        messages: [{
          role: 'user',
          content: `Classify this message as either "query" or "add_contact".

- "query" = user is searching/asking about existing contacts (e.g., "who has venmo", "find designers", "who do I owe", "show contacts")
- "add_contact" = user is adding new contact info (e.g., "John has venmo", "met Sarah she does design", "Mike's number is 555-1234")

Message: "${text}"

Reply with ONLY one word: query OR add_contact`
        }]
      })
    });

    const data = await response.json();
    
    if (data.content && data.content[0]) {
      const intent = data.content[0].text.toLowerCase().trim();
      console.log(`🧠 Intent for "${text}": ${intent}`);
      res.json({ intent: intent.includes('query') ? 'query' : 'add_contact' });
    } else {
      res.json({ intent: 'unknown' });
    }
  } catch (error) {
    console.error('❌ Intent detection error:', error);
    res.json({ intent: 'unknown' });
  }
});


// =============================================
// START SERVER
// =============================================

connectDB();

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
  console.log(`📍 http://localhost:${PORT}/health`);
});