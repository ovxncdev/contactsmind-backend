// server.js - Main Entry Point

const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');

const config = require('./config');
const { securityHeaders, sanitizeMiddleware } = require('./middleware/security');
const { generalLimiter } = require('./middleware/rateLimiter');

// Route imports
const authRoutes = require('./routes/auth');
const contactRoutes = require('./routes/contacts');
const calendarRoutes = require('./routes/calendar');
const aiRoutes = require('./routes/ai');
const adminRoutes = require('./routes/admin');

const app = express();

// =============================================
// MIDDLEWARE
// =============================================

// Security headers
app.use(securityHeaders);

// CORS
const corsOptions = {
  origin: (origin, callback) => {
    if (!origin && config.NODE_ENV !== 'production') {
      return callback(null, true);
    }
    if (!origin || config.ALLOWED_ORIGINS.includes(origin)) {
      callback(null, true);
    } else {
      callback(new Error('Not allowed by CORS'));
    }
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  maxAge: 86400
};
app.use(cors(corsOptions));

// Request parsing
app.use(express.json({ limit: '10kb' }));
app.use(express.urlencoded({ extended: true, limit: '10kb' }));

// Input sanitization
app.use(sanitizeMiddleware);

// Rate limiting (skip health check)
app.use((req, res, next) => {
  if (req.path === '/health') return next();
  generalLimiter(req, res, next);
});

// =============================================
// ROUTES
// =============================================

// Health check
app.get('/health', (req, res) => {
  res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

// API routes
app.use('/api/auth', authRoutes);
app.use('/api/contacts', contactRoutes);
app.use('/api/calendar', calendarRoutes);
app.use('/api/contacts', aiRoutes);  // AI routes under /api/contacts
app.use('/api', adminRoutes);         // /api/events, /api/feedback, /api/admin/stats

// =============================================
// ERROR HANDLING
// =============================================

// Global error handler
app.use((err, req, res, next) => {
  console.error('Unhandled error:', err.message);
  
  if (err.message === 'Not allowed by CORS') {
    return res.status(403).json({ error: 'CORS policy violation' });
  }

  res.status(err.status || 500).json({
    error: config.NODE_ENV === 'production' ? 'Internal server error' : err.message
  });
});

// 404 handler
app.use((req, res) => {
  res.status(404).json({ error: 'Endpoint not found' });
});

// =============================================
// DATABASE & SERVER START
// =============================================

const connectDB = async () => {
  try {
    await mongoose.connect(config.MONGODB_URI, {
      maxPoolSize: 10,
      serverSelectionTimeoutMS: 5000,
      socketTimeoutMS: 45000,
    });
    console.log('✅ MongoDB connected');
  } catch (error) {
    console.error('❌ MongoDB connection error');
    process.exit(1);
  }
};

connectDB();

app.listen(config.PORT, () => {
  console.log(`🚀 Server running on port ${config.PORT}`);
  console.log(`🔒 Security features enabled`);
  console.log(`📍 Environment: ${config.NODE_ENV}`);
});

module.exports = app;