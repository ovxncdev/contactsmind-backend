// middleware/security.js - Security Headers & Sanitization

const config = require('../config');

// Security headers middleware
const securityHeaders = (req, res, next) => {
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  res.setHeader('Content-Security-Policy', "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'");
  
  if (config.NODE_ENV === 'production') {
    res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
  }
  
  res.removeHeader('X-Powered-By');
  next();
};

// Input sanitization
const sanitizeInput = (obj) => {
  if (obj === null || obj === undefined) return obj;
  
  if (typeof obj === 'string') return obj;
  
  if (Array.isArray(obj)) {
    return obj.map(sanitizeInput);
  }
  
  if (typeof obj === 'object') {
    const sanitized = {};
    for (const [key, value] of Object.entries(obj)) {
      if (key.startsWith('$') || key.includes('.')) {
        console.warn(`Blocked potentially malicious key: ${key}`);
        continue;
      }
      sanitized[key] = sanitizeInput(value);
    }
    return sanitized;
  }
  
  return obj;
};

const sanitizeMiddleware = (req, res, next) => {
  if (req.body) req.body = sanitizeInput(req.body);
  if (req.query) req.query = sanitizeInput(req.query);
  if (req.params) req.params = sanitizeInput(req.params);
  next();
};

// AI input sanitization
const sanitizeAIInput = (text) => {
  if (typeof text !== 'string') return '';
  return text
    .replace(/\n{3,}/g, '\n\n')
    .replace(/[<>{}]/g, '')
    .substring(0, 5000);
};

module.exports = {
  securityHeaders,
  sanitizeMiddleware,
  sanitizeAIInput
};