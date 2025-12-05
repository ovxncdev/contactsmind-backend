// middleware/rateLimiter.js - Rate Limiting

const rateLimitStore = new Map();

const createRateLimiter = (windowMs, maxRequests, keyGenerator = (req) => req.ip) => {
  return (req, res, next) => {
    const key = keyGenerator(req);
    const now = Date.now();
    
    // Clean old entries periodically
    if (Math.random() < 0.01) {
      for (const [k, v] of rateLimitStore) {
        if (now - v.windowStart > windowMs) {
          rateLimitStore.delete(k);
        }
      }
    }
    
    let record = rateLimitStore.get(key);
    
    if (!record || now - record.windowStart > windowMs) {
      record = { windowStart: now, count: 0 };
    }
    
    record.count++;
    rateLimitStore.set(key, record);
    
    res.setHeader('X-RateLimit-Limit', maxRequests);
    res.setHeader('X-RateLimit-Remaining', Math.max(0, maxRequests - record.count));
    
    if (record.count > maxRequests) {
      return res.status(429).json({ error: 'Too many requests, please try again later' });
    }
    
    next();
  };
};

// Pre-configured limiters
const generalLimiter = createRateLimiter(15 * 60 * 1000, 100);
const authLimiter = createRateLimiter(15 * 60 * 1000, 5, (req) => `auth:${req.ip}`);
const aiLimiter = createRateLimiter(60 * 1000, 10, (req) => `ai:${req.userId || req.ip}`);

module.exports = {
  createRateLimiter,
  generalLimiter,
  authLimiter,
  aiLimiter
};