// middleware/validators.js - Input Validation

const validators = {
  isEmail: (str) => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(str),
  
  isStrongPassword: (str) => 
    str.length >= 8 && /[a-z]/.test(str) && /[A-Z]/.test(str) && /\d/.test(str),
  
  isObjectId: (str) => /^[a-f\d]{24}$/i.test(str),
  
  sanitizeString: (str, maxLen = 1000) => 
    typeof str === 'string' ? str.trim().substring(0, maxLen) : ''
};

const validateRegister = (body) => {
  const errors = [];
  
  if (!body.email || !validators.isEmail(body.email)) {
    errors.push('Valid email is required');
  }
  if (!body.password || body.password.length < 8) {
    errors.push('Password must be at least 8 characters');
  }
  if (body.password && !validators.isStrongPassword(body.password)) {
    errors.push('Password must contain uppercase, lowercase, and number');
  }
  if (body.password && body.password.length > 128) {
    errors.push('Password too long');
  }
  if (body.name && body.name.length > 100) {
    errors.push('Name too long');
  }
  
  return errors;
};

const validateLogin = (body) => {
  const errors = [];
  if (!body.email) errors.push('Email is required');
  if (!body.password) errors.push('Password is required');
  return errors;
};

module.exports = {
  validators,
  validateRegister,
  validateLogin
};