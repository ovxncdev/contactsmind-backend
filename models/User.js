// models/User.js

const mongoose = require('mongoose');

const userSchema = new mongoose.Schema({
  email: { 
    type: String, 
    required: true, 
    unique: true, 
    lowercase: true, 
    maxlength: 255 
  },
  password: { 
    type: String, 
    required: function() { return !this.googleId; } 
  },
  googleId: String,
  avatar: String,
  name: { type: String, maxlength: 100 },
  role: { type: String, default: 'user', enum: ['user', 'admin'] },
  createdAt: { type: Date, default: Date.now },
  lastLogin: Date,
  failedLoginAttempts: { type: Number, default: 0 },
  lockUntil: Date,
  plan: { type: String, default: 'free', enum: ['free', 'pro', 'business'] },
  googleCalendarTokens: {
    access_token: String,
    refresh_token: String,
    scope: String,
    token_type: String,
    expiry_date: Number
  }
});

userSchema.methods.isLocked = function() {
  return this.lockUntil && this.lockUntil > Date.now();
};

module.exports = mongoose.model('User', userSchema);