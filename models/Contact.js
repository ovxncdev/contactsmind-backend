const mongoose = require('mongoose');

const ContactSchema = new mongoose.Schema({
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  name: {
    type: String,
    required: true,
    lowercase: true,
    trim: true
  },
  phone: {
    type: String,
    default: null
  },
  email: {
    type: String,
    default: null
  },
  paymentMethods: [{
    type: { type: String },  // venmo, cashapp, paypal, zelle, etransfer
    username: String
  }],
  skills: [{
    type: String
  }],
  notes: [{
    text: String,
    date: { type: Date, default: Date.now }
  }],
  debts: [{
    amount: Number,
    direction: { type: String, enum: ['i_owe_them', 'they_owe_me'] },
    note: String,
    date: { type: Date, default: Date.now }
  }],
  reminders: [{
    text: String,
    date: String,
    createdAt: { type: Date, default: Date.now }
  }],
  metadata: {
    type: Map,
    of: String,
    default: {}
  },
  createdAt: {
    type: Date,
    default: Date.now
  },
  updatedAt: {
    type: Date,
    default: Date.now
  }
});

// Update timestamp on save
ContactSchema.pre('save', function(next) {
  this.updatedAt = new Date();
  next();
});

module.exports = mongoose.model('Contact', ContactSchema);