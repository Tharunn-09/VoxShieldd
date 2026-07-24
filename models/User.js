const mongoose = require('mongoose');

const userSchema = new mongoose.Schema({
  employeeId: {
    type: String,
    required: true,
    unique: true,
    trim: true
  },
  name: {
    type: String,
    required: true,
    trim: true
  },
  email: {
    type: String,
    required: true,
    trim: true
  },
  password: {
    type: String,
    required: true
  },
  mfaSecret: {
    type: String,
    default: ''
  },
  mfaEnrolled: {
    type: Boolean,
    default: false
  },
  status: {
    type: String,
    enum: ['pending', 'active'],
    default: 'pending'
  },
  otp: {
    code: { type: String, default: '' },
    expiresAt: { type: Date }
  },
  loginAttempts: {
    count: { type: Number, default: 0 },
    lockUntil: { type: Date }
  }
}, {
  timestamps: true
});

module.exports = mongoose.model('User', userSchema);
