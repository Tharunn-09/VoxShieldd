const mongoose = require('mongoose');

const auditLogSchema = new mongoose.Schema({
  timestamp: {
    type: Date,
    default: Date.now,
    required: true
  },
  employeeId: {
    type: String,
    required: true,
    trim: true
  },
  eventType: {
    type: String,
    required: true,
    trim: true
  },
  ipAddress: {
    type: String,
    default: ''
  },
  details: {
    type: String,
    required: true
  }
});

module.exports = mongoose.model('AuditLog', auditLogSchema);
