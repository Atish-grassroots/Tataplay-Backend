const mongoose = require('mongoose');

const agentsBiometricSchema = new mongoose.Schema({
  UserID: mongoose.Schema.Types.ObjectId,
  AStartTime: Date,
  AEndTime: Date,
  BreakStartTime: Date,
  BreakEndTime: Date,
  UserStatus: String,
  BreakStatus: String,
  TDate: Date
});

const AgentsBiometric = mongoose.model('AgentsBiometric', agentsBiometricSchema);

module.exports = AgentsBiometric;