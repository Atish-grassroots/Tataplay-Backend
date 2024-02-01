const mongoose = require('mongoose');

const breakSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  name: String,
  breakType: String,
  startTime: Date,
  endTime: Date,
  duration: Number,
});

module.exports = mongoose.model('Break', breakSchema);