const mongoose = require('mongoose');

const UserSchema = new mongoose.Schema({
  UserName: String,
  Password: String,
  EmployeeName: String,
  Profile: String,
  UserPhone: String,
  EmailID: String
});

module.exports = mongoose.model('User', UserSchema);