   // models/UserMaster.js
   const mongoose = require('mongoose');

   const userMasterSchema = new mongoose.Schema({
     UserName: String,
     Password: String,
     EmployeeName: String,
     Profile: String,
     UserPhone: String,
     EmailID: String,
   });

   const UserMaster = mongoose.model('UserMaster', userMasterSchema);

   module.exports = UserMaster;