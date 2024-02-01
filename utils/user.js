const bcrypt = require('bcrypt');
const User = require('../model/user'); 

async function ValidateUser(UserName, Password) {
  const user = await User.findOne({ UserName });

  if (!user || !bcrypt.compareSync(Password, user.Password)) {
    throw new Error('Invalid username or password');
  }

  return user;
}

module.exports = ValidateUser;