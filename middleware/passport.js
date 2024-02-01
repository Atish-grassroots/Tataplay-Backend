const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const { getDb } = require('../config/connect');
const { decrypt } = require('../config/encryption');
const express = require('express');
const app = express();

app.use(express.json());

const mongodb = require('mongodb');
//const ObjectId = mongodb.ObjectId;

passport.serializeUser(function(user, done) {
  console.log('Serializing user:', user._id);
  done(null, user._id); // Just store the user's _id
});

// passport.deserializeUser(async function(id, done) {
//   console.log('Deserializing user with ID:', id);
//   const db = getDb();
//   try {
//     const user = await db.collection('UserMaster').findOne({ _id: id });
//     done(null, user);
//   } catch (error) {
//     done(error, null);
//   }
// });
// passport.deserializeUser(async function(id, done) {
//   console.log('Deserializing user function called with ID:', id);
//   if (!id) {
//     console.log('No ID provided to deserializeUser function');
//     return done(new Error('No ID provided'), null);
//   }
  
//   const db = getDb();
//   try {
//    // await db.collection('UserMaster').findOne({ _id: aid });
//    const user = await db.collection('UserMaster').findOne({ _id: new mongodb.ObjectId(id._id) });
//    console.log('User found during deserialization:', user);
//     done(null, JSON.parse(user));
//   } catch (error) {
//     console.error('Error during deserialization:', error);
//     done(error, JSON.parse(user));
//   }
// });
passport.deserializeUser(async function(id, done) {
  console.log('Deserializing user function called with ID:', id);
  if (!id) {
    console.log('No ID provided to deserializeUser function');
    return done(new Error('No ID provided'), null);
  }
  
  const db = getDb();
  try {
    const user = await db.collection('UserMaster').findOne({ _id: new mongodb.ObjectId(id) }); // id is just the _id now
    console.log('User found during deserialization:', user);
    done(null, user);
  } catch (error) {
    console.error('Error during deserialization:', error);
    done(error, null);
  }
});


passport.use(new LocalStrategy(
  async function(username, password, done) {
    const db = getDb();
    const user = await db.collection('UserMaster').findOne({ UserName: username });
    console.log('User found:', user); 
    if (!user) {
      return done(null, false, { message: 'Incorrect username.' });
    }
    // Assuming you have a decrypt function similar to the one in loginroutes.js
    const decryptedPassword = decrypt(user.Password); // Decrypt the stored password
    console.log('Provided password:', password); // Log the password provided by the user
    console.log('Decrypted stored password:', decryptedPassword); // Log the decrypted stored password for comparison

    if (password === decryptedPassword) { // Compare with the provided password
      return done(null, user);
    } else {
      return done(null, false, { message: 'Incorrect password.' });
    }
  }
));



module.exports = passport;