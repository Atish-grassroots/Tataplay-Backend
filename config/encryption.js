const crypto = require("crypto");

// Encryption and decryption settings
const ENCRYPTION_KEY = process.env.ENCRYPTION_KEY || "abcdefghijklmnop".repeat(2); // Must be 256 bits (32 characters)
const IV_LENGTH = 16; // For AES, this is always 16

function encrypt(text) {
  let iv = crypto.randomBytes(IV_LENGTH);
  let cipher = crypto.createCipheriv('aes-256-cbc', Buffer.from(ENCRYPTION_KEY), iv);
  let encrypted = cipher.update(text);

  encrypted = Buffer.concat([encrypted, cipher.final()]);

  return iv.toString('hex') + ':' + encrypted.toString('hex');
}

function decrypt(text) {
    let textParts = text.split(':');
    let iv = Buffer.from(textParts.shift(), 'hex');
    let encryptedText = Buffer.from(textParts.join(':'), 'hex');
   // console.log(`IV length: ${iv.length}, IV: ${iv.toString('hex')}`); 
    //console.log(`Encrypted text: ${encryptedText.toString('hex')}`); 
    let decipher = crypto.createDecipheriv('aes-256-cbc', Buffer.from(ENCRYPTION_KEY), iv);
    let decrypted = decipher.update(encryptedText);
  
    decrypted = Buffer.concat([decrypted, decipher.final()]);
  
    return decrypted.toString();
  }
  

module.exports = { encrypt, decrypt };