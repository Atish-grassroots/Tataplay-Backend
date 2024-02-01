const { MongoClient } = require('mongodb');

const url = 'mongodb://127.0.0.1:27017';
const dbName = 'TataPlay';

let dbInstance = null;

const connectToServer = async () => {
  if (dbInstance) return dbInstance;

  try {
    const client = await MongoClient.connect(url);
    dbInstance = client.db(dbName);
    console.log("Successfully connected to MongoDB.");
  } catch (err) {
    console.error("Failed to connect to MongoDB", err);
    throw err; // Rethrow the error to handle it in the calling function
  }

  return dbInstance;
};

const getDb = () => {
  if (!dbInstance) throw new Error("DB not initialized. Call connectToServer first.");
  return dbInstance;
};

module.exports = { connectToServer, getDb };