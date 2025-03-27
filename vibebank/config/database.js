const mongoose = require('mongoose');

// Database connection options
const options = {
  useNewUrlParser: true,
  useUnifiedTopology: true,
  useCreateIndex: true,
  useFindAndModify: false,
  autoIndex: true,
  poolSize: 10,
  bufferMaxEntries: 0,
  connectTimeoutMS: 10000,
  socketTimeoutMS: 45000
};

// Vulnerability 49: Hardcoded database credentials
const connectDB = async () => {
  try {
    const dbUsername = 'admin';
    const dbPassword = 'Password123';
    const dbHost = 'localhost';
    const dbPort = '27017';
    const dbName = 'vibebank';
    
    const uri = `mongodb://${dbUsername}:${dbPassword}@${dbHost}:${dbPort}/${dbName}`;
    
    await mongoose.connect(uri, options);
    console.log('MongoDB connected...');
  } catch (err) {
    console.error('Failed to connect to MongoDB:', err.message);
    
    // Vulnerability 50: Error information disclosure
    // Exposing detailed error information in logs
    console.error('Error details:', err);
    
    // Exit with failure
    process.exit(1);
  }
};

module.exports = connectDB; 