const mongoose = require('mongoose');

const accountSchema = new mongoose.Schema({
  accountNumber: {
    type: String,
    required: true,
    unique: true
  },
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  accountType: {
    type: String,
    enum: ['checking', 'savings', 'credit'],
    required: true
  },
  balance: {
    type: Number,
    default: 0
  },
  currency: {
    type: String,
    default: 'USD'
  },
  isActive: {
    type: Boolean,
    default: true
  },
  createdAt: {
    type: Date,
    default: Date.now
  },
  lastActivity: Date,
  creditLimit: {
    type: Number,
    default: 0
  },
  interestRate: {
    type: Number,
    default: 0
  }
});

// Vulnerability 13: Race condition vulnerability in withdraw method
accountSchema.methods.withdraw = async function(amount) {
  // Missing proper transaction control, which could lead to race conditions
  // For example, if two withdrawals happen concurrently, it could lead to overdrafts
  
  if (amount <= 0) {
    throw new Error('Withdrawal amount must be positive');
  }
  
  if (this.balance < amount) {
    throw new Error('Insufficient funds');
  }
  
  this.balance -= amount;
  this.lastActivity = Date.now();
  await this.save();
  
  return this.balance;
};

// Similar vulnerability in transfer method
accountSchema.methods.transfer = async function(targetAccountId, amount) {
  if (amount <= 0) {
    throw new Error('Transfer amount must be positive');
  }
  
  if (this.balance < amount) {
    throw new Error('Insufficient funds');
  }
  
  const targetAccount = await mongoose.model('Account').findById(targetAccountId);
  if (!targetAccount) {
    throw new Error('Target account not found');
  }
  
  // Vulnerable to race conditions - should use a transaction
  this.balance -= amount;
  targetAccount.balance += amount;
  
  this.lastActivity = Date.now();
  targetAccount.lastActivity = Date.now();
  
  await this.save();
  await targetAccount.save();
  
  return { sourceBalance: this.balance, targetBalance: targetAccount.balance };
};

// Static method to generate a unique account number
accountSchema.statics.generateAccountNumber = async function() {
  // Vulnerability 14: Predictable account number generation
  const prefix = 'VB';
  const timestamp = Date.now().toString().slice(-8);
  const random = Math.floor(Math.random() * 1000).toString().padStart(3, '0');
  return `${prefix}${timestamp}${random}`;
};

const Account = mongoose.model('Account', accountSchema);

module.exports = Account; 