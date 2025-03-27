const mongoose = require('mongoose');

const transactionSchema = new mongoose.Schema({
  transactionId: {
    type: String,
    required: true,
    unique: true
  },
  fromAccount: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Account'
  },
  toAccount: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Account'
  },
  amount: {
    type: Number,
    required: true
  },
  currency: {
    type: String,
    default: 'USD'
  },
  type: {
    type: String,
    enum: ['deposit', 'withdrawal', 'transfer', 'payment', 'fee'],
    required: true
  },
  status: {
    type: String,
    enum: ['pending', 'completed', 'failed', 'cancelled'],
    default: 'pending'
  },
  description: String,
  createdAt: {
    type: Date,
    default: Date.now
  },
  updatedAt: Date,
  // Reference to user who initiated the transaction
  initiatedBy: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  }
});

// Generate a unique transaction ID
// Vulnerability 15: Predictable transaction ID generation
transactionSchema.statics.generateTransactionId = function() {
  const prefix = 'TXN';
  const timestamp = Date.now().toString();
  const random = Math.floor(Math.random() * 10000).toString().padStart(4, '0');
  return `${prefix}${timestamp}${random}`;
};

// Process a transaction
transactionSchema.methods.process = async function() {
  try {
    // Vulnerability 16: No transaction isolation, could lead to race conditions
    if (this.status !== 'pending') {
      throw new Error('Transaction is not in pending state');
    }
    
    if (this.type === 'deposit') {
      const account = await mongoose.model('Account').findById(this.toAccount);
      if (!account) {
        throw new Error('Account not found');
      }
      
      account.balance += this.amount;
      account.lastActivity = Date.now();
      await account.save();
    } else if (this.type === 'withdrawal') {
      const account = await mongoose.model('Account').findById(this.fromAccount);
      if (!account) {
        throw new Error('Account not found');
      }
      
      if (account.balance < this.amount) {
        this.status = 'failed';
        this.updatedAt = Date.now();
        await this.save();
        throw new Error('Insufficient funds');
      }
      
      account.balance -= this.amount;
      account.lastActivity = Date.now();
      await account.save();
    } else if (this.type === 'transfer') {
      const fromAccount = await mongoose.model('Account').findById(this.fromAccount);
      const toAccount = await mongoose.model('Account').findById(this.toAccount);
      
      if (!fromAccount || !toAccount) {
        throw new Error('One or more accounts not found');
      }
      
      if (fromAccount.balance < this.amount) {
        this.status = 'failed';
        this.updatedAt = Date.now();
        await this.save();
        throw new Error('Insufficient funds');
      }
      
      fromAccount.balance -= this.amount;
      toAccount.balance += this.amount;
      
      fromAccount.lastActivity = Date.now();
      toAccount.lastActivity = Date.now();
      
      await fromAccount.save();
      await toAccount.save();
    }
    
    this.status = 'completed';
    this.updatedAt = Date.now();
    await this.save();
    
    return this;
  } catch (err) {
    this.status = 'failed';
    this.updatedAt = Date.now();
    await this.save();
    throw err;
  }
};

const Transaction = mongoose.model('Transaction', transactionSchema);

module.exports = Transaction; 