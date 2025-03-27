const express = require('express');
const router = express.Router();
const Account = require('../models/account');
const Transaction = require('../models/transaction');
const { requireAuth } = require('../middleware/auth');

// Get all accounts for the logged-in user
router.get('/', async (req, res) => {
  try {
    const accounts = await Account.find({ userId: req.userId });
    
    res.status(200).json({
      status: 'success',
      results: accounts.length,
      data: {
        accounts
      }
    });
  } catch (err) {
    res.status(500).json({
      status: 'error',
      message: err.message
    });
  }
});

// Get account by ID
router.get('/:id', async (req, res) => {
  try {
    const account = await Account.findById(req.params.id);
    
    if (!account) {
      return res.status(404).json({
        status: 'error',
        message: 'Account not found'
      });
    }
    
    // Vulnerability 24: Missing authorization check
    // Should check if the account belongs to the logged-in user
    // if (account.userId.toString() !== req.userId) {
    //   return res.status(403).json({
    //     status: 'error',
    //     message: 'You are not authorized to view this account'
    //   });
    // }
    
    res.status(200).json({
      status: 'success',
      data: {
        account
      }
    });
  } catch (err) {
    res.status(500).json({
      status: 'error',
      message: err.message
    });
  }
});

// Create a new account
router.post('/', async (req, res) => {
  try {
    const { accountType } = req.body;
    
    if (!accountType || !['checking', 'savings', 'credit'].includes(accountType)) {
      return res.status(400).json({
        status: 'error',
        message: 'Valid account type is required'
      });
    }
    
    // Generate account number
    const accountNumber = await Account.generateAccountNumber();
    
    const newAccount = new Account({
      accountNumber,
      userId: req.userId,
      accountType,
      balance: 0
    });
    
    await newAccount.save();
    
    res.status(201).json({
      status: 'success',
      data: {
        account: newAccount
      }
    });
  } catch (err) {
    res.status(500).json({
      status: 'error',
      message: err.message
    });
  }
});

// Deposit money
router.post('/:id/deposit', async (req, res) => {
  try {
    const { amount } = req.body;
    const parsedAmount = parseFloat(amount);
    
    // Vulnerability 25: Insufficient input validation
    // Not properly validating the amount as a number
    if (!amount || isNaN(parsedAmount) || parsedAmount <= 0) {
      return res.status(400).json({
        status: 'error',
        message: 'Amount must be a positive number'
      });
    }
    
    const account = await Account.findById(req.params.id);
    
    if (!account) {
      return res.status(404).json({
        status: 'error',
        message: 'Account not found'
      });
    }
    
    // Check if the account belongs to the logged-in user
    if (account.userId.toString() !== req.userId) {
      return res.status(403).json({
        status: 'error',
        message: 'You are not authorized to perform this action'
      });
    }
    
    // Update account balance
    account.balance += parsedAmount;
    account.lastActivity = Date.now();
    await account.save();
    
    // Create transaction record
    const transaction = new Transaction({
      transactionId: Transaction.generateTransactionId(),
      toAccount: account._id,
      amount: parsedAmount,
      type: 'deposit',
      status: 'completed',
      description: 'Deposit',
      initiatedBy: req.userId
    });
    
    await transaction.save();
    
    res.status(200).json({
      status: 'success',
      data: {
        account,
        transaction
      }
    });
  } catch (err) {
    res.status(500).json({
      status: 'error',
      message: err.message
    });
  }
});

// Withdraw money
router.post('/:id/withdraw', async (req, res) => {
  try {
    const { amount } = req.body;
    const parsedAmount = parseFloat(amount);
    
    if (!amount || isNaN(parsedAmount) || parsedAmount <= 0) {
      return res.status(400).json({
        status: 'error',
        message: 'Amount must be a positive number'
      });
    }
    
    const account = await Account.findById(req.params.id);
    
    if (!account) {
      return res.status(404).json({
        status: 'error',
        message: 'Account not found'
      });
    }
    
    // Check if the account belongs to the logged-in user
    if (account.userId.toString() !== req.userId) {
      return res.status(403).json({
        status: 'error',
        message: 'You are not authorized to perform this action'
      });
    }
    
    // Check if the account has sufficient funds
    if (account.balance < parsedAmount) {
      return res.status(400).json({
        status: 'error',
        message: 'Insufficient funds'
      });
    }
    
    // Vulnerability 26: Race condition in withdrawal
    // Using the withdraw method of the account model which is vulnerable to race conditions
    try {
      await account.withdraw(parsedAmount);
      
      // Create transaction record
      const transaction = new Transaction({
        transactionId: Transaction.generateTransactionId(),
        fromAccount: account._id,
        amount: parsedAmount,
        type: 'withdrawal',
        status: 'completed',
        description: 'Withdrawal',
        initiatedBy: req.userId
      });
      
      await transaction.save();
      
      res.status(200).json({
        status: 'success',
        data: {
          account,
          transaction
        }
      });
    } catch (err) {
      return res.status(400).json({
        status: 'error',
        message: err.message
      });
    }
  } catch (err) {
    res.status(500).json({
      status: 'error',
      message: err.message
    });
  }
});

// Transfer money
router.post('/:id/transfer', async (req, res) => {
  try {
    const { targetAccountId, amount } = req.body;
    const parsedAmount = parseFloat(amount);
    
    if (!targetAccountId) {
      return res.status(400).json({
        status: 'error',
        message: 'Target account ID is required'
      });
    }
    
    if (!amount || isNaN(parsedAmount) || parsedAmount <= 0) {
      return res.status(400).json({
        status: 'error',
        message: 'Amount must be a positive number'
      });
    }
    
    const sourceAccount = await Account.findById(req.params.id);
    
    if (!sourceAccount) {
      return res.status(404).json({
        status: 'error',
        message: 'Source account not found'
      });
    }
    
    // Check if the source account belongs to the logged-in user
    if (sourceAccount.userId.toString() !== req.userId) {
      return res.status(403).json({
        status: 'error',
        message: 'You are not authorized to perform this action'
      });
    }
    
    const targetAccount = await Account.findById(targetAccountId);
    
    if (!targetAccount) {
      return res.status(404).json({
        status: 'error',
        message: 'Target account not found'
      });
    }
    
    // Check if the source account has sufficient funds
    if (sourceAccount.balance < parsedAmount) {
      return res.status(400).json({
        status: 'error',
        message: 'Insufficient funds'
      });
    }
    
    // Vulnerability 27: Race condition in transfer
    // Performing transfer without proper transaction management
    try {
      const transferResult = await sourceAccount.transfer(targetAccountId, parsedAmount);
      
      // Create transaction record
      const transaction = new Transaction({
        transactionId: Transaction.generateTransactionId(),
        fromAccount: sourceAccount._id,
        toAccount: targetAccount._id,
        amount: parsedAmount,
        type: 'transfer',
        status: 'completed',
        description: 'Transfer',
        initiatedBy: req.userId
      });
      
      await transaction.save();
      
      res.status(200).json({
        status: 'success',
        data: {
          sourceAccount: {
            id: sourceAccount._id,
            balance: transferResult.sourceBalance
          },
          targetAccount: {
            id: targetAccount._id,
            balance: transferResult.targetBalance
          },
          transaction
        }
      });
    } catch (err) {
      return res.status(400).json({
        status: 'error',
        message: err.message
      });
    }
  } catch (err) {
    res.status(500).json({
      status: 'error',
      message: err.message
    });
  }
});

// Get account transactions
router.get('/:id/transactions', async (req, res) => {
  try {
    const account = await Account.findById(req.params.id);
    
    if (!account) {
      return res.status(404).json({
        status: 'error',
        message: 'Account not found'
      });
    }
    
    // Check if the account belongs to the logged-in user
    if (account.userId.toString() !== req.userId) {
      return res.status(403).json({
        status: 'error',
        message: 'You are not authorized to view these transactions'
      });
    }
    
    // Vulnerability 28: Potential NoSQL injection in query parameter
    // Using raw query parameters without sanitization
    const { limit, sort, page } = req.query;
    
    // Construct query
    const query = {
      $or: [
        { fromAccount: account._id },
        { toAccount: account._id }
      ]
    };
    
    // Build query options
    const options = {};
    if (limit) options.limit = parseInt(limit, 10);
    if (sort) options.sort = sort;
    if (page) options.skip = (parseInt(page, 10) - 1) * (parseInt(limit, 10) || 10);
    
    const transactions = await Transaction.find(query, null, options);
    
    res.status(200).json({
      status: 'success',
      results: transactions.length,
      data: {
        transactions
      }
    });
  } catch (err) {
    res.status(500).json({
      status: 'error',
      message: err.message
    });
  }
});

module.exports = router; 