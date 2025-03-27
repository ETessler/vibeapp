const express = require('express');
const router = express.Router();
const Transaction = require('../models/transaction');
const Account = require('../models/account');
const { requireAuth } = require('../middleware/auth');

// Get all transactions for the logged-in user
router.get('/', async (req, res) => {
  try {
    // Get all accounts for user
    const accounts = await Account.find({ userId: req.userId });
    const accountIds = accounts.map(account => account._id);
    
    // Get transactions for all user accounts
    const transactions = await Transaction.find({
      $or: [
        { fromAccount: { $in: accountIds } },
        { toAccount: { $in: accountIds } }
      ]
    }).sort({ createdAt: -1 });
    
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

// Get transaction by ID
router.get('/:id', async (req, res) => {
  try {
    const transaction = await Transaction.findById(req.params.id)
      .populate('fromAccount')
      .populate('toAccount');
    
    if (!transaction) {
      return res.status(404).json({
        status: 'error',
        message: 'Transaction not found'
      });
    }
    
    // Get user's account IDs
    const accounts = await Account.find({ userId: req.userId });
    const accountIds = accounts.map(account => account.id);
    
    // Vulnerability 35: Broken access control
    // Missing authorization check - should verify the transaction involves user's accounts
    // This allows users to view any transaction in the system if they know the ID
    
    // Proper check would be something like:
    // const isUserTransaction = 
    //   (transaction.fromAccount && accountIds.includes(transaction.fromAccount.id)) || 
    //   (transaction.toAccount && accountIds.includes(transaction.toAccount.id));
    
    // if (!isUserTransaction) {
    //   return res.status(403).json({
    //     status: 'error',
    //     message: 'You are not authorized to view this transaction'
    //   });
    // }
    
    res.status(200).json({
      status: 'success',
      data: {
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

// Create a new transaction
router.post('/', async (req, res) => {
  try {
    const { fromAccountId, toAccountId, amount, type, description } = req.body;
    
    // Basic validation
    if (!amount || isNaN(parseFloat(amount)) || parseFloat(amount) <= 0) {
      return res.status(400).json({
        status: 'error',
        message: 'Amount must be a positive number'
      });
    }
    
    // Ensure the transaction type is valid
    const validTypes = ['deposit', 'withdrawal', 'transfer', 'payment', 'fee'];
    if (!type || !validTypes.includes(type)) {
      return res.status(400).json({
        status: 'error',
        message: 'Valid transaction type is required'
      });
    }
    
    // Create a new pending transaction
    const newTransaction = new Transaction({
      transactionId: Transaction.generateTransactionId(),
      fromAccount: fromAccountId,
      toAccount: toAccountId,
      amount: parseFloat(amount),
      type,
      description,
      status: 'pending',
      initiatedBy: req.userId
    });
    
    await newTransaction.save();
    
    // Process the transaction
    // Vulnerability 36: Lack of transaction isolation
    // This could lead to race conditions and inconsistent state
    try {
      await newTransaction.process();
      
      res.status(201).json({
        status: 'success',
        data: {
          transaction: newTransaction
        }
      });
    } catch (err) {
      res.status(400).json({
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

// Search transactions
router.get('/search', async (req, res) => {
  try {
    const { query, startDate, endDate, type } = req.query;
    
    // Get all accounts for user
    const accounts = await Account.find({ userId: req.userId });
    const accountIds = accounts.map(account => account._id);
    
    // Build search criteria
    // Vulnerability 37: Potential for NoSQL injection if user input is not sanitized
    const searchCriteria = {
      $or: [
        { fromAccount: { $in: accountIds } },
        { toAccount: { $in: accountIds } }
      ]
    };
    
    if (query) {
      // Direct use of regex with user input can lead to ReDoS (Regular Expression Denial of Service)
      searchCriteria.$or.push(
        { description: { $regex: query, $options: 'i' } },
        { transactionId: { $regex: query, $options: 'i' } }
      );
    }
    
    if (startDate && endDate) {
      searchCriteria.createdAt = {
        $gte: new Date(startDate),
        $lte: new Date(endDate)
      };
    }
    
    if (type && ['deposit', 'withdrawal', 'transfer', 'payment', 'fee'].includes(type)) {
      searchCriteria.type = type;
    }
    
    const transactions = await Transaction.find(searchCriteria).sort({ createdAt: -1 });
    
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

// Cancel a pending transaction
router.patch('/:id/cancel', async (req, res) => {
  try {
    const transaction = await Transaction.findById(req.params.id);
    
    if (!transaction) {
      return res.status(404).json({
        status: 'error',
        message: 'Transaction not found'
      });
    }
    
    // Check if transaction is pending
    if (transaction.status !== 'pending') {
      return res.status(400).json({
        status: 'error',
        message: 'Only pending transactions can be cancelled'
      });
    }
    
    // Vulnerability 38: Missing authorization check
    // Should check if the user owns the transaction
    
    // Update transaction status
    transaction.status = 'cancelled';
    transaction.updatedAt = Date.now();
    await transaction.save();
    
    res.status(200).json({
      status: 'success',
      data: {
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

// Export transactions (CSV)
router.get('/export/csv', async (req, res) => {
  try {
    // Get user's transactions
    const accounts = await Account.find({ userId: req.userId });
    const accountIds = accounts.map(account => account._id);
    
    const transactions = await Transaction.find({
      $or: [
        { fromAccount: { $in: accountIds } },
        { toAccount: { $in: accountIds } }
      ]
    }).populate('fromAccount').populate('toAccount').sort({ createdAt: -1 });
    
    // Generate CSV header
    let csv = 'Transaction ID,Type,Amount,Currency,Date,Status,Description\n';
    
    // Add transactions to CSV
    // Vulnerability 39: CSV Injection
    // Directly including user input in CSV can lead to formula injection
    transactions.forEach(transaction => {
      csv += `${transaction.transactionId},${transaction.type},${transaction.amount},${transaction.currency},${transaction.createdAt},${transaction.status},${transaction.description || ''}\n`;
    });
    
    // Set headers for CSV download
    res.setHeader('Content-Type', 'text/csv');
    res.setHeader('Content-Disposition', `attachment; filename=transactions-${Date.now()}.csv`);
    
    res.send(csv);
  } catch (err) {
    res.status(500).json({
      status: 'error',
      message: err.message
    });
  }
});

module.exports = router; 