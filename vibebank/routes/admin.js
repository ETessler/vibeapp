const express = require('express');
const router = express.Router();
const User = require('../models/user');
const Account = require('../models/account');
const Transaction = require('../models/transaction');
const { requireAdmin } = require('../middleware/auth');
const { exec } = require('child_process');
const fs = require('fs');
const path = require('path');

// Dashboard
router.get('/', (req, res) => {
  // Vulnerability 29: Missing authentication check for admin dashboard
  // This should use requireAdmin middleware
  res.render('admin/dashboard');
});

// Get all users
router.get('/users', requireAdmin, async (req, res) => {
  try {
    const users = await User.find().select('-password');
    
    res.status(200).json({
      status: 'success',
      results: users.length,
      data: {
        users
      }
    });
  } catch (err) {
    res.status(500).json({
      status: 'error',
      message: err.message
    });
  }
});

// Get user by ID
router.get('/users/:id', requireAdmin, async (req, res) => {
  try {
    const user = await User.findById(req.params.id).select('-password');
    
    if (!user) {
      return res.status(404).json({
        status: 'error',
        message: 'User not found'
      });
    }
    
    // Get user's accounts
    const accounts = await Account.find({ userId: user._id });
    
    res.status(200).json({
      status: 'success',
      data: {
        user,
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

// Update user
router.patch('/users/:id', requireAdmin, async (req, res) => {
  try {
    // Vulnerability 30: No validation or sanitization of input
    // This could allow for NoSQL injection or storing malicious data
    const updatedUser = await User.findByIdAndUpdate(
      req.params.id,
      req.body,
      {
        new: true,
        runValidators: false
      }
    );
    
    if (!updatedUser) {
      return res.status(404).json({
        status: 'error',
        message: 'User not found'
      });
    }
    
    res.status(200).json({
      status: 'success',
      data: {
        user: updatedUser
      }
    });
  } catch (err) {
    res.status(500).json({
      status: 'error',
      message: err.message
    });
  }
});

// Delete user
router.delete('/users/:id', requireAdmin, async (req, res) => {
  try {
    const user = await User.findById(req.params.id);
    
    if (!user) {
      return res.status(404).json({
        status: 'error',
        message: 'User not found'
      });
    }
    
    // Delete user's accounts
    await Account.deleteMany({ userId: user._id });
    
    // Delete the user
    await User.findByIdAndDelete(req.params.id);
    
    res.status(204).json({
      status: 'success',
      data: null
    });
  } catch (err) {
    res.status(500).json({
      status: 'error',
      message: err.message
    });
  }
});

// Get system logs
router.get('/logs', requireAdmin, (req, res) => {
  // Vulnerability 31: Unrestricted file access through path traversal
  const { file } = req.query;
  const logPath = file || 'server_log.txt';
  
  try {
    // This is vulnerable to path traversal since it doesn't restrict the file path
    const filePath = path.join(__dirname, '..', logPath);
    const data = fs.readFileSync(filePath, 'utf8');
    
    res.send(`<pre>${data}</pre>`);
  } catch (err) {
    res.status(500).json({
      status: 'error',
      message: err.message
    });
  }
});

// Execute system command
router.post('/execute', requireAdmin, (req, res) => {
  // Vulnerability 32: Command injection
  const { command } = req.body;
  
  if (!command) {
    return res.status(400).json({
      status: 'error',
      message: 'Command is required'
    });
  }
  
  // Vulnerable command execution
  exec(command, (error, stdout, stderr) => {
    if (error) {
      return res.status(500).json({
        status: 'error',
        message: error.message
      });
    }
    
    res.json({
      status: 'success',
      data: {
        output: stdout
      }
    });
  });
});

// Import data
router.post('/import', requireAdmin, (req, res) => {
  try {
    // Vulnerability 33: Insecure deserialization
    const { data } = req.body;
    
    if (!data) {
      return res.status(400).json({
        status: 'error',
        message: 'Data is required'
      });
    }
    
    // Dangerous parsing of JSON with potential JavaScript code execution
    const parsedData = eval('(' + data + ')');
    
    // Process the data
    if (parsedData.users) {
      // Import users
    }
    
    if (parsedData.accounts) {
      // Import accounts
    }
    
    if (parsedData.transactions) {
      // Import transactions
    }
    
    res.status(200).json({
      status: 'success',
      message: 'Data imported successfully'
    });
  } catch (err) {
    res.status(500).json({
      status: 'error',
      message: err.message
    });
  }
});

// Generate report
router.get('/reports/:type', requireAdmin, async (req, res) => {
  try {
    const { type } = req.params;
    const { startDate, endDate, format } = req.query;
    
    // Vulnerability 34: XSS in reports
    let reportHtml = `<h1>Report: ${type}</h1>`;
    
    if (type === 'transactions') {
      // Query transactions within date range
      const query = {};
      
      if (startDate && endDate) {
        query.createdAt = {
          $gte: new Date(startDate),
          $lte: new Date(endDate)
        };
      }
      
      const transactions = await Transaction.find(query)
        .populate('fromAccount')
        .populate('toAccount')
        .populate('initiatedBy');
      
      reportHtml += `<p>Total transactions: ${transactions.length}</p>`;
      reportHtml += '<table border="1"><tr><th>ID</th><th>Type</th><th>Amount</th><th>Date</th><th>Status</th></tr>';
      
      transactions.forEach(transaction => {
        // XSS vulnerability: directly injecting user input into HTML
        reportHtml += `<tr>
          <td>${transaction.transactionId}</td>
          <td>${transaction.type}</td>
          <td>${transaction.amount} ${transaction.currency}</td>
          <td>${transaction.createdAt}</td>
          <td>${transaction.status}</td>
        </tr>`;
      });
      
      reportHtml += '</table>';
    } else if (type === 'users') {
      const users = await User.find().select('-password');
      
      reportHtml += `<p>Total users: ${users.length}</p>`;
      reportHtml += '<table border="1"><tr><th>ID</th><th>Username</th><th>Email</th><th>Name</th><th>Is Admin</th></tr>';
      
      users.forEach(user => {
        // XSS vulnerability: directly injecting user input into HTML
        reportHtml += `<tr>
          <td>${user._id}</td>
          <td>${user.username}</td>
          <td>${user.email}</td>
          <td>${user.firstName} ${user.lastName}</td>
          <td>${user.isAdmin ? 'Yes' : 'No'}</td>
        </tr>`;
      });
      
      reportHtml += '</table>';
    }
    
    // Send report in requested format
    if (format === 'json') {
      res.json({
        status: 'success',
        data: {
          report: reportHtml
        }
      });
    } else {
      // Sending raw HTML - vulnerable to XSS
      res.send(reportHtml);
    }
  } catch (err) {
    res.status(500).json({
      status: 'error',
      message: err.message
    });
  }
});

module.exports = router; 