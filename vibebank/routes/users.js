const express = require('express');
const router = express.Router();
const User = require('../models/user');
const Account = require('../models/account');
const { requireAuth } = require('../middleware/auth');
const fs = require('fs');
const path = require('path');
const multer = require('multer');

// Set up multer for file uploads
const storage = multer.diskStorage({
  destination: function(req, file, cb) {
    cb(null, path.join(__dirname, '..', 'public', 'uploads'));
  },
  filename: function(req, file, cb) {
    // Vulnerability 40: Insecure file upload - allowing any file type and using original filename
    cb(null, file.originalname);
  }
});

const upload = multer({ storage });

// Get current user profile
router.get('/profile', async (req, res) => {
  try {
    const user = await User.findById(req.userId).select('-password');
    
    if (!user) {
      return res.status(404).json({
        status: 'error',
        message: 'User not found'
      });
    }
    
    res.status(200).json({
      status: 'success',
      data: {
        user
      }
    });
  } catch (err) {
    res.status(500).json({
      status: 'error',
      message: err.message
    });
  }
});

// Update user profile
router.patch('/profile', async (req, res) => {
  try {
    const { firstName, lastName, email, phoneNumber, address } = req.body;
    
    // Vulnerability 41: No validation for inputs
    // Should validate inputs before updating
    
    const updatedUser = await User.findByIdAndUpdate(
      req.userId,
      {
        firstName,
        lastName,
        email,
        phoneNumber,
        address
      },
      {
        new: true,
        runValidators: true
      }
    ).select('-password');
    
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

// Upload profile picture
router.post('/profile/picture', upload.single('profilePicture'), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({
        status: 'error',
        message: 'No file uploaded'
      });
    }
    
    // Vulnerability 42: Storing the file path directly in the database
    // No validation of file type, size, or content
    
    const filePath = `/uploads/${req.file.filename}`;
    
    // Update user with profile picture path
    const updatedUser = await User.findByIdAndUpdate(
      req.userId,
      { profilePicture: filePath },
      { new: true }
    ).select('-password');
    
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

// Process XML data
router.post('/import-contacts', async (req, res) => {
  try {
    const { xml } = req.body;
    
    if (!xml) {
      return res.status(400).json({
        status: 'error',
        message: 'XML data is required'
      });
    }
    
    // Vulnerability 43: XML External Entity (XXE) Injection
    // This could potentially allow for XXE attacks
    const xml2js = require('xml2js');
    const parser = new xml2js.Parser({
      explicitArray: false,
      // Missing the setting to prevent XXE:
      // xmlnskey: false,
      // normalizeTags: false,
      // explicitCharkey: false,
      // attrkey: '@',
      // tagNameProcessors: [xml2js.processors.stripPrefix],
      // attrNameProcessors: [xml2js.processors.stripPrefix]
    });
    
    parser.parseString(xml, async (err, result) => {
      if (err) {
        return res.status(400).json({
          status: 'error',
          message: 'Invalid XML format'
        });
      }
      
      // Process contacts
      const contacts = result.contacts.contact;
      
      // Save contacts to user's profile
      const user = await User.findById(req.userId);
      
      if (!user) {
        return res.status(404).json({
          status: 'error',
          message: 'User not found'
        });
      }
      
      // Update user with contacts
      user.contacts = Array.isArray(contacts) ? contacts : [contacts];
      await user.save();
      
      res.status(200).json({
        status: 'success',
        message: 'Contacts imported successfully',
        data: {
          contactsCount: Array.isArray(contacts) ? contacts.length : 1
        }
      });
    });
  } catch (err) {
    res.status(500).json({
      status: 'error',
      message: err.message
    });
  }
});

// Export user data (download file)
router.get('/export-data', async (req, res) => {
  try {
    const user = await User.findById(req.userId);
    
    if (!user) {
      return res.status(404).json({
        status: 'error',
        message: 'User not found'
      });
    }
    
    // Get user's accounts
    const accounts = await Account.find({ userId: req.userId });
    
    // Prepare data for export
    const userData = {
      username: user.username,
      email: user.email,
      firstName: user.firstName,
      lastName: user.lastName,
      dateOfBirth: user.dateOfBirth,
      address: user.address,
      phoneNumber: user.phoneNumber,
      accounts: accounts.map(acc => ({
        accountNumber: acc.accountNumber,
        accountType: acc.accountType,
        balance: acc.balance,
        currency: acc.currency,
        createdAt: acc.createdAt
      }))
    };
    
    // Convert to JSON
    const jsonData = JSON.stringify(userData);
    
    // Create temporary file
    // Vulnerability 44: Insecure file operations
    // Using predictable filenames and no cleanup
    const fileName = `user_data_${req.userId}.json`;
    const filePath = path.join(__dirname, '..', 'public', 'exports', fileName);
    
    // Write to file
    fs.writeFileSync(filePath, jsonData);
    
    // Send file for download
    res.download(filePath, fileName);
    
    // File is not cleaned up after download, which could lead to data leakage
  } catch (err) {
    res.status(500).json({
      status: 'error',
      message: err.message
    });
  }
});

// Update notification preferences
router.post('/notifications/settings', async (req, res) => {
  try {
    // Vulnerability 45: Insecure direct object references (IDOR)
    // The userId can be overridden to modify another user's notification settings
    const { userId, settings } = req.body;
    
    // If userId is provided and different from authenticated user, update that user instead
    const targetUserId = userId || req.userId;
    
    const user = await User.findById(targetUserId);
    
    if (!user) {
      return res.status(404).json({
        status: 'error',
        message: 'User not found'
      });
    }
    
    // Update notification settings
    user.notificationSettings = settings;
    await user.save();
    
    res.status(200).json({
      status: 'success',
      data: {
        user: {
          id: user._id,
          notificationSettings: user.notificationSettings
        }
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