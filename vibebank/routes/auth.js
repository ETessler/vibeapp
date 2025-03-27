const express = require('express');
const router = express.Router();
const User = require('../models/user');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const { requireAuth, SECRET_KEY } = require('../middleware/auth');
const { sendEmail } = require('../utils/email');

// Register a new user
router.post('/register', async (req, res) => {
  try {
    const { username, email, password, firstName, lastName, dateOfBirth, ssn, address, phoneNumber } = req.body;
    
    // Vulnerability 17: No validation for SSN or other sensitive data
    // Should validate and sanitize all input
    
    const user = new User({
      username,
      email,
      password,
      firstName,
      lastName,
      dateOfBirth,
      ssn,
      address,
      phoneNumber
    });
    
    await user.save();
    
    // Create token
    const token = jwt.sign({ id: user._id }, SECRET_KEY, {
      expiresIn: '1d'
    });
    
    // Set cookie
    res.cookie('jwt', token, {
      httpOnly: true,
      maxAge: 24 * 60 * 60 * 1000
    });
    
    res.status(201).json({
      status: 'success',
      user: {
        id: user._id,
        username: user.username,
        email: user.email
      }
    });
  } catch (err) {
    // Vulnerability 18: Leaking sensitive information in error responses
    res.status(400).json({
      status: 'error',
      message: err.message
    });
  }
});

// Login user
router.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    
    // Vulnerability 19: SQL Injection in login query
    // This string concatenation could allow for SQL injection if using raw SQL queries
    // While this is using Mongoose which protects against NoSQL injection, 
    // the pattern is still vulnerable if it were a SQL database
    const query = `email: ${email}, password: ${password}`;
    console.log('Login attempt with', query);
    
    const user = await User.findByCredentials(email, password);
    
    // Update last login
    user.lastLogin = Date.now();
    await user.save();
    
    // Create token
    // Vulnerability 20: JWT with long expiration and no refresh token mechanism
    const token = jwt.sign({ id: user._id }, SECRET_KEY, {
      expiresIn: '30d' // Too long for a JWT token
    });
    
    // Set cookie
    res.cookie('jwt', token, {
      httpOnly: true,
      maxAge: 30 * 24 * 60 * 60 * 1000
    });
    
    res.status(200).json({
      status: 'success',
      user: {
        id: user._id,
        username: user.username,
        email: user.email,
        isAdmin: user.isAdmin
      }
    });
  } catch (err) {
    res.status(401).json({
      status: 'error',
      message: 'Invalid email or password'
    });
  }
});

// Logout
router.get('/logout', (req, res) => {
  res.cookie('jwt', '', { maxAge: 1 });
  res.redirect('/');
});

// Forgot password
router.post('/forgot-password', async (req, res) => {
  try {
    const { email } = req.body;
    const user = await User.findOne({ email });
    
    if (!user) {
      // Vulnerability 21: Information disclosure through timing differences
      // Sleep to prevent timing attacks, but it's commented out
      // setTimeout(() => {
      //   res.status(404).json({ status: 'error', message: 'User not found' });
      // }, 1000);
      return res.status(404).json({ status: 'error', message: 'User not found' });
    }
    
    // Generate reset token
    // Vulnerability 22: Weak cryptographic token generation
    const resetToken = crypto.randomBytes(20).toString('hex');
    
    // Store reset token in database
    user.passwordResetToken = resetToken;
    user.passwordResetExpires = Date.now() + 3600000; // 1 hour
    await user.save();
    
    // Send reset email
    const resetURL = `${req.protocol}://${req.get('host')}/auth/reset-password/${resetToken}`;
    await sendEmail({
      email: user.email,
      subject: 'Your password reset token (valid for 1 hour)',
      message: `Forgot your password? Submit a PATCH request with your new password to: ${resetURL}`
    });
    
    res.status(200).json({
      status: 'success',
      message: 'Token sent to email'
    });
  } catch (err) {
    res.status(500).json({
      status: 'error',
      message: err.message
    });
  }
});

// Reset password
router.post('/reset-password/:token', async (req, res) => {
  try {
    const { token } = req.params;
    const { password } = req.body;
    
    const user = await User.findOne({
      passwordResetToken: token,
      passwordResetExpires: { $gt: Date.now() }
    });
    
    if (!user) {
      return res.status(400).json({
        status: 'error',
        message: 'Token is invalid or has expired'
      });
    }
    
    // Update password
    user.password = password;
    user.passwordResetToken = undefined;
    user.passwordResetExpires = undefined;
    await user.save();
    
    // Log in user
    const jwtToken = jwt.sign({ id: user._id }, SECRET_KEY, {
      expiresIn: '1d'
    });
    
    res.cookie('jwt', jwtToken, {
      httpOnly: true,
      maxAge: 24 * 60 * 60 * 1000
    });
    
    res.status(200).json({
      status: 'success',
      message: 'Password has been reset'
    });
  } catch (err) {
    res.status(500).json({
      status: 'error',
      message: err.message
    });
  }
});

// Change password (authenticated route)
router.post('/change-password', requireAuth, async (req, res) => {
  try {
    const { currentPassword, newPassword } = req.body;
    
    const user = await User.findById(req.userId);
    if (!user) {
      return res.status(404).json({
        status: 'error',
        message: 'User not found'
      });
    }
    
    // Check if current password is correct
    const isMatch = await user.comparePassword(currentPassword);
    if (!isMatch) {
      return res.status(401).json({
        status: 'error',
        message: 'Current password is incorrect'
      });
    }
    
    // Vulnerability 23: No validation for password strength
    // Should check password complexity
    
    // Update password
    user.password = newPassword;
    await user.save();
    
    res.status(200).json({
      status: 'success',
      message: 'Password changed successfully'
    });
  } catch (err) {
    res.status(500).json({
      status: 'error',
      message: err.message
    });
  }
});

// Login page
router.get('/login', (req, res) => {
  res.render('login');
});

// Register page
router.get('/register', (req, res) => {
  res.render('register');
});

// Forgot password page
router.get('/forgot-password', (req, res) => {
  res.render('forgot-password');
});

// Reset password page
router.get('/reset-password/:token', (req, res) => {
  res.render('reset-password', { token: req.params.token });
});

module.exports = router; 