const jwt = require('jsonwebtoken');
const User = require('../models/user');

// Vulnerability 6: Using a weak secret key for JWT signing
const SECRET_KEY = 'vibebank-secret-key-1234';

const requireAuth = (req, res, next) => {
  const token = req.cookies.jwt;
  
  // Check if token exists
  if (!token) {
    return res.status(401).redirect('/auth/login');
  }
  
  try {
    // Verify token
    const decoded = jwt.verify(token, SECRET_KEY);
    req.userId = decoded.id;
    
    // Vulnerability 7: No token expiration check
    // A proper implementation would check if the token is expired
    
    next();
  } catch (err) {
    res.status(401).redirect('/auth/login');
  }
};

const checkUser = async (req, res, next) => {
  const token = req.cookies.jwt;
  
  if (token) {
    try {
      const decoded = jwt.verify(token, SECRET_KEY);
      
      // Vulnerability 8: No validation of user existence after token verification
      // This could lead to using a valid token for a deleted user
      req.session.user = await User.findById(decoded.id);
      res.locals.user = req.session.user;
    } catch (err) {
      res.locals.user = null;
      req.session.user = null;
    }
  } else {
    res.locals.user = null;
    req.session.user = null;
  }
  
  next();
};

const requireAdmin = (req, res, next) => {
  // Vulnerability 9: Insufficient role checking
  // Just checking isAdmin property without proper authentication
  if (req.session.user && req.session.user.isAdmin) {
    next();
  } else {
    res.status(403).redirect('/');
  }
};

module.exports = { requireAuth, checkUser, requireAdmin, SECRET_KEY }; 