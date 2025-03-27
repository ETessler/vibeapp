const express = require('express');
const bodyParser = require('body-parser');
const path = require('path');
const mongoose = require('mongoose');
const session = require('express-session');
const MongoStore = require('connect-mongo')(session);
const cookieParser = require('cookie-parser');
const { exec } = require('child_process');
const fs = require('fs');

// Import routes
const authRoutes = require('./routes/auth');
const accountRoutes = require('./routes/accounts');
const transactionRoutes = require('./routes/transactions');
const adminRoutes = require('./routes/admin');
const userRoutes = require('./routes/users');

// Import middleware
const { requireAuth } = require('./middleware/auth');

// Initialize express app
const app = express();
const PORT = process.env.PORT || 3000;

// Connect to MongoDB
// Vulnerability 1: Hardcoded credentials in the source code
const dbUri = 'mongodb://admin:Password123@localhost:27017/vibebank';
mongoose.connect(dbUri, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
  useCreateIndex: true
}).then(() => {
  console.log('Connected to MongoDB');
}).catch(err => {
  console.error('MongoDB connection error:', err);
});

// Middleware
app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());
app.use(cookieParser());

// Session configuration
app.use(session({
  secret: 'vibebankSecret2023',
  resave: false,
  saveUninitialized: false,
  store: new MongoStore({ mongooseConnection: mongoose.connection }),
  cookie: { maxAge: 60 * 60 * 1000 } // 1 hour
}));

// Template engine
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// Static files
app.use(express.static(path.join(__dirname, 'public')));

// Vulnerability 2: Information leakage through verbose errors
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).send(err.stack);
});

// Helper function that's vulnerable to command injection
// Vulnerability 3: Command injection
app.get('/ping', (req, res) => {
  const { host } = req.query;
  if (!host) {
    return res.status(400).send('Host parameter is required');
  }
  
  // Vulnerable code: directly using user input in exec
  exec(`ping -c 4 ${host}`, (error, stdout, stderr) => {
    if (error) {
      return res.status(500).send(`Error: ${error.message}`);
    }
    res.send(`<pre>${stdout}</pre>`);
  });
});

// Debug route to get system info
app.get('/debug/system', (req, res) => {
  exec('systeminfo', (error, stdout) => {
    res.send(`<pre>${stdout}</pre>`);
  });
});

// Routes
app.use('/auth', authRoutes);
app.use('/accounts', requireAuth, accountRoutes);
app.use('/transactions', requireAuth, transactionRoutes);
app.use('/users', requireAuth, userRoutes);
app.use('/admin', adminRoutes); // Vulnerability 4: No authentication middleware on admin routes

// Home route
app.get('/', (req, res) => {
  res.render('index', { user: req.session.user || null });
});

// Error handler - should be last
app.use((req, res) => {
  res.status(404).render('404');
});

// Start server
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
  
  // Vulnerability 5: Using fs.writeFile synchronously with user-controlled data
  fs.writeFileSync('server_log.txt', `Server started at ${new Date()}`);
});

module.exports = app; 