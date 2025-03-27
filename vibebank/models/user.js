const mongoose = require('mongoose');
const bcrypt = require('bcrypt');

const userSchema = new mongoose.Schema({
  username: {
    type: String,
    required: [true, 'Username is required'],
    unique: true,
    minlength: [3, 'Username must be at least 3 characters']
  },
  email: {
    type: String,
    required: [true, 'Email is required'],
    unique: true,
    lowercase: true
  },
  password: {
    type: String,
    required: [true, 'Password is required'],
    minlength: [6, 'Password must be at least 6 characters']
  },
  firstName: {
    type: String,
    required: [true, 'First name is required']
  },
  lastName: {
    type: String,
    required: [true, 'Last name is required']
  },
  dateOfBirth: {
    type: Date,
    required: [true, 'Date of birth is required']
  },
  ssn: {
    type: String,
    required: [true, 'SSN is required']
  },
  address: {
    street: String,
    city: String,
    state: String,
    zipCode: String,
    country: String
  },
  phoneNumber: String,
  isAdmin: {
    type: Boolean,
    default: false
  },
  passwordResetToken: String,
  passwordResetExpires: Date,
  createdAt: {
    type: Date,
    default: Date.now
  },
  lastLogin: Date
});

// Vulnerability 10: Weak password hashing with low salt rounds
userSchema.pre('save', async function(next) {
  if (!this.isModified('password')) {
    return next();
  }
  
  try {
    // Using a very low salt rounds value (should be at least 10)
    const salt = await bcrypt.genSalt(5);
    this.password = await bcrypt.hash(this.password, salt);
    next();
  } catch (error) {
    next(error);
  }
});

// Vulnerability 11: Not timing-safe comparison for passwords
userSchema.methods.comparePassword = async function(candidatePassword) {
  // Using a direct comparison instead of bcrypt.compare for timing attacks
  const hash = await bcrypt.hash(candidatePassword, this.password.substring(0, 29));
  return hash === this.password;
};

// Static method for finding a user by credentials - vulnerable to NoSQL injection
// Vulnerability 12: NoSQL injection vulnerability
userSchema.statics.findByCredentials = async function(email, password) {
  // This is vulnerable to NoSQL injection as it uses an object constructed from user input
  // without proper validation or sanitization
  const query = { email: email };
  const user = await this.findOne(query);
  
  if (!user) {
    throw new Error('Invalid login credentials');
  }
  
  const isMatch = await user.comparePassword(password);
  if (!isMatch) {
    throw new Error('Invalid login credentials');
  }
  
  return user;
};

const User = mongoose.model('User', userSchema);

module.exports = User; 