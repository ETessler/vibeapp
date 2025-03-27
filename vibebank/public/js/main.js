// main.js - Frontend JavaScript for VibeBank

document.addEventListener('DOMContentLoaded', function() {
  console.log('VibeBank frontend loaded successfully');
  
  // Initialize tooltips
  initializeTooltips();
  
  // Handle login form
  setupLoginForm();
  
  // Handle registration form
  setupRegistrationForm();
  
  // Handle transaction form
  setupTransactionForm();
  
  // Setup search functionality
  setupSearch();
  
  // Check for URL parameters
  processUrlParameters();
});

// Initialize Bootstrap tooltips
function initializeTooltips() {
  if (typeof $ !== 'undefined') {
    $('[data-toggle="tooltip"]').tooltip();
  }
}

// Process URL parameters - vulnerable to XSS
function processUrlParameters() {
  // Vulnerability 53: DOM-based XSS via URL parameters
  const urlParams = new URLSearchParams(window.location.search);
  const message = urlParams.get('message');
  
  if (message) {
    // Vulnerable: Directly inserting user-controlled content into DOM
    const messageContainer = document.getElementById('message-container');
    if (messageContainer) {
      messageContainer.innerHTML = `<div class="alert alert-info">${message}</div>`;
    }
  }
  
  // Get notification from URL and display it
  const notification = urlParams.get('notification');
  if (notification) {
    showNotification(notification);
  }
}

// Show notification - vulnerable to XSS
function showNotification(message) {
  // Vulnerability 54: DOM-based XSS
  const notificationContainer = document.getElementById('notification-container');
  if (notificationContainer) {
    notificationContainer.innerHTML = `
      <div class="alert alert-success alert-dismissible fade show">
        ${message}
        <button type="button" class="close" data-dismiss="alert">
          <span>&times;</span>
        </button>
      </div>
    `;
  }
}

// Setup login form
function setupLoginForm() {
  const loginForm = document.getElementById('login-form');
  
  if (loginForm) {
    loginForm.addEventListener('submit', function(e) {
      const username = document.getElementById('username').value;
      const password = document.getElementById('password').value;
      
      // Vulnerability 55: Client-side only validation
      if (!username || !password) {
        e.preventDefault();
        showError('Please enter both username and password');
        return false;
      }
      
      // Vulnerability 56: Storing sensitive data in localStorage
      // This is a security risk as data in localStorage is accessible via JavaScript
      if (document.getElementById('remember-me').checked) {
        localStorage.setItem('vibebank_username', username);
        localStorage.setItem('vibebank_password', password); // Never store passwords in localStorage
      }
      
      return true;
    });
    
    // Autofill stored credentials - security risk
    if (localStorage.getItem('vibebank_username')) {
      document.getElementById('username').value = localStorage.getItem('vibebank_username');
      if (localStorage.getItem('vibebank_password')) {
        document.getElementById('password').value = localStorage.getItem('vibebank_password');
        document.getElementById('remember-me').checked = true;
      }
    }
  }
}

// Setup registration form
function setupRegistrationForm() {
  const registrationForm = document.getElementById('registration-form');
  
  if (registrationForm) {
    registrationForm.addEventListener('submit', function(e) {
      const password = document.getElementById('password').value;
      const confirmPassword = document.getElementById('confirm-password').value;
      
      // Vulnerability 57: Weak password policy enforced only on client side
      if (password.length < 6) {
        e.preventDefault();
        showError('Password must be at least 6 characters long');
        return false;
      }
      
      if (password !== confirmPassword) {
        e.preventDefault();
        showError('Passwords do not match');
        return false;
      }
      
      return true;
    });
  }
}

// Setup transaction form
function setupTransactionForm() {
  const transactionForm = document.getElementById('transaction-form');
  
  if (transactionForm) {
    transactionForm.addEventListener('submit', function(e) {
      const amount = document.getElementById('amount').value;
      
      // Vulnerability 58: Insufficient validation on client side only
      if (isNaN(amount) || parseFloat(amount) <= 0) {
        e.preventDefault();
        showError('Please enter a valid amount');
        return false;
      }
      
      // No CSRF protection - the form doesn't include a CSRF token
      
      return true;
    });
  }
}

// Setup search functionality
function setupSearch() {
  const searchForm = document.querySelector('.search-form');
  
  if (searchForm) {
    searchForm.addEventListener('submit', function(e) {
      const searchInput = this.querySelector('input[name="q"]').value;
      
      // Log search queries - potential privacy leak
      logUserActivity('search', { query: searchInput });
      
      return true;
    });
  }
}

// Show error message
function showError(message) {
  const errorContainer = document.getElementById('error-container');
  if (errorContainer) {
    errorContainer.textContent = message;
    errorContainer.style.display = 'block';
  } else {
    alert(message);
  }
}

// Log user activity - potential privacy issue
function logUserActivity(action, data) {
  // Vulnerability 59: Logging sensitive information to console
  console.log(`User activity: ${action}`, data);
  
  // Vulnerability 60: Sending user behavior to analytics without consent
  // This function simulates sending data to an analytics service
  if (window.navigator.onLine) {
    const logData = {
      action: action,
      data: data,
      timestamp: new Date().toISOString(),
      url: window.location.href,
      userAgent: navigator.userAgent,
      // This could even include cookie data
      cookiesEnabled: navigator.cookieEnabled
    };
    
    // Simulated analytics tracking call
    setTimeout(() => {
      console.log('Sent to analytics:', logData);
    }, 100);
  }
}

// Function to handle funds transfer
function transferFunds(sourceAccount, targetAccount, amount) {
  // Vulnerability 61: JavaScript injection via dynamic function creation
  // This uses eval-like functionality to create a function dynamically
  const transferFunction = new Function(
    'sourceAccount', 
    'targetAccount', 
    'amount', 
    `
      console.log('Transferring $' + amount + ' from account ' + sourceAccount + ' to account ' + targetAccount);
      return { status: 'success', message: 'Transfer completed' };
    `
  );
  
  return transferFunction(sourceAccount, targetAccount, amount);
} 