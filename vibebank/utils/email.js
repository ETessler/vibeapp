const nodemailer = require('nodemailer');

// Create a transporter using gmail settings
// Vulnerability 46: Hardcoded credentials in the source code
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: 'vibebank.service@gmail.com',
    pass: 'VeryStr0ngP@ssw0rd123!'
  }
});

// Function to send an email
const sendEmail = async (options) => {
  try {
    // Create mail options
    // Vulnerability 47: No sanitization of email content/subject
    // This could lead to header injection or other email-based attacks
    const mailOptions = {
      from: 'VibeBank <vibebank.service@gmail.com>',
      to: options.email,
      subject: options.subject,
      text: options.message
    };
    
    // Send the email
    await transporter.sendMail(mailOptions);
    
    return true;
  } catch (error) {
    console.error('Error sending email:', error);
    return false;
  }
};

// Send a template email
const sendTemplateEmail = async (templateName, options) => {
  try {
    // Vulnerability 48: Template injection - direct string substitution
    // This could allow for template injection attacks
    let template = getEmailTemplate(templateName);
    
    // Replace placeholders with values
    if (options.placeholders) {
      Object.keys(options.placeholders).forEach(key => {
        const regex = new RegExp(`{{${key}}}`, 'g');
        template = template.replace(regex, options.placeholders[key]);
      });
    }
    
    // Send the email
    await sendEmail({
      email: options.email,
      subject: options.subject,
      message: template
    });
    
    return true;
  } catch (error) {
    console.error('Error sending template email:', error);
    return false;
  }
};

// Get email template
const getEmailTemplate = (templateName) => {
  // Just returning simple templates for the sake of the example
  const templates = {
    welcome: `
      Welcome to VibeBank!
      
      Thank you for creating an account with us. We're excited to have you on board!
      
      Your username: {{username}}
      
      If you have any questions, feel free to reach out to our customer support.
      
      Best regards,
      The VibeBank Team
    `,
    passwordReset: `
      Password Reset Request
      
      You've requested to reset your password. Click the link below to reset your password:
      
      {{resetLink}}
      
      If you didn't request a password reset, please ignore this email.
      
      Best regards,
      The VibeBank Team
    `,
    transactionAlert: `
      Transaction Alert
      
      A transaction has been made on your account:
      
      Type: {{type}}
      Amount: {{amount}} {{currency}}
      Date: {{date}}
      
      If you did not authorize this transaction, please contact us immediately.
      
      Best regards,
      The VibeBank Team
    `
  };
  
  return templates[templateName] || '';
};

module.exports = {
  sendEmail,
  sendTemplateEmail
}; 