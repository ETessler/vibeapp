# VibeBank - Vulnerable Banking Application

**WARNING: This application is intentionally vulnerable and should NEVER be deployed in a production environment or exposed to the public internet.**

VibeBank is a deliberately vulnerable banking application designed for testing Static Application Security Testing (SAST) tools. It contains numerous security vulnerabilities of varying complexity to evaluate which types of issues SAST tools can reliably detect.

## Application Overview

VibeBank simulates a simple online banking platform with the following features:

- User registration and authentication
- Account management (checking, savings)
- Money transfers and transactions
- User profile management
- Admin panel for system management

## Security Notice

This application contains intentional security vulnerabilities for educational and testing purposes. Running this application may expose your system to risk. Always:

1. Run in an isolated development environment
2. Never expose to the public internet
3. Use a dedicated database for testing only
4. Never use real personal information

## Setup Instructions

### Prerequisites

- Node.js (v12 or later)
- MongoDB
- npm or yarn

### Installation

1. Clone this repository
   ```
   git clone https://github.com/yourusername/vibebank.git
   cd vibebank
   ```

2. Install dependencies
   ```
   npm install
   ```

3. Configure MongoDB
   - Start MongoDB on your system
   - The application will attempt to connect to MongoDB at `mongodb://admin:Password123@localhost:27017/vibebank`
   - You can modify the connection string in `app.js` and `config/database.js`

4. Start the application
   ```
   npm start
   ```

5. Access the application
   - Open your browser and navigate to `http://localhost:3000`
   - For admin access: username `admin@vibebank.com`, password `admin1234`

## Running SAST Tools

This application is designed to test SAST tools. For testing:

1. Point your chosen SAST tool at this codebase
2. Run a complete scan
3. Compare the results with the known vulnerabilities (see "Vulnerability Checklist" below)
4. Evaluate which vulnerabilities were detected and which were missed

## Vulnerability Checklist

Below is a summary of the vulnerabilities intentionally included in this application. After the scan, use this list to check which vulnerabilities your SAST tool detected:

1. SQL injection vulnerabilities
2. Command injection
3. Hardcoded credentials
4. Cross-site scripting (XSS)
5. Missing input validation
6. Insecure deserialization
7. Information leakage
8. Broken access control
9. CSRF vulnerabilities
10. Use of outdated libraries
11. Authentication flaws
12. Race conditions
13. And many more...

For a detailed list with exact file locations, see the VULNERABILITIES.md file.

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Disclaimer

This application is provided for educational and testing purposes only. The authors are not responsible for any misuse or damage that may result from the use of this application. 