# ![Juice Shop Logo](https://raw.githubusercontent.com/juice-shop/juice-shop/master/frontend/src/assets/public/images/JuiceShop_Logo_100px.png) OWASP Juice Shop Secured

> **This is a secured version of OWASP Juice Shop** - A demonstration of how to properly secure a web application by implementing security best practices and fixing vulnerabilities.

## Overview

This repository contains a **secured version** of the OWASP Juice Shop application. While the original Juice Shop is intentionally vulnerable for security training purposes, this version demonstrates proper security implementations and fixes common vulnerabilities.

**⚠️ Important:** This repository is for educational purposes to show security best practices. The original OWASP Juice Shop is intentionally vulnerable and should be used for security training.

## Security Improvements Implemented

This secured version includes the following security enhancements:

### 🔒 Critical Security Fixes

1. **SQL Injection Prevention (T38)**
   - Fixed SQL injection vulnerabilities in login and search routes
   - Implemented parameterized queries using Sequelize replacements
   - All user input is now properly bound and escaped

2. **Secure Password Hashing (T60)**
   - Replaced MD5 with bcrypt (10 salt rounds)
   - Added `hashPassword()` and `verifyPassword()` functions
   - Supports both bcrypt (new passwords) and MD5 (backward compatibility during migration)

3. **Secret Key Protection (T248)**
   - Moved JWT private key to environment variable `JWT_PRIVATE_KEY`
   - Falls back to file-based storage, then hardcoded key for compatibility
   - Keys should be stored securely in production using key management systems

4. **Account Lockout Mechanism (T70)**
   - Implemented account lockout after 5 failed login attempts
   - Accounts are locked for 15 minutes
   - Tracks attempts per email/IP address combination
   - Prevents brute-force attacks

5. **Browser Data Clearing on Logout (T1539)**
   - New logout route with Clear-Site-Data header
   - Clears browser cache, cookies, and storage on logout
   - Properly removes user sessions and tokens

6. **SSRF Mitigation (T1365)**
   - Fixed Server-Side Request Forgery vulnerabilities
   - Added URL validation and hostname whitelist
   - Restricted to HTTP/HTTPS protocols only
   - Added fetch timeout and proper error handling

7. **Database Activity Logging (T2602)**
   - Comprehensive database logging system
   - Logs all queries, transactions, config changes, and data modifications
   - Integrated with Sequelize hooks for audit purposes

8. **Authorization Checks (T378, T50)**
   - New authorization middleware to prevent IDOR vulnerabilities
   - Verifies resource ownership before allowing access
   - Admin users have appropriate access controls

9. **Input Validation (T42)**
   - Enhanced URL validation for profile uploads
   - Search input limited to 200 characters
   - Parameterized queries provide type validation

### 📁 New Files Created

- `routes/logout.ts` - Secure logout route with Clear-Site-Data header
- `lib/authorization.ts` - Authorization middleware for resource access control
- `lib/dbLogger.ts` - Database activity logging system

### 🔧 Modified Files

- `routes/login.ts` - SQL injection fix, account lockout, secure password verification
- `routes/search.ts` - SQL injection fix with parameterized queries
- `routes/profileImageUrlUpload.ts` - SSRF mitigation with URL validation
- `lib/insecurity.ts` - Bcrypt functions, environment variable for private key
- `server.ts` - Registered logout route, initialized database logging
- `models/user.ts` - Updated password hashing documentation
- `package.json` - Added bcryptjs dependency

## Setup

### Prerequisites

- Node.js 20.x or higher
- npm or yarn

### Installation

```bash
# Install dependencies
npm install

# Build the application
npm run build:frontend
npm run build:server

# Start the server
npm start
```

### Environment Variables

Set the following environment variables for production:

```bash
JWT_PRIVATE_KEY=your-private-key-here
NODE_ENV=production
PORT=3000
```

## Security Notes

- **Password Migration**: Existing passwords using MD5 will continue to work, but new passwords use bcrypt. Consider migrating all passwords to bcrypt in production.
- **Private Key**: Never commit private keys to version control. Use environment variables or a key management system.
- **Database Logging**: Database logs may contain sensitive information. Ensure proper access controls and log retention policies.
- **TLS/SSL**: TLS configuration should be handled at the infrastructure level (reverse proxy, load balancer, or CDN).

## Original Project

This secured version is based on the original [OWASP Juice Shop](https://github.com/juice-shop/juice-shop) project. The original project is intentionally vulnerable and is an excellent resource for security training.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- Original OWASP Juice Shop project and contributors
- Security countermeasures implemented based on SD Elements security requirements

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## Disclaimer

This secured version is for educational purposes to demonstrate security best practices. Always conduct proper security assessments and follow your organization's security policies.
