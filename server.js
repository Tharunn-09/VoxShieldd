const http = require('http');
const fs = require('fs');
const path = require('path');
const nodemailer = require('nodemailer');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const dns = require('dns');

// Configure global DNS servers to resolve MongoDB SRV records (Google & Cloudflare DNS)
dns.setServers(['8.8.8.8', '1.1.1.1']);

// Load environment variables
require('dotenv').config();

const User = require('./models/User');
const AuditLog = require('./models/AuditLog');

const PORT = process.env.PORT || 3000;

// Connect to MongoDB
mongoose.connect(process.env.MONGODB_URI || 'mongodb://localhost:27017/voxshield')
  .then(() => {
    console.log('Connected to MongoDB successfully.');
    seedDefaultUser();
  })
  .catch((err) => console.error('MongoDB connection error:', err));

// Setup Nodemailer transporter with Gmail
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.GMAIL_USER,
    pass: process.env.GMAIL_APP_PASS
  }
});

// Seed default user if not present
async function seedDefaultUser() {
  try {
    const existing = await User.findOne({ employeeId: 'UCO-AGT-1042' });
    if (!existing) {
      const hashedPassword = await bcrypt.hash('ucobank@2026', 10);
      const user = new User({
        employeeId: 'UCO-AGT-1042',
        name: 'UCO Agent 1042',
        email: 'agent1042@ucobank.co.in',
        password: hashedPassword,
        mfaSecret: 'ABCDEFGHIJKLMNOPQRST', // 20 character base32
        mfaEnrolled: false,
        status: 'active'
      });
      await user.save();
      console.log('Seeded default agent UCO-AGT-1042 successfully.');
    }
  } catch (err) {
    console.error('Error seeding default user:', err);
  }
}

// Strong Password Validation
function isStrongPassword(password) {
  if (password.length < 8) return false;
  const hasUpper = /[A-Z]/.test(password);
  const hasLower = /[a-z]/.test(password);
  const hasDigit = /[0-9]/.test(password);
  const hasSpecial = /[^A-Za-z0-9]/.test(password);
  return hasUpper && hasLower && hasDigit && hasSpecial;
}

// TOTP Verification Helpers (RFC 6238)
function base32ToBytes(b32) {
  b32 = b32.replace(/=+$/, '').toUpperCase().replace(/[^A-Z2-7]/g, '');
  let bits = '';
  for (let i = 0; i < b32.length; i++) {
    const v = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'.indexOf(b32[i]);
    if (v === -1) continue;
    bits += v.toString(2).padStart(5, '0');
  }
  const bytes = [];
  for (let i = 0; i + 8 <= bits.length; i += 8) {
    bytes.push(parseInt(bits.substr(i, 8), 2));
  }
  return Buffer.from(bytes);
}

function hotp(keyBuffer, counter) {
  const buf = Buffer.alloc(8);
  buf.writeUInt32BE(Math.floor(counter / 0x100000000), 0);
  buf.writeUInt32BE(counter % 0x100000000, 4);

  const hmac = crypto.createHmac('sha1', keyBuffer);
  hmac.update(buf);
  const hmacResult = hmac.digest();

  const offset = hmacResult[hmacResult.length - 1] & 0xf;
  const code = ((hmacResult[offset] & 0x7f) << 24) |
               ((hmacResult[offset + 1] & 0xff) << 16) |
               ((hmacResult[offset + 2] & 0xff) << 8) |
               (hmacResult[offset + 3] & 0xff);

  return (code % 1000000).toString().padStart(6, '0');
}

function verifyTotp(secret, code, period = 30, skew = 1) {
  try {
    const keyBytes = base32ToBytes(secret);
    const counter = Math.floor(Date.now() / 1000 / period);
    for (let w = -skew; w <= skew; w++) {
      if (hotp(keyBytes, counter + w) === code) {
        return true;
      }
    }
    return false;
  } catch (e) {
    console.error('Error verifying TOTP:', e);
    return false;
  }
}

function generateBase32Secret(length = 20) {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  let secret = '';
  for (let i = 0; i < length; i++) {
    secret += alphabet[crypto.randomInt(0, alphabet.length)];
  }
  return secret;
}

// Audit Logger Helper
async function logAuditEvent(employeeId, eventType, req, details) {
  try {
    const ipAddress = req.headers['x-forwarded-for'] || req.socket.remoteAddress || '';
    const log = new AuditLog({
      employeeId: employeeId || 'GUEST',
      eventType,
      ipAddress,
      details
    });
    await log.save();
    console.log(`[AUDIT LOG] ${eventType} for user ${employeeId || 'GUEST'}: ${details}`);
  } catch (err) {
    console.error('Failed to save audit log:', err);
  }
}

// Helper to read JSON request body
function readBody(req, callback) {
  let body = '';
  req.on('data', chunk => { body += chunk; });
  req.on('end', () => {
    try {
      callback(null, JSON.parse(body));
    } catch (e) {
      callback(e, null);
    }
  });
}


const MIME_TYPES = {
  '.html': 'text/html',
  '.css': 'text/css',
  '.js': 'application/javascript',
  '.png': 'image/png',
  '.jpg': 'image/jpeg',
  '.gif': 'image/gif',
  '.svg': 'image/svg+xml',
  '.json': 'application/json',
  '.ico': 'image/x-icon'
};

const server = http.createServer(async (req, res) => {
  console.log(`[REQUEST] ${req.method} ${req.url}`);
  // Secure User Registration Init (OTP generation and hashing)
  if (req.method === 'POST' && req.url === '/api/auth/register-init') {
    readBody(req, async (err, data) => {
      if (err || !data) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Invalid request payload' }));
        return;
      }
      const { name, email, user, pass } = data;
      if (!name || !email || !user || !pass) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'All fields are required' }));
        return;
      }

      if (!isStrongPassword(pass)) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Password must be at least 8 characters long and contain 1 uppercase, 1 lowercase, 1 number, and 1 special character.' }));
        return;
      }

      try {
        const existingUser = await User.findOne({ employeeId: user });
        if (existingUser && existingUser.status === 'active') {
          res.writeHead(400, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: 'Employee ID is already registered' }));
          return;
        }

        const existingEmail = await User.findOne({
          email: { $regex: new RegExp("^" + email.trim().replace(/[-\/\\^$*+?.()|[\]{}]/g, '\\$&') + "$", "i") },
          status: 'active'
        });
        if (existingEmail) {
          res.writeHead(400, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: 'Email address is already registered' }));
          return;
        }

        const hashedPassword = await bcrypt.hash(pass, 10);
        const otpCode = Math.floor(100000 + Math.random() * 900000).toString();
        const otpExpires = new Date(Date.now() + 5 * 60 * 1000); // 5 minutes

        if (existingUser) {
          existingUser.name = name;
          existingUser.email = email;
          existingUser.password = hashedPassword;
          existingUser.otp = { code: otpCode, expiresAt: otpExpires };
          await existingUser.save();
        } else {
          const newUser = new User({
            employeeId: user,
            name,
            email,
            password: hashedPassword,
            otp: { code: otpCode, expiresAt: otpExpires },
            status: 'pending'
          });
          await newUser.save();
        }

        // Send OTP Email using Nodemailer
        const mailOptions = {
          from: `"VoxShield Security" <${process.env.GMAIL_USER}>`,
          to: email,
          subject: 'VoxShield Verification Code',
          text: `Hello Officer,\n\nWelcome to VoxShield!\n\nVoxShield is a real-time, explainable voice forensics and synthetic audio detection system built to protect banking channels from deepfake voice clones.\n\nPlease enter the 6-digit One-Time Password (OTP) below to verify your email address and authorize your officer profile creation:\n\nVerification Code: ${otpCode}\n\nThis verification code was generated for a new registration request. It is valid for 5 minutes. If you did not initiate this request, please change your credentials immediately or contact your Zonal IT Administrator.\n\nUCO Bank VoxShield Safety & Cybersecurity Division`,
          html: `
            <div style="font-family: Arial, sans-serif; max-width: 500px; margin: 0 auto; padding: 20px; border: 1px solid #e0e0e0; border-radius: 8px; background-color: #070b14; color: #eef3fb;">
              <h2 style="color: #F2A900; text-align: center; margin-bottom: 5px;">VoxShield Security</h2>
              <p style="text-align: center; color: #9fb0cc; font-size: 13px; text-transform: uppercase; letter-spacing: 1px; margin-top: 0;">Voice Forensics System</p>
              <hr style="border: none; border-top: 1px solid rgba(242, 169, 0, 0.2); margin: 20px 0;" />
              <p>Hello Officer,</p>
              <p style="font-size: 15px; font-weight: 600; color: #F2A900; margin-top: 15px; margin-bottom: 5px;">Welcome to VoxShield!</p>
              <p style="margin-top: 0; margin-bottom: 15px; line-height: 1.5; color: #eef3fb;">VoxShield is a real-time, explainable voice forensics and synthetic audio detection system built to protect banking channels from deepfake voice clones.</p>
              <p>Please enter the 6-digit One-Time Password (OTP) below to verify your email address and authorize your officer profile creation:</p>
              <div style="background-color: #0f1726; border: 1px solid rgba(242, 169, 0, 0.4); padding: 18px; text-align: center; font-size: 32px; font-weight: bold; letter-spacing: 6px; color: #F2A900; margin: 24px 0; border-radius: 8px; font-family: monospace;">
                ${otpCode}
              </div>
              <p style="font-size: 12px; color: #5f6f8f; line-height: 1.5;">This verification code was generated for a new registration request. If you did not initiate this request, please change your credentials immediately or contact your Zonal IT Administrator.</p>
              <hr style="border: none; border-top: 1px solid rgba(242, 169, 0, 0.1); margin: 20px 0;" />
              <p style="font-size: 11px; color: #5f6f8f; text-align: center; margin-bottom: 0;">UCO Bank VoxShield Safety &amp; Cybersecurity Division</p>
            </div>
          `
        };

        await transporter.sendMail(mailOptions);
        await logAuditEvent(user, 'REGISTRATION_OTP_SENT', req, `Verification OTP code sent to ${email}.`);

        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ success: true }));
      } catch (err) {
        console.error('Error in register-init:', err);
        res.writeHead(500, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: err.message || 'Internal server error' }));
      }
    });
    return;
  }

  // Secure User Registration Verify (OTP check, MFA seed generation)
  if (req.method === 'POST' && req.url === '/api/auth/register-verify') {
    readBody(req, async (err, data) => {
      if (err || !data) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Invalid request payload' }));
        return;
      }
      const { user, otp } = data;
      if (!user || !otp) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Employee ID and OTP are required' }));
        return;
      }

      try {
        const dbUser = await User.findOne({ employeeId: user, status: 'pending' });
        if (!dbUser) {
          res.writeHead(400, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: 'No pending registration found for this Employee ID' }));
          return;
        }

        if (dbUser.otp.code !== otp) {
          await logAuditEvent(user, 'REGISTRATION_OTP_FAILED', req, `Failed OTP entry during registration.`);
          res.writeHead(400, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: 'Incorrect verification code' }));
          return;
        }

        if (dbUser.otp.expiresAt < new Date()) {
          await logAuditEvent(user, 'REGISTRATION_OTP_EXPIRED', req, `Expired OTP entry attempt.`);
          res.writeHead(400, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: 'OTP has expired (valid for 5 minutes)' }));
          return;
        }

        const mfaSecret = generateBase32Secret();
        dbUser.status = 'active';
        dbUser.mfaSecret = mfaSecret;
        dbUser.mfaEnrolled = false;
        dbUser.otp = { code: '', expiresAt: null };
        await dbUser.save();

        const tempToken = jwt.sign(
          { employeeId: dbUser.employeeId, stage: 'mfa' },
          process.env.JWT_SECRET,
          { expiresIn: '5m' }
        );

        await logAuditEvent(user, 'REGISTRATION_COMPLETED', req, `Registration completed. Account activated.`);

        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ success: true, mfaSecret, tempToken }));
      } catch (err) {
        console.error('Error in register-verify:', err);
        res.writeHead(500, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Internal server error' }));
      }
    });
    return;
  }

  // Secure Login Credentials Validation (Password compare, lock checks)
  if (req.method === 'POST' && req.url === '/api/auth/login-creds') {
    readBody(req, async (err, data) => {
      if (err || !data) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Invalid request payload' }));
        return;
      }
      const { user, pass } = data;
      if (!user || !pass) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Employee ID and password are required' }));
        return;
      }

      try {
        const dbUser = await User.findOne({ employeeId: user, status: 'active' });
        if (!dbUser) {
          await logAuditEvent(user, 'LOGIN_FAILED', req, `Failed login attempt with unregistered ID.`);
          res.writeHead(401, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: 'Invalid Employee ID or password' }));
          return;
        }

        // Check lockout status
        if (dbUser.loginAttempts.lockUntil && dbUser.loginAttempts.lockUntil > new Date()) {
          const remainingMs = dbUser.loginAttempts.lockUntil - Date.now();
          const remainingMins = Math.ceil(remainingMs / 1000 / 60);
          res.writeHead(423, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: `Account locked due to consecutive failures. Try again in ${remainingMins} minute(s).` }));
          return;
        }

        const isMatch = await bcrypt.compare(pass, dbUser.password);
        if (!isMatch) {
          dbUser.loginAttempts.count += 1;
          if (dbUser.loginAttempts.count >= 5) {
            dbUser.loginAttempts.lockUntil = new Date(Date.now() + 15 * 60 * 1000); // 15 minutes lockout
            await dbUser.save();
            await logAuditEvent(user, 'ACCOUNT_LOCKED', req, `Account automatically locked for 15 minutes.`);
            res.writeHead(423, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ error: 'Invalid credentials. Account locked for 15 minutes.' }));
          } else {
            await dbUser.save();
            await logAuditEvent(user, 'LOGIN_FAILED', req, `Failed login credential attempt (${dbUser.loginAttempts.count}/5).`);
            res.writeHead(401, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ error: `Invalid credentials. (${5 - dbUser.loginAttempts.count} attempt(s) remaining)` }));
          }
          return;
        }

        // Reset failures on login success
        dbUser.loginAttempts.count = 0;
        dbUser.loginAttempts.lockUntil = null;
        await dbUser.save();

        const tempToken = jwt.sign(
          { employeeId: dbUser.employeeId, stage: 'mfa' },
          process.env.JWT_SECRET,
          { expiresIn: '5m' }
        );

        await logAuditEvent(user, 'CREDS_VERIFICATION_SUCCESS', req, `Credentials verified. Awaiting 2FA.`);

        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({
          success: true,
          tempToken,
          mfaEnrolled: dbUser.mfaEnrolled,
          mfaSecret: dbUser.mfaEnrolled ? null : dbUser.mfaSecret
        }));
      } catch (err) {
        console.error('Error in login-creds:', err);
        res.writeHead(500, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Internal server error' }));
      }
    });
    return;
  }

  // Secure MFA Validation (TOTP verify + Session JWT generation)
  if (req.method === 'POST' && req.url === '/api/auth/login-mfa') {
    readBody(req, async (err, data) => {
      if (err || !data) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Invalid request payload' }));
        return;
      }
      const { tempToken, mfaCode } = data;
      if (!tempToken || !mfaCode) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Temporary session token and MFA code are required' }));
        return;
      }

      try {
        let decoded;
        try {
          decoded = jwt.verify(tempToken, process.env.JWT_SECRET);
        } catch (e) {
          res.writeHead(401, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: 'Temporary login session expired. Please log in again.' }));
          return;
        }

        if (decoded.stage !== 'mfa') {
          res.writeHead(403, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: 'Invalid login phase' }));
          return;
        }

        const dbUser = await User.findOne({ employeeId: decoded.employeeId, status: 'active' });
        if (!dbUser) {
          res.writeHead(401, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: 'User account not found' }));
          return;
        }

        const isMfaValid = verifyTotp(dbUser.mfaSecret, mfaCode);
        if (!isMfaValid) {
          await logAuditEvent(dbUser.employeeId, 'MFA_VERIFICATION_FAILED', req, `Failed 2FA Authenticator token match attempt.`);
          res.writeHead(401, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: 'Incorrect code. Check your authenticator app.' }));
          return;
        }

        if (!dbUser.mfaEnrolled) {
          dbUser.mfaEnrolled = true;
          await dbUser.save();
          await logAuditEvent(dbUser.employeeId, 'MFA_ENROLLED', req, `Completed initial TOTP authenticator device setup.`);
        }

        const finalToken = jwt.sign(
          { employeeId: dbUser.employeeId, name: dbUser.name, email: dbUser.email },
          process.env.JWT_SECRET,
          { expiresIn: '12h' }
        );

        await logAuditEvent(dbUser.employeeId, 'LOGIN_SUCCESS', req, `User logged in successfully.`);

        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({
          success: true,
          token: finalToken,
          user: {
            employeeId: dbUser.employeeId,
            name: dbUser.name,
            email: dbUser.email
          }
        }));
      } catch (err) {
        console.error('Error in login-mfa:', err);
        res.writeHead(500, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Internal server error' }));
      }
    });
    return;
  }

  // Secure Forgot Password Request (OTP generation and Email dispatch)
  if (req.method === 'POST' && req.url === '/api/auth/forgot-password') {
    readBody(req, async (err, data) => {
      if (err || !data) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Invalid request payload' }));
        return;
      }
      const { email } = data;
      if (!email) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Email address is required' }));
        return;
      }

      try {
        const dbUser = await User.findOne({ email: email.trim(), status: 'active' });
        if (!dbUser) {
          res.writeHead(400, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: 'Email address not registered' }));
          return;
        }

        const otpCode = Math.floor(100000 + Math.random() * 900000).toString();
        const otpExpires = new Date(Date.now() + 5 * 60 * 1000); // 5 minutes

        dbUser.otp = { code: otpCode, expiresAt: otpExpires };
        await dbUser.save();

        const mailOptions = {
          from: `"VoxShield Security" <${process.env.GMAIL_USER}>`,
          to: dbUser.email,
          subject: 'VoxShield Password Reset Code',
          text: `Hello Officer,\n\nPassword Reset Request\n\nYou have requested a password reset for your VoxShield officer account associated with Employee ID: ${dbUser.employeeId}.\n\nPlease enter the 6-digit verification code below to authorize your password reset:\n\nVerification Code: ${otpCode}\n\nThis code is valid for 5 minutes. If you did not request this password reset, please secure your account immediately or notify your Zonal IT Administrator.\n\nUCO Bank VoxShield Safety & Cybersecurity Division`,
          html: `
            <div style="font-family: Arial, sans-serif; max-width: 500px; margin: 0 auto; padding: 20px; border: 1px solid #e0e0e0; border-radius: 8px; background-color: #070b14; color: #eef3fb;">
              <h2 style="color: #F2A900; text-align: center; margin-bottom: 5px;">VoxShield Security</h2>
              <p style="text-align: center; color: #9fb0cc; font-size: 13px; text-transform: uppercase; letter-spacing: 1px; margin-top: 0;">Voice Forensics System</p>
              <hr style="border: none; border-top: 1px solid rgba(242, 169, 0, 0.2); margin: 20px 0;" />
              <p>Hello Officer,</p>
              <p style="font-size: 15px; font-weight: 600; color: #F2A900; margin-top: 15px; margin-bottom: 5px;">Password Reset Request</p>
              <p style="margin-top: 0; margin-bottom: 15px; line-height: 1.5; color: #eef3fb;">You have requested a password reset for your VoxShield officer account associated with Employee ID: <strong>${dbUser.employeeId}</strong>.</p>
              <p>Please enter the 6-digit verification code below to authorize your password reset:</p>
              <div style="background-color: #0f1726; border: 1px solid rgba(242, 169, 0, 0.4); padding: 18px; text-align: center; font-size: 32px; font-weight: bold; letter-spacing: 6px; color: #F2A900; margin: 24px 0; border-radius: 8px; font-family: monospace;">
                ${otpCode}
              </div>
              <p style="font-size: 12px; color: #5f6f8f; line-height: 1.5;">This code is valid for 5 minutes. If you did not request this password reset, please secure your account immediately or notify your Zonal IT Administrator.</p>
              <hr style="border: none; border-top: 1px solid rgba(242, 169, 0, 0.1); margin: 20px 0;" />
              <p style="font-size: 11px; color: #5f6f8f; text-align: center; margin-bottom: 0;">UCO Bank VoxShield Safety &amp; Cybersecurity Division</p>
            </div>
          `
        };

        await transporter.sendMail(mailOptions);
        await logAuditEvent(dbUser.employeeId, 'PASSWORD_RESET_OTP_SENT', req, `Password reset OTP code sent to ${dbUser.email}.`);

        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ success: true }));
      } catch (err) {
        console.error('Error in forgot-password:', err);
        res.writeHead(500, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: err.message || 'Internal server error' }));
      }
    });
    return;
  }

  // Secure Password Reset (OTP verification and password modification)
  if (req.method === 'POST' && req.url === '/api/auth/reset-password') {
    readBody(req, async (err, data) => {
      if (err || !data) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Invalid request payload' }));
        return;
      }
      const { email, otp, newPassword } = data;
      if (!email || !otp || !newPassword) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'All fields (email, OTP, new password) are required' }));
        return;
      }

      if (!isStrongPassword(newPassword)) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Password must be at least 8 characters long and contain 1 uppercase, 1 lowercase, 1 number, and 1 special character.' }));
        return;
      }

      try {
        const dbUser = await User.findOne({ email: email.trim(), status: 'active' });
        if (!dbUser) {
          res.writeHead(400, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: 'User not found' }));
          return;
        }

        if (!dbUser.otp.code || dbUser.otp.code !== otp) {
          await logAuditEvent(dbUser.employeeId, 'PASSWORD_RESET_OTP_FAILED', req, `Failed OTP entry during password reset.`);
          res.writeHead(400, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: 'Incorrect verification code' }));
          return;
        }

        if (dbUser.otp.expiresAt < new Date()) {
          await logAuditEvent(dbUser.employeeId, 'PASSWORD_RESET_OTP_EXPIRED', req, `Expired OTP entry attempt during password reset.`);
          res.writeHead(400, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: 'OTP has expired (valid for 5 minutes)' }));
          return;
        }

        const hashedPassword = await bcrypt.hash(newPassword, 10);
        dbUser.password = hashedPassword;
        dbUser.otp = { code: '', expiresAt: null };
        dbUser.loginAttempts = { count: 0, lockUntil: null };
        await dbUser.save();

        await logAuditEvent(dbUser.employeeId, 'PASSWORD_RESET_SUCCESS', req, `Password reset successfully.`);

        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ success: true }));
      } catch (err) {
        console.error('Error in reset-password:', err);
        res.writeHead(500, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Internal server error' }));
      }
    });
    return;
  }


  // Get Audit Logs (JWT Protected)
  if (req.method === 'GET' && req.url === '/api/audit-logs') {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (!token) {
      res.writeHead(401, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Authorization header required' }));
      return;
    }

    try {
      jwt.verify(token, process.env.JWT_SECRET);
      const logs = await AuditLog.find().sort({ timestamp: -1 }).limit(100);
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ success: true, logs }));
    } catch (e) {
      res.writeHead(403, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Invalid or expired credentials token' }));
    }
    return;
  }

  // Add Custom Audit Log Event (JWT Protected)
  if (req.method === 'POST' && req.url === '/api/audit-log') {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (!token) {
      res.writeHead(401, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Authorization header required' }));
      return;
    }

    readBody(req, async (err, data) => {
      if (err || !data) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Invalid payload' }));
        return;
      }
      const { eventType, details } = data;
      if (!eventType || !details) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'eventType and details fields are required' }));
        return;
      }

      try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        await logAuditEvent(decoded.employeeId, eventType, req, details);
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ success: true }));
      } catch (e) {
        res.writeHead(403, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Invalid or expired credentials token' }));
      }
    });
    return;
  }

  // Verify Transaction Bypass TOTP (JWT Protected)
  if (req.method === 'POST' && req.url === '/api/verify-bypass') {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (!token) {
      res.writeHead(401, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Authorization header required' }));
      return;
    }

    readBody(req, async (err, data) => {
      if (err || !data) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Invalid payload' }));
        return;
      }
      const { otp } = data;
      if (!otp) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'otp code is required' }));
        return;
      }

      try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        const dbUser = await User.findOne({ employeeId: decoded.employeeId, status: 'active' });
        if (!dbUser) {
          res.writeHead(404, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: 'User not found' }));
          return;
        }

        // Verify the TOTP code
        const isValid = verifyTotp(dbUser.mfaSecret, otp);
        if (isValid) {
          await logAuditEvent(decoded.employeeId, 'TRANSACTION_BYPASS_APPROVED', req, `High-risk transaction security override approved using MFA code.`);
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ success: true }));
        } else {
          await logAuditEvent(decoded.employeeId, 'TRANSACTION_BYPASS_REJECTED', req, `Attempted high-risk transaction override with invalid MFA code.`);
          res.writeHead(400, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: 'Invalid authenticator code. Bypass denied.' }));
        }
      } catch (e) {
        res.writeHead(403, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Invalid or expired credentials token' }));
      }
    });
    return;
  }

  // Analyze Audio Recording (JWT Protected)
  if (req.method === 'POST' && req.url === '/api/analyze-audio') {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (!token) {
      res.writeHead(401, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Authorization header required' }));
      return;
    }

    try {
      jwt.verify(token, process.env.JWT_SECRET);
      
      const fileName = req.headers['x-file-name'] || 'upload.wav';
      const cleanFileName = fileName.replace(/[^a-zA-Z0-9_.-]/g, '_');
      const uploadDir = path.join(__dirname, 'temp_uploads');
      if (!fs.existsSync(uploadDir)) {
        fs.mkdirSync(uploadDir, { recursive: true });
      }
      
      const tempFilePath = path.join(uploadDir, `upload_${Date.now()}_${cleanFileName}`);
      const writeStream = fs.createWriteStream(tempFilePath);
      
      req.pipe(writeStream);
      
      writeStream.on('error', (streamErr) => {
        console.error('Error writing upload file:', streamErr);
        res.writeHead(500, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Failed to save audio file.' }));
      });
      
      writeStream.on('finish', () => {
        const codecType = req.headers['x-codec-type'] || 'none';
        const cleanCodec = ['gsm', 'landline', 'none'].includes(codecType) ? codecType : 'none';
        const { exec } = require('child_process');
        const scriptPath = path.join(__dirname, 'audio_forensics', 'audio_forensics.py');
        const cmd = `python "${scriptPath}" "${tempFilePath}" --codec ${cleanCodec}`;
        
        exec(cmd, { env: { ...process.env, PYTHONIOENCODING: 'utf-8' } }, (err, stdout, stderr) => {
          // Cleanup temp file
          fs.unlink(tempFilePath, (unlinkErr) => {
            if (unlinkErr) console.error('Failed to delete temp file:', unlinkErr);
          });
          
          if (err) {
            console.error('Python forensics script error:', err);
            console.error('Stderr:', stderr);
            res.writeHead(500, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ error: 'Failed to process audio analysis engine.' }));
            return;
          }
          
          try {
            const lines = stdout.split('\n');
            let jsonString = '';
            for (let i = lines.length - 1; i >= 0; i--) {
              const trimmedLine = lines[i].trim();
              if (trimmedLine.startsWith('{') && trimmedLine.endsWith('}')) {
                jsonString = trimmedLine;
                break;
              }
            }
            if (!jsonString) {
              throw new Error('No valid JSON string found in forensics stdout');
            }
            const output = JSON.parse(jsonString);
            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify(output));
          } catch (jsonErr) {
            console.error('JSON parse error from forensics output:', jsonErr);
            console.error('Forensics output was:', stdout);
            res.writeHead(500, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ error: 'Invalid response format from forensics engine.' }));
          }
        });
      });
    } catch (e) {
      res.writeHead(403, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Invalid or expired credentials token' }));
    }
    return;
  }

  // Send Forensic Report via Email (JWT Protected)
  if (req.method === 'POST' && req.url === '/api/send-report') {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (!token) {
      res.writeHead(401, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Authorization header required' }));
      return;
    }

    readBody(req, async (err, data) => {
      if (err || !data) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Invalid payload' }));
        return;
      }
      const { email, report } = data;
      if (!email || !report) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'email and report fields are required' }));
        return;
      }

      try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        
        const verdictLabel = report.verdict ? (report.verdict.label || report.verdict) : 'UNKNOWN';
        const verdictKey = report.verdict ? (report.verdict.key || report.verdict) : 'unknown';
        const verdictColor = report.verdict ? (report.verdict.color || '#64748b') : '#64748b';
        const score = report.score !== undefined ? report.score : (report.risk_score || 0);
        const customer = report.customer || 'Unidentified Caller';
        const callId = report.id || report.call_id || 'N/A';
        const timestamp = report.timestamp || new Date().toLocaleString('en-IN');
        const source = report.source || 'N/A';
        
        const features = report.features || {};
        const jitter = features.pitch_jitter_pct !== undefined ? features.pitch_jitter_pct : 0;
        const shimmer = features.amplitude_shimmer_pct !== undefined ? features.amplitude_shimmer_pct : 0;
        const flatness = features.spectral_flatness !== undefined ? features.spectral_flatness : 0;
        const hfAnom = features.hf_energy_anomaly !== undefined ? features.hf_energy_anomaly : 0;
        const duration = features.duration_sec !== undefined ? features.duration_sec : 0;
        const frames = features.frames_analyzed !== undefined ? features.frames_analyzed : 0;
        
        const sha256 = report.audio_sha256 || 'N/A (Calculated locally upon capture/upload)';
        const signature = report.report_digital_signature || 'N/A (Sealed locally)';

        // Plain English explanation
        let plainEnglishSummary = "";
        let plainEnglishJitter = "";
        let plainEnglishShimmer = "";
        let plainEnglishFlatness = "";
        let plainEnglishHF = "";
        let actionItem = "";
        let riskBadgeBg = "#64748b";

        const lowerVerdict = verdictKey.toLowerCase();
        if (lowerVerdict === 'critical' || score >= 75) {
          riskBadgeBg = "#ef4444"; // Red
          plainEnglishSummary = `This call has been marked as a <strong>CRITICAL SECURITY THREAT</strong>. The voice scan has confirmed multiple synthetic audio signatures. The pitch variations are artificially flat (smoothed) and amplitude is over-regulated. This combination is a classic fingerprint of neural speech synthesis engines (like ElevenLabs). The caller's voice is highly likely an AI deepfake clone.`;
          actionItem = `<strong>CRITICAL ACTION REQUIRED:</strong> Terminate the caller session immediately. Flag the account for review, freeze active transaction requests initiated during this call, and require high-level, out-of-band verification (such as a hardware token or in-person branch verification) before authorizing any operations.`;
        } else if (lowerVerdict === 'high' || score >= 50) {
          riskBadgeBg = "#f59e0b"; // Orange
          plainEnglishSummary = `This call has been marked as <strong>HIGH RISK</strong>. Several acoustic anomalies deviate significantly from standard human voice biometrics, typical of low-latency voice conversion engines. There is a high probability of a voice cloning attempt.`;
          actionItem = `<strong>SECURITY ACTIONS ADVISED:</strong> Suspend high-value transaction requests. Ask multi-factor out-of-band security questions (details not available in public records or social media) and call the customer back on their verified registered mobile number.`;
        } else if (lowerVerdict === 'moderate' || score >= 25) {
          riskBadgeBg = "#1d4ed8"; // Blue
          plainEnglishSummary = `This call has been marked as <strong>MODERATE RISK</strong>. Minor acoustic anomalies were identified. While it could indicate a very simple voice changer tool, it is also highly likely to be caused by cellular connection degradation, bad line noise, or a speakerphone environment.`;
          actionItem = `<strong>MONITOR WITH CAUTION:</strong> Continue standard security verification processes. Run standard security checks, note the call line status, and request standard validation before performing any banking transactions.`;
        } else {
          riskBadgeBg = "#10b981"; // Green
          plainEnglishSummary = `This call has been marked as <strong>LOW RISK</strong>. The acoustic and biometric characteristics reside safely within standard human biological ranges. Jitter, shimmer, and vocal resonances confirm standard human vocal chord mechanics.`;
          actionItem = `<strong>STANDARD PROTOCOL:</strong> Proceed with normal operations. The voice print is verified as a natural human speaker.`;
        }

        // Jitter explain
        if (jitter < 0.3) {
          plainEnglishJitter = `Abnormally flat/low (${jitter.toFixed(2)}%). Natural human voices always contain micro-fluctuations in pitch (typically 0.5% - 3.0%). A value below 0.3% suggests that the voice is artificially generated and 'smoothed' by AI text-to-speech vocoders.`;
        } else if (jitter > 6.0) {
          plainEnglishJitter = `Abnormally high (${jitter.toFixed(2)}%). Pitch stability is erratic, indicating bad cellular line quality, severe voice compression, or vocoder stitching errors.`;
        } else {
          plainEnglishJitter = `Normal (${jitter.toFixed(2)}%). Falls within the expected range of human pitch variations (0.5% - 3.0%).`;
        }

        // Shimmer explain
        if (shimmer < 2.0) {
          plainEnglishShimmer = `Abnormally low (${shimmer.toFixed(2)}%). Natural human speech fluctuates in loudness cycle-to-cycle (typically 3% - 15%) due to breathing. Suppressed shimmer indicates artificial voice generation.`;
        } else if (shimmer > 25.0) {
          plainEnglishShimmer = `Abnormally high (${shimmer.toFixed(2)}%). Amplitude is highly unstable, typical of severe background environment noise or synthetic speech conversion distortion.`;
        } else {
          plainEnglishShimmer = `Normal (${shimmer.toFixed(2)}%). Amplitude fluctuations match expected natural human respiration and speech rhythm.`;
        }

        // Flatness explain
        if (flatness > 0.3) {
          plainEnglishFlatness = `Abnormally flat/noisy (${flatness.toFixed(3)}). Human voices resonance creates clear frequency peaks (harmonics). Generative AI speech models often introduce high-frequency flat noise, leading to high spectral flatness.`;
        } else if (flatness > 0.15) {
          plainEnglishFlatness = `Elevated noise (${flatness.toFixed(3)}). Deviations in the tone-to-noise ratio, suggesting background line hiss or neural vocoder noise artifacts.`;
        } else {
          plainEnglishFlatness = `Normal (${flatness.toFixed(3)}). Rich in harmonic resonances, matching natural human throat acoustic patterns.`;
        }

        // HF Anomaly explain
        if (hfAnom > 0.4) {
          plainEnglishHF = `Abnormal high frequency (${hfAnom.toFixed(3)}). Standard telephone channels filter out high-frequency signals. The presence of anomalous high frequency indicates artificial noise synthesized by voice cloning.`;
        } else if (hfAnom > 0.2) {
          plainEnglishHF = `Elevated (${hfAnom.toFixed(3)}). Minor high-frequency energy deviations in the 4kHz-8kHz band.`;
        } else {
          plainEnglishHF = `Normal (${hfAnom.toFixed(3)}). High-frequency sounds fall off naturally, matching cellular standard parameters.`;
        }

        const mailOptions = {
          from: `"VoxShield Security" <${process.env.GMAIL_USER}>`,
          to: email,
          subject: `[VoxShield Report] Forensic Voice Scan Alert - Call ID: ${callId}`,
          text: `VoxShield Forensic Voice Report\n========================================\n\nCall ID: ${callId}\nCustomer Name: ${customer}\nThreat Score: ${score}/100\nVerdict: ${verdictLabel}\nTimestamp: ${timestamp}\nChannel Source: ${source}\n\nEXECUTIVE SUMMARY (PLAIN LANGUAGE)\n${plainEnglishSummary.replace(/<[^>]+>/g, '')}\n\nRECOMMENDED ACTIONS\n${actionItem.replace(/<[^>]+>/g, '')}\n\nFORENSIC BREAKDOWN (PLAIN ENGLISH)\n1. Pitch Jitter (Pitch Variation): ${plainEnglishJitter}\n2. Amplitude Shimmer (Loudness Stability): ${plainEnglishShimmer}\n3. Spectral Flatness (Speech Resonance): ${plainEnglishFlatness}\n4. HF Energy Anomaly (High-Freq Artifacts): ${plainEnglishHF}\n\nINTEGRITY SEAL & CHAIN OF CUSTODY\nSHA-256 Hash: ${sha256}\nDigital Signature: ${signature}\nOfficer Investigator ID: ${decoded.employeeId}\n\nUCO Bank VoxShield Cybersecurity Division. Confidential Report.`,
          html: `
            <div style="font-family: Arial, sans-serif; background-color: #f4f7fc; padding: 24px; color: #0a1220; line-height: 1.5;">
              <div style="max-width: 600px; margin: 0 auto; background-color: #ffffff; border-radius: 12px; border: 1px solid rgba(0, 68, 170, 0.08); overflow: hidden; box-shadow: 0 4px 12px rgba(0,0,0,0.05);">
                <!-- Header -->
                <div style="background-color: #0044AA; padding: 24px; text-align: center; color: #ffffff;">
                  <h2 style="margin: 0; font-size: 20px; font-weight: 700; letter-spacing: 0.5px;">VoxShield Audio Forensics</h2>
                  <p style="margin: 4px 0 0 0; font-size: 12px; color: #ffd771; text-transform: uppercase; letter-spacing: 1px;">UCO Bank Security &amp; Risk Management</p>
                </div>
                
                <div style="padding: 24px;">
                  <!-- Title Block -->
                  <table style="width:100%; border-collapse: collapse; margin-bottom: 20px; border-bottom: 1px solid rgba(0, 68, 170, 0.08); padding-bottom: 16px;">
                    <tr>
                      <td>
                        <span style="font-size: 11px; color: #64748b; font-weight: 600; text-transform: uppercase; display: block; margin-bottom: 4px;">Investigation Report</span>
                        <h3 style="margin: 0; color: #0044AA; font-size: 18px; font-weight: 700;">ID: ${callId}</h3>
                      </td>
                      <td style="text-align: right; vertical-align: middle;">
                        <span style="background-color: ${riskBadgeBg}; color: #ffffff; padding: 6px 14px; border-radius: 20px; font-size: 11px; font-weight: bold; text-transform: uppercase; display: inline-block;">
                          ${verdictLabel.replace(/ — LIKELY HUMAN| — REVIEW ADVISED| — SUSPECTED CLONING| — LIKELY SYNTHETIC/g, '')}
                        </span>
                      </td>
                    </tr>
                  </table>

                  <!-- Executive Summary -->
                  <div style="background-color: #f8fafc; border-left: 4px solid #0044AA; padding: 16px; margin-bottom: 16px; border-radius: 0 8px 8px 0;">
                    <h4 style="margin: 0 0 8px 0; color: #0044AA; font-size: 14px; font-weight: 700;">📢 Executive Summary (Plain Language)</h4>
                    <p style="margin: 0; font-size: 13px; color: #334155; line-height: 1.6;">
                      ${plainEnglishSummary}
                    </p>
                  </div>

                  <!-- Recommended Action -->
                  <div style="background-color: rgba(242, 169, 0, 0.08); border-left: 4px solid #F2A900; padding: 16px; margin-bottom: 24px; border-radius: 0 8px 8px 0;">
                    <h4 style="margin: 0 0 8px 0; color: #c28500; font-size: 14px; font-weight: 700;">🛡️ Recommended Action</h4>
                    <p style="margin: 0; font-size: 13px; color: #334155; line-height: 1.6;">
                      ${actionItem}
                    </p>
                  </div>

                  <!-- Quick Stats -->
                  <table style="width: 100%; border-collapse: collapse; margin-bottom: 24px; font-size: 13px; background-color: #f8fafc; border: 1px solid rgba(0, 68, 170, 0.05); border-radius: 8px;">
                    <tr>
                      <td style="padding: 10px 14px; border-bottom: 1px solid rgba(0, 68, 170, 0.05); color: #64748b; font-weight: bold; width: 40%;">Caller Name:</td>
                      <td style="padding: 10px 14px; border-bottom: 1px solid rgba(0, 68, 170, 0.05); color: #0a1220; font-weight: 600;">${customer}</td>
                    </tr>
                    <tr>
                      <td style="padding: 10px 14px; border-bottom: 1px solid rgba(0, 68, 170, 0.05); color: #64748b; font-weight: bold;">Composite Threat Score:</td>
                      <td style="padding: 10px 14px; border-bottom: 1px solid rgba(0, 68, 170, 0.05); color: ${verdictColor}; font-weight: bold; font-size: 14px;">${score} / 100</td>
                    </tr>
                    <tr>
                      <td style="padding: 10px 14px; border-bottom: 1px solid rgba(0, 68, 170, 0.05); color: #64748b; font-weight: bold;">Time of Scan:</td>
                      <td style="padding: 10px 14px; border-bottom: 1px solid rgba(0, 68, 170, 0.05); color: #0a1220; font-family: monospace;">${timestamp}</td>
                    </tr>
                    <tr>
                      <td style="padding: 10px 14px; border-bottom: 1px solid rgba(0, 68, 170, 0.05); color: #64748b; font-weight: bold;">Capture Channel:</td>
                      <td style="padding: 10px 14px; border-bottom: 1px solid rgba(0, 68, 170, 0.05); color: #0a1220;">${source}</td>
                    </tr>
                    <tr>
                      <td style="padding: 10px 14px; color: #64748b; font-weight: bold;">Audio Length:</td>
                      <td style="padding: 10px 14px; color: #0a1220;">${duration.toFixed(1)}s (${frames} analysis frames)</td>
                    </tr>
                  </table>

                  <!-- Forensic Breakdown -->
                  <h4 style="margin: 0 0 12px 0; color: #0044AA; font-size: 14px; font-weight: 700; border-bottom: 1px solid rgba(0, 68, 170, 0.08); padding-bottom: 6px;">🔍 Forensic Metric Breakdown (Easy-to-Read)</h4>
                  <div style="font-size: 12px; margin-bottom: 24px;">
                    
                    <div style="background-color: #ffffff; border: 1px solid rgba(0,68,170,0.08); padding: 12px; border-radius: 8px; margin-bottom: 10px; box-shadow: 0 2px 4px rgba(0,0,0,0.02);">
                      <div style="font-weight: bold; color: #0044AA; margin-bottom: 4px; display: flex; justify-content: space-between;">
                        <span>1. Pitch Jitter (Vocal Imperfection)</span>
                        <span style="color: #64748b;">${jitter.toFixed(2)}%</span>
                      </div>
                      <div style="color: #475569; line-height: 1.5; font-size: 11.5px;">${plainEnglishJitter}</div>
                    </div>
                    
                    <div style="background-color: #ffffff; border: 1px solid rgba(0,68,170,0.08); padding: 12px; border-radius: 8px; margin-bottom: 10px; box-shadow: 0 2px 4px rgba(0,0,0,0.02);">
                      <div style="font-weight: bold; color: #0044AA; margin-bottom: 4px; display: flex; justify-content: space-between;">
                        <span>2. Amplitude Shimmer (Loudness Cycle Stability)</span>
                        <span style="color: #64748b;">${shimmer.toFixed(2)}%</span>
                      </div>
                      <div style="color: #475569; line-height: 1.5; font-size: 11.5px;">${plainEnglishShimmer}</div>
                    </div>
                    
                    <div style="background-color: #ffffff; border: 1px solid rgba(0,68,170,0.08); padding: 12px; border-radius: 8px; margin-bottom: 10px; box-shadow: 0 2px 4px rgba(0,0,0,0.02);">
                      <div style="font-weight: bold; color: #0044AA; margin-bottom: 4px; display: flex; justify-content: space-between;">
                        <span>3. Spectral Flatness (Voice Warmth vs static)</span>
                        <span style="color: #64748b;">${flatness.toFixed(3)}</span>
                      </div>
                      <div style="color: #475569; line-height: 1.5; font-size: 11.5px;">${plainEnglishFlatness}</div>
                    </div>
                    
                    <div style="background-color: #ffffff; border: 1px solid rgba(0,68,170,0.08); padding: 12px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.02);">
                      <div style="font-weight: bold; color: #0044AA; margin-bottom: 4px; display: flex; justify-content: space-between;">
                        <span>4. High-Frequency Anomaly (Synthesizer Signatures)</span>
                        <span style="color: #64748b;">${hfAnom.toFixed(3)}</span>
                      </div>
                      <div style="color: #475569; line-height: 1.5; font-size: 11.5px;">${plainEnglishHF}</div>
                    </div>

                  </div>

                  <!-- Cryptographic Custody Seal -->
                  <h4 style="margin: 0 0 12px 0; color: #0044AA; font-size: 14px; font-weight: 700; border-bottom: 1px solid rgba(0, 68, 170, 0.08); padding-bottom: 6px;">🛡️ Chain of Custody &amp; Forensic Integrity</h4>
                  <div style="background-color: rgba(16, 185, 129, 0.03); border: 1px dashed #10b981; padding: 14px; border-radius: 8px; font-size: 11.5px; line-height: 1.5;">
                    <div style="margin-bottom: 6px; font-weight: bold; color: #10b981; text-transform: uppercase;">Cryptographic Chain Sealed</div>
                    <div style="font-family: monospace; color: #475569; margin-bottom: 3px; word-break: break-all;"><b>SHA-256 Hash:</b> ${sha256}</div>
                    <div style="font-family: monospace; color: #475569; margin-bottom: 6px; word-break: break-all;"><b>Digital Signature:</b> ${signature}</div>
                    <div style="border-top: 1px solid rgba(16, 185, 129, 0.15); padding-top: 6px; font-size: 10.5px; color: #64748b; font-style: italic;">
                      Certified by Authorized UCO Investigator Employee ID: <b>${decoded.employeeId}</b>
                    </div>
                  </div>

                </div>

                <!-- Footer -->
                <div style="background-color: #0c1524; color: #64748b; padding: 16px; text-align: center; font-size: 11px; border-top: 1px solid rgba(0, 68, 170, 0.08);">
                  UCO Bank VoxShield Voice Forensics Cybersecurity System.<br/>
                  Confidential document intended solely for internal risk assessment. Do not distribute externally.
                </div>
              </div>
            </div>
          `
        };

        await transporter.sendMail(mailOptions);
        await logAuditEvent(decoded.employeeId, 'REPORT_EMAILED', req, `Forensic report for call ${callId} emailed to ${email}.`);

        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ success: true }));
      } catch (err) {
        console.error('Error in send-report:', err);
        res.writeHead(500, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: err.message || 'Internal server error' }));
      }
    });
    return;
  }

  // Serve static web pages
  let filePath = path.join(__dirname, req.url === '/' ? 'index.html' : req.url);
  
  // Clean query strings or hash parameters from filepath
  const questionMarkIndex = filePath.indexOf('?');
  if (questionMarkIndex !== -1) {
    filePath = filePath.substring(0, questionMarkIndex);
  }
  
  const ext = path.extname(filePath);
  const contentType = MIME_TYPES[ext] || 'application/octet-stream';

  fs.readFile(filePath, (err, content) => {
    if (err) {
      if (err.code === 'ENOENT') {
        res.writeHead(404, { 'Content-Type': 'text/html' });
        res.end('<h1>404 File Not Found</h1>');
      } else {
        res.writeHead(500);
        res.end(`Server Error: ${err.code}`);
      }
    } else {
      res.writeHead(200, { 'Content-Type': contentType });
      res.end(content, 'utf-8');
    }
  });
});

server.listen(PORT, () => {
  console.log(`VoxShield proxy server running at http://localhost:${PORT}`);
});
