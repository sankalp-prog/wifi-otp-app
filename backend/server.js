import express from 'express';
import nodemailer from 'nodemailer';
import dotenv from 'dotenv';
import sqlite3 from 'sqlite3';
import { open } from 'sqlite';
import cors from 'cors';
import https from 'https';
import fs from 'fs/promises';
import path from 'path';
import { fileURLToPath } from 'url';
import { exec } from 'child_process';
import { UAParser } from 'ua-parser-js';

dotenv.config();
const app = express();
app.use(express.json());
app.use(cors({ origin: true, credentials: true }));
app.set('trust proxy', true);

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Logging utility
const log = {
  info: (msg, data = {}) => console.log(`[INFO] ${new Date().toISOString()} - ${msg}`, data),
  error: (msg, error = {}) => console.error(`[ERROR] ${new Date().toISOString()} - ${msg}`, error),
  warn: (msg, data = {}) => console.warn(`[WARN] ${new Date().toISOString()} - ${msg}`, data),
  debug: (msg, data = {}) => console.log(`[DEBUG] ${new Date().toISOString()} - ${msg}`, data),
};

/* ================================================================
   HTTPS CERTIFICATE LOADING
================================================================ */
let privateKey, certificate, credentials, httpsServer;

try {
  log.info('Loading SSL certificates...');
  privateKey = await fs.readFile(path.join(__dirname, 'nginx-selfsigned.key'), 'utf8');
  certificate = await fs.readFile(path.join(__dirname, 'nginx-selfsigned.crt'), 'utf8');
  credentials = { key: privateKey, cert: certificate };
  httpsServer = https.createServer(credentials, app);
  log.info('SSL certificates loaded successfully');
} catch (error) {
  log.error('Failed to load SSL certificates', {
    error: error.message,
    keyPath: path.join(__dirname, 'nginx-selfsigned.key'),
    certPath: path.join(__dirname, 'nginx-selfsigned.crt'),
  });
  process.exit(1);
}

/* ================================================================
   DB SETUP
================================================================ */
let db;
const dbFile = process.env.DB_FILE || './data/otp.db';

try {
  log.info('Initializing database...', { dbFile });
  db = await open({
    filename: dbFile,
    driver: sqlite3.Database,
  });
  log.info('Database connection established');

  // OTP table
  await db.exec(`CREATE TABLE IF NOT EXISTS otps (
    email TEXT, otp TEXT, expires INTEGER
  )`);
  log.info('OTP table verified/created');

  // CLIENT INFO table
  await db.exec(`CREATE TABLE IF NOT EXISTS client_info (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT,
    user_agent TEXT,
    client_IP TEXT,
    mac_address TEXT,
    browser TEXT,
    browser_version TEXT,
    os TEXT,
    os_version TEXT,
    device TEXT,
    engine TEXT,
    is_mobile INTEGER,
    captive INTEGER DEFAULT 1,
    expires_at INTEGER
  )`);
  log.info('Client info table verified/created');
} catch (error) {
  log.error('Database initialization failed', {
    error: error.message,
    dbFile,
    stack: error.stack,
  });
  process.exit(1);
}

/* ================================================================
   MAILER
================================================================ */
let transporter;

try {
  log.info('Configuring email transporter...');

  if (!process.env.EMAIL_USER || !process.env.EMAIL_PASS) {
    throw new Error('EMAIL_USER or EMAIL_PASS not configured in environment variables');
  }

  transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
      user: process.env.EMAIL_USER,
      pass: process.env.EMAIL_PASS,
    },
  });

  log.info('Email transporter configured', {
    emailUser: process.env.EMAIL_USER,
  });
} catch (error) {
  log.error('Email transporter configuration failed', {
    error: error.message,
    hasEmailUser: !!process.env.EMAIL_USER,
    hasEmailPass: !!process.env.EMAIL_PASS,
  });
  process.exit(1);
}

/* ================================================================
   DNSMASQ LEASE FILE READER
================================================================ */
async function readDnsmasqLeases(searchIP) {
  const leaseFilePath = process.env.LEASE_FILE_PATH;

  if (!leaseFilePath) {
    log.error('LEASE_FILE_PATH not configured in environment variables');
    return null;
  }

  try {
    log.debug('Reading dnsmasq leases file', { searchIP, leaseFilePath });

    const data = await fs.readFile(leaseFilePath, 'utf8');

    if (!data.trim()) {
      log.warn('Dnsmasq leases file is empty', { leaseFilePath });
      return null;
    }

    const lines = data.trim().split('\n');
    log.debug('Parsed lease file', { totalLeases: lines.length });

    const foundLease = lines.find((line) => {
      const [expiry, mac, ip, hostname, clientId] = line.trim().split(/\s+/);
      return ip === searchIP;
    });

    if (!foundLease) {
      log.warn('No lease found for IP', { searchIP, totalLeases: lines.length });
      return null;
    }

    const [, mac] = foundLease.trim().split(/\s+/);
    log.info('MAC address resolved from lease file', { searchIP, mac });
    return mac;
  } catch (err) {
    log.error('Error reading dnsmasq leases file', {
      error: err.message,
      leaseFilePath,
      searchIP,
      errorCode: err.code,
    });
    return null;
  }
}

/* ================================================================
   RFC 8908 CAPPORT API
================================================================ */
app.get('/capport/api', async (req, res) => {
  const ip = req.query.ip || req.ip;
  const portalUrl = process.env.PORTAL_URL || 'https://cp.example.com/portal';

  log.info('Capport API request received', { ip, queryIP: req.query.ip, requestIP: req.ip });

  try {
    const mac = await readDnsmasqLeases(ip);

    if (!mac) {
      log.warn('MAC address not found for IP, defaulting to captive state', { ip });
    }

    res.setHeader('Content-Type', 'application/captive+json');
    res.setHeader('Cache-Control', 'private, no-store');

    const row = mac ? await db.get('SELECT * FROM client_info WHERE mac_address = ? AND client_IP = ? ORDER BY id DESC LIMIT 1', [mac, ip]) : null;

    if (!row) {
      log.info('No client info found, returning captive state', { ip, mac });
      return res.status(200).send(
        JSON.stringify({
          captive: true,
          'user-portal-url': portalUrl,
        })
      );
    }

    // Handle expiration
    if (row.expires_at && Date.now() > row.expires_at) {
      log.info('Client session expired, updating to captive state', {
        ip,
        mac,
        expiresAt: new Date(row.expires_at).toISOString(),
        now: new Date().toISOString(),
      });

      await db.run('UPDATE client_info SET captive = 1 WHERE mac_address = ? AND client_IP = ?', [mac, ip]);
      row.captive = 1;
    }

    const response = {
      captive: !!row.captive,
      'user-portal-url': portalUrl,
    };

    if (!row.captive && row.expires_at) {
      const secs = Math.max(0, Math.floor((row.expires_at - Date.now()) / 1000));
      response['seconds-remaining'] = secs;
      response['can-extend-session'] = true;

      log.info('Active session found', {
        ip,
        mac,
        secondsRemaining: secs,
        expiresAt: new Date(row.expires_at).toISOString(),
      });
    } else {
      log.info('Client in captive state', { ip, mac, captive: row.captive });
    }

    return res.status(200).send(JSON.stringify(response));
  } catch (error) {
    log.error('Capport API error', {
      error: error.message,
      stack: error.stack,
      ip,
    });

    return res.status(500).send(
      JSON.stringify({
        captive: true,
        'user-portal-url': portalUrl,
        error: 'Internal server error',
      })
    );
  }
});

/* ================================================================
   OTP FLOW
================================================================ */

// Send OTP
app.post('/send-otp', async (req, res) => {
  const { email, browserInfo: { userAgent, platform } = {} } = req.body;
  const ip = req.ip || req.connection.remoteAddress;

  log.info('OTP send request initiated', { email, ip, userAgent });

  if (!email) {
    log.warn('OTP request missing email', { ip });
    return res.status(400).json({ success: false, error: 'Email is required' });
  }

  try {
    const mac = await readDnsmasqLeases(ip);

    if (!mac) {
      log.warn('MAC address not resolved for OTP request', { email, ip });
    }

    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    const expires = Date.now() + 5 * 60 * 1000; // 5 min

    const parser = new UAParser(userAgent);
    const result = parser.getResult();

    log.debug('Parsed user agent', {
      email,
      ip,
      browser: result.browser.name,
      os: result.os.name,
      device: result.device.type,
    });

    // Send email
    log.info('Sending OTP email', { email, ip });
    await transporter.sendMail({
      from: process.env.EMAIL_USER,
      to: email,
      subject: 'Your OTP Code',
      text: `Your OTP is ${otp}. It expires in 5 minutes.`,
    });
    log.info('OTP email sent successfully', { email, ip });

    // Store OTP
    await db.run('INSERT INTO otps (email, otp, expires) VALUES (?, ?, ?)', [email, otp, expires]);
    log.debug('OTP stored in database', { email, expiresAt: new Date(expires).toISOString() });

    // Store client info
    const expiresAt = Date.now() + 24 * 60 * 60 * 1000;
    await db.run(
      `INSERT INTO client_info (
        email, user_agent, client_IP, mac_address, browser, browser_version,
        os, os_version, device, engine, is_mobile, captive, expires_at
      )
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?)`,
      [
        email,
        userAgent,
        ip,
        mac || 'NULL',
        result.browser.name || 'Unknown',
        result.browser.version || '',
        result.os.name || '',
        result.os.version || '',
        result.device.type || 'Desktop',
        result.engine.name || '',
        result.device.type === 'mobile' ? 1 : 0,
        expiresAt,
      ]
    );
    log.info('Client info stored in database', {
      email,
      ip,
      mac,
      browser: result.browser.name,
      expiresAt: new Date(expiresAt).toISOString(),
    });

    res.json({ success: true, message: 'OTP sent to email' });
  } catch (err) {
    log.error('Failed to send OTP', {
      error: err.message,
      stack: err.stack,
      email,
      ip,
      errorCode: err.code,
    });
    res.status(500).json({ success: false, error: 'Failed to send OTP' });
  }
});

// Verify OTP
app.post('/verify-otp', async (req, res) => {
  const { email, otp } = req.body;
  const ip = req.ip || req.connection.remoteAddress;

  log.info('OTP verification request received', { email, ip, otpProvided: !!otp });

  if (!email || !otp) {
    log.warn('OTP verification missing required fields', { email: !!email, otp: !!otp, ip });
    return res.status(400).json({ success: false, error: 'Email and OTP are required' });
  }

  try {
    // Fetch latest OTP for the email
    const row = await db.get('SELECT * FROM otps WHERE email = ? ORDER BY expires DESC LIMIT 1', [email]);

    if (!row) {
      log.warn('No OTP found for email', { email, ip });
      return res.json({ success: false, error: 'No OTP found' });
    }

    log.debug('OTP record retrieved', {
      email,
      ip,
      expiresAt: new Date(row.expires).toISOString(),
      isExpired: Date.now() >= row.expires,
    });

    // Check OTP validity
    if (row.otp !== otp) {
      log.warn('Invalid OTP provided', { email, ip, providedOTP: otp });
      return res.json({ success: false, error: 'Invalid OTP' });
    }

    if (Date.now() >= row.expires) {
      log.warn('Expired OTP used', {
        email,
        ip,
        expiresAt: new Date(row.expires).toISOString(),
        now: new Date().toISOString(),
      });
      return res.json({ success: false, error: 'OTP has expired' });
    }

    // Mark as non-captive
    const newExpiresAt = Date.now() + 2 * 60 * 60 * 1000; // +2h
    const updateResult = await db.run('UPDATE client_info SET captive = 0, expires_at = ? WHERE client_IP = ?', [newExpiresAt, ip]);

    log.info('Client marked as authenticated', {
      email,
      ip,
      rowsUpdated: updateResult.changes,
      expiresAt: new Date(newExpiresAt).toISOString(),
    });

    if (updateResult.changes === 0) {
      log.warn('No client_info rows updated during OTP verification', { email, ip });
    }

    // Execute iptables rules
    const interface_name = process.env.INTERFACE_NAME || 'enp0s3';
    const tcpCmd = `sudo /usr/sbin/iptables -t nat -I PREROUTING 1 -i ${interface_name} -p tcp -s ${ip} --dport 53 -j ACCEPT`;
    const udpCmd = `sudo /usr/sbin/iptables -t nat -I PREROUTING 1 -i ${interface_name} -p udp -s ${ip} --dport 53 -j ACCEPT`;

    log.info('Executing iptables rules', { email, ip, interface_name });

    exec(tcpCmd, (err, stdout, stderr) => {
      if (err) {
        log.error('iptables TCP rule failed', {
          error: err.message,
          exitCode: err.code,
          command: tcpCmd,
          email,
          ip,
        });
      } else if (stderr) {
        log.warn('iptables TCP rule stderr output', {
          stderr: stderr.trim(),
          command: tcpCmd,
          email,
          ip,
        });
      } else {
        log.info('iptables TCP rule added successfully', { email, ip });
      }
    });

    exec(udpCmd, (err, stdout, stderr) => {
      if (err) {
        log.error('iptables UDP rule failed', {
          error: err.message,
          exitCode: err.code,
          command: udpCmd,
          email,
          ip,
        });
      } else if (stderr) {
        log.warn('iptables UDP rule stderr output', {
          stderr: stderr.trim(),
          command: udpCmd,
          email,
          ip,
        });
      } else {
        log.info('iptables UDP rule added successfully', { email, ip });
      }
    });

    log.info('OTP verification successful', { email, ip });
    return res.json({ success: true, message: 'OTP verified' });
  } catch (err) {
    log.error('OTP verification error', {
      error: err.message,
      stack: err.stack,
      email,
      ip,
    });
    res.status(500).json({ success: false, error: 'Server error during verification' });
  }
});

/* ================================================================
   ERROR HANDLING MIDDLEWARE
================================================================ */
app.use((err, req, res, next) => {
  log.error('Unhandled error in request', {
    error: err.message,
    stack: err.stack,
    method: req.method,
    path: req.path,
    ip: req.ip,
  });
  res.status(500).json({ success: false, error: 'Internal server error' });
});

/* ================================================================
   START SERVER
================================================================ */
const PORT = process.env.PORT || 443;

if (!PORT) {
  log.error('PORT not configured in environment variables');
  process.exit(1);
}

httpsServer.listen(PORT, '0.0.0.0', () => {
  log.info('HTTPS Server started successfully', {
    port: PORT,
    nodeEnv: process.env.NODE_ENV || 'development',
    dbFile,
    portalUrl: process.env.PORTAL_URL,
  });
});

// Handle uncaught exceptions
process.on('uncaughtException', (error) => {
  log.error('Uncaught Exception - Server will exit', {
    error: error.message,
    stack: error.stack,
  });
  process.exit(1);
});

// Handle unhandled promise rejections
process.on('unhandledRejection', (reason, promise) => {
  log.error('Unhandled Promise Rejection', {
    reason: reason,
    promise: promise,
  });
});

// Graceful shutdown
process.on('SIGTERM', async () => {
  log.info('SIGTERM received, shutting down gracefully...');

  httpsServer.close(async () => {
    log.info('HTTPS server closed');

    try {
      await db.close();
      log.info('Database connection closed');
    } catch (error) {
      log.error('Error closing database', { error: error.message });
    }

    process.exit(0);
  });
});

process.on('SIGINT', async () => {
  log.info('SIGINT received, shutting down gracefully...');

  httpsServer.close(async () => {
    log.info('HTTPS server closed');

    try {
      await db.close();
      log.info('Database connection closed');
    } catch (error) {
      log.error('Error closing database', { error: error.message });
    }

    process.exit(0);
  });
});
