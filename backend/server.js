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
    hostname TEXT,
    browser_engine TEXT,
    is_mobile INTEGER,
    captive INTEGER DEFAULT 1,
    expires_at INTEGER,
    UNIQUE(email, mac_address)
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

    const [, mac, ip, hostname] = foundLease.trim().split(/\s+/);
    log.info('MAC address resolved from lease file', { searchIP, mac, ip, hostname });
    return {
      mac,
      hostname,
    };
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
app.get('/capport', async (req, res) => {
  const ip = req.query.ip || req.ip;
  const portalUrl = process.env.PORTAL_URL || 'https://10.12.30.13:443';

  log.info('Capport API request received', { ip, queryIP: req.query.ip, requestIP: req.ip });

  try {
    const { mac, hostname } = await readDnsmasqLeases(ip);

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
app.post('/api/send-otp', async (req, res) => {
  const { email } = req.body;
  const ip = req.ip || req.connection.remoteAddress;

  const allowedDomains = ['underscorecs.com'];

  log.info('OTP send request initiated', { email, ip });

  if (!email) {
    log.warn('OTP request missing email', { ip });
    return res.status(400).json({ success: false, error: 'Email is required' });
  }

  // Extract domain from email
  const domain = email.split('@')[1]?.toLowerCase();

  if (!allowedDomains.includes(domain)) {
    return res.status(400).json({
      success: false,
      error: `Email domain not allowed. Allowed domains: ${allowedDomains.join(', ')}`,
    });
  }

  try {
    const { mac } = (await readDnsmasqLeases(ip)) || {};

    if (!mac) {
      log.warn('MAC address not resolved during send-otp', { email, ip });
      return res.json({
        success: false,
        error: 'Unable to identify device, please check you network connection',
      });
    }

    // Check if the device
    const existingDevices = await db.get('SELECT id FROM client_info WHERE email = ? AND mac_address = ?', [email, mac]);

    if (!existingDevices) {
      // New device, check limit
      const MAX_DEVICES = parseInt(process.env.MAX_DEVICES_PER_EMAIL || '3');

      const deviceCount = await db.get('SELECT COUNT(DISTINCT mac_address) as count FROM client_info WHERE email = ?', [email]);

      if (deviceCount.count > MAX_DEVICES) {
        log.warn('Device limit exceeded at OTP request', { email, mac, ip, currentDevices: deviceCount.count, maxDevices: MAX_DEVICES });
        return res.status(403).json({
          success: false,
          error: `Maximun ${MAX_DEVICES} devices allowed per account. Please disconnect a device first.`,
        });
      }
    } else {
      log.info('Existing device re-authenticating', { email, mac, ip });
    }

    // Generate and send OTP
    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    const expires = Date.now() + 5 * 60 * 1000; // 5 min

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
app.post('/api/verify-otp', async (req, res) => {
  // const { email, otp } = req.body;
  const { email, otp, browserInfo: { userAgent, platform } = {} } = req.body;
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

    const { mac, hostname } = (await readDnsmasqLeases(ip)) || {};

    if (!mac) {
      // log.warn('MAC address not resolved for OTP request', { email, ip });
      return res.json({ success: false, error: 'MAC address not resolved in DNS lease file' });
    }

    const parser = new UAParser(userAgent);
    const result = parser.getResult();

    log.debug('Parsed user agent', {
      email,
      ip,
      hostname,
      browser: result.browser.name,
      os: result.os.name,
      device: result.device.type,
    });

    const expiresAt = Date.now() + 24 * 60 * 60 * 1000; // 24 hours

    await db.run(
      ` INSERT INTO client_info ( email, user_agent, client_IP, mac_address, browser, browser_version, os, os_version, hostname, browser_engine, is_mobile, captive, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, ?) ON CONFLICT(email, mac_address) DO UPDATE SET user_agent = excluded.user_agent, client_IP = excluded.client_IP, browser = excluded.browser, browser_version = excluded.browser_version, os = excluded.os, os_version = excluded.os_version, hostname = excluded.hostname, browser_engine = excluded.browser_engine, is_mobile = excluded.is_mobile, captive = 0, expires_at = excluded.expires_at `,
      [
        email,
        userAgent,
        ip,
        mac || 'NULL',
        result.browser.name || 'Unknown',
        result.browser.version || '',
        result.os.name || '',
        result.os.version || '',
        hostname || 'Undefined',
        result.engine.name || '',
        result.device.type === 'mobile' ? 1 : 0,
        expiresAt,
      ]
    );

    // const prevClientData = await db.get(`SELECT * FROM client_info WHERE email = ?, mac_address = ?`, [email, mac]);

    // let clientDataUpdateResult;

    // if (prevClientData) {
    //   clientDataUpdateResult = await db.run(
    //     `UPDATE client_info SET email = ?, user_agent = ?, client_IP = ?, mac_address = ?, browser = ?, browser_version = ?, os = ?, os_version = ?, device = ?, engine = ?, is_mobile =?, captive = 0, expires_at = ? WHERE client_IP = ?`,
    //     [
    //       email,
    //       userAgent,
    //       ip,
    //       mac || 'NULL',
    //       result.browser.name || 'Unknown',
    //       result.browser.version || '',
    //       result.os.name || '',
    //       result.os.version || '',
    //       hostname || 'Undefined',
    //       result.engine.name || '',
    //       result.device.type === 'mobile' ? 1 : 0,
    //       expiresAt,
    //     ]
    //   );
    // } else {
    //   // Store client info
    //   await db.run(
    //     `INSERT INTO client_info (
    //     email, user_agent, client_IP, mac_address, browser, browser_version,
    //     os, os_version, device, engine, is_mobile, captive, expires_at
    //   )
    //   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?)`,
    //     [
    //       email,
    //       userAgent,
    //       ip,
    //       mac || 'NULL',
    //       result.browser.name || 'Unknown',
    //       result.browser.version || '',
    //       result.os.name || '',
    //       result.os.version || '',
    //       hostname || 'Undefined',
    //       result.engine.name || '',
    //       result.device.type === 'mobile' ? 1 : 0,
    //       expiresAt,
    //     ]
    //   );
    // }
    log.info('Client info stored in database', {
      email,
      ip,
      mac,
      browser: result.browser.name,
      hostname,
      expiresAt: new Date(expiresAt).toISOString(),
    });

    // // TODO: change this to the new update variable
    // if (clientDataUpdateResult.changes === 0) {
    //   log.warn('No client_info table rows updated during OTP verification', { email, ip });
    // }

    // Execute iptables rules
    // const interface_name = process.env.INTERFACE_NAME || 'eth0';
    const tcpCmd = `sudo /usr/sbin/iptables -t nat -I PREROUTING 1 -p tcp -s ${ip} --dport 53 -j ACCEPT`;
    const udpCmd = `sudo /usr/sbin/iptables -t nat -I PREROUTING 1 -p udp -s ${ip} --dport 53 -j ACCEPT`;

    log.info('Executing iptables rules', { email, ip });

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
