import express from 'express';
import nodemailer from 'nodemailer';
import dotenv from 'dotenv';
import sqlite3 from 'sqlite3';
import { open } from 'sqlite';
import cors from 'cors';
import http from 'http';
import { UAParser } from 'ua-parser-js';

dotenv.config();
const app = express();
app.use(express.json());
app.use(cors({ origin: true, credentials: true }));
app.set('trust proxy', true);

/* ================================================================
   DB SETUP
================================================================ */
const db = await open({
  filename: process.env.DB_FILE || './data/otp.db',
  driver: sqlite3.Database,
});

// OTP table
await db.exec(`CREATE TABLE IF NOT EXISTS otps (
  email TEXT, otp TEXT, expires INTEGER
)`);

// CLIENT INFO now holds captive state as well
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

/* ================================================================
   MAILER
================================================================ */
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: { user: process.env.EMAIL_USER, pass: process.env.EMAIL_PASS },
});

/* ================================================================
   RFC 8908 CAPPORT API
================================================================ */
app.get('/capport/api', async (req, res) => {
  const ip = req.query.ip || req.ip;
  const mac = req.query.mac;

  res.setHeader('Content-Type', 'application/captive+json');
  res.setHeader('Cache-Control', 'private, no-store');

  if (!mac) {
    return res.status(400).send(
      JSON.stringify({
        error: 'MAC address required',
        captive: true,
      })
    );
  }

  const row = await db.get('SELECT * FROM client_info WHERE mac_address = ? AND client_IP = ? ORDER BY id DESC LIMIT 1', [mac, ip]);

  const portalUrl = process.env.PORTAL_URL || 'https://cp.example.com/portal';

  if (!row) {
    // Default captive = true
    return res.status(200).send(
      JSON.stringify({
        captive: true,
        'user-portal-url': portalUrl,
      })
    );
  }

  // Handle expiration
  if (row.expires_at && Date.now() > row.expires_at) {
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
  }

  return res.status(200).send(JSON.stringify(response));
});

/* ================================================================
   OTP FLOW (uses client_info for state)
================================================================ */

// Send OTP
app.post('/send-otp', async (req, res) => {
  const { email, mac, browserInfo: { userAgent, platform } = {} } = req.body;
  const ip = req.ip || req.connection.remoteAddress;

  if (!mac) {
    return res.status(400).json({ success: false, error: 'MAC address required' });
  }

  const otp = Math.floor(100000 + Math.random() * 900000).toString();
  const expires = Date.now() + 5 * 60 * 1000; // 5 min

  const parser = new UAParser(userAgent);
  const result = parser.getResult();

  try {
    await transporter.sendMail({
      from: process.env.EMAIL_USER,
      to: email,
      subject: 'Your OTP Code',
      text: `Your OTP is ${otp}. It expires in 5 minutes.`,
    });

    await db.run('INSERT INTO otps (email, otp, expires) VALUES (?, ?, ?)', [email, otp, expires]);

    // Add or update client_info record — captive = 1 until verified
    await db.run(
      `INSERT INTO client_info (
        email, user_agent, client_IP, mac_address, browser, browser_version,
        os, os_version, device, engine, is_mobile, captive, expires_at
      )
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?)
      ON CONFLICT(mac_address, client_IP)
      DO UPDATE SET
        email = excluded.email,
        user_agent = excluded.user_agent,
        captive = 1,
        expires_at = excluded.expires_at`,
      [
        email,
        userAgent,
        ip,
        mac,
        result.browser.name || 'Unknown',
        result.browser.version || '',
        result.os.name || '',
        result.os.version || '',
        result.device.type || 'Desktop',
        result.engine.name || '',
        result.device.type === 'mobile' ? 1 : 0,
        Date.now() + 24 * 60 * 60 * 1000,
      ]
    );

    res.json({ success: true, message: 'OTP sent to email' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, error: 'Failed to send OTP' });
  }
});

// Verify OTP
app.post('/verify-otp', async (req, res) => {
  const { email, otp, mac } = req.body;
  const ip = req.ip || req.connection.remoteAddress;

  if (!mac) {
    return res.status(400).json({ success: false, error: 'MAC address required' });
  }

  const row = await db.get('SELECT * FROM otps WHERE email = ? ORDER BY expires DESC LIMIT 1', [email]);

  if (!row) return res.json({ success: false, error: 'No OTP found' });

  if (row.otp === otp && Date.now() < row.expires) {
    // ✅ Mark as non-captive
    await db.run(
      'UPDATE client_info SET captive = 0, expires_at = ? WHERE mac_address = ? AND client_IP = ?',
      [Date.now() + 2 * 60 * 60 * 1000, mac, ip] // 2h
    );

    return res.json({ success: true, message: 'OTP verified' });
  } else {
    return res.json({ success: false, error: 'Invalid or expired OTP' });
  }
});

/* ================================================================
   START SERVER
================================================================ */
const PORT = process.env.PORT || 8080;
const httpServer = http.createServer(app);
httpServer.listen(PORT, '0.0.0.0', () => console.log(`CAPPORT (client_info-based) + OTP server running on port ${PORT}`));
