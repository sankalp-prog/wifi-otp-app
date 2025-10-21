import express from 'express';
import nodemailer from 'nodemailer';
import dotenv from 'dotenv';
import sqlite3 from 'sqlite3';
import { open } from 'sqlite';
import cors from 'cors';
import http from 'http';
import { UAParser } from 'ua-parser-js';
import path from 'path';
import fs from 'fs/promises';
import { fileURLToPath } from 'url';

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

// Existing tables
await db.exec(`CREATE TABLE IF NOT EXISTS otps (
  email TEXT, otp TEXT, expires INTEGER
)`);

await db.exec(`CREATE TABLE IF NOT EXISTS client_info (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  email TEXT,
  user_agent TEXT,
  client_IP TEXT,
  browser TEXT,
  browser_version TEXT,
  os TEXT,
  os_version TEXT,
  device TEXT,
  engine TEXT,
  is_mobile INTEGER
)`);

// CAPPORT session state table
await db.exec(`CREATE TABLE IF NOT EXISTS capport_sessions (
  token TEXT PRIMARY KEY,
  email TEXT,
  mac TEXT,
  ip4 TEXT,
  ip6 TEXT,
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
app.get('/capport/api/:token', async (req, res) => {
  const token = req.params.token;
  res.setHeader('Content-Type', 'application/captive+json');
  res.setHeader('Cache-Control', 'private, no-store');

  const row = await db.get('SELECT * FROM capport_sessions WHERE token = ?', [token]);

  const portalUrl = process.env.PORTAL_URL || 'https://cp.example.com/portal';

  // Default response if token not found
  if (!row) {
    return res.status(200).send(
      JSON.stringify({
        captive: true,
        'user-portal-url': portalUrl,
      })
    );
  }

  // If session expired, mark captive again
  if (row.expires_at && Date.now() > row.expires_at) {
    await db.run('UPDATE capport_sessions SET captive = 1 WHERE token = ?', [token]);
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
   OTP FLOW
================================================================ */

// Send OTP
app.post('/send-otp', async (req, res) => {
  const { email, token, browserInfo: { userAgent, platform } = {} } = req.body;
  const otp = Math.floor(100000 + Math.random() * 900000).toString();
  const expires = Date.now() + 5 * 60 * 1000; // 5 min

  const parser = new UAParser(userAgent);
  const result = parser.getResult();
  const ip = req.ip || req.connection.remoteAddress;

  try {
    await transporter.sendMail({
      from: process.env.EMAIL_USER,
      to: email,
      subject: 'Your OTP Code',
      text: `Your OTP is ${otp}. It expires in 5 minutes.`,
    });

    await db.run('INSERT INTO otps (email, otp, expires) VALUES (?, ?, ?)', [email, otp, expires]);

    await db.run(
      `INSERT INTO client_info
        (email, user_agent, client_IP, browser, browser_version,
         os, os_version, device, engine, is_mobile)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [
        email,
        userAgent,
        ip,
        result.browser.name || 'Unknown',
        result.browser.version || '',
        result.os.name || '',
        result.os.version || '',
        result.device.type || 'Desktop',
        result.engine.name || '',
        result.device.type === 'mobile' ? 1 : 0,
      ]
    );

    // Create or update CAPPORT session (mark captive)
    if (token) {
      await db.run(
        `INSERT INTO capport_sessions (token, email, captive, expires_at)
         VALUES (?, ?, 1, ?)
         ON CONFLICT(token) DO UPDATE
           SET email = excluded.email, captive = 1`,
        [token, email, Date.now() + 24 * 60 * 60 * 1000]
      );
    }

    res.json({ success: true, message: 'OTP sent to email' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, error: 'Failed to send OTP' });
  }
});

// Verify OTP
app.post('/verify-otp', async (req, res) => {
  const { email, otp, token } = req.body;
  const row = await db.get('SELECT * FROM otps WHERE email = ? ORDER BY expires DESC LIMIT 1', [email]);

  if (!row) return res.json({ success: false, error: 'No OTP found' });

  if (row.otp === otp && Date.now() < row.expires) {
    // ✅ OTP verified: mark CAPPORT session as open
    if (token) {
      await db.run(
        'UPDATE capport_sessions SET captive = 0, expires_at = ? WHERE token = ?',
        [Date.now() + 2 * 60 * 60 * 1000, token] // 2-hour session
      );
    }
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
httpServer.listen(PORT, '0.0.0.0', () => console.log(`CAPPORT + OTP server running on port ${PORT}`));
