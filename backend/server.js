import express from 'express';
import nodemailer from 'nodemailer';
import dotenv from 'dotenv';
import sqlite3 from 'sqlite3';
import { open } from 'sqlite';
import cors from 'cors';
import http from 'http';
import https from 'https';
import fs from 'fs/promises';
import path from 'path';
import { fileURLToPath } from 'url';
import { UAParser } from "ua-parser-js";

dotenv.config();
const app = express();
app.use(express.json());
app.use(cors({ origin: true, credentials: true })); //allow frontend https://localhost to call backend

/*
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const privateKey  = await fs.readFile(path.join(__dirname, 'vite-server-key.pem'), 'utf8');
const certificate = await fs.readFile(path.join(__dirname, 'vite-server-cert.pem'), 'utf8');
const credentials = { key: privateKey, cert: certificate };
const httpsServer = https.createServer(credentials, app);
*/
const httpServer = http.createServer(app);
app.set('trust proxy', true);
// Open SQLite DB
const db = await open({
  filename: process.env.DB_FILE || './data/otp.db',
  driver: sqlite3.Database,
});
await db.exec('CREATE TABLE IF NOT EXISTS otps (email TEXT, otp TEXT, expires INTEGER)');
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
  )
`);
// Nodemailer config
const transporter = nodemailer.createTransport({
  service: 'gmail', // or use SMTP if not Gmail
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS,
  },
});

// Route: Send OTP
app.post('/send-otp', async (req, res) => {
  const { email, browserInfo: {userAgent, platform} } = req.body;
  const otp = Math.floor(100000 + Math.random() * 900000).toString();
  const expires = Date.now() + 5 * 60 * 1000; // 5 min
  
  // const userAgent = req.get("User-Agent");
  const parser = new UAParser(userAgent);
  const result = parser.getResult();

  const ip = req.ip || req.connection.remoteAddress;
  console.log('Client IP:', ip);

  try {
    await transporter.sendMail({
      from: process.env.EMAIL_USER,
      to: email,
      subject: 'Your OTP Code',
      text: `Your OTP is ${otp}. It expires in 5 minutes.`,
    });

    await db.run('INSERT INTO otps (email, otp, expires) VALUES (?, ?, ?)', [email, otp, expires]);

//  await db.run('INSERT INTO client_info (email, user_agent, platform) VALUES (?, ?, ?)', [email, userAgent, platform])
  // Store parsed client info
    await db.run(`INSERT INTO client_info
       (email, user_agent, client_IP, browser, browser_version, os, os_version, device, engine, is_mobile)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [
        email,
        userAgent,
        ip,
        result.browser.name || "Unknown",
        result.browser.version || "",
        result.os.name || "",
        result.os.version || "",
        result.device.type || "Desktop",
        result.engine.name || "",
        result.device.type === "mobile" ? 1 : 0,
      ]
    );
    res.json({ success: true, message: 'OTP sent to email' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, error: 'Failed to send OTP' });
    }
});

// Route: Verify OTP
app.post('/verify-otp', async (req, res) => {
  const { email, otp } = req.body;
  const row = await db.get('SELECT * FROM otps WHERE email = ? ORDER BY expires DESC LIMIT 1', [email]);

  if (!row) return res.json({ success: false, error: 'No OTP found' });

  if (row.otp === otp && Date.now() < row.expires) {
    res.json({ success: true, message: 'OTP verified' });
    

  } else {
    res.json({ success: false, error: 'Invalid or expired OTP' });
  }
});

app.listen(process.env.PORT, '0.0.0.0', () => {
  console.log(`HTTP Server running on port ${process.env.PORT}`);
  });
//httpsServer.listen(process.env.PORT, '0.0.0.0', () => {
//  console.log(`HTTPS Server running on port ${process.env.PORT}`);
//  });