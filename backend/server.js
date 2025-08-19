import express from 'express';
import nodemailer from 'nodemailer';
import dotenv from 'dotenv';
import sqlite3 from 'sqlite3';
import { open } from 'sqlite';
import cors from 'cors';

dotenv.config();
const app = express();
app.use(express.json());
app.use(cors()); // allow frontend http://localhost:3000 to call backend

// Open SQLite DB
const db = await open({
  filename: process.env.DB_FILE || './data/otp.db',
  driver: sqlite3.Database,
});
await db.exec('CREATE TABLE IF NOT EXISTS otps (email TEXT, otp TEXT, expires INTEGER)');

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
  const { email } = req.body;
  const otp = Math.floor(100000 + Math.random() * 900000).toString();
  const expires = Date.now() + 5 * 60 * 1000; // 5 min

  try {
    await transporter.sendMail({
      from: process.env.EMAIL_USER,
      to: email,
      subject: 'Your OTP Code',
      text: `Your OTP is ${otp}. It expires in 5 minutes.`,
    });

    await db.run('INSERT INTO otps (email, otp, expires) VALUES (?, ?, ?)', [email, otp, expires]);

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

app.listen(process.env.PORT || 5000, () => console.log(`Backend running on http://localhost:${process.env.PORT || 5000}`));
