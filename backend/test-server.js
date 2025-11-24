import express from 'express';
import cors from 'cors';
import { open } from 'sqlite';
import sqlite3 from 'sqlite3';

const app = express();
app.use(express.json());
app.use(cors({ origin: true, credentials: true }));

let db;

try {
  db = await open({
    filename: './test_data/database.db',
    driver: sqlite3.Database,
  });
  console.log('Database Connected');
} catch (err) {
  console.log('Database connection failed: ', err.message);
  process.exit(1);
}

const PORT = process.env.PORT || 3001;

// Helper to generate random 6-digit OTP
function generateOTP() {
  return Math.floor(100000 + Math.random() * 900000).toString();
}

async function checkCooldown(identifier, limitType, cooldownMs) {
  const data = await db.get(`SELECT * FROM rate_limits WHERE identifier = ? AND limit_type = ?`, [identifier, limitType]);

  // If no record exists, allow the request
  if (!data) {
    return {
      allowed: true,
    };
  }

  // Calculate time since last request
  const timeSinceLastRequest = Date.now() - data.last_request;

  // If not enough time has passed yet, reject
  if (timeSinceLastRequest < cooldownMs) {
    const remainingMs = cooldownMs - timeSinceLastRequest;
    const remainingSeconds = Math.ceil(remainingMs / 1000);

    return {
      allowed: false,
      remainingSeconds: remainingSeconds,
      message: `Please wait ${remainingSeconds} seconds before requesting again`,
    };
  }

  // Enough time has passed, allow
  return {
    allowed: true,
  };
}
async function checkHourlyWindow(identifier, limitType, maxRequests) {
  // Query database for existing rate limit record
  const data = await db.get('SELECT * FROM rate_limits WHERE identifier = ? AND limit_type = ?', [identifier, limitType]);

  const now = Date.now();
  const oneHour = 60 * 60 * 1000; // 1 hour in milliseconds

  // If no record exists, create new one
  if (!data) {
    await db.run(
      `INSERT INTO rate_limits 
       (identifier, limit_type, request_count, window_start, last_request) 
       VALUES (?, ?, ?, ?, ?)`,
      [identifier, limitType, 1, now, now]
    );

    return {
      allowed: true,
    };
  }

  // Check if window has expired (older than 1 hour)
  const timeSinceWindowStart = now - data.window_start;

  if (timeSinceWindowStart > oneHour) {
    // Window expired - reset count and start new window
    await db.run(
      `UPDATE rate_limits 
       SET request_count = 1, 
           window_start = ?, 
           last_request = ? 
       WHERE identifier = ? AND limit_type = ?`,
      [now, now, identifier, limitType]
    );

    return {
      allowed: true,
    };
  }

  // Window still active - check if limit exceeded
  if (data.request_count >= maxRequests) {
    const remainingMs = oneHour - timeSinceWindowStart;
    const remainingMinutes = Math.ceil(remainingMs / 60000);

    return {
      allowed: false,
      message: `Too many requests. Please try again in ${remainingMinutes} minutes`,
    };
  }

  // Within limit - increment count
  await db.run(
    `UPDATE rate_limits 
     SET request_count = request_count + 1, 
         last_request = ? 
     WHERE identifier = ? AND limit_type = ?`,
    [now, identifier, limitType]
  );

  return {
    allowed: true,
  };
}
async function updateRateLimit(identifier, limitType, timestamp) {
  // Check if record exists
  const existing = await db.get('SELECT * FROM rate_limits WHERE identifier = ? AND limit_type = ?', [identifier, limitType]);

  if (existing) {
    // Update existing record
    await db.run(
      `UPDATE rate_limits 
       SET last_request = ? 
       WHERE identifier = ? AND limit_type = ?`,
      [timestamp, identifier, limitType]
    );
  } else {
    // Insert new record
    await db.run(
      `INSERT INTO rate_limits 
       (identifier, limit_type, request_count, window_start, last_request) 
       VALUES (?, ?, ?, ?, ?)`,
      [identifier, limitType, 1, timestamp, timestamp]
    );
  }
}

// Send OTP endpoint
app.post('/send-otp', async (req, res) => {
  const { email, browserInfo } = req.body;
  const ip = req.ip;

  if (!email) {
    return res.status(400).json({
      success: false,
      error: 'Email is required',
    });
  }

  // 1. Check email cooldown (60 seconds)
  const emailCooldown = await checkCooldown(email, 'send_otp_email', 60000);
  if (!emailCooldown.allowed) {
    return res.json({
      success: false,
      error: emailCooldown.message,
      retryAfter: emailCooldown.remainingSeconds,
    });
  }

  // 2. Check email hourly window (3 requests)
  const emailWindow = await checkHourlyWindow(email, 'send_otp_email', 3);
  if (!emailWindow.allowed) {
    console.log('❌ Email hourly limit hit');
    return res.json({
      success: false,
      error: emailWindow.message,
    });
  }

  // 3. Check IP hourly window (10 requests)
  const ipWindow = await checkHourlyWindow(ip, 'send_otp_ip', 10);
  if (!ipWindow.allowed) {
    console.log('❌ IP hourly limit hit');
    return res.json({
      success: false,
      error: ipWindow.message,
    });
  }

  console.log('✅ All rate limit checks passed');

  // 4. Update rate limits for BOTH
  await updateRateLimit(email, 'send_otp_email', Date.now());
  await updateRateLimit(ip, 'send_otp_ip', Date.now());

  // Continue with OTP generation...
  // Generate OTP
  const otp = generateOTP();
  const created_at = Date.now();
  const expires = created_at + 5 * 60 * 1000; // 5 minutes

  let isClient;
  try {
    // returns undefined if record isn't there
    isClient = await db.get(`SELECT * FROM client_info WHERE email = ?`, [email]);
  } catch (err) {
    console.log('error reading/fetching data from client_info table: ', err.message);
  }

  if (isClient && isClient.expires_at >= Date.now()) {
    return res.json({
      success: false,
      message: 'You already have access',
    });
  }

  try {
    await db.run(
      `INSERT INTO otps (email, otp, expires_at, created_at) 
     VALUES (?, ?, ?, ?)`,
      [email, otp, expires, created_at]
    );
    console.log('user info written in DB, otps table');
  } catch (err) {
    console.log('error writing info to otps table: ', err.message);
  }

  try {
    await db.run(`INSERT INTO client_info (email, client_ip, created_at, expires_at) VALUES (?, ?, ?, ?)`, [email, ip, created_at, expires]);
    console.log('successfully written to client_info table');
  } catch (err) {
    console.log('error in writing to client_info table: ', err.message);
  }

  // Log the OTP (in real app, this would be sent via email)
  console.log('\n✅ OTP Generated:');
  console.log('═══════════════════════════════');
  console.log('  EMAIL:', email);
  console.log('  OTP:', otp);
  console.log('  EXPIRES:', new Date(expires).toLocaleTimeString());
  console.log('═══════════════════════════════\n');

  res.json({
    success: true,
    message: 'OTP sent to email',
  });
});

// Verify OTP endpoint
app.post('/verify-otp', async (req, res) => {
  const { email, otp } = req.body;

  console.log('\n🔐 OTP Verification Request:');
  console.log('Email:', email);
  console.log('OTP Provided:', otp);

  if (!email || !otp) {
    return res.status(400).json({
      success: false,
      error: 'Email and OTP are required',
    });
  }

  // Check if OTP exists
  // const storedOTP = otpStore.get(email);
  let storedOTP;
  try {
    storedOTP = await db.get(`SELECT * FROM otps WHERE email = ?`, [email]);
    console.log('🚀 -> test-server.js:119 -> storedOTP: ', storedOTP);
  } catch (err) {
    console.log('Error reading otp from db: ', err.message);
  }

  if (!storedOTP) {
    console.log('❌ No OTP found for this email\n');
    return res.json({
      success: false,
      error: 'No OTP found',
    });
  }

  // Check if OTP is expired
  if (Date.now() >= storedOTP.expires) {
    console.log('❌ OTP has expired\n');
    // otpStore.delete(email);
    // TODO: Delete records from otp table
    try {
      await db.run(`DELETE FROM otps WHERE email = ?`, [email]);
      console.log('Successfully deleted expired otp record');
    } catch (err) {
      console.log('Error deleting otp record of expired otp: ', err.message);
    }

    return res.json({
      success: false,
      error: 'OTP has expired',
    });
  }

  // Check if OTP matches
  if (storedOTP.otp !== otp) {
    try {
      await db.run(`UPDATE otps SET failed_attempts = failed_attempts + 1 WHERE email = ?`, [email]);
      console.log('❌ Invalid OTP\n');
    } catch (err) {
      console.log('error updating failed attempts: ', err.message);
    }
    return res.json({
      success: false,
      error: 'Invalid OTP',
    });
  }

  // Success!
  try {
    await db.run(`UPDATE client_info SET captive = ?, last_authenticated = ? WHERE email = ?`, [0, Date.now(), email]);
  } catch (err) {
    console.log('error setting captive to false/0 in client_info: ', err.message);
  }
  console.log('✅ OTP Verified Successfully!\n');
  // otpStore.delete(email); // Remove used OTP

  try {
    await db.run(`DELETE FROM otps WHERE email = ?`, [email]);
    console.log('successfuly deleted record after verification!');
  } catch (err) {
    console.log('Error deleting record after verification');
  }

  res.json({
    success: true,
    message: 'OTP verified',
  });
});

// Mock Capport API endpoint
app.get('/capport/api', (req, res) => {
  console.log('🌐 Capport API called');

  res.setHeader('Content-Type', 'application/captive+json');
  res.setHeader('Cache-Control', 'private, no-store');

  res.status(200).json({
    captive: false,
    'user-portal-url': 'https://example.com/portal',
    'seconds-remaining': 7200,
    'can-extend-session': true,
  });
});

// Health check endpoint
app.get('/health', (req, res) => {
  res.json({
    status: 'ok',
    timestamp: new Date().toISOString(),
    activeOTPs: otpStore.size,
  });
});

// Error handling middleware
app.use((err, req, res, next) => {
  console.error('❌ Server Error:', err.message);
  res.status(500).json({
    success: false,
    error: 'Internal server error',
  });
});

// Start server
app.listen(PORT, '0.0.0.0', () => {
  console.log('\n🚀 Test Server Started');
  console.log('═══════════════════════════════════════');
  console.log(`  URL: http://localhost:${PORT}`);
  console.log(`  Network: http://0.0.0.0:${PORT}`);
  console.log('═══════════════════════════════════════');
  console.log('\n📝 Available Endpoints:');
  console.log('  POST /send-otp');
  console.log('  POST /verify-otp');
  console.log('  GET  /capport/api');
  console.log('  GET  /health');
  console.log('\n⚡ Ready to accept requests!\n');
});

// Graceful shutdown
process.on('SIGTERM', () => {
  console.log('\n👋 Shutting down gracefully...');
  process.exit(0);
});

process.on('SIGINT', () => {
  console.log('\n👋 Shutting down gracefully...');
  process.exit(0);
});
