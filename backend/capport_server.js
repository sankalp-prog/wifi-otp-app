import express from 'express';
import dotenv from 'dotenv';
import sqlite3 from 'sqlite3';
import { open } from 'sqlite';
import fs from 'fs/promises';
import path from 'path';
import { fileURLToPath } from 'url';

dotenv.config();
const app = express();
app.use(express.json());
app.set('trust proxy', true);

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

/* ================================================================
   BASIC LOGGER (same API as your original)
================================================================ */
const log = {
  info: (msg, data = {}) => console.log(`[INFO] ${new Date().toISOString()} - ${msg}`, data),
  error: (msg, error = {}) => console.error(`[ERROR] ${new Date().toISOString()} - ${msg}`, error),
  warn: (msg, data = {}) => console.warn(`[WARN] ${new Date().toISOString()} - ${msg}`, data),
  debug: (msg, data = {}) => console.log(`[DEBUG] ${new Date().toISOString()} - ${msg}`, data),
};

/* ================================================================
   DB SETUP (same schema as your main server)
================================================================ */
let db;
// const dbFile = process.env.DB_FILE || './data/otp.db';
const dbFile = './data/otp1.db';

try {
  log.info('Initializing database...', { dbFile });

  db = await open({
    filename: dbFile,
    driver: sqlite3.Database,
  });

  log.info('Database connected');

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
   DNSMASQ LEASE FILE READER (unchanged)
================================================================ */
async function readDnsmasqLeases(searchIP) {
  const leaseFilePath = process.env.LEASE_FILE_PATH;

  if (!leaseFilePath) {
    log.error('LEASE_FILE_PATH not configured');
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

    const foundLease = lines.find((line) => {
      const [expiry, mac, ip] = line.trim().split(/\s+/);
      return ip === searchIP;
    });

    if (!foundLease) {
      log.warn('No lease found for IP', { searchIP });
      return null;
    }

    const [, mac] = foundLease.trim().split(/\s+/);
    log.info('MAC address resolved', { searchIP, mac });
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
   RFC 8908 CAPPORT API (UNCHANGED — EXACT COPY)
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
   START HTTP SERVER
================================================================ */
const PORT = process.env.HTTP_PORT || 80;

app.listen(PORT, '0.0.0.0', () => {
  log.info('HTTP CAPPORT API Server running', {
    port: PORT,
    nodeEnv: process.env.NODE_ENV || 'development',
  });
});
