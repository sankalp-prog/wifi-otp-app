-- ============================================
-- OTP STORAGE
-- ============================================
CREATE TABLE IF NOT EXISTS otps (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  email TEXT NOT NULL,
  otp TEXT NOT NULL,
  expires_at INTEGER NOT NULL,           -- Unix timestamp (milliseconds)
  failed_attempts INTEGER DEFAULT 0,     -- Track verification attempts
  is_used INTEGER DEFAULT 0,             -- 0 = not used, 1 = used
  created_at INTEGER NOT NULL,           -- Unix timestamp (milliseconds)
  used_at INTEGER                        -- Unix timestamp when verified
);

CREATE INDEX idx_otps_email ON otps(email);
CREATE INDEX idx_otps_expires ON otps(expires_at);

-- ============================================
-- RATE LIMITING
-- ============================================
CREATE TABLE IF NOT EXISTS rate_limits (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  identifier TEXT NOT NULL,              -- email or IP address
  limit_type TEXT NOT NULL,              -- 'send_otp', 'resend_otp', 'verify_otp'
  request_count INTEGER DEFAULT 1,       -- Number of requests in current window
  window_start INTEGER NOT NULL,         -- Window start timestamp (milliseconds)
  last_request INTEGER NOT NULL,         -- Last request timestamp (milliseconds)
  locked_until INTEGER DEFAULT 0,        -- Temporary lock timestamp (0 = not locked)
  
  UNIQUE(identifier, limit_type)         -- One row per identifier+type combo
);

CREATE INDEX idx_rate_limits_lookup ON rate_limits(identifier, limit_type);
CREATE INDEX idx_rate_limits_locked ON rate_limits(locked_until);

-- ============================================
-- CLIENT INFO
-- ============================================
CREATE TABLE IF NOT EXISTS client_info (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  email TEXT NOT NULL,
  user_agent TEXT,
  client_ip TEXT NOT NULL,
  mac_address TEXT,
  browser TEXT,
  browser_version TEXT,
  os TEXT,
  os_version TEXT,
  device TEXT,
  engine TEXT,
  is_mobile INTEGER DEFAULT 0,           -- 0 = desktop, 1 = mobile
  captive INTEGER DEFAULT 1,             -- 0 = has access, 1 = needs auth
  expires_at INTEGER,                    -- Session expiration timestamp
  created_at INTEGER NOT NULL,           -- First seen timestamp
  last_authenticated INTEGER             -- Last successful auth timestamp
);

CREATE INDEX idx_client_info_email ON client_info(email);
CREATE INDEX idx_client_info_ip ON client_info(client_ip);
CREATE INDEX idx_client_info_mac ON client_info(mac_address);
CREATE INDEX idx_client_info_expires ON client_info(expires_at);

-- ============================================
-- AUDIT LOGS (Optional but Recommended)
-- ============================================
CREATE TABLE IF NOT EXISTS audit_logs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  event_type TEXT NOT NULL,              -- 'otp_sent', 'otp_verified', 'otp_failed', 'rate_limited'
  email TEXT,
  ip_address TEXT,
  details TEXT,                          -- JSON string with additional info
  created_at INTEGER NOT NULL            -- Unix timestamp (milliseconds)
);

CREATE INDEX idx_audit_logs_email ON audit_logs(email);
CREATE INDEX idx_audit_logs_type ON audit_logs(event_type);
CREATE INDEX idx_audit_logs_created ON audit_logs(created_at);