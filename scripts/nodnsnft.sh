#!/usr/bin/env bash
#
# Periodically:
# - extract DNS-requesting IPs
# - compare with outhenticated devices in otp.db
# - report connected IPs with NO DNS activity in specified time
# - exclude INLINE exception IPs
#

DNS_LOG="${1:-/var/log/dnsmasq1.log}"
DB_FILE="${2:-/var/www/backend/data/otp.db}"
log_file="/var/log/mynodns.log"

WINDOW_MINUTES=150     # DNS inactivity window
INTERVAL=500           # repeat

# -------------------------------------------------
# CONFIGURABLE EXCEPTION IP ARRAY
# -------------------------------------------------
exception_IPs=(
  "0.0.0.0"
  "10.12.30.13"
  "10.40.13.50"
  "10.40.13.53"
  "10.40.13.151"
  "10.40.13.45"
  "10.40.13.169"
  "10.40.13.205"
  "10.40.13.162"
)
# -------------------------------------------------

TMP_DNS="/tmp/dns_ips_current0.txt"
TMP_DB="/tmp/db_ips_all0.txt"
TMP_EXC="/tmp/exception_ips0.txt"

# -----------------------------
# Sanity checks
# -----------------------------
[[ ! -f "$DB_FILE" ]] && { echo "ERROR: sqlite DB not found"; exit 1; }
[[ ! -f "$DNS_LOG" ]] && { echo "ERROR: dnsmasq log not found"; exit 1; }

is_ip_online() {
  local ip="$1"
  ip neigh show | awk '{print $1}' | grep -qx "$ip"
}
# -----------------------------
# DNS extraction (BusyBox-safe)
# -----------------------------
extract_dns_ips() {
  gawk -v window_min="$WINDOW_MINUTES" '
  BEGIN {
    # Build month lookup
    split("Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec", m)
    for (i = 1; i <= 12; i++) mon[m[i]] = i

    # Time window
    now = systime()
    cutoff = now - (window_min * 60)

    year = strftime("%Y", now)
  }

  {
    # Parse timestamp: Feb  6 17:31:24
    month = mon[$1]
    day   = $2
    split($3, t, ":")
    hour = t[1]; min = t[2]; sec = t[3]

    if (!month) next

    # Convert to epoch (GNU gawk)
    epoch = mktime(year " " month " " day " " hour " " min " " sec)

    if (epoch < cutoff) next

    # Extract client IP ONLY from query lines
    if (match($0, /from ([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)$/, a)) {
      print a[1]
    }
  }
  ' "$DNS_LOG" | sort -u
}


# -----------------------------
# Prepare exception file
# -----------------------------
printf "%s\n" "${exception_IPs[@]}" | sort -u > "$TMP_EXC"

# =============================
# MAIN LOOP
# =============================
while true; do
  {
    echo
    echo "[INFO] Run at $(date)"
    echo "====================="
  } >> "$log_file"

  # -----------------------------
  # Extract DNS IPs
  # -----------------------------
  extract_dns_ips > "$TMP_DNS"

  # -----------------------------
  # Extract DB IPs
  # -----------------------------
  sqlite3 "$DB_FILE" <<EOF | sort -u > "$TMP_DB"
.headers off
.mode list
SELECT DISTINCT client_IP
FROM client_info
WHERE client_IP IS NOT NULL
  AND client_IP != '';
EOF

  # -----------------------------
  # Compare + Actions
  # -----------------------------
  echo "IPs in otp.db with NO DNS requests:" >> "$log_file"

  comm -13 "$TMP_DNS" "$TMP_DB" \
    | comm -23 - "$TMP_EXC" \
    | while read -r ip; do
        if ! is_ip_online "$ip"; then
           echo "[SKIP] $ip is offline — ignoring" >> "$log_file"
           continue
        fi

        echo "[ACTION] Processing delete for IP: $ip" >> "$log_file"
        if nft delete element inet captive auth_clients { "$ip" } 2>/dev/null; then
          echo "[OK] Removed $ip from nft set auth_clients" >> "$log_file"
        else
          echo "[SKIP] $ip not present in auth_clients set" >> "$log_file"
        fi
      done
  echo "[INFO] Sleeping for $INTERVAL seconds..." >> "$log_file"
  sleep "$INTERVAL"
done
