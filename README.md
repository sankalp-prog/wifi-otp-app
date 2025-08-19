# WiFi OTP App

A simple email OTP authentication application using **Node.js, Express, SQLite, React, and Vite**.  
Users can request an OTP to their email and verify it.

---

## Project Structure

```
wifi-otp-app/
├─ frontend/       # React + Vite frontend
├─ backend/        # Express + SQLite backend
├─ .prettierrc     # Optional Prettier config
├─ README.md
```

---

## Prerequisites

- Node.js >= 20.x
- npm >= 10.x
- A Gmail account (for sending OTP emails)
  - Make sure you generate an **App Password** for SMTP

---

## Setup Instructions

### 1. Clone the repo

```bash
git clone <repo-url>
cd wifi-otp-app
```

### 2. Backend Setup

```bash
cd backend
npm install
```

- Create a `.env` file in `backend/` with the following:

```
PORT=5000

# Gmail or SMTP creds
EMAIL_USER=your-email@gmail.com
EMAIL_PASS=your-app-password

# SQLite DB file
DB_FILE=./data/otp.db
```

- Start the backend server:

```bash
npm run dev
```

Default backend runs on `http://localhost:5000`.

### 3. Frontend Setup

```bash
cd ../frontend
npm install
```

- Start the Vite dev server:

```bash
npm run dev
```

Default frontend runs on `http://localhost:5173`.

---

## Usage

1. Open the frontend URL in your browser.
2. Enter your email and click **Send OTP**.
3. Check your email for the OTP code.
4. Enter the OTP on the frontend and click **Verify OTP**.
5. You will see a success or failure message.

---

## Notes

- SQLite database is stored in `backend/otp.db`.
- OTP expires in 5 minutes.
- You can customize the OTP expiry time in `backend/server.js`.
- For production, consider:
  - Using HTTPS
  - Hashing OTPs before storing
  - Adding rate-limiting to prevent spam

---

## Optional Tools

- Prettier: `.prettierrc` at repo root for consistent formatting
- VSCode recommended for development

---

## License

MIT
