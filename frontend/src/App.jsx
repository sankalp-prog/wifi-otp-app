import './App.css';
import React, { useEffect, useState } from 'react';

function App() {
  const [email, setEmail] = useState('');
  const [otp, setOtp] = useState('');
  const [step, setStep] = useState('request'); // 'request' | 'verify'
  const [message, setMessage] = useState('');
  const [token, setToken] = useState(null);

  // ================== CAPPORT token handling ==================
  useEffect(() => {
    const params = new URLSearchParams(window.location.search);
    const t = params.get('token');
    if (t) setToken(t);
    else {
      // fallback for testing without a gateway
      const fallback = Math.random().toString(36).slice(2);
      setToken(fallback);
    }
  }, []);

  // ================== Optional: browser capability info ==================
  useEffect(() => {
    const API_BASE_URL = import.meta.env.VITE_API_BASE_URL;
    const browserInfo = {
      userAgent: navigator.userAgent,
      platform: navigator.platform,
      language: navigator.language,
    };

    fetch(`${API_BASE_URL}/browser-info`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(browserInfo),
    }).catch(() => {});
  }, []);

  // ================== Send OTP ==================
  const sendOtp = async () => {
    try {
      const API_BASE_URL = import.meta.env.VITE_API_BASE_URL;
      const browserInfo = {
        userAgent: navigator.userAgent,
        platform: navigator.platform,
      };

      const res = await fetch(`${API_BASE_URL}/send-otp`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, browserInfo, token }),
      });
      const data = await res.json();
      setMessage(data.message || data.error);
      if (data.success) setStep('verify');
    } catch (err) {
      setMessage('Failed to send OTP');
    }
  };

  // ================== Verify OTP + CAPPORT state update ==================
  const verifyOtp = async () => {
    try {
      const API_BASE_URL = import.meta.env.VITE_API_BASE_URL;
      const res = await fetch(`${API_BASE_URL}/verify-otp`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, otp, token }),
      });
      const data = await res.json();

      if (data.success) {
        setMessage('✅ Authentication successful! You now have Internet access.');
        // Force CAPPORT API poll so OS sees captive:false immediately
        await fetch(`${API_BASE_URL}/capport/api/${token}`, {
          cache: 'no-store',
        }).catch(() => {});
      } else {
        setMessage(data.error || 'Failed to verify OTP');
      }
    } catch (err) {
      setMessage('Failed to verify OTP');
    }
  };

  // ================== UI ==================
  return (
    <div className="container">
      <h1>Authenticate using OTP</h1>

      {step === 'request' && (
        <div className="form">
          <input type="email" placeholder="Enter your email" value={email} onChange={(e) => setEmail(e.target.value)} />
          <button onClick={sendOtp}>Send OTP</button>
        </div>
      )}

      {step === 'verify' && (
        <div className="form">
          <input type="text" placeholder="Enter OTP" value={otp} onChange={(e) => setOtp(e.target.value)} />
          <button onClick={verifyOtp}>Verify OTP</button>
        </div>
      )}

      {message && <p className="message">{message}</p>}
    </div>
  );
}

export default App;
