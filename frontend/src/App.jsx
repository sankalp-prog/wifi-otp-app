import './App.css';
import React, { useEffect, useState } from 'react';

function App() {
  const [email, setEmail] = useState('');
  const [otp, setOtp] = useState('');
  const [step, setStep] = useState('request'); // request | verify
  const [message, setMessage] = useState('');

   // ================== BrowserCap section starts ==================
  // useEffect(() => {
  //   const API_BASE_URL = import.meta.env.VITE_API_BASE_URL;

  //   // Build client-side browser capability info
  //   const browserInfo = {
  //     userAgent: navigator.userAgent,
  //     platform: navigator.platform,

  //   };

  //   // Send it to backend (non-blocking)
  //   fetch(`${API_BASE_URL}/browser-info`, {
  //     method: 'POST',
  //     headers: { 'Content-Type': 'application/json' },
  //     body: JSON.stringify(browserInfo)
  //   }).catch(err => console.error('Failed to send browser info:', err));
  // }, []);
  // ================== BrowserCap section ends ==================

  async function test() {
  //  const res = await fetch('https://api.ipify.org?format=json');
  //  const data = await res.json();
  //  console.log('Public IP:', data.ip);
  }
  test()
  // Send OTP
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
        body: JSON.stringify({ email, browserInfo }),
      });
      const data = await res.json();
      setMessage(data.message || data.error);
      if (data.success) setStep('verify');
    } catch (err) {
      setMessage('Failed to send OTP');
    }
  };

  // Verify OTP
  const verifyOtp = async () => {
    try {
      const API_BASE_URL = import.meta.env.VITE_API_BASE_URL;
      const res = await fetch(`${API_BASE_URL}/verify-otp`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, otp }),
      });
      const data = await res.json();
      setMessage(data.message || data.error);
    } catch (err) {
      setMessage('Failed to verify OTP');
    }
  };

  return (
    <div className="container">
      <h1>Authenticate using OTP </h1>

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
