import './App.css';
import { useState } from 'react';

function App() {
  const [email, setEmail] = useState('');
  const [otp, setOtp] = useState('');
  const [mac, setMac] = useState('');
  const [step, setStep] = useState('request');
  const [message, setMessage] = useState('');

  const API_BASE_URL = import.meta.env.VITE_API_BASE_URL;

  const sendOtp = async () => {
    try {
      const browserInfo = {
        userAgent: navigator.userAgent,
        platform: navigator.platform,
      };
      const res = await fetch(`${API_BASE_URL}/send-otp`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, mac, browserInfo }),
      });
      const data = await res.json();
      setMessage(data.message || data.error);
      if (data.success) setStep('verify');
    } catch {
      setMessage('Failed to send OTP');
    }
  };

  const verifyOtp = async () => {
    try {
      const res = await fetch(`${API_BASE_URL}/verify-otp`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, otp, mac }),
      });
      const data = await res.json();
      if (data.success) {
        setMessage('✅ OTP verified! Internet access unlocked.');
        await fetch(`${API_BASE_URL}/capport/api?mac=${mac}`, { cache: 'no-store' });
      } else {
        setMessage(data.error || 'Verification failed.');
      }
    } catch {
      setMessage('Failed to verify OTP');
    }
  };

  return (
    <div className="container">
      <h1>Network Sign-In (MAC/IP)</h1>

      {step === 'request' && (
        <div className="form">
          <input type="text" placeholder="Device MAC (AA:BB:CC:DD:EE:FF)" value={mac} onChange={(e) => setMac(e.target.value.trim())} />
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
