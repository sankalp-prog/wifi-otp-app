import { useState } from 'react';
import './App.css';

function App() {
  const [email, setEmail] = useState('');
  const [otp, setOtp] = useState('');
  const [step, setStep] = useState('request'); // request | verify
  const [message, setMessage] = useState('');

  // Send OTP
  const sendOtp = async () => {
    try {
      const res = await fetch('http://localhost:5000/send-otp', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email }),
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
      const res = await fetch('http://localhost:5000/verify-otp', {
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
      <h1>OTP Demo</h1>

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
