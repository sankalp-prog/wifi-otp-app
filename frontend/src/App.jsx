import './App.css';
import { useState, useEffect, useRef } from 'react';

function App() {
  const [email, setEmail] = useState('');
  const [otp, setOtp] = useState('');
  const [step, setStep] = useState('request'); // 'request', 'verify', 'success'
  const [message, setMessage] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  const emailInputRef = useRef(null);
  const otpInputRef = useRef(null);

  const API_BASE_URL = import.meta.env.VITE_API_BASE_URL;

  // Auto-focus inputs when steps change
  useEffect(() => {
    if (step === 'request' && emailInputRef.current) {
      emailInputRef.current.focus();
    } else if (step === 'verify' && otpInputRef.current) {
      otpInputRef.current.focus();
    }
  }, [step]);

  // Email validation
  const isValidEmail = (email) => {
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return emailRegex.test(email);
  };

  // Clear error when user types
  const handleEmailChange = (e) => {
    setEmail(e.target.value);
    setError('');
  };

  const handleOtpChange = (e) => {
    const value = e.target.value.replace(/\D/g, ''); // Only digits
    if (value.length <= 6) {
      setOtp(value);
      setError('');
    }
  };

  const sendOtp = async () => {
    if (!isValidEmail(email)) {
      setError('Please enter a valid email address');
      return;
    }

    setLoading(true);
    setError('');
    setMessage('');

    try {
      const browserInfo = {
        userAgent: navigator.userAgent,
        platform: navigator.platform,
      };
      // const res = await fetch(`${API_BASE_URL}/send-otp`, {
      const res = await fetch(`/api/send-otp`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, browserInfo }),
      });
      const data = await res.json();

      if (data.success) {
        setMessage('OTP sent successfully!');
        setTimeout(() => {
          setStep('verify');
          setMessage('');
        }, 500);
      } else {
        setError(data.error || 'Failed to send OTP');
      }
    } catch (err) {
      setError('Unable to connect. Please check your connection and try again.');
    } finally {
      setLoading(false);
    }
  };

  const verifyOtp = async () => {
    if (otp.length !== 6) {
      setError('Please enter a valid 6-digit OTP');
      return;
    }

    setLoading(true);
    setError('');
    setMessage('');

    try {
      // const res = await fetch(`${API_BASE_URL}/verify-otp`, {
      const res = await fetch(`/api/verify-otp`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, otp }),
      });
      const data = await res.json();

      if (data.success) {
        setStep('success');
        await fetch(`${API_BASE_URL}/capport/api`, { cache: 'no-store' });
      } else {
        setError(data.error || 'Verification failed');
      }
    } catch (err) {
      setError('Unable to connect. Please check your connection and try again.');
    } finally {
      setLoading(false);
    }
  };

  const handleChangeEmail = () => {
    setStep('request');
    setOtp('');
    setError('');
    setMessage('');
  };

  const handleKeyPress = (e, action) => {
    if (e.key === 'Enter') {
      action();
    }
  };

  return (
    <div className="container">
      <h1>Authentication</h1>

      {step === 'request' && (
        <div className="form">
          <input
            ref={emailInputRef}
            type="email"
            placeholder="Enter your email"
            value={email}
            onChange={handleEmailChange}
            onKeyPress={(e) => handleKeyPress(e, sendOtp)}
            disabled={loading}
            className={error ? 'error' : ''}
            aria-label="Email address"
            aria-invalid={!!error}
          />

          {!loading ? (
            <button onClick={sendOtp} disabled={!isValidEmail(email) || loading} className="primary-button">
              Send OTP
            </button>
          ) : (
            <div className="spinner-container">
              <div className="spinner"></div>
            </div>
          )}
        </div>
      )}

      {step === 'verify' && (
        <div className="form">
          <p className="email-display">
            OTP sent to: <strong>{email}</strong>
          </p>

          <input
            ref={otpInputRef}
            type="text"
            inputMode="numeric"
            placeholder="Enter OTP"
            value={otp}
            onChange={handleOtpChange}
            onKeyPress={(e) => handleKeyPress(e, verifyOtp)}
            disabled={loading}
            className={`otp-input ${error ? 'error' : ''}`}
            maxLength={6}
            aria-label="One-time password"
            aria-invalid={!!error}
          />

          {!loading ? (
            <button onClick={verifyOtp} disabled={otp.length !== 6 || loading} className="primary-button">
              Verify OTP
            </button>
          ) : (
            <div className="spinner-container">
              <div className="spinner"></div>
            </div>
          )}

          <div className="secondary-actions">
            <button onClick={handleChangeEmail} className="secondary-button" disabled={loading}>
              Change Email
            </button>
            <button className="secondary-button resend-button" disabled title="Coming soon">
              Resend OTP
            </button>
          </div>
        </div>
      )}

      {step === 'success' && (
        <div className="success-container">
          <div className="success-icon">✓</div>
          <h2 className="success-title">Authentication Successful!</h2>
          <p className="success-message">You now have internet access.</p>
          {/* <p className="session-info">Your session is valid for 2 hours.</p> */}
        </div>
      )}

      {error && (
        <p className="message error-message" role="alert">
          {error}
        </p>
      )}
      {message && !error && <p className="message info-message">{message}</p>}
    </div>
  );
}

export default App;
