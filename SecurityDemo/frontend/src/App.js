import React, { useState } from 'react';

function App() {
  const [token, setToken] = useState(null);
  const [message, setMessage] = useState('');

  // Login function: fetches JWT from the backend.
  const login = async () => {
    try {
      const response = await fetch('https://localhost:5001/api/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username: 'test', password: 'password' }),
      });
      if (!response.ok) {
        throw new Error('Login failed');
      }
      const data = await response.json();
      setToken(data.token);
      console.log('Logged in, token received.');
    } catch (error) {
      console.error('Error during login:', error);
    }
  };

  // Fetch secure data using the token.
  const fetchSecureMessage = async () => {
    try {
      const response = await fetch('https://localhost:5001/api/secure', {
        headers: {
          'Authorization': `Bearer ${token}`
        }
      });
      if (!response.ok) {
        throw new Error('Failed to fetch secure message');
      }
      const data = await response.json();
      setMessage(data.message);
    } catch (error) {
      console.error('Error fetching secure message:', error);
    }
  };

  return (
    <div style={{ margin: '50px' }}>
      <h1>Security Best Practices Demo</h1>
      {!token ? (
         <button onClick={login}>Login</button>
      ) : (
         <>
           <p><strong>Token:</strong> {token}</p>
           <button onClick={fetchSecureMessage}>Fetch Secure Message</button>
         </>
      )}
      {message && <p><strong>Secure Message:</strong> {message}</p>}
    </div>
  );
}

export default App;
