import React, { useState } from 'react';

function App() {
  const [token, setToken] = useState(null);
  const [secureMessage, setSecureMessage] = useState('');
  const [createdResource, setCreatedResource] = useState(null);
  const [retrievedResource, setRetrievedResource] = useState(null);

  // Login: fetches JWT from the backend.
  const login = async () => {
    try {
      const response = await fetch('https://localhost:5001/api/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username: 'test', password: 'password' }),
      });
      if (!response.ok) throw new Error('Login failed');
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
        headers: { 'Authorization': `Bearer ${token}` }
      });
      if (!response.ok) throw new Error('Failed to fetch secure message');
      const data = await response.json();
      setSecureMessage(data.message);
    } catch (error) {
      console.error('Error fetching secure message:', error);
    }
  };

  // Create a new resource (POST) and store the returned resource.
  const createResource = async () => {
    try {
      const response = await fetch('https://localhost:5001/api/resource', {
        method: 'POST'
      });
      if (!response.ok) throw new Error('Failed to create resource');
      const data = await response.json();
      setCreatedResource(data);
    } catch (error) {
      console.error('Error creating resource:', error);
    }
  };

  // Retrieve a resource by UUID (GET) using the resource ID from createdResource.
  const getResource = async () => {
    if (!createdResource?.id) return;
    try {
      const response = await fetch(`https://localhost:5001/api/resource/${createdResource.id}`);
      if (!response.ok) throw new Error('Resource not found');
      const data = await response.json();
      setRetrievedResource(data);
    } catch (error) {
      console.error('Error retrieving resource:', error);
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
          <button onClick={createResource}>Create Resource</button>
          <button onClick={getResource}>Get Resource by UUID</button>
        </>
      )}
      {secureMessage && <p><strong>Secure Message:</strong> {secureMessage}</p>}
      {createdResource && (
        <div>
          <h3>Created Resource:</h3>
          <pre>{JSON.stringify(createdResource, null, 2)}</pre>
        </div>
      )}
      {retrievedResource && (
        <div>
          <h3>Retrieved Resource:</h3>
          <pre>{JSON.stringify(retrievedResource, null, 2)}</pre>
        </div>
      )}
    </div>
  );
}

export default App;
