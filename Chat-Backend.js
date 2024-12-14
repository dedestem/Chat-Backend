const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const speakeasy = require('speakeasy');
const qrcode = require('qrcode');
const bodyParser = require('body-parser');
const helmet = require('helmet');
const cors = require('cors');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const app = express();
const port = 6000;
const dbFile = path.join(__dirname, 'users.db');

// Middleware
app.use(helmet()); // Security best practices
app.use(cors({
  origin: 'http://127.0.0.1:1430', // Allow requests from the Tauri app
  methods: ['GET', 'POST'],
  allowedHeaders: ['Content-Type'],
}));
app.use(bodyParser.json());

// Setup database
if (!fs.existsSync(dbFile)) {
  console.log('Database file not found. Creating a new one...');
  fs.writeFileSync(dbFile, '');
}
const db = new sqlite3.Database(dbFile, (err) => {
  if (err) {
    console.error('Database connection error:', err.message);
    process.exit(1);
  } else {
    console.log('Connected to SQLite database.');
  }
});

db.run(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    secret TEXT NOT NULL,
    token TEXT,
    token_expiry INTEGER
  );
`);

// Helper function to generate a random token
function generateToken() {
  return crypto.randomBytes(16).toString('hex');
}

// Signup API
app.post('/signup', (req, res) => {
  const { username } = req.body;

  if (!username) {
    console.log('Error: Username is missing');
    return res.status(400).json({ error: 'Username is required' });
  }

  const secret = speakeasy.generateSecret({ length: 20, name: `Chat (${username})` });
  console.log('Generated secret for user:', secret.base32);

  db.run('INSERT INTO users (username, secret) VALUES (?, ?)', [username, secret.base32], function (err) {
    if (err) {
      if (err.code === 'SQLITE_CONSTRAINT') {
        console.log('Error: Username already exists');
        return res.status(400).json({ error: 'Username already exists' });
      }
      console.error('Database error during signup:', err);
      return res.status(500).json({ error: 'Database error' });
    }

    console.log('User created in database with ID:', this.lastID);

    qrcode.toDataURL(secret.otpauth_url, (err, qrCodeUrl) => {
      if (err) {
        console.error('Failed to generate QR code:', err);
        return res.status(500).json({ error: 'Failed to generate QR code' });
      }
      res.status(201).json({ message: 'User created', qrCodeUrl });
    });
  });
});

// Login API
app.post('/login', (req, res) => {
  const { username, token } = req.body;

  if (!username || !token) {
    console.log('Error: Username or token is missing');
    return res.status(400).json({ error: 'Username and token are required' });
  }

  db.get('SELECT secret FROM users WHERE username = ?', [username], (err, row) => {
    if (err) {
      console.error('Database error during login:', err);
      return res.status(500).json({ error: 'Database error' });
    }
    if (!row) {
      console.log('Error: User not found for username:', username);
      return res.status(404).json({ error: 'User not found' });
    }

    const isValid = speakeasy.totp.verify({
      secret: row.secret,
      encoding: 'base32',
      token
    });

    if (isValid) {
      console.log('Login successful for username:', username);

      // Generate a new token and set expiry time (e.g., 1 hour)
      const token = generateToken();
      const expiry = Date.now() + 3600000; // 1 hour expiry

      db.run('UPDATE users SET token = ?, token_expiry = ? WHERE username = ?', [token, expiry, username], function (err) {
        if (err) {
          console.error('Database error during token update:', err);
          return res.status(500).json({ error: 'Database error' });
        }

        console.log('Token updated for username:', username);
        res.status(200).json({ message: 'Login successful', token });
      });
    } else {
      console.log('Error: Invalid token for username:', username);
      res.status(401).json({ error: 'Invalid token' });
    }
  });
});

// Check session validity API
app.post('/check-session', (req, res) => {
  const { username, authToken } = req.body;

  if (!username || !authToken) {
    console.log('Error: Username or authToken is missing');
    return res.status(400).json({ error: 'Username and authToken are required' });
  }

  db.get('SELECT token, token_expiry FROM users WHERE username = ?', [username], (err, row) => {
    if (err) {
      console.error('Database error during session check:', err);
      return res.status(500).json({ error: 'Database error' });
    }
    if (!row) {
      console.log('Error: User not found for username:', username);
      return res.status(404).json({ error: 'User not found' });
    }

    // Check if the token matches
    if (row.token !== authToken) {
      console.log('Error: Invalid authToken for username:', username);
      return res.status(401).json({ error: 'Invalid authToken' });
    }

    // Check if the token has expired
    if (Date.now() > row.token_expiry) {
      console.log('Error: Token has expired for username:', username);
      return res.status(401).json({ error: 'Token has expired' });
    }

    // Token is valid
    console.log('Session is valid for username:', username);
    res.status(200).json({ message: 'Session is valid', valid: true });
  });
});


// Catch-all route
app.use((req, res) => {
  console.log('404 Error: Endpoint not found for', req.method, req.url);
  res.status(404).json({ error: 'Endpoint not found' });
});

// Start the server
app.listen(port, () => {
  console.log(`Server running at http://localhost:${port}`);
});
