const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const speakeasy = require('speakeasy');
const qrcode = require('qrcode');
const bodyParser = require('body-parser');
const helmet = require('helmet');
const cors = require('cors');
const fs = require('fs');
const path = require('path');

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
    secret TEXT NOT NULL
  );
`);

// Signup API
app.post('/signup', (req, res) => {
  const { username } = req.body;
  console.log('Signup request received with username:', username);
  
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

      console.log('QR Code URL generated:', qrCodeUrl);
      res.status(201).json({ message: 'User created', qrCodeUrl });
    });
  });
});

// Login API
app.post('/login', (req, res) => {
  console.log(req);
  console.log(req.body);
  console.log(res);
  const { username, token } = req.body;
  console.log('Login request received with username:', username, 'and token:', token);

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
      res.status(200).json({ message: 'Login successful' });
    } else {
      console.log('Error: Invalid token for username:', username);
      res.status(401).json({ error: 'Invalid token' });
    }
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
