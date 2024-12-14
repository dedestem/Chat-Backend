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
app.use(helmet()); // Adds security headers
app.use(cors({
  origin: 'http://127.0.0.1:1430', // Tauri app origin
  methods: ['GET', 'POST'],
  allowedHeaders: ['Content-Type'],
}));
app.use(bodyParser.json());

// Set up SQLite database
if (!fs.existsSync(dbFile)) {
  fs.writeFileSync(dbFile, '');
}
const db = new sqlite3.Database(dbFile, (err) => {
  if (err) {
    console.error('Database connection error:', err.message);
    process.exit(1);
  }
  console.log('Connected to SQLite database.');
});

// Create users table if not exists
db.run(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    secret TEXT NOT NULL,
    token TEXT,
    token_expiry INTEGER
  );
`);

// Create chats table if not exists
db.run(`
  CREATE TABLE IF NOT EXISTS chats (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username1 TEXT NOT NULL,
    username2 TEXT NOT NULL,
    FOREIGN KEY (username1) REFERENCES users(username),
    FOREIGN KEY (username2) REFERENCES users(username),
    UNIQUE(username1, username2)
  );
`);

// Helper function to generate a random token
function generateToken() {
  return crypto.randomBytes(16).toString('hex');
}

// Signup API
app.post('/signup', (req, res) => {
  const { username } = req.body;
  if (!username) return res.status(400).json({ error: 'Username is required' });

  const secret = speakeasy.generateSecret({ length: 20, name: `Chat (${username})` });

  db.run('INSERT INTO users (username, secret) VALUES (?, ?)', [username, secret.base32], function (err) {
    if (err) {
      if (err.code === 'SQLITE_CONSTRAINT') {
        return res.status(400).json({ error: 'Username already exists' });
      }
      return res.status(500).json({ error: 'Database error' });
    }

    qrcode.toDataURL(secret.otpauth_url, (err, qrCodeUrl) => {
      if (err) return res.status(500).json({ error: 'Failed to generate QR code' });
      res.status(201).json({ message: 'User created', qrCodeUrl });
    });
  });
});

// Login API
app.post('/login', (req, res) => {
  const { username, token } = req.body;
  if (!username || !token) return res.status(400).json({ error: 'Username and token are required' });

  db.get('SELECT secret FROM users WHERE username = ?', [username], (err, row) => {
    if (err) return res.status(500).json({ error: 'Database error' });
    if (!row) return res.status(404).json({ error: 'User not found' });

    const isValid = speakeasy.totp.verify({
      secret: row.secret,
      encoding: 'base32',
      token
    });

    if (isValid) {
      const token = generateToken();
      const expiry = Date.now() + 3600000; // 1 hour expiry
      db.run('UPDATE users SET token = ?, token_expiry = ? WHERE username = ?', [token, expiry, username], function (err) {
        if (err) return res.status(500).json({ error: 'Database error' });
        res.status(200).json({ message: 'Login successful', token });
      });
    } else {
      res.status(401).json({ error: 'Invalid token' });
    }
  });
});

// Check session validity API
app.post('/check-session', (req, res) => {
  const { username, authToken } = req.body;
  if (!username || !authToken) return res.status(400).json({ error: 'Username and authToken are required' });

  db.get('SELECT token, token_expiry FROM users WHERE username = ?', [username], (err, row) => {
    if (err) return res.status(500).json({ error: 'Database error' });
    if (!row) return res.status(404).json({ error: 'User not found' });

    // Check token and expiry
    if (row.token !== authToken) return res.status(401).json({ error: 'Invalid authToken' });
    if (Date.now() > row.token_expiry) return res.status(401).json({ error: 'Token has expired' });

    res.status(200).json({ message: 'Session is valid', valid: true });
  });
});

// Create a new chat
app.post('/new-chat', (req, res) => {
  const { username, authToken, otherUsername } = req.body;
  if (!username || !authToken || !otherUsername) return res.status(400).json({ error: 'Username, authToken, and otherUsername are required' });

  // Validate the session
  db.get('SELECT token FROM users WHERE username = ?', [username], (err, row) => {
    if (err) return res.status(500).json({ error: 'Database error' });
    if (!row || row.token !== authToken) return res.status(401).json({ error: 'Invalid session' });

    // Check if the other user exists
    db.get('SELECT username FROM users WHERE username = ?', [otherUsername], (err, row2) => {
      if (err) return res.status(500).json({ error: 'Database error' });
      if (!row2) return res.status(404).json({ error: 'Other user not found' });

      // Check if the chat already exists
      db.get('SELECT id FROM chats WHERE (username1 = ? AND username2 = ?) OR (username1 = ? AND username2 = ?)', [username, otherUsername, otherUsername, username], (err, chatRow) => {
        if (err) return res.status(500).json({ error: 'Database error' });
        if (chatRow) return res.status(400).json({ error: 'Chat already exists' });

        // Create the new chat
        db.run('INSERT INTO chats (username1, username2) VALUES (?, ?)', [username, otherUsername], function (err) {
          if (err) return res.status(500).json({ error: 'Failed to create chat' });
          res.status(201).json({ message: 'Chat created' });
        });
      });
    });
  });
});

// Get all chats for a user
app.post('/get-chats', (req, res) => {
  const { username, authToken } = req.body;
  if (!username || !authToken) return res.status(400).json({ error: 'Username and authToken are required' });

  // Validate the session
  db.get('SELECT token FROM users WHERE username = ?', [username], (err, row) => {
    if (err) return res.status(500).json({ error: 'Database error' });
    if (!row || row.token !== authToken) return res.status(401).json({ error: 'Invalid session' });

    // Get all chats for the user
    db.all('SELECT username1, username2 FROM chats WHERE username1 = ? OR username2 = ?', [username, username], (err, chats) => {
      if (err) return res.status(500).json({ error: 'Database error' });
      res.status(200).json({ chats });
    });
  });
});

// Catch-all route for invalid endpoints
app.use((req, res) => {
  res.status(404).json({ error: 'Endpoint not found' });
});

// Start the server
app.listen(port, () => {
  console.log(`Server running at http://localhost:${port}`);
});
