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

// Create necessary tables
db.run(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    secret TEXT NOT NULL,
    token TEXT,
    token_expiry INTEGER,
    public_key TEXT
  );
`);

db.run(`
  CREATE TABLE IF NOT EXISTS messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    sender TEXT NOT NULL,
    recipient TEXT NOT NULL,
    encrypted_message TEXT NOT NULL,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
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

// Upload Public Key API
app.post('/upload-key', (req, res) => {
  const { username, publicKey } = req.body;
  if (!username || !publicKey) return res.status(400).json({ error: 'Username and public key are required' });

  db.run('UPDATE users SET public_key = ? WHERE username = ?', [publicKey, username], function (err) {
    if (err) return res.status(500).json({ error: 'Database error' });
    res.status(200).json({ message: 'Public key updated' });
  });
});

// Fetch Public Key API
app.get('/get-key/:username', (req, res) => {
  const { username } = req.params;

  db.get('SELECT public_key FROM users WHERE username = ?', [username], (err, row) => {
    if (err) return res.status(500).json({ error: 'Database error' });
    if (!row) return res.status(404).json({ error: 'User not found' });

    res.status(200).json({ publicKey: row.public_key });
  });
});

// Send Encrypted Message API
app.post('/send-message', (req, res) => {
  const { from, to, encryptedMessage } = req.body;
  if (!from || !to || !encryptedMessage) return res.status(400).json({ error: 'All fields are required' });

  db.run(
    'INSERT INTO messages (sender, recipient, encrypted_message) VALUES (?, ?, ?)',
    [from, to, encryptedMessage],
    function (err) {
      if (err) return res.status(500).json({ error: 'Database error' });
      res.status(200).json({ message: 'Message sent' });
    }
  );
});

// Fetch Encrypted Messages API
app.get('/fetch-messages/:username', (req, res) => {
  const { username } = req.params;

  db.all('SELECT * FROM messages WHERE recipient = ?', [username], (err, rows) => {
    if (err) return res.status(500).json({ error: 'Database error' });

    db.run('DELETE FROM messages WHERE recipient = ?', [username], function (err) {
      if (err) return res.status(500).json({ error: 'Failed to clear messages' });
      res.status(200).json({ messages: rows });
    });
  });
});

// Check Session Validity API
app.post('/check-session', (req, res) => {
  const { username, authToken } = req.body;
  if (!username || !authToken) return res.status(400).json({ error: 'Username and authToken are required' });

  db.get('SELECT token, token_expiry FROM users WHERE username = ?', [username], (err, row) => {
    if (err) return res.status(500).json({ error: 'Database error' });
    if (!row) return res.status(404).json({ error: 'User not found' });

    if (row.token !== authToken) return res.status(401).json({ error: 'Invalid authToken' });
    if (Date.now() > row.token_expiry) return res.status(401).json({ error: 'Token has expired' });

    res.status(200).json({ message: 'Session is valid', valid: true });
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
