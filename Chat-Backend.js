const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const speakeasy = require('speakeasy');
const qrcode = require('qrcode');
const crypto = require('crypto');
const bodyParser = require('body-parser');
const helmet = require('helmet');
const cors = require('cors');
const fs = require('fs');
const path = require('path');

const app = express();
const port = 6000;
const dbFile = path.join(__dirname, 'users.db');

// Middleware
app.use(helmet()); // Adds security headers
app.use(cors({
  origin: 'http://127.0.0.1:1430', // Frontend origin
  methods: ['GET', 'POST'],
  allowedHeaders: ['Content-Type'],
}));
app.use(bodyParser.json());

// SQLite Database setup
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

// Create users and chats tables if not exists
db.run(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    secret TEXT NOT NULL,
    token TEXT,
    token_expiry INTEGER
  );
`);

db.run(`
  CREATE TABLE IF NOT EXISTS chats (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username1 TEXT NOT NULL,
    username2 TEXT NOT NULL,
    encryption_key TEXT,
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

// Create a new chat with encryption key generation
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
      db.get('SELECT id, encryption_key FROM chats WHERE (username1 = ? AND username2 = ?) OR (username1 = ? AND username2 = ?)', [username, otherUsername, otherUsername, username], (err, chatRow) => {
        if (err) return res.status(500).json({ error: 'Database error' });
        if (chatRow) return res.status(400).json({ error: 'Chat already exists' });

        // Generate a unique encryption key for this chat
        const encryptionKey = crypto.randomBytes(32).toString('hex'); // 256-bit encryption key

        // Create the new chat and store the encryption key temporarily
        db.run('INSERT INTO chats (username1, username2, encryption_key) VALUES (?, ?, ?)', [username, otherUsername, encryptionKey], function (err) {
          if (err) return res.status(500).json({ error: 'Failed to create chat' });
          res.status(201).json({ message: 'Chat created', encryptionKey });
        });
      });
    });
  });
});

// Get chat details and encryption key
app.post('/get-chat-keys', (req, res) => {
  const { username, authToken, otherUsername } = req.body;
  if (!username || !authToken || !otherUsername) return res.status(400).json({ error: 'Username, authToken, and otherUsername are required' });

  // Validate the session
  db.get('SELECT token FROM users WHERE username = ?', [username], (err, row) => {
    if (err) return res.status(500).json({ error: 'Database error' });
    if (!row || row.token !== authToken) return res.status(401).json({ error: 'Invalid session' });

    // Get the encryption key from the database for this chat
    db.get('SELECT encryption_key FROM chats WHERE (username1 = ? AND username2 = ?) OR (username1 = ? AND username2 = ?)', [username, otherUsername, otherUsername, username], (err, chatRow) => {
      if (err) return res.status(500).json({ error: 'Database error' });
      if (!chatRow) return res.status(404).json({ error: 'Chat not found' });

      const encryptionKey = chatRow.encryption_key;

      // Store the encryption key in localStorage on the client side (this is done via the frontend)
      res.status(200).json({ encryptionKey });
    });
  });
});

// Delete the encryption keys from the database once both parties have the key
app.post('/delete-keys', (req, res) => {
  const { username, otherUsername } = req.body;
  if (!username || !otherUsername) return res.status(400).json({ error: 'Username and otherUsername are required' });

  // Validate the session before deleting keys
  db.get('SELECT token FROM users WHERE username = ?', [username], (err, row) => {
    if (err) return res.status(500).json({ error: 'Database error' });
    if (!row) return res.status(404).json({ error: 'User not found' });

    // Check if both parties have retrieved the key
    // You can set a flag in your database for when both users have accessed the encryption key, and then delete it
    db.get('SELECT encryption_key FROM chats WHERE (username1 = ? AND username2 = ?) OR (username1 = ? AND username2 = ?)', [username, otherUsername, otherUsername, username], (err, chatRow) => {
      if (err) return res.status(500).json({ error: 'Database error' });
      if (!chatRow) return res.status(404).json({ error: 'Chat not found' });

      // Delete the encryption key once both parties have fetched it
      db.run('UPDATE chats SET encryption_key = NULL WHERE (username1 = ? AND username2 = ?) OR (username1 = ? AND username2 = ?)', [username, otherUsername, otherUsername, username], (err) => {
        if (err) return res.status(500).json({ error: 'Failed to delete keys' });
        res.status(200).json({ message: 'Keys deleted successfully' });
      });
    });
  });
});

// Start server
app.listen(port, () => {
  console.log(`Server is running on port ${port}`);
});
