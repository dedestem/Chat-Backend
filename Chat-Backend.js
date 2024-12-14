const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const speakeasy = require('speakeasy');
const qrcode = require('qrcode');
const bodyParser = require('body-parser');

const app = express();
const port = 3000;

// SQLite DB setup
const db = new sqlite3.Database('./users.db', (err) => {
  if (err) {
    console.error('Error opening database:', err.message);
  } else {
    console.log('Connected to SQLite database.');
  }
});

// Create table if not exists
db.run(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE,
    secret TEXT
  );
`);

// Middleware for parsing JSON
app.use(bodyParser.json());

// Debug
app.get('/'), (req, res) => {
  res.send('Hello!');
}

// Signup API
app.post('/signup', (req, res) => {
  const { username } = req.body;

  // Generate a secret for the user using speakeasy
  const secret = speakeasy.generateSecret({ length: 20 });

  // Save the username and secret in the database
  db.run('INSERT INTO users (username, secret) VALUES (?, ?)', [username, secret.base32], function (err) {
    if (err) {
      return res.status(400).json({ error: err.message });
    }

    // Generate QR code for the user to scan
    qrcode.toDataURL(secret.otpauth_url, (err, data_url) => {
      if (err) {
        return res.status(400).json({ error: 'Failed to generate QR code' });
      }

      res.status(201).json({
        message: 'User created successfully',
        qrCodeUrl: data_url, // Send the QR code URL to the frontend for display
      });
    });
  });
});

// Login API
app.post('/login', (req, res) => {
  const { username, token } = req.body;

  // Fetch the user's secret from the database
  db.get('SELECT secret FROM users WHERE username = ?', [username], (err, row) => {
    if (err || !row) {
      return res.status(400).json({ error: 'Invalid username' });
    }

    const secret = row.secret;

    // Verify the token using the secret
    const isValid = speakeasy.totp.verify({ secret, encoding: 'base32', token });

    if (isValid) {
      res.status(200).json({ message: 'Login successful' });
    } else {
      res.status(400).json({ error: 'Invalid token' });
    }
  });
});

// Start the server
app.listen(port, () => {
  console.log(`Server running on http://localhost:${port}`);
});
