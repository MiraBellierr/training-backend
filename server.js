const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const cors = require('cors');
const path = require('path');

const app = express();
const PORT = 3001;

// Middleware
app.use(cors());
app.use(express.json());

// Initialize SQLite database
const dbPath = path.join(__dirname, 'registrations.db');
const db = new sqlite3.Database(dbPath, (err) => {
  if (err) {
    console.error('Error opening database:', err);
  } else {
    console.log('Connected to SQLite database');
    initializeDatabase();
  }
});

// Create tables if they don't exist
function initializeDatabase() {
  db.run(`
    CREATE TABLE IF NOT EXISTS registrations (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL,
      phone TEXT NOT NULL,
      email TEXT NOT NULL,
      interests TEXT NOT NULL,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
  `, (err) => {
    if (err) {
      console.error('Error creating table:', err);
    } else {
      console.log('Database table ready');
    }
  });
}

// POST endpoint to register new user
app.post('/api/register', (req, res) => {
  const { name, phone, email, interests } = req.body;

  // Validation
  if (!name || !phone || !email || !interests || interests.length === 0) {
    return res.status(400).json({ 
      error: 'All fields are required and at least one interest must be selected' 
    });
  }

  // Convert interests array to comma-separated string
  const interestsString = interests.join(',');

  const sql = `
    INSERT INTO registrations (name, phone, email, interests) 
    VALUES (?, ?, ?, ?)
  `;

  db.run(sql, [name, phone, email, interestsString], function(err) {
    if (err) {
      console.error('Error inserting data:', err);
      return res.status(500).json({ error: 'Failed to save registration' });
    }

    res.status(201).json({
      message: 'Registration successful',
      id: this.lastID
    });
  });
});

// GET endpoint to retrieve all registrations
app.get('/api/registrations', (req, res) => {
  const sql = 'SELECT * FROM registrations ORDER BY created_at DESC';

  db.all(sql, [], (err, rows) => {
    if (err) {
      console.error('Error fetching data:', err);
      return res.status(500).json({ error: 'Failed to fetch registrations' });
    }

    // Convert interests string back to array
    const formattedRows = rows.map(row => ({
      ...row,
      interests: row.interests.split(',')
    }));

    res.json(formattedRows);
  });
});

// GET endpoint to retrieve single registration by ID
app.get('/api/registrations/:id', (req, res) => {
  const { id } = req.params;
  const sql = 'SELECT * FROM registrations WHERE id = ?';

  db.get(sql, [id], (err, row) => {
    if (err) {
      console.error('Error fetching data:', err);
      return res.status(500).json({ error: 'Failed to fetch registration' });
    }

    if (!row) {
      return res.status(404).json({ error: 'Registration not found' });
    }

    res.json({
      ...row,
      interests: row.interests.split(',')
    });
  });
});

// DELETE endpoint to remove a registration
app.delete('/api/registrations/:id', (req, res) => {
  const { id } = req.params;
  const sql = 'DELETE FROM registrations WHERE id = ?';

  db.run(sql, [id], function(err) {
    if (err) {
      console.error('Error deleting data:', err);
      return res.status(500).json({ error: 'Failed to delete registration' });
    }

    if (this.changes === 0) {
      return res.status(404).json({ error: 'Registration not found' });
    }

    res.json({ message: 'Registration deleted successfully' });
  });
});

// Health check endpoint
app.get('/health', (req, res) => {
  res.json({ status: 'OK', timestamp: new Date().toISOString() });
});

// Start server
app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});

// Graceful shutdown
process.on('SIGINT', () => {
  db.close((err) => {
    if (err) {
      console.error('Error closing database:', err);
    } else {
      console.log('Database connection closed');
    }
    process.exit(0);
  });
});