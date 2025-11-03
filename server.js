require('dotenv').config();
const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const cors = require('cors');
const path = require('path');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const fs = require('fs');

const app = express();
const PORT = 3001;
const JWT_SECRET = process.env.JWT_TOKEN;

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

// Add middleware
app.use(cors());
app.use(express.json());
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

// Ensure uploads directory exists
fs.mkdirSync(path.join(__dirname, 'uploads'), { recursive: true });

// File upload configuration
const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    const orderFolder = path.join(__dirname, 'uploads', req.params.orderId || 'temp');
    // Create directory if it doesn't exist
    fs.mkdirSync(orderFolder, { recursive: true });
    cb(null, orderFolder);
  },
  filename: function (req, file, cb) {
    // Use original name but make it safe for filesystem
    const safeName = file.originalname.replace(/[^a-zA-Z0-9.-]/g, '_');
    cb(null, Date.now() + '-' + safeName);
  }
});

const upload = multer({ 
  storage: storage,
  limits: { fileSize: 10 * 1024 * 1024 }, // 10MB limit
  fileFilter: (req, file, cb) => {
    // Allow images and Lighburn files
    if (file.fieldname === 'screenshot' || file.fieldname === 'pictures') {
      if (!file.mimetype.startsWith('image/')) {
        return cb(new Error('Only image files are allowed!'));
      }
    } else if (file.fieldname === 'lighburn') {
      if (!file.originalname.endsWith('.lbrn')) {
        return cb(new Error('Only Lighburn files (.lbrn) are allowed!'));
      }
    }
    cb(null, true);
  }
});

// Utility function to clean up old files
async function cleanupOldFiles(orderId, files) {
  const orderDir = path.join(__dirname, 'uploads', orderId.toString());
  if (fs.existsSync(orderDir)) {
    const currentFiles = await fs.promises.readdir(orderDir);
    for (const file of currentFiles) {
      const filePath = path.join(orderDir, file);
      await fs.promises.unlink(filePath);
    }
  }
}

// Middleware
app.use(cors());
app.use(express.json());
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

// Create tables if they don't exist
function initializeDatabase() {
  // Registrations table
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
      console.error('Error creating registrations table:', err);
    } else {
      console.log('Registrations table ready');
    }
  });

  // Orders table with new fields
  db.run(`
    CREATE TABLE IF NOT EXISTS orders (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      order_no TEXT UNIQUE NOT NULL,
      date TEXT NOT NULL,
      time TEXT NOT NULL,
      collection TEXT NOT NULL,
      order_status TEXT NOT NULL,
      product TEXT NOT NULL,
      price REAL NOT NULL,
      customer_name TEXT NOT NULL,
      phone TEXT NOT NULL,
      sales TEXT NOT NULL,
      due_date TEXT NOT NULL,
      notes TEXT,
      screenshot_path TEXT,
      pictures_path TEXT,
      lighburn_path TEXT,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
  `, (err) => {
    if (err) {
      console.error('Error creating orders table:', err);
    } else {
      console.log('Orders table ready');
    }
  });

  // Admin users table
  db.run(`
    CREATE TABLE IF NOT EXISTS admin_users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
  `, (err) => {
    if (err) {
      console.error('Error creating admin_users table:', err);
    } else {
      console.log('Admin users table ready');
      createDefaultAdmin();
    }
  });
}

function createDefaultAdmin() {
  const username = process.env.ADMIN_USERNAME;
  const password = process.env.ADMIN_PASSWORD;
  
  db.get('SELECT * FROM admin_users WHERE username = ?', [username], async (err, row) => {
    if (err) {
      console.error('Error checking for admin:', err);
      return;
    }
    
    if (!row) {
      const passwordHash = await bcrypt.hash(password, 10);
      db.run(
        'INSERT INTO admin_users (username, password_hash) VALUES (?, ?)',
        [username, passwordHash],
        (err) => {
          if (err) {
            console.error('Error creating default admin:', err);
          } else {
            console.log('Default admin created');
          }
        }
      );
    }
  });
}

// Generate unique order number with INV prefix
function generateOrderNumber() {
  const timestamp = Date.now();
  const random = Math.floor(Math.random() * 1000).toString().padStart(3, '0');
  return `INV${timestamp}${random}`;
}

// Format date to GMT+8
function formatDateGMT8() {
  const date = new Date();
  const options = { timeZone: 'Asia/Kuching', year: 'numeric', month: '2-digit', day: '2-digit' };
  return date.toLocaleDateString('en-CA', options);
}

// Format time to GMT+8
function formatTimeGMT8() {
  const date = new Date();
  const options = { timeZone: 'Asia/Kuching', hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false };
  return date.toLocaleTimeString('en-US', options);
}

// Middleware to verify JWT token
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'Access token required' });
  }

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ error: 'Invalid or expired token' });
    }
    req.user = user;
    next();
  });
}

// ============= ENDPOINT DECLARATIONS =============

// ============= AUTH ENDPOINTS =============
// Admin login endpoint
app.post('/api/admin/login', async (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({ error: 'Username and password required' });
  }

  db.get(
    'SELECT * FROM admin_users WHERE username = ?',
    [username],
    async (err, user) => {
      if (err) {
        console.error('Database error:', err);
        return res.status(500).json({ error: 'Server error' });
      }

      if (!user) {
        return res.status(401).json({ error: 'Invalid credentials' });
      }

      const validPassword = await bcrypt.compare(password, user.password_hash);
      if (!validPassword) {
        return res.status(401).json({ error: 'Invalid credentials' });
      }

      // Generate JWT token
      const token = jwt.sign(
        { id: user.id, username: user.username },
        JWT_SECRET,
        { expiresIn: '24h' }
      );

      res.json({
        message: 'Login successful',
        token,
        username: user.username
      });
    }
  );
});

// Create new admin endpoint (PROTECTED)
app.post('/api/admin/create', authenticateToken, async (req, res) => {
  const { username, email, password } = req.body;

  // Validation
  if (!username || !email || !password) {
    return res.status(400).json({ error: 'Username, email and password are required' });
  }

  if (password.length < 8) {
    return res.status(400).json({ error: 'Password must be at least 8 characters long' });
  }

  // Check if username already exists
  db.get('SELECT * FROM admin_users WHERE username = ?', [username], async (err, row) => {
    if (err) {
      console.error('Database error:', err);
      return res.status(500).json({ error: 'Server error' });
    }

    if (row) {
      return res.status(400).json({ error: 'Username already exists' });
    }

    const passwordHash = await bcrypt.hash(password, 10);

    // Insert new admin
    db.run(
      'INSERT INTO admin_users (username, password_hash) VALUES (?, ?)',
      [username, passwordHash],
      (err) => {
        if (err) {
          console.error('Error creating new admin:', err);
          return res.status(500).json({ error: 'Failed to create admin account' });
        }

        res.status(201).json({
          message: 'Admin account created successfully'
        });
      }
    );
  });
});

// Verify token endpoint
app.get('/api/admin/verify', authenticateToken, (req, res) => {
  res.json({ valid: true, username: req.user.username });
});

// Change password endpoint
app.post('/api/admin/change-password', authenticateToken, async (req, res) => {
  const { currentPassword, newPassword } = req.body;

  if (!currentPassword || !newPassword) {
    return res.status(400).json({ error: 'Current and new password required' });
  }

  if (newPassword.length < 6) {
    return res.status(400).json({ error: 'Password must be at least 6 characters' });
  }

  db.get(
    'SELECT * FROM admin_users WHERE id = ?',
    [req.user.id],
    async (err, user) => {
      if (err || !user) {
        return res.status(500).json({ error: 'Server error' });
      }

      const validPassword = await bcrypt.compare(currentPassword, user.password_hash);
      if (!validPassword) {
        return res.status(401).json({ error: 'Current password is incorrect' });
      }

      const newPasswordHash = await bcrypt.hash(newPassword, 10);
      db.run(
        'UPDATE admin_users SET password_hash = ? WHERE id = ?',
        [newPasswordHash, req.user.id],
        (err) => {
          if (err) {
            return res.status(500).json({ error: 'Failed to update password' });
          }
          res.json({ message: 'Password updated successfully' });
        }
      );
    }
  );
});

// ============= REGISTRATION ENDPOINTS =============
// POST endpoint to register new user (PUBLIC)
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

// GET endpoint to retrieve all registrations (PROTECTED)
app.get('/api/registrations', authenticateToken, (req, res) => {
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

// GET endpoint to retrieve single registration by ID (PROTECTED)
app.get('/api/registrations/:id', authenticateToken, (req, res) => {
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

// DELETE endpoint to remove a registration (PROTECTED)
app.delete('/api/registrations/:id', authenticateToken, (req, res) => {
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

// ============= ORDERS ENDPOINTS =============
// GET endpoint to retrieve all orders (PROTECTED)
app.get('/api/orders', authenticateToken, (req, res) => {
  const sql = 'SELECT * FROM orders ORDER BY created_at DESC';

  db.all(sql, [], (err, rows) => {
    if (err) {
      console.error('Error fetching orders:', err);
      return res.status(500).json({ error: 'Failed to fetch orders' });
    }

    res.json(rows);
  });
});

// GET endpoint to retrieve single order by ID (PROTECTED)
app.get('/api/orders/:id', authenticateToken, (req, res) => {
  const { id } = req.params;
  const sql = 'SELECT * FROM orders WHERE id = ?';

  db.get(sql, [id], (err, row) => {
    if (err) {
      console.error('Error fetching order:', err);
      return res.status(500).json({ error: 'Failed to fetch order' });
    }

    if (!row) {
      return res.status(404).json({ error: 'Order not found' });
    }

    res.json(row);
  });
});

// POST endpoint to create new order with file uploads (PROTECTED)
app.post('/api/orders', authenticateToken, upload.fields([
  { name: 'screenshot', maxCount: 1 },
  { name: 'pictures', maxCount: 5 },
  { name: 'lighburn', maxCount: 1 }
]), (req, res) => {
  const { collection, orderStatus, product, price, customerName, phone, sales, notes, dueDate } = req.body;

  // Validation
  if (!collection || !orderStatus || !product || !price || !customerName || !phone || !sales || !dueDate) {
    return res.status(400).json({ error: 'Required fields are missing' });
  }

  // Validate phone number
  if (!phone.startsWith('+60')) {
    return res.status(400).json({ error: 'Phone number must start with +60' });
  }

  // Validate price
  const priceNum = parseFloat(price);
  if (isNaN(priceNum) || priceNum < 0) {
    return res.status(400).json({ error: 'Invalid price' });
  }

  // Process uploaded files
  const files = req.files;
  const screenshotPath = files?.screenshot?.[0]?.path;
  const picturesPath = files?.pictures?.map(file => file.path).join(',');
  const lighburnPath = files?.lighburn?.[0]?.path;

  // Generate order details
  const orderNo = generateOrderNumber();
  const date = formatDateGMT8();
  const time = formatTimeGMT8();

  const sql = `
    INSERT INTO orders (
      order_no, date, time, collection, order_status, product, 
      price, customer_name, phone, sales, notes, due_date,
      screenshot_path, pictures_path, lighburn_path
    ) 
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `;

  db.run(sql, [
    orderNo, date, time, collection, orderStatus, product,
    priceNum, customerName, phone, sales, notes || null, dueDate,
    screenshotPath || null, picturesPath || null, lighburnPath || null
  ], function(err) {
    if (err) {
      console.error('Error inserting order:', err);
      return res.status(500).json({ error: 'Failed to create order' });
    }

    res.status(201).json({
      message: 'Order created successfully',
      order: {
        id: this.lastID,
        order_no: orderNo,
        date,
        time,
        collection,
        order_status: orderStatus,
        product,
        price: priceNum,
        customer_name: customerName,
        phone,
        sales,
        notes,
        due_date: dueDate,
        screenshot_path: screenshotPath,
        pictures_path: picturesPath,
        lighburn_path: lighburnPath
      }
    });
  });
});

// PUT endpoint to update order with file uploads (PROTECTED)
app.put('/api/orders/:id', authenticateToken, upload.fields([
  { name: 'screenshot', maxCount: 1 },
  { name: 'pictures', maxCount: 5 },
  { name: 'lighburn', maxCount: 1 }
]), async (req, res) => {
  const { id } = req.params;
  const { collection, orderStatus, product, price, customerName, phone, sales, notes, dueDate } = req.body;

  // Validation
  if (!collection || !orderStatus || !product || !price || !customerName || !phone || !sales || !dueDate) {
    return res.status(400).json({ error: 'Required fields are missing' });
  }

  // Validate phone number
  if (!phone.startsWith('+60')) {
    return res.status(400).json({ error: 'Phone number must start with +60' });
  }

  const priceNum = parseFloat(price);
  if (isNaN(priceNum) || priceNum < 0) {
    return res.status(400).json({ error: 'Invalid price' });
  }

  try {
    // Clean up old files if new ones are uploaded
    const files = req.files;
    if (files && Object.keys(files).length > 0) {
      await cleanupOldFiles(id);
    }

    // Process uploaded files
    let fileUpdateSQL = '';
    const fileValues = [];

    if (files?.screenshot?.[0]) {
      fileUpdateSQL += ', screenshot_path = ?';
      fileValues.push(files.screenshot[0].path);
    }
    if (files?.pictures?.length) {
      fileUpdateSQL += ', pictures_path = ?';
      fileValues.push(files.pictures.map(file => file.path).join(','));
    }
    if (files?.lighburn?.[0]) {
      fileUpdateSQL += ', lighburn_path = ?';
      fileValues.push(files.lighburn[0].path);
    }

    const sql = `
      UPDATE orders 
      SET collection = ?, order_status = ?, product = ?, price = ?, 
          customer_name = ?, phone = ?, sales = ?, notes = ?, due_date = ?,
          updated_at = CURRENT_TIMESTAMP${fileUpdateSQL}
      WHERE id = ?
    `;

    const values = [
      collection, orderStatus, product, priceNum,
      customerName, phone, sales, notes || null, dueDate,
      ...fileValues,
      id
    ];

    db.run(sql, values, function(err) {
      if (err) {
        console.error('Error updating order:', err);
        return res.status(500).json({ error: 'Failed to update order' });
      }

      if (this.changes === 0) {
        return res.status(404).json({ error: 'Order not found' });
      }

      res.json({ message: 'Order updated successfully' });
    });
  } catch (err) {
    console.error('Error during file cleanup:', err);
    res.status(500).json({ error: 'Failed to update order' });
  }
});

// DELETE endpoint to remove an order and its files (PROTECTED)
app.delete('/api/orders/:id', authenticateToken, async (req, res) => {
  const { id } = req.params;

  try {
    // Clean up files first
    await cleanupOldFiles(id);

    const sql = 'DELETE FROM orders WHERE id = ?';
    db.run(sql, [id], function(err) {
      if (err) {
        console.error('Error deleting order:', err);
        return res.status(500).json({ error: 'Failed to delete order' });
      }

      if (this.changes === 0) {
        return res.status(404).json({ error: 'Order not found' });
      }

      res.json({ message: 'Order deleted successfully' });
    });
  } catch (err) {
    console.error('Error during file cleanup:', err);
    res.status(500).json({ error: 'Failed to delete order' });
  }
});

// Download files endpoint (PROTECTED)
app.get('/api/orders/:id/files/:type', authenticateToken, (req, res) => {
  const { id, type } = req.params;
  
  const sql = 'SELECT * FROM orders WHERE id = ?';
  db.get(sql, [id], (err, order) => {
    if (err) {
      return res.status(500).json({ error: 'Failed to fetch order' });
    }
    
    if (!order) {
      return res.status(404).json({ error: 'Order not found' });
    }

    let filePath;
    switch (type) {
      case 'screenshot':
        filePath = order.screenshot_path;
        break;
      case 'pictures':
        filePath = order.pictures_path?.split(',')[0]; // Send first picture
        break;
      case 'lighburn':
        filePath = order.lighburn_path;
        break;
      default:
        return res.status(400).json({ error: 'Invalid file type' });
    }

    if (!filePath) {
      return res.status(404).json({ error: 'File not found' });
    }

    res.download(filePath);
  });
});

// Health check endpoint
app.get('/health', (req, res) => {
  res.json({ status: 'OK', timestamp: new Date().toISOString() });
});

// Start server
app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
  console.log('='.repeat(50));
  console.log('📝 Registration endpoints:');
  console.log(`   POST   http://localhost:${PORT}/api/register (public)`);
  console.log('');
  console.log('🔐 Admin endpoints:');
  console.log(`   POST   http://localhost:${PORT}/api/admin/login`);
  console.log(`   GET    http://localhost:${PORT}/api/admin/verify`);
  console.log(`   POST   http://localhost:${PORT}/api/admin/change-password`);
  console.log('');
  console.log('📊 Protected registration endpoints (require auth):');
  console.log(`   GET    http://localhost:${PORT}/api/registrations`);
  console.log(`   GET    http://localhost:${PORT}/api/registrations/:id`);
  console.log(`   DELETE http://localhost:${PORT}/api/registrations/:id`);
  console.log('');
  console.log('🛒 Protected order endpoints (require auth):');
  console.log(`   POST   http://localhost:${PORT}/api/orders`);
  console.log(`   GET    http://localhost:${PORT}/api/orders`);
  console.log(`   GET    http://localhost:${PORT}/api/orders/:id`);
  console.log(`   PUT    http://localhost:${PORT}/api/orders/:id`);
  console.log(`   DELETE http://localhost:${PORT}/api/orders/:id`);
  console.log(`   GET    http://localhost:${PORT}/api/orders/:id/files/:type`);
  console.log('='.repeat(50));
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