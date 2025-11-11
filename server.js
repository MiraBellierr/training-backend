require('dotenv').config();
const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const cors = require('cors');
const path = require('path');
const archiver = require('archiver');
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
    // Extract orderId from URL path if available (for PUT requests)
    const urlParts = req.url.split('/');
    const ordersIndex = urlParts.indexOf('orders');
    let orderId = 'temp';
    
    if (ordersIndex !== -1 && urlParts[ordersIndex + 1]) {
      // Extract the ID from URL (e.g., /api/orders/123)
      const potentialId = urlParts[ordersIndex + 1];
      if (!isNaN(potentialId)) {
        orderId = potentialId;
      }
    }
    
    const orderFolder = path.join(__dirname, 'uploads', orderId);
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

// Helper function to convert absolute path to relative path for database storage
function getRelativePath(absolutePath) {
  if (!absolutePath) return null;
  // Remove the base directory path, keep only uploads/... part
  const uploadsIndex = absolutePath.indexOf('uploads');
  if (uploadsIndex !== -1) {
    return absolutePath.substring(uploadsIndex);
  }
  return absolutePath;
}

// Helper function to get absolute path from relative path
function getAbsolutePath(relativePath) {
  if (!relativePath) return null;
  // If already absolute, return as is
  if (path.isAbsolute(relativePath)) {
    return relativePath;
  }
  return path.join(__dirname, relativePath);
}

// Utility function to clean up old files
async function cleanupOldFiles(orderId) {
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
      city TEXT,
      agensi TEXT,
      sales TEXT NOT NULL,
      due_date TEXT NOT NULL,
      notes TEXT,
      screenshot_path TEXT,
      pictures_path TEXT,
      lighburn_path TEXT,
      carbon_footprint REAL,
      quantity INTEGER DEFAULT 1,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
  `, (err) => {
    if (err) {
      console.error('Error creating orders table:', err);
    } else {
      console.log('Orders table ready');
      // Add carbon_footprint column if it doesn't exist (for existing databases)
      db.run(`ALTER TABLE orders ADD COLUMN carbon_footprint REAL`, (alterErr) => {
        if (alterErr) {
          // Column might already exist, ignore error
          if (!alterErr.message.includes('duplicate column')) {
            console.error('Note: carbon_footprint column may already exist');
          }
        } else {
          console.log('Added carbon_footprint column to orders table');
        }
      });
      
      // Add quantity column if it doesn't exist (for existing databases)
      db.run(`ALTER TABLE orders ADD COLUMN quantity INTEGER DEFAULT 1`, (alterErr) => {
        if (alterErr) {
          // Column might already exist, ignore error
          if (!alterErr.message.includes('duplicate column')) {
            console.error('Note: quantity column may already exist');
          }
        } else {
          console.log('Added quantity column to orders table');
        }
      });
      
      // Add city column if it doesn't exist (for existing databases)
      db.run(`ALTER TABLE orders ADD COLUMN city TEXT`, (alterErr) => {
        if (alterErr && !alterErr.message.includes('duplicate column')) {
          console.error('Note: city column may already exist');
        }
      });
      
      // Add agensi column if it doesn't exist (for existing databases)
      db.run(`ALTER TABLE orders ADD COLUMN agensi TEXT`, (alterErr) => {
        if (alterErr && !alterErr.message.includes('duplicate column')) {
          console.error('Note: agensi column may already exist');
        }
      });
    }
  });

  // Admin users table
  db.run(`
    CREATE TABLE IF NOT EXISTS admin_users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      email TEXT,
      phone TEXT,
      company TEXT,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
  `, (err) => {
    if (err) {
      console.error('Error creating admin_users table:', err);
    } else {
      console.log('Admin users table ready');
      
      // Add email, phone, and company columns if they don't exist (for existing databases)
      db.run(`ALTER TABLE admin_users ADD COLUMN email TEXT`, (alterErr) => {
        if (alterErr && !alterErr.message.includes('duplicate column')) {
          console.error('Note: email column may already exist');
        }
      });
      
      db.run(`ALTER TABLE admin_users ADD COLUMN phone TEXT`, (alterErr) => {
        if (alterErr && !alterErr.message.includes('duplicate column')) {
          console.error('Note: phone column may already exist');
        }
      });
      
      db.run(`ALTER TABLE admin_users ADD COLUMN company TEXT`, (alterErr) => {
        if (alterErr && !alterErr.message.includes('duplicate column')) {
          console.error('Note: company column may already exist');
        }
      });
      
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

// Generate unique order number with INV prefix in format: INVyear_month_numbering
async function generateOrderNumber(db) {
  const now = new Date();
  const year = now.getFullYear();
  const month = String(now.getMonth() + 1).padStart(2, '0');
  const prefix = `INV${year}_${month}_`;
  
  // Get the count of orders for this month
  return new Promise((resolve, reject) => {
    const sql = `SELECT COUNT(*) as count FROM orders WHERE order_no LIKE ?`;
    db.get(sql, [`${prefix}%`], (err, row) => {
      if (err) {
        reject(err);
      } else {
        const nextNumber = (row.count + 1).toString().padStart(4, '0');
        resolve(`${prefix}${nextNumber}`);
      }
    });
  });
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

// Get admin profile endpoint (PROTECTED)
app.get('/api/admin/profile', authenticateToken, (req, res) => {
  db.get(
    'SELECT id, username, email, phone, company, created_at FROM admin_users WHERE id = ?',
    [req.user.id],
    (err, user) => {
      if (err) {
        console.error('Database error:', err);
        return res.status(500).json({ error: 'Server error' });
      }

      if (!user) {
        return res.status(404).json({ error: 'User not found' });
      }

      res.json({
        username: user.username,
        email: user.email || `${user.username}@aanguscraft.com`,
        phone: user.phone || '+60123456789',
        role: 'Administrator',
        company: user.company || 'Aangus Craft',
        created_at: user.created_at
      });
    }
  );
});

// Update admin profile endpoint (PROTECTED)
app.put('/api/admin/profile', authenticateToken, async (req, res) => {
  const { username, email, phone, company } = req.body;

  if (!username) {
    return res.status(400).json({ error: 'Username is required' });
  }

  // Validate email format if provided
  if (email && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    return res.status(400).json({ error: 'Invalid email format' });
  }

  // Validate phone format if provided (basic validation)
  if (phone && phone.length < 10) {
    return res.status(400).json({ error: 'Invalid phone number' });
  }

  // Check if new username is already taken by another user
  db.get(
    'SELECT * FROM admin_users WHERE username = ? AND id != ?',
    [username, req.user.id],
    (err, existingUser) => {
      if (err) {
        console.error('Database error:', err);
        return res.status(500).json({ error: 'Server error' });
      }

      if (existingUser) {
        return res.status(400).json({ error: 'Username already taken' });
      }

      // Check if new email is already taken by another user
      if (email) {
        db.get(
          'SELECT * FROM admin_users WHERE email = ? AND id != ?',
          [email, req.user.id],
          (err, existingEmail) => {
            if (err) {
              console.error('Database error:', err);
              return res.status(500).json({ error: 'Server error' });
            }

            if (existingEmail) {
              return res.status(400).json({ error: 'Email already in use' });
            }

            // Update all profile fields
            db.run(
              'UPDATE admin_users SET username = ?, email = ?, phone = ?, company = ? WHERE id = ?',
              [username, email, phone, company, req.user.id],
              (err) => {
                if (err) {
                  console.error('Error updating profile:', err);
                  return res.status(500).json({ error: 'Failed to update profile' });
                }

                res.json({
                  message: 'Profile updated successfully',
                  username: username,
                  email: email,
                  phone: phone,
                  company: company
                });
              }
            );
          }
        );
      } else {
        // Update without email validation
        db.run(
          'UPDATE admin_users SET username = ?, email = ?, phone = ?, company = ? WHERE id = ?',
          [username, email, phone, company, req.user.id],
          (err) => {
            if (err) {
              console.error('Error updating profile:', err);
              return res.status(500).json({ error: 'Failed to update profile' });
            }

            res.json({
              message: 'Profile updated successfully',
              username: username,
              email: email,
              phone: phone,
              company: company
            });
          }
        );
      }
    }
  );
});

// List all admin users endpoint (PROTECTED)
app.get('/api/admin/list', authenticateToken, (req, res) => {
  const sql = 'SELECT id, username, email, phone, company, created_at FROM admin_users ORDER BY created_at DESC';

  db.all(sql, [], (err, rows) => {
    if (err) {
      console.error('Error fetching admins:', err);
      return res.status(500).json({ error: 'Failed to fetch admin users' });
    }

    // Format the response
    const admins = rows.map(admin => ({
      id: admin.id,
      username: admin.username,
      email: admin.email || `${admin.username}@aanguscraft.com`,
      phone: admin.phone || '',
      company: admin.company || '',
      created_at: admin.created_at
    }));

    res.json(admins);
  });
});

// Delete admin user endpoint (PROTECTED)
app.delete('/api/admin/:id', authenticateToken, (req, res) => {
  const { id } = req.params;

  // Prevent self-deletion
  if (parseInt(id) === req.user.id) {
    return res.status(400).json({ error: 'Cannot delete your own account' });
  }

  const sql = 'DELETE FROM admin_users WHERE id = ?';

  db.run(sql, [id], function(err) {
    if (err) {
      console.error('Error deleting admin:', err);
      return res.status(500).json({ error: 'Failed to delete admin user' });
    }

    if (this.changes === 0) {
      return res.status(404).json({ error: 'Admin user not found' });
    }

    res.json({ message: 'Admin user deleted successfully' });
  });
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

// GET endpoint to retrieve unique customers with their details (PROTECTED)
app.get('/api/customers', authenticateToken, (req, res) => {
  const sql = `
    SELECT DISTINCT 
      customer_name, 
      phone, 
      city, 
      agensi,
      MAX(created_at) as last_order_date
    FROM orders 
    GROUP BY customer_name, phone, city, agensi
    ORDER BY last_order_date DESC
  `;

  db.all(sql, [], (err, rows) => {
    if (err) {
      console.error('Error fetching customers:', err);
      return res.status(500).json({ error: 'Failed to fetch customers' });
    }

    res.json(rows);
  });
});

// POST endpoint to create new order with file uploads (PROTECTED)
app.post('/api/orders', authenticateToken, upload.fields([
  { name: 'screenshot', maxCount: 100 },
  { name: 'pictures', maxCount: 100 },
  { name: 'lighburn', maxCount: 100 }
]), async (req, res) => {
  console.log('Received order creation request');
  console.log('Files received:', req.files ? Object.keys(req.files) : 'No files');
  
  const { collection, orderStatus, product, price, customerName, phone, city, agensi, sales, notes, dueDate, quantity } = req.body;

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

  // Validate quantity
  const quantityNum = quantity ? parseInt(quantity) : 1;
  if (isNaN(quantityNum) || quantityNum < 1) {
    return res.status(400).json({ error: 'Invalid quantity' });
  }

  // Process uploaded files
  const files = req.files;
  const screenshotPath = files?.screenshot?.[0]?.path;
  const picturesPath = files?.pictures?.map(file => file.path).join(',');
  const lighburnPath = files?.lighburn?.[0]?.path;

  // Generate order details
  let orderNo;
  try {
    orderNo = await generateOrderNumber(db);
  } catch (err) {
    console.error('Error generating order number:', err);
    return res.status(500).json({ error: 'Failed to generate order number' });
  }
  const date = formatDateGMT8();
  const time = formatTimeGMT8();

  const sql = `
    INSERT INTO orders (
      order_no, date, time, collection, order_status, product, 
      price, customer_name, phone, city, agensi, sales, notes, due_date,
      screenshot_path, pictures_path, lighburn_path, quantity
    ) 
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `;

  db.run(sql, [
    orderNo, date, time, collection, orderStatus, product,
    priceNum, customerName, phone, city || null, agensi || null, sales, notes || null, dueDate,
    getRelativePath(screenshotPath), getRelativePath(picturesPath), getRelativePath(lighburnPath), quantityNum
  ], async function(err) {
    if (err) {
      console.error('Error inserting order:', err);
      return res.status(500).json({ error: 'Failed to create order' });
    }

    const orderId = this.lastID;

    // Move files from temp to actual order folder
    try {
      const tempFolder = path.join(__dirname, 'uploads', 'temp');
      const orderFolder = path.join(__dirname, 'uploads', orderId.toString());
      
      if (fs.existsSync(tempFolder)) {
        // Create order folder
        fs.mkdirSync(orderFolder, { recursive: true });
        
        // Move files and update paths
        let newScreenshotPath = screenshotPath;
        let newPicturesPath = picturesPath;
        let newLighburnPath = lighburnPath;

        if (screenshotPath) {
          const filename = path.basename(screenshotPath);
          const newPath = path.join(orderFolder, filename);
          fs.renameSync(screenshotPath, newPath);
          newScreenshotPath = getRelativePath(newPath);
        }

        if (picturesPath) {
          const picturePaths = picturesPath.split(',');
          const newPicturePaths = picturePaths.map(picPath => {
            const filename = path.basename(picPath);
            const newPath = path.join(orderFolder, filename);
            fs.renameSync(picPath, newPath);
            return getRelativePath(newPath);
          });
          newPicturesPath = newPicturePaths.join(',');
        }

        if (lighburnPath) {
          const filename = path.basename(lighburnPath);
          const newPath = path.join(orderFolder, filename);
          fs.renameSync(lighburnPath, newPath);
          newLighburnPath = getRelativePath(newPath);
        }

        // Update database with new paths (already relative)
        const updateSql = 'UPDATE orders SET screenshot_path = ?, pictures_path = ?, lighburn_path = ? WHERE id = ?';
        db.run(updateSql, [newScreenshotPath, newPicturesPath, newLighburnPath, orderId], (updateErr) => {
          if (updateErr) {
            console.error('Error updating file paths:', updateErr);
          }
        });

        // Clean up temp folder
        try {
          fs.rmdirSync(tempFolder);
        } catch (e) {
          // Ignore if folder not empty or doesn't exist
        }
      }
    } catch (moveErr) {
      console.error('Error moving files:', moveErr);
      // Continue even if file move fails
    }

    res.status(201).json({
      message: 'Order created successfully',
      order: {
        id: orderId,
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
  { name: 'screenshot', maxCount: 100 },
  { name: 'pictures', maxCount: 100 },
  { name: 'lighburn', maxCount: 100 }
]), async (req, res) => {
  const { id } = req.params;
  const { collection, orderStatus, product, price, customerName, phone, city, agensi, sales, notes, dueDate, carbonFootprint, quantity } = req.body;

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

  // Parse carbon footprint if provided
  const carbonFootprintNum = carbonFootprint ? parseFloat(carbonFootprint) : null;
  if (carbonFootprint && (isNaN(carbonFootprintNum) || carbonFootprintNum < 0)) {
    return res.status(400).json({ error: 'Invalid carbon footprint value' });
  }

  // Validate quantity
  const quantityNum = quantity ? parseInt(quantity) : 1;
  if (isNaN(quantityNum) || quantityNum < 1) {
    return res.status(400).json({ error: 'Invalid quantity' });
  }

  try {
    // Clean up old files if new ones are uploaded
    const files = req.files;
    if (files && Object.keys(files).length > 0) {
      await cleanupOldFiles(id);
    }

    // Process uploaded files - store relative paths
    let fileUpdateSQL = '';
    const fileValues = [];

    if (files?.screenshot?.[0]) {
      fileUpdateSQL += ', screenshot_path = ?';
      fileValues.push(getRelativePath(files.screenshot[0].path));
    }
    if (files?.pictures?.length) {
      fileUpdateSQL += ', pictures_path = ?';
      const relativePaths = files.pictures.map(file => getRelativePath(file.path)).join(',');
      fileValues.push(relativePaths);
    }
    if (files?.lighburn?.[0]) {
      fileUpdateSQL += ', lighburn_path = ?';
      fileValues.push(getRelativePath(files.lighburn[0].path));
    }

    const sql = `
      UPDATE orders 
      SET collection = ?, order_status = ?, product = ?, price = ?, 
          customer_name = ?, phone = ?, city = ?, agensi = ?, sales = ?, notes = ?, due_date = ?,
          carbon_footprint = ?, quantity = ?,
          updated_at = CURRENT_TIMESTAMP${fileUpdateSQL}
      WHERE id = ?
    `;

    const values = [
      collection, orderStatus, product, priceNum,
      customerName, phone, city || null, agensi || null, sales, notes || null, dueDate,
      carbonFootprintNum, quantityNum,
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

// Download files endpoint (PROTECTED) - returns zip for multiple files
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

    let relativePaths = [];
    let zipFileName = '';
    
    switch (type) {
      case 'screenshot':
        if (order.screenshot_path) {
          relativePaths = order.screenshot_path.split(',').filter(p => p);
        }
        zipFileName = `order_${order.order_no}_screenshots.zip`;
        break;
      case 'pictures':
        if (order.pictures_path) {
          relativePaths = order.pictures_path.split(',').filter(p => p);
        }
        zipFileName = `order_${order.order_no}_pictures.zip`;
        break;
      case 'lighburn':
        if (order.lighburn_path) {
          relativePaths = order.lighburn_path.split(',').filter(p => p);
        }
        zipFileName = `order_${order.order_no}_lighburn.zip`;
        break;
      default:
        return res.status(400).json({ error: 'Invalid file type' });
    }

    if (relativePaths.length === 0) {
      return res.status(404).json({ error: 'No files found' });
    }

    // Convert relative paths to absolute paths and check if they exist
    const existingPaths = absolutePaths.filter(p => fs.existsSync(p));
    
    if (existingPaths.length === 0) {
      console.error('No files found on server');
      return res.status(404).json({ error: 'Files not found on server' });
    }

    // If only one file, send it directly
    if (existingPaths.length === 1) {
      return res.download(existingPaths[0]);
    }

    // Multiple files - create zip
    res.setHeader('Content-Type', 'application/zip');
    res.setHeader('Content-Disposition', `attachment; filename="${zipFileName}"`);

    const archive = archiver('zip', {
      zlib: { level: 9 } // Maximum compression
    });

    archive.on('error', (err) => {
      console.error('Archive error:', err);
      res.status(500).json({ error: 'Failed to create zip file' });
    });

    // Pipe archive to response
    archive.pipe(res);

    // Add files to archive
    existingPaths.forEach((filePath, index) => {
      const fileName = path.basename(filePath);
      archive.file(filePath, { name: fileName });
    });

    // Finalize archive
    archive.finalize();
  });
});

// Health check endpoint
app.get('/health', (req, res) => {
  res.json({ status: 'OK', timestamp: new Date().toISOString() });
});

// Error handling middleware for multer
app.use((err, req, res, next) => {
  if (err instanceof multer.MulterError) {
    console.error('Multer error:', err);
    if (err.code === 'LIMIT_FILE_SIZE') {
      return res.status(400).json({ error: 'File size too large. Maximum is 10MB.' });
    }
    return res.status(400).json({ error: `Upload error: ${err.message}` });
  } else if (err) {
    console.error('General error:', err);
    return res.status(500).json({ error: err.message || 'An error occurred' });
  }
  next();
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
  console.log(`   POST   http://localhost:${PORT}/api/admin/create`);
  console.log(`   GET    http://localhost:${PORT}/api/admin/verify`);
  console.log(`   GET    http://localhost:${PORT}/api/admin/profile`);
  console.log(`   PUT    http://localhost:${PORT}/api/admin/profile`);
  console.log(`   GET    http://localhost:${PORT}/api/admin/list`);
  console.log(`   DELETE http://localhost:${PORT}/api/admin/:id`);
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
  console.log(`   GET    http://localhost:${PORT}/api/customers`);
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